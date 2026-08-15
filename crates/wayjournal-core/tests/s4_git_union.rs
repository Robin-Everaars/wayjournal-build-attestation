#[allow(dead_code)]
mod support;

use std::{
    collections::BTreeSet,
    fs,
    io::{BufWriter, Write},
    mem::MaybeUninit,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

use serde_json::json;
use wayjournal_core::{
    ActorId, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, DomainRegistration,
    DomainRegistry, GitQuarantineReason, GitSyncError, GitSyncOutcome, GitSyncRequest, KindId,
    LegacyEntry, LegacyEntrySource, LegacyStoreAdapter, LegacyStreamRequirement,
    LegacyStreamingError, LocalTrustBinding, MAX_RECORD_BYTES, Record, Store, prepare_batch,
    wayjournal_domain_registry, wayjournal_domain_registry_with,
};

use support::BoundedNoLegacy as NoLegacy;

#[derive(Debug)]
struct CollectingLegacy;
impl LegacyStoreAdapter for CollectingLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug)]
struct NonDrainingStreamingLegacy;
impl LegacyStoreAdapter for NonDrainingStreamingLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
    }

    fn require_streaming(&self, _: LegacyStreamRequirement) -> Result<(), LegacyStreamingError> {
        Ok(())
    }

    fn validate_stream(
        &self,
        _: LegacyStreamRequirement,
        _: &mut dyn LegacyEntrySource,
    ) -> Result<(), LegacyStreamingError> {
        Ok(())
    }
}

type ObservedLegacyStream = (LegacyStreamRequirement, BTreeSet<Vec<u8>>);
type ObservedLegacyStreams = Arc<Mutex<Vec<ObservedLegacyStream>>>;

#[derive(Debug)]
struct ObservingStreamingLegacy {
    seen: ObservedLegacyStreams,
}
impl LegacyStoreAdapter for ObservingStreamingLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
    }

    fn require_streaming(&self, _: LegacyStreamRequirement) -> Result<(), LegacyStreamingError> {
        Ok(())
    }

    fn validate_stream(
        &self,
        requirement: LegacyStreamRequirement,
        source: &mut dyn LegacyEntrySource,
    ) -> Result<(), LegacyStreamingError> {
        self.require_streaming(requirement)?;
        let mut paths = BTreeSet::new();
        while let Some(entry) = source.next_entry().map_err(LegacyStreamingError::Source)? {
            paths.insert(entry.path().to_vec());
        }
        self.seen
            .lock()
            .expect("seen lock")
            .push((requirement, paths));
        Ok(())
    }
}

struct TestDir(PathBuf);
impl TestDir {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("wayjournal-s4b-{label}-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git() -> PathBuf {
    PathBuf::from(std::env::var_os("WAYJOURNAL_TEST_GIT").expect("Git"))
}
fn run(cwd: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new(git())
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("Git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn run_with_input(cwd: &Path, args: &[&str], input: &[u8]) -> Vec<u8> {
    let mut child = Command::new(git())
        .current_dir(cwd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Git");
    child
        .stdin
        .take()
        .expect("Git stdin")
        .write_all(input)
        .expect("write Git stdin");
    let output = child.wait_with_output().expect("Git output");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn mktree(cwd: &Path, git_dir: &Path, entries: &[u8]) -> String {
    String::from_utf8(run_with_input(
        cwd,
        &["--git-dir", git_dir.to_str().expect("git dir"), "mktree"],
        entries,
    ))
    .expect("UTF-8")
    .trim()
    .to_owned()
}

fn oid(cwd: &Path, value: &str) -> String {
    String::from_utf8(run(cwd, &["rev-parse", value]))
        .expect("UTF-8")
        .trim()
        .to_owned()
}
fn configure(cwd: &Path) {
    run(cwd, &["config", "user.name", "Wayjournal Test"]);
    run(cwd, &["config", "user.email", "wayjournal@example.invalid"]);
}
struct TransferProbe {
    descriptor: rustix::fd::OwnedFd,
    watch: i32,
}

fn install_transfer_probe(remote: &Path) -> TransferProbe {
    use rustix::fs::inotify;

    let path = remote.join("objects/info/alternates");
    fs::write(&path, b"wayjournal-contact-probe\n").expect("install transfer probe");
    let descriptor = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)
        .expect("create transfer probe");
    let watch = inotify::add_watch(&descriptor, &path, inotify::WatchFlags::OPEN)
        .expect("watch transfer probe");
    TransferProbe { descriptor, watch }
}

fn transfer_probe_contacted(probe: &TransferProbe) -> bool {
    use rustix::fs::inotify;

    let mut buffer = [MaybeUninit::uninit(); 256];
    let mut reader = inotify::Reader::new(&probe.descriptor, &mut buffer);
    loop {
        match reader.next() {
            Ok(event)
                if event.wd() == probe.watch
                    && event.events().contains(inotify::ReadFlags::OPEN) =>
            {
                return true;
            }
            Ok(_) => {}
            Err(rustix::io::Errno::AGAIN) => return false,
            Err(error) => panic!("read transfer probe: {error}"),
        }
    }
}

fn request(remote: &Path) -> GitSyncRequest {
    request_with_git(remote, git())
}

fn request_with_git(remote: &Path, executable: PathBuf) -> GitSyncRequest {
    GitSyncRequest::new(
        executable,
        LocalTrustBinding::parse(
            "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        )
        .expect("trust"),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(url::Url::from_file_path(remote).expect("URL").as_str())
                .expect("locator"),
            ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
    )
    .expect("request")
}

fn genesis() -> Record {
    Record {
        record_schema: "wayjournal.identity/v1".parse().expect("schema"),
        domain: "wayjournal.identity".parse().expect("domain"),
        kind: "store.genesis".parse().expect("kind"),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174011"
            .parse()
            .expect("record"),
        entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010"
            .parse()
            .expect("entity"),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174012"
            .parse()
            .expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: Vec::new(),
        payload: json!({"store_kind":"wayjournal.personal","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"}),
    }
}

fn validate_bulk(kind: &KindId, payload: &serde_json::Value) -> Result<(), String> {
    if kind.as_str() != "bulk.write"
        || payload
            .as_object()
            .and_then(|value| value.get("blob"))
            .and_then(serde_json::Value::as_str)
            .is_none()
        || payload.as_object().is_none_or(|value| value.len() != 1)
    {
        return Err("bulk payload must contain only a blob string".to_owned());
    }
    Ok(())
}
static BULK_KINDS: &[&str] = &["bulk.write"];
static BULK_REGISTRATION: &[DomainRegistration] = &[DomainRegistration::new(
    "example.bulk",
    "example.bulk/v1",
    BULK_KINDS,
    validate_bulk,
)];
const MAX_PATH_DOMAIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.c";
const MAX_PATH_SCHEMA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.c/v1";
static MAX_PATH_REGISTRATION: &[DomainRegistration] = &[DomainRegistration::new(
    MAX_PATH_DOMAIN,
    MAX_PATH_SCHEMA,
    BULK_KINDS,
    validate_bulk,
)];

fn bulk_record(record: &str, batch: &str, entity: &str, blob_bytes: usize) -> Record {
    Record {
        record_schema: "example.bulk/v1".parse().expect("schema"),
        domain: "example.bulk".parse().expect("domain"),
        kind: "bulk.write".parse().expect("kind"),
        record_id: record.parse().expect("record"),
        entity_id: entity.parse().expect("entity"),
        batch_id: batch.parse().expect("batch"),
        actor: ActorId::parse("system:bulk-gate").expect("actor"),
        occurred_at: "2026-08-12T13:01:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:02:00Z".parse().expect("time"),
        parents: Vec::new(),
        payload: json!({"blob":"x".repeat(blob_bytes)}),
    }
}

fn profile(record: &str, batch: &str, value: &str, second: u8) -> Record {
    profile_for_entity(
        record,
        batch,
        "01913f1d-8e2a-7c30-8f4a-426614174010",
        value,
        second,
    )
}

fn profile_for_entity(record: &str, batch: &str, entity: &str, value: &str, second: u8) -> Record {
    Record {
        record_schema: "wayjournal.profile/v1".parse().expect("schema"),
        domain: "wayjournal.profile".parse().expect("domain"),
        kind: "profile.display_name.set".parse().expect("kind"),
        record_id: record.parse().expect("record"),
        entity_id: entity.parse().expect("entity"),
        batch_id: batch.parse().expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: format!("2026-08-12T13:01:{second:02}Z")
            .parse()
            .expect("time"),
        recorded_at: format!("2026-08-12T13:02:{second:02}Z")
            .parse()
            .expect("time"),
        parents: Vec::new(),
        payload: json!({"value":value}),
    }
}

struct Fixture {
    root: TestDir,
    remote: PathBuf,
    local: PathBuf,
    store: Store,
    request: GitSyncRequest,
}
fn fixture(label: &str) -> Fixture {
    fixture_with_legacy(label, Arc::new(NoLegacy))
}

fn fixture_with_legacy(label: &str, legacy: Arc<dyn LegacyStoreAdapter>) -> Fixture {
    fixture_with_registry(
        label,
        wayjournal_domain_registry().expect("registry"),
        legacy,
    )
}

fn fixture_with_registry(
    label: &str,
    registry: DomainRegistry,
    legacy: Arc<dyn LegacyStoreAdapter>,
) -> Fixture {
    let root = TestDir::new(label);
    let remote = root.0.join("remote.git");
    run(
        &root.0,
        &["init", "--bare", remote.to_str().expect("remote")],
    );
    let local = root.0.join("local");
    fs::create_dir(&local).expect("local");
    let store = Store::open(&local, registry, legacy).expect("store");
    let batch = prepare_batch(&[genesis()], "genesis", &registry).expect("batch");
    store
        .append(&batch, store.read().expect("read").revision())
        .expect("append");
    run(&local, &["init", "-b", "main"]);
    configure(&local);
    run(&local, &["add", "events", "batches", "journal"]);
    run(&local, &["commit", "-m", "genesis"]);
    run(
        &local,
        &[
            "push",
            remote.to_str().expect("remote"),
            "HEAD:refs/heads/main",
        ],
    );
    run(
        &root.0,
        &[
            "--git-dir",
            remote.to_str().expect("remote"),
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ],
    );
    let request = request(&remote);
    store.bootstrap_git_admission(&request).expect("bootstrap");
    Fixture {
        root,
        remote,
        local,
        store,
        request,
    }
}

#[test]
fn collecting_adapter_is_rejected_before_transfer_or_mutation() {
    let fixture = fixture_with_legacy("collecting-adapter-gate", Arc::new(CollectingLegacy));
    let remote_before = oid(&fixture.remote, "refs/heads/main");
    let checkpoint = fixture
        .local
        .join(".wayjournal-local/checkpoints/admission-v1.json");
    let checkpoint_before = fs::read(&checkpoint).expect("checkpoint");
    let pending = fixture.local.join(".wayjournal-local/sync-pending");
    let quarantine = fixture.local.join(".wayjournal-local/quarantine");
    let attempts = fixture.local.join(".wayjournal-local/admission-attempts");
    let names = |path: &Path| {
        let mut names = fs::read_dir(path)
            .expect("directory")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let pending_before = names(&pending);
    let quarantine_before = names(&quarantine);
    let attempts_before = names(&attempts);

    assert!(matches!(
        fixture.store.sync_git_union(&fixture.request),
        Err(GitSyncError::LegacyStreaming(
            wayjournal_core::LegacyStreamingError::UnsupportedFullDomain
        ))
    ));
    assert_eq!(oid(&fixture.remote, "refs/heads/main"), remote_before);
    assert_eq!(fs::read(checkpoint).expect("checkpoint"), checkpoint_before);
    assert_eq!(names(&pending), pending_before);
    assert_eq!(names(&quarantine), quarantine_before);
    assert_eq!(names(&attempts), attempts_before);
}

#[test]
fn bounded_adapter_must_consume_every_legacy_entry() {
    const LEGACY: &str =
        "events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174040.json";
    let fixture = fixture_with_legacy("stream-must-drain", Arc::new(NonDrainingStreamingLegacy));
    let clone = fixture.root.0.join("stream-must-drain-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    let target = clone.join(LEGACY);
    fs::create_dir_all(target.parent().expect("legacy parent")).expect("legacy parent");
    fs::write(&target, b"legacy").expect("legacy entry");
    run(&clone, &["add", LEGACY]);
    run(&clone, &["commit", "-m", "legacy"]);
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);

    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("closed quarantine outcome"),
        GitSyncOutcome::Quarantined {
            reason: GitQuarantineReason::InvalidCommitSnapshot,
            ..
        }
    ));
}

#[test]
fn hostile_snapshot_bounds_in_new_history_quarantine_durably() {
    for kind in ["oversized-canonical-blob", "overlong-tree-record"] {
        let fixture = fixture(&format!("history-{kind}"));
        let clone = fixture.root.0.join(format!("history-{kind}-writer"));
        run(
            &fixture.root.0,
            &[
                "clone",
                fixture.remote.to_str().expect("remote"),
                clone.to_str().expect("clone"),
            ],
        );
        configure(&clone);
        match kind {
            "overlong-tree-record" => {
                let component = "a".repeat(200);
                let path = clone
                    .join("journal/records")
                    .join(&component)
                    .join(&component)
                    .join("b".repeat(40))
                    .join("entry.json");
                fs::create_dir_all(path.parent().expect("hostile path parent")).unwrap();
                fs::write(&path, b"{}\n").unwrap();
                run(&clone, &["add", "journal"]);
            }
            "oversized-canonical-blob" => {
                let registry = wayjournal_domain_registry().unwrap();
                let prepared = prepare_batch(
                    &[profile(
                        "01913f1d-8e2a-7c30-8f4a-426614174070",
                        "01913f1d-8e2a-7c30-8f4a-426614174071",
                        "oversized",
                        0,
                    )],
                    "oversized-history",
                    &registry,
                )
                .unwrap();
                fs::create_dir_all(
                    clone
                        .join(prepared.records()[0].path())
                        .parent()
                        .expect("record parent"),
                )
                .unwrap();
                fs::write(
                    clone.join(prepared.records()[0].path()),
                    vec![b'x'; MAX_RECORD_BYTES + 1],
                )
                .unwrap();
                fs::create_dir_all(
                    clone
                        .join(prepared.manifest_path())
                        .parent()
                        .expect("manifest parent"),
                )
                .unwrap();
                fs::write(
                    clone.join(prepared.manifest_path()),
                    prepared.manifest_bytes(),
                )
                .unwrap();
                run(&clone, &["add", "journal"]);
            }
            _ => unreachable!(),
        }
        run(&clone, &["commit", "-m", kind]);
        run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);

        let first = fixture.store.sync_git_union(&fixture.request).unwrap();
        let GitSyncOutcome::Quarantined {
            incident_id,
            reason: GitQuarantineReason::InvalidCommitSnapshot,
        } = first
        else {
            panic!("{kind} was not quarantined: {first:?}")
        };
        assert!(matches!(
            fixture.store.sync_git_union(&fixture.request).unwrap(),
            GitSyncOutcome::Quarantined {
                incident_id: retry,
                reason: GitQuarantineReason::InvalidCommitSnapshot,
            } if retry == incident_id
        ));
    }
}

#[test]
fn every_intermediate_tree_uses_full_domain_streaming_validation() {
    const LEGACY_A: &str =
        "events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174041.json";
    const LEGACY_B: &str =
        "events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174042.json";

    let seen = Arc::new(Mutex::new(Vec::new()));
    let fixture = fixture_with_legacy(
        "stream-every-tree",
        Arc::new(ObservingStreamingLegacy {
            seen: Arc::clone(&seen),
        }),
    );
    let clone = fixture.root.0.join("stream-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    for (path, value) in [(LEGACY_A, b"one".as_slice()), (LEGACY_B, b"two".as_slice())] {
        let target = clone.join(path);
        fs::create_dir_all(target.parent().expect("legacy parent")).expect("legacy parent");
        fs::write(&target, value).expect("legacy entry");
        run(&clone, &["add", path]);
        run(&clone, &["commit", "-m", path]);
    }
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);

    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("sync"),
        GitSyncOutcome::Advanced { .. }
    ));
    let observed = seen.lock().expect("seen lock");
    let first = BTreeSet::from([LEGACY_A.as_bytes().to_vec()]);
    let both = BTreeSet::from([LEGACY_A.as_bytes().to_vec(), LEGACY_B.as_bytes().to_vec()]);
    assert!(
        observed.iter().any(|(requirement, paths)| {
            *requirement == LegacyStreamRequirement::FullDomainBounded && paths == &first
        }),
        "first intermediate tree was not full-domain stream-validated: {observed:?}"
    );
    assert!(
        observed.iter().any(|(requirement, paths)| {
            *requirement == LegacyStreamRequirement::FullDomainBounded && paths == &both
        }),
        "second intermediate tree was not full-domain stream-validated: {observed:?}"
    );
}

fn clone_store(root: &Path, remote: &Path, name: &str) -> (PathBuf, Store, GitSyncRequest) {
    run(root, &["clone", remote.to_str().expect("remote"), name]);
    let path = root.join(name);
    configure(&path);
    run(&path, &["remote", "remove", "origin"]);
    let store = Store::open(
        &path,
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    )
    .expect("store");
    let request = request(remote);
    store.bootstrap_git_admission(&request).expect("bootstrap");
    (path, store, request)
}

fn append_profile(store: &Store, path: &Path, record: Record, key: &str) {
    let registry = wayjournal_domain_registry().expect("registry");
    let prepared = prepare_batch(&[record], key, &registry).expect("batch");
    store
        .append(&prepared, store.read().expect("read").revision())
        .expect("append");
    run(path, &["add", "journal"]);
    run(path, &["commit", "-m", key]);
}

#[test]
fn hostile_git_entry_quarantines_before_transfer_or_pending_mutation() {
    let fixture = fixture("hostile-git-entry-quarantine");
    let retained = fixture.local.join(".git.retained");
    fs::rename(fixture.local.join(".git"), &retained).unwrap();
    std::os::unix::fs::symlink(&retained, fixture.local.join(".git")).unwrap();
    let probe = install_transfer_probe(&fixture.remote);

    assert!(matches!(
        fixture.store.sync_git_union(&fixture.request).unwrap(),
        GitSyncOutcome::Quarantined {
            reason: GitQuarantineReason::UnsafeRepositoryState,
            ..
        }
    ));
    assert!(
        !transfer_probe_contacted(&probe),
        "hostile .git contacted remote"
    );
    assert_eq!(
        fs::read_dir(fixture.local.join(".wayjournal-local/sync-pending"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn linked_worktree_advances_and_publishes_through_the_common_repository() {
    let fixture = fixture("linked-advance");
    run(&fixture.local, &["checkout", "--detach"]);
    let linked = fixture.root.0.join("linked");
    run(
        &fixture.local,
        &[
            "worktree",
            "add",
            linked.to_str().expect("linked path"),
            "main",
        ],
    );
    let linked_store = Store::open(
        &linked,
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    )
    .expect("linked store");
    linked_store
        .bootstrap_git_admission(&fixture.request)
        .expect("linked bootstrap");

    let (writer_path, writer, _) = clone_store(&fixture.root.0, &fixture.remote, "writer");
    run(
        &writer_path,
        &[
            "remote",
            "add",
            "origin",
            fixture.remote.to_str().expect("remote"),
        ],
    );
    append_profile(
        &writer,
        &writer_path,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174021",
            "01913f1d-8e2a-7c30-8f4a-426614174022",
            "linked advance",
            3,
        ),
        "linked-advance",
    );
    run(&writer_path, &["push", "origin", "HEAD:refs/heads/main"]);

    assert!(matches!(
        linked_store.sync_git_union(&fixture.request).expect("sync"),
        GitSyncOutcome::Advanced { .. }
    ));
    assert_eq!(oid(&linked, "HEAD"), oid(&fixture.local, "refs/heads/main"));
    assert!(
        !fixture
            .local
            .join(".git/refs/wayjournal/candidate")
            .exists()
    );
}

#[test]
fn api_contract_red() {
    fn assert_sync_api(
        store: &Store,
        request: &GitSyncRequest,
    ) -> Result<GitSyncOutcome, GitSyncError> {
        store.sync_git_union(request)
    }
    let _ = assert_sync_api;
}

#[test]
fn history_requires_checkpoint_ancestry_for_both_tips() {
    let fixture = fixture("rollback");
    let cloneroot = fixture.root.0.join("rollback-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            cloneroot.to_str().expect("clone"),
        ],
    );
    configure(&cloneroot);
    let tree = oid(&cloneroot, "HEAD^{tree}");
    let unrelated = String::from_utf8(run(&cloneroot, &["commit-tree", &tree, "-m", "unrelated"]))
        .expect("UTF-8")
        .trim()
        .to_owned();
    run(
        &cloneroot,
        &[
            "push",
            "--force",
            "origin",
            &format!("{unrelated}:refs/heads/main"),
        ],
    );
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("typed"),
        GitSyncOutcome::Quarantined {
            reason: GitQuarantineReason::RollbackNonAncestry,
            ..
        }
    ));
}

#[test]
fn history_rejects_delete_modify_and_restore() {
    let fixture = fixture("delete-restore");
    let clone = fixture.root.0.join("delete-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    let record = "journal/records/wayjournal.identity/01913f1d-8e2a-7c30-8f4a-426614174010/01913f1d-8e2a-7c30-8f4a-426614174011.json";
    run(&clone, &["rm", record]);
    run(&clone, &["commit", "-m", "delete"]);
    run(&clone, &["checkout", "HEAD^", "--", record]);
    run(&clone, &["commit", "-am", "restore"]);
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);
    let first = fixture
        .store
        .sync_git_union(&fixture.request)
        .expect("typed");
    let GitSyncOutcome::Quarantined {
        incident_id,
        reason: GitQuarantineReason::Deletion,
    } = first
    else {
        panic!("deletion did not durably quarantine")
    };
    // Removing the remote makes any retry transfer observable as a failure. Durable quarantine
    // must return the identical incident before attempting Git/network work.
    fs::rename(&fixture.remote, fixture.root.0.join("remote-unavailable")).unwrap();
    assert!(matches!(
        fixture.store.sync_git_union(&fixture.request).expect("blocked before transfer"),
        GitSyncOutcome::Quarantined { incident_id: retry, reason: GitQuarantineReason::Deletion }
            if retry == incident_id
    ));
}

#[test]
fn every_intermediate_commit_is_a_complete_store() {
    let fixture = fixture("partial-intermediate");
    let (clone, store, _) = clone_store(&fixture.root.0, &fixture.remote, "partial-clone");
    let registry = wayjournal_domain_registry().expect("registry");
    let prepared = prepare_batch(
        &[profile(
            "01913f1d-8e2a-7c30-8f4a-426614174021",
            "01913f1d-8e2a-7c30-8f4a-426614174022",
            "partial",
            1,
        )],
        "partial",
        &registry,
    )
    .expect("batch");
    store
        .append(&prepared, store.read().expect("read").revision())
        .expect("append");
    run(&clone, &["add", prepared.records()[0].path()]);
    run(&clone, &["commit", "-m", "record only"]);
    run(&clone, &["add", prepared.manifest_path()]);
    run(&clone, &["commit", "-m", "manifest later"]);
    run(
        &clone,
        &[
            "push",
            fixture.remote.to_str().expect("remote"),
            "HEAD:refs/heads/main",
        ],
    );
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("typed"),
        GitSyncOutcome::Quarantined {
            reason: GitQuarantineReason::InvalidCommitSnapshot,
            ..
        }
    ));
}

#[test]
fn equal_tree_remote_without_local_ancestry_requires_merge() {
    let fixture = fixture("equal-tree-merge");
    let base = oid(&fixture.local, "HEAD");
    run(&fixture.local, &["commit", "--allow-empty", "-m", "local"]);
    let local_tip = oid(&fixture.local, "HEAD");
    let clone = fixture.root.0.join("equal-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    assert_eq!(oid(&clone, "HEAD"), base);
    run(&clone, &["commit", "--allow-empty", "-m", "remote"]);
    let remote_tip = oid(&clone, "HEAD");
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);
    let outcome = fixture
        .store
        .sync_git_union(&fixture.request)
        .expect("sync");
    let GitSyncOutcome::Advanced { commit, .. } = outcome else {
        panic!("not advanced")
    };
    for parent in [&local_tip, &remote_tip] {
        let status = Command::new(git())
            .current_dir(&fixture.local)
            .args(["merge-base", "--is-ancestor", parent, commit.as_hex()])
            .status()
            .expect("merge-base");
        assert!(status.success());
    }
}

#[test]
fn two_offline_clones_converge_by_set_and_revision() {
    let fixture = fixture("two-clone");
    let (path_a, store_a, request_a) = clone_store(&fixture.root.0, &fixture.remote, "clone-a");
    let (path_b, store_b, request_b) = clone_store(&fixture.root.0, &fixture.remote, "clone-b");
    append_profile(
        &store_a,
        &path_a,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174021",
            "01913f1d-8e2a-7c30-8f4a-426614174022",
            "A",
            1,
        ),
        "a",
    );
    append_profile(
        &store_b,
        &path_b,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174031",
            "01913f1d-8e2a-7c30-8f4a-426614174032",
            "B",
            2,
        ),
        "b",
    );
    assert!(matches!(
        store_a.sync_git_union(&request_a).expect("A"),
        GitSyncOutcome::Advanced { .. }
    ));
    assert!(matches!(
        store_b.sync_git_union(&request_b).expect("B"),
        GitSyncOutcome::Advanced { .. }
    ));
    let second = store_a.sync_git_union(&request_a).expect("A second");
    assert!(
        matches!(
            second,
            GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. }
        ),
        "unexpected A second outcome: {second:?}"
    );
    assert_eq!(
        store_a.read().expect("A read").revision(),
        store_b.read().expect("B read").revision()
    );
}

#[test]
fn union_only_duplicate_global_record_id_quarantines_durably() {
    let fixture = fixture("union-duplicate-global-record-id");
    let (path_a, store_a, request_a) = clone_store(&fixture.root.0, &fixture.remote, "duplicate-a");
    let (path_b, store_b, request_b) = clone_store(&fixture.root.0, &fixture.remote, "duplicate-b");
    let duplicate = "01913f1d-8e2a-7c30-8f4a-426614174051";
    append_profile(
        &store_a,
        &path_a,
        profile_for_entity(
            duplicate,
            "01913f1d-8e2a-7c30-8f4a-426614174052",
            "01913f1d-8e2a-7c30-8f4a-426614174053",
            "A",
            4,
        ),
        "duplicate-a",
    );
    append_profile(
        &store_b,
        &path_b,
        profile_for_entity(
            duplicate,
            "01913f1d-8e2a-7c30-8f4a-426614174062",
            "01913f1d-8e2a-7c30-8f4a-426614174063",
            "B",
            5,
        ),
        "duplicate-b",
    );
    assert!(matches!(
        store_a.sync_git_union(&request_a).expect("publish A"),
        GitSyncOutcome::Advanced { .. }
    ));
    let first = store_b
        .sync_git_union(&request_b)
        .expect("closed quarantine outcome");
    let GitSyncOutcome::Quarantined {
        incident_id,
        reason: GitQuarantineReason::UuidCollision,
    } = first
    else {
        panic!("union-only UUID collision was not quarantined: {first:?}")
    };
    assert!(matches!(
        store_b.sync_git_union(&request_b).expect("durable retry"),
        GitSyncOutcome::Quarantined {
            incident_id: retry,
            reason: GitQuarantineReason::UuidCollision,
        } if retry == incident_id
    ));
}

#[test]
fn union_only_idempotency_collision_quarantines_durably() {
    let fixture = fixture("union-idempotency-collision");
    let (path_a, store_a, request_a) =
        clone_store(&fixture.root.0, &fixture.remote, "idempotency-a");
    let (path_b, store_b, request_b) =
        clone_store(&fixture.root.0, &fixture.remote, "idempotency-b");
    append_profile(
        &store_a,
        &path_a,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174071",
            "01913f1d-8e2a-7c30-8f4a-426614174072",
            "A",
            6,
        ),
        "shared-idempotency-key",
    );
    append_profile(
        &store_b,
        &path_b,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174081",
            "01913f1d-8e2a-7c30-8f4a-426614174082",
            "B",
            7,
        ),
        "shared-idempotency-key",
    );
    assert!(matches!(
        store_a.sync_git_union(&request_a).expect("publish A"),
        GitSyncOutcome::Advanced { .. }
    ));
    let first = store_b
        .sync_git_union(&request_b)
        .expect("closed quarantine outcome");
    let GitSyncOutcome::Quarantined {
        incident_id,
        reason: GitQuarantineReason::IdempotencyCollision,
    } = first
    else {
        panic!("union-only idempotency collision was not quarantined: {first:?}")
    };
    assert!(matches!(
        store_b.sync_git_union(&request_b).expect("durable retry"),
        GitSyncOutcome::Quarantined {
            incident_id: retry,
            reason: GitQuarantineReason::IdempotencyCollision,
        } if retry == incident_id
    ));
}

#[test]
fn operational_ancestry_exit_is_typed_and_writes_no_incident() {
    let fixture = fixture("operational-history-failure");
    let writer = fixture.root.0.join("operational-writer");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            writer.to_str().expect("writer"),
        ],
    );
    configure(&writer);
    run(&writer, &["commit", "--allow-empty", "-m", "advance"]);
    run(&writer, &["push", "origin", "HEAD:refs/heads/main"]);

    let wrapper_source = fixture.root.0.join("git-history-wrapper.rs");
    let wrapper = fixture.root.0.join("git-history-wrapper");
    let marker = fixture.root.0.join("fail-history");
    fs::write(
        &wrapper_source,
        format!(
            r#"use std::{{env, ffi::OsStr, path::Path, process::Command}};
fn main() {{
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if Path::new({marker:?}).exists() && args.iter().any(|arg| arg == OsStr::new("merge-base")) {{
        std::process::exit(2);
    }}
    let status = Command::new({git:?}).args(&args).status().unwrap();
    std::process::exit(status.code().unwrap_or(127));
}}
"#,
            marker = marker,
            git = git(),
        ),
    )
    .expect("wrapper source");
    assert!(
        Command::new("rustc")
            .args([
                wrapper_source.as_os_str(),
                "-o".as_ref(),
                wrapper.as_os_str()
            ])
            .status()
            .expect("compile wrapper")
            .success()
    );
    fs::write(&marker, b"fail\n").expect("failure marker");
    let request = request_with_git(&fixture.remote, wrapper);
    let checkpoint = fs::read(
        fixture
            .local
            .join(".wayjournal-local/checkpoints/admission-v1.json"),
    )
    .expect("checkpoint");
    let local_tip = oid(&fixture.local, "refs/heads/main");

    let operational = fixture.store.sync_git_union(&request);
    assert!(
        matches!(
            operational,
            Err(GitSyncError::Admission(
                wayjournal_core::GitAdmissionError::Git(_)
            ))
        ),
        "unexpected operational history result: {operational:?}"
    );
    assert_eq!(
        fs::read_dir(fixture.local.join(".wayjournal-local/quarantine"))
            .expect("quarantine")
            .count(),
        0,
        "operational history failure wrote a permanent incident"
    );
    assert_eq!(oid(&fixture.local, "refs/heads/main"), local_tip);
    assert_eq!(
        fs::read(
            fixture
                .local
                .join(".wayjournal-local/checkpoints/admission-v1.json")
        )
        .expect("checkpoint"),
        checkpoint
    );
    fs::remove_file(marker).expect("remove failure marker");
    assert!(matches!(
        fixture.store.sync_git_union(&request).expect("retry"),
        GitSyncOutcome::Advanced { .. }
    ));
}

#[test]
fn initially_missing_approved_ref_is_durably_quarantined_without_creation() {
    let fixture = fixture("initial-missing-ref");
    let local_tip = oid(&fixture.local, "refs/heads/main");
    run(&fixture.remote, &["update-ref", "-d", "refs/heads/main"]);
    let first = fixture
        .store
        .sync_git_union(&fixture.request)
        .expect("closed missing-ref outcome");
    let GitSyncOutcome::Quarantined {
        incident_id,
        reason: GitQuarantineReason::MissingApprovedRef,
    } = first
    else {
        panic!("missing approved ref was not quarantined: {first:?}")
    };
    assert_eq!(oid(&fixture.local, "refs/heads/main"), local_tip);
    let remote_ref = Command::new(git())
        .current_dir(&fixture.remote)
        .args(["rev-parse", "--verify", "refs/heads/main"])
        .output()
        .expect("remote ref probe");
    assert!(!remote_ref.status.success(), "sync recreated missing ref");
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("durable retry"),
        GitSyncOutcome::Quarantined {
            incident_id: retry,
            reason: GitQuarantineReason::MissingApprovedRef,
        } if retry == incident_id
    ));
}

fn process_high_water_bytes() -> u64 {
    let status = fs::read_to_string("/proc/self/status").expect("procfs status");
    status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .expect("VmHWM value")
        .parse::<u64>()
        .expect("VmHWM integer")
        * 1024
}

fn write_prepared(root: &Path, prepared: &wayjournal_core::PreparedBatch) {
    for record in prepared.records() {
        let path = root.join(record.path());
        fs::create_dir_all(path.parent().expect("record parent")).expect("record directory");
        fs::write(path, record.bytes()).expect("record bytes");
    }
    fs::write(
        root.join(prepared.manifest_path()),
        prepared.manifest_bytes(),
    )
    .expect("manifest bytes");
}

#[test]
fn journal_heavy_semantic_replay_stays_bounded() {
    const RECORDS: usize = 512;
    let fixture = fixture("journal-heavy-memory");
    let clone = fixture.root.0.join("journal-heavy-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    let registry = wayjournal_domain_registry().expect("registry");
    for ordinal in 0..RECORDS {
        let record_id = format!(
            "01913f1d-8e2a-7c30-8f4a-{:012x}",
            0x5266_1417_4100 + ordinal * 3
        );
        let batch_id = format!(
            "01913f1d-8e2a-7c30-8f4a-{:012x}",
            0x5266_1417_4101 + ordinal * 3
        );
        let entity_id = format!(
            "01913f1d-8e2a-7c30-8f4a-{:012x}",
            0x5266_1417_4102 + ordinal * 3
        );
        let mut record = profile(
            &record_id,
            &batch_id,
            &format!("profile-{ordinal:04}"),
            u8::try_from(ordinal % 60).expect("second"),
        );
        record.entity_id = entity_id.parse().expect("entity");
        let prepared = prepare_batch(&[record], &format!("journal-heavy-{ordinal}"), &registry)
            .expect("journal-heavy batch");
        write_prepared(&clone, &prepared);
    }
    run(&clone, &["add", "journal"]);
    run(&clone, &["commit", "-m", "journal-heavy tip"]);
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);
    let before = process_high_water_bytes();
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("sync"),
        GitSyncOutcome::Advanced { .. }
    ));
    let growth = process_high_water_bytes().saturating_sub(before);
    eprintln!("journal-heavy semantic replay VmHWM growth: {growth} bytes");
    assert!(
        growth < 256 * 1024 * 1024,
        "journal-heavy replay retained {growth} bytes"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "exact-4096-operation valid built-in fold memory gate"]
fn exact_large_builtin_fold_sync_stays_below_256_mib() {
    const OPERATIONS: usize = wayjournal_core::MAX_CAUSAL_OPERATIONS;
    const RECORDS_PER_BATCH: usize = 64;
    const PREVIOUS_WORKING_SET_CAP: usize = 32 * 1024 * 1024;
    let fixture = fixture("exact-large-built-in-fold");
    let clone = fixture.root.0.join("exact-large-built-in-fold-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    let registry = wayjournal_domain_registry().expect("registry");
    let entity = "01913f1d-8e2a-7c30-8f4a-426614176000"
        .parse()
        .expect("entity");
    let value = "\u{10ffff}".repeat(2048);
    let mut encoded_group_bytes = 0_usize;
    for batch_start in (0..OPERATIONS).step_by(RECORDS_PER_BATCH) {
        let batch_id = format!("01913f1d-8e2a-7c30-8f4a-426615{batch_start:06x}");
        let records = (batch_start..batch_start + RECORDS_PER_BATCH)
            .map(|ordinal| Record {
                record_schema: "wayjournal.profile/v1".parse().expect("schema"),
                domain: "wayjournal.profile".parse().expect("domain"),
                kind: "profile.description.set".parse().expect("kind"),
                record_id: format!("01913f1d-8e2a-7c30-8f4a-42661419{ordinal:04x}")
                    .parse()
                    .expect("record"),
                entity_id: entity,
                batch_id: batch_id.parse().expect("batch"),
                actor: ActorId::parse("human:memory-gate").expect("actor"),
                occurred_at: "2026-08-12T13:01:00Z".parse().expect("time"),
                recorded_at: "2026-08-12T13:02:00Z".parse().expect("time"),
                parents: Vec::new(),
                payload: json!({"value": value}),
            })
            .collect::<Vec<_>>();
        let prepared = prepare_batch(
            &records,
            &format!("exact-large-fold-{batch_start}"),
            &registry,
        )
        .expect("large fold batch");
        encoded_group_bytes += prepared
            .records()
            .iter()
            .map(|record| record.bytes().len())
            .sum::<usize>();
        write_prepared(&clone, &prepared);
    }
    assert!(encoded_group_bytes > PREVIOUS_WORKING_SET_CAP);
    run(&clone, &["add", "journal"]);
    run(&clone, &["commit", "-m", "exact large built-in fold tip"]);
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);

    let before = process_high_water_bytes();
    let outcome = fixture
        .store
        .sync_git_union(&fixture.request)
        .expect("sync");
    let growth = process_high_water_bytes().saturating_sub(before);
    let GitSyncOutcome::Advanced { revision, .. } = outcome else {
        panic!("large valid fold did not advance")
    };
    eprintln!("exact large built-in fold VmHWM growth: {growth} bytes");
    let reference = Store::open(&clone, registry, Arc::new(NoLegacy)).expect("reference store");
    let reference_snapshot = reference.read().expect("collected reference");
    assert_eq!(revision, reference_snapshot.revision());
    assert_eq!(
        fixture.store.read().expect("synced snapshot").identity(),
        reference_snapshot.identity()
    );
    assert!(
        growth < 256 * 1024 * 1024,
        "exact large built-in fold retained {growth} bytes"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "capacity-heavy hostile 4096-by-4096 same-entity fold memory gate"]
fn hostile_same_entity_fold_rejection_stays_below_256_mib() {
    const OPERATIONS: usize = wayjournal_core::MAX_CAUSAL_OPERATIONS;
    const REFERENCES: usize = 4096;
    const RECORDS_PER_BATCH: usize = 64;
    let fixture = fixture("hostile-same-entity-memory");
    let clone = fixture.root.0.join("hostile-same-entity-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    let registry = wayjournal_domain_registry().expect("registry");
    let parents = (0..REFERENCES)
        .map(|ordinal| {
            format!("01913f1d-8e2a-7c30-8f4a-{ordinal:012x}")
                .parse()
                .expect("parent")
        })
        .collect::<Vec<_>>();
    let entity = "01913f1d-8e2a-7c30-8f4a-426614176000"
        .parse()
        .expect("entity");
    for batch_start in (0..OPERATIONS).step_by(RECORDS_PER_BATCH) {
        let batch_id = format!(
            "01913f1d-8e2a-7c30-8f4a-{:012x}",
            0x7266_1417_4100 + batch_start
        );
        let records = (batch_start..batch_start + RECORDS_PER_BATCH)
            .map(|ordinal| Record {
                record_schema: "wayjournal.profile/v1".parse().expect("schema"),
                domain: "wayjournal.profile".parse().expect("domain"),
                kind: "profile.display_name.set".parse().expect("kind"),
                record_id: format!(
                    "01913f1d-8e2a-7c30-8f4a-{:012x}",
                    0x7366_1417_4100 + ordinal
                )
                .parse()
                .expect("record"),
                entity_id: entity,
                batch_id: batch_id.parse().expect("batch"),
                actor: ActorId::parse("human:memory-gate").expect("actor"),
                occurred_at: "2026-08-12T13:01:00Z".parse().expect("time"),
                recorded_at: "2026-08-12T13:02:00Z".parse().expect("time"),
                parents: parents.clone(),
                payload: json!({"value":"hostile"}),
            })
            .collect::<Vec<_>>();
        let prepared = prepare_batch(
            &records,
            &format!("hostile-same-entity-{batch_start}"),
            &registry,
        )
        .expect("hostile batch");
        write_prepared(&clone, &prepared);
    }
    assert!(canonical_payload_bytes(&clone) < 1024 * 1024 * 1024);
    run(&clone, &["add", "journal"]);
    run(&clone, &["commit", "-m", "hostile same-entity tip"]);
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);
    let before = process_high_water_bytes();
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("typed rejection"),
        GitSyncOutcome::Quarantined {
            reason: GitQuarantineReason::InvalidCommitSnapshot,
            ..
        }
    ));
    let growth = process_high_water_bytes().saturating_sub(before);
    eprintln!("hostile same-entity fold VmHWM growth: {growth} bytes");
    assert!(
        growth < 256 * 1024 * 1024,
        "hostile same-entity replay retained {growth} bytes"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "capacity-heavy 4096-by-4096 remove-reference fold memory gate"]
fn hostile_same_entity_remove_references_stay_below_256_mib() {
    const OPERATIONS: usize = wayjournal_core::MAX_CAUSAL_OPERATIONS;
    const REFERENCES: usize = 4096;
    const RECORDS_PER_BATCH: usize = 64;
    let fixture = fixture("hostile-same-entity-remove-memory");
    let clone = fixture.root.0.join("hostile-same-entity-remove-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    let registry = wayjournal_domain_registry().expect("registry");
    let adds = (0..REFERENCES)
        .map(|ordinal| format!("01913f1d-8e2a-7c30-8f4a-{ordinal:012x}"))
        .collect::<Vec<_>>();
    let entity = "01913f1d-8e2a-7c30-8f4a-426614176100"
        .parse()
        .expect("entity");
    for batch_start in (0..OPERATIONS).step_by(RECORDS_PER_BATCH) {
        let batch_id = format!("01913f1d-8e2a-7c30-8f4a-426616{batch_start:06x}");
        let records = (batch_start..batch_start + RECORDS_PER_BATCH)
            .map(|ordinal| Record {
                record_schema: "wayjournal.profile/v1".parse().expect("schema"),
                domain: "wayjournal.profile".parse().expect("domain"),
                kind: "profile.alias.remove".parse().expect("kind"),
                record_id: format!("01913f1d-8e2a-7c30-8f4a-42661719{ordinal:04x}")
                    .parse()
                    .expect("record"),
                entity_id: entity,
                batch_id: batch_id.parse().expect("batch"),
                actor: ActorId::parse("human:memory-gate").expect("actor"),
                occurred_at: "2026-08-12T13:01:00Z".parse().expect("time"),
                recorded_at: "2026-08-12T13:02:00Z".parse().expect("time"),
                parents: Vec::new(),
                payload: json!({"adds": adds, "key": "hostile"}),
            })
            .collect::<Vec<_>>();
        let prepared = prepare_batch(
            &records,
            &format!("hostile-remove-{batch_start}"),
            &registry,
        )
        .expect("hostile remove batch");
        write_prepared(&clone, &prepared);
    }
    assert!(canonical_payload_bytes(&clone) < 1024 * 1024 * 1024);
    run(&clone, &["add", "journal"]);
    run(&clone, &["commit", "-m", "hostile same-entity remove tip"]);
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);
    let before = process_high_water_bytes();
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("typed rejection"),
        GitSyncOutcome::Quarantined {
            reason: GitQuarantineReason::InvalidCommitSnapshot,
            ..
        }
    ));
    let growth = process_high_water_bytes().saturating_sub(before);
    eprintln!("hostile remove-reference fold VmHWM growth: {growth} bytes");
    assert!(
        growth < 256 * 1024 * 1024,
        "hostile remove-reference replay retained {growth} bytes"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "explicit exact-million-entry and maximum-path S4b release RSS gate"]
fn exact_maximum_entry_and_path_sync_stays_below_256_mib() {
    const MAX_CANONICAL_ENTRIES: usize = 1_000_000;
    // Canonical root anchors are excluded by `CanonicalEntryBudget`.
    const BASE_ENTRIES: usize = 6;
    const MAX_PATH_ADDITION_ENTRIES: usize = 4;
    const LEGACY_PARENT_ENTRIES: usize = 1;
    const LEGACY_FILES: usize =
        MAX_CANONICAL_ENTRIES - BASE_ENTRIES - MAX_PATH_ADDITION_ENTRIES - LEGACY_PARENT_ENTRIES;
    const LEGACY_ENTITY: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn canonical_entry_count(root: &Path) -> usize {
        fn count(path: &Path) -> usize {
            1 + fs::read_dir(path)
                .expect("canonical directory")
                .map(|entry| entry.expect("canonical entry"))
                .map(|entry| {
                    if entry.file_type().expect("canonical type").is_dir() {
                        count(&entry.path())
                    } else {
                        1
                    }
                })
                .sum::<usize>()
        }
        ["events", "journal"]
            .into_iter()
            .map(|name| root.join(name))
            .filter(|path| path.exists())
            .map(|path| count(&path) - 1)
            .sum()
    }

    fn parse_mktree(output: std::process::Output) -> String {
        assert!(
            output.status.success(),
            "mktree: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("mktree UTF-8")
            .trim()
            .to_owned()
    }

    let registry =
        wayjournal_domain_registry_with(MAX_PATH_REGISTRATION).expect("maximum-path registry");
    let fixture = fixture_with_registry("exact-maximum-entry-path", registry, Arc::new(NoLegacy));
    let base = oid(&fixture.remote, "refs/heads/main");
    let long = prepare_batch(
        &[Record {
            record_schema: MAX_PATH_SCHEMA.parse().expect("schema"),
            domain: MAX_PATH_DOMAIN.parse().expect("domain"),
            kind: "bulk.write".parse().expect("kind"),
            record_id: "01913f1d-8e2a-7c30-8f4a-426614174091"
                .parse()
                .expect("record"),
            entity_id: "01913f1d-8e2a-7c30-8f4a-426614174090"
                .parse()
                .expect("entity"),
            batch_id: "01913f1d-8e2a-7c30-8f4a-426614174092"
                .parse()
                .expect("batch"),
            actor: ActorId::parse("system:maximum-entry-gate").expect("actor"),
            occurred_at: "2026-08-12T13:01:00Z".parse().expect("time"),
            recorded_at: "2026-08-12T13:02:00Z".parse().expect("time"),
            parents: Vec::new(),
            payload: json!({"blob":"maximum path"}),
        }],
        "maximum-path",
        &registry,
    )
    .expect("maximum-path batch");
    let long_record = &long.records()[0];
    assert_eq!(
        long_record.path().len(),
        220,
        "fixture missed the longest path permitted by a 128-byte schema id"
    );

    let shared_blob = String::from_utf8(run_with_input(
        &fixture.remote,
        &["hash-object", "-w", "--stdin"],
        b"x",
    ))
    .expect("blob UTF-8")
    .trim()
    .to_owned();
    let long_record_blob = String::from_utf8(run_with_input(
        &fixture.remote,
        &["hash-object", "-w", "--stdin"],
        long_record.bytes(),
    ))
    .expect("record blob UTF-8")
    .trim()
    .to_owned();
    let long_manifest_blob = String::from_utf8(run_with_input(
        &fixture.remote,
        &["hash-object", "-w", "--stdin"],
        long.manifest_bytes(),
    ))
    .expect("manifest blob UTF-8")
    .trim()
    .to_owned();

    let mut exact_child = Command::new(git())
        .current_dir(&fixture.remote)
        .arg("mktree")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("exact mktree");
    let mut overflow_child = Command::new(git())
        .current_dir(&fixture.remote)
        .arg("mktree")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("overflow mktree");
    let mut exact_input = BufWriter::new(exact_child.stdin.take().expect("exact stdin"));
    let mut overflow_input = BufWriter::new(overflow_child.stdin.take().expect("overflow stdin"));
    for ordinal in 0..=LEGACY_FILES {
        let record = format!("00000000-0000-7000-8000-{ordinal:012x}.json");
        if ordinal < LEGACY_FILES {
            writeln!(exact_input, "100644 blob {shared_blob}\t{record}").expect("exact tree entry");
        }
        writeln!(overflow_input, "100644 blob {shared_blob}\t{record}")
            .expect("overflow tree entry");
    }
    drop(exact_input);
    drop(overflow_input);
    let exact_entity = parse_mktree(exact_child.wait_with_output().expect("exact mktree output"));
    let overflow_entity = parse_mktree(
        overflow_child
            .wait_with_output()
            .expect("overflow mktree output"),
    );
    let exact_events = mktree(
        &fixture.remote,
        &fixture.remote,
        format!("040000 tree {exact_entity}\t{LEGACY_ENTITY}\n").as_bytes(),
    );
    let overflow_events = mktree(
        &fixture.remote,
        &fixture.remote,
        format!("040000 tree {overflow_entity}\t{LEGACY_ENTITY}\n").as_bytes(),
    );

    let long_entity = mktree(
        &fixture.remote,
        &fixture.remote,
        format!("100644 blob {long_record_blob}\t01913f1d-8e2a-7c30-8f4a-426614174091.json\n")
            .as_bytes(),
    );
    let long_domain = mktree(
        &fixture.remote,
        &fixture.remote,
        format!("040000 tree {long_entity}\t01913f1d-8e2a-7c30-8f4a-426614174090\n").as_bytes(),
    );
    let identity_tree = oid(
        &fixture.remote,
        &format!("{base}^{{tree}}:journal/records/wayjournal.identity"),
    );
    let records = mktree(
        &fixture.remote,
        &fixture.remote,
        format!(
            "040000 tree {long_domain}\t{MAX_PATH_DOMAIN}\n040000 tree {identity_tree}\twayjournal.identity\n"
        )
        .as_bytes(),
    );
    let mut batch_entries = run(
        &fixture.remote,
        &["ls-tree", &format!("{base}^{{tree}}:journal/batches")],
    );
    writeln!(
        batch_entries,
        "100644 blob {long_manifest_blob}\t01913f1d-8e2a-7c30-8f4a-426614174092.json"
    )
    .expect("batch tree entry");
    let batches = mktree(&fixture.remote, &fixture.remote, &batch_entries);
    let journal = mktree(
        &fixture.remote,
        &fixture.remote,
        format!("040000 tree {batches}\tbatches\n040000 tree {records}\trecords\n").as_bytes(),
    );
    let exact_root = mktree(
        &fixture.remote,
        &fixture.remote,
        format!("040000 tree {exact_events}\tevents\n040000 tree {journal}\tjournal\n").as_bytes(),
    );
    let overflow_root = mktree(
        &fixture.remote,
        &fixture.remote,
        format!("040000 tree {overflow_events}\tevents\n040000 tree {journal}\tjournal\n")
            .as_bytes(),
    );
    let exact_commit = String::from_utf8(run_with_input(
        &fixture.remote,
        &["commit-tree", &exact_root, "-p", &base],
        b"exact maximum canonical entries\n",
    ))
    .expect("commit UTF-8")
    .trim()
    .to_owned();
    let overflow_commit = String::from_utf8(run_with_input(
        &fixture.remote,
        &["commit-tree", &overflow_root, "-p", &exact_commit],
        b"one canonical entry over limit\n",
    ))
    .expect("commit UTF-8")
    .trim()
    .to_owned();
    run(
        &fixture.remote,
        &["update-ref", "refs/heads/main", &exact_commit, &base],
    );

    let before = process_high_water_bytes();
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("exact maximum-entry sync"),
        GitSyncOutcome::Advanced { .. }
    ));
    let growth = process_high_water_bytes().saturating_sub(before);
    eprintln!("exact-million-entry Git sync VmHWM growth: {growth} bytes");
    assert_eq!(canonical_entry_count(&fixture.local), MAX_CANONICAL_ENTRIES);
    assert_eq!(oid(&fixture.local, "refs/heads/main"), exact_commit);
    assert!(
        growth < 256 * 1024 * 1024,
        "exact-million-entry sync retained {growth} bytes"
    );

    let checkpoint_path = fixture
        .local
        .join(".wayjournal-local/checkpoints/admission-v1.json");
    let checkpoint = fs::read(&checkpoint_path).expect("checkpoint");
    run(
        &fixture.remote,
        &[
            "update-ref",
            "refs/heads/main",
            &overflow_commit,
            &exact_commit,
        ],
    );
    let overflow = fixture
        .store
        .sync_git_union(&fixture.request)
        .expect("typed limit-plus-one rejection");
    assert!(
        matches!(overflow, GitSyncOutcome::Quarantined { .. }),
        "unexpected limit-plus-one result: {overflow:?}"
    );
    assert_eq!(canonical_entry_count(&fixture.local), MAX_CANONICAL_ENTRIES);
    assert_eq!(oid(&fixture.local, "refs/heads/main"), exact_commit);
    assert_eq!(fs::read(checkpoint_path).expect("checkpoint"), checkpoint);
    assert_eq!(oid(&fixture.remote, "refs/heads/main"), overflow_commit);
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "explicit exact-1-GiB legacy Git-tip compatibility gate"]
fn exact_one_gib_git_tip_sync_stays_below_the_memory_budget() {
    const EXACT_BYTES: u64 = 1024 * 1024 * 1024;
    const FILE_BYTES: usize = wayjournal_core::MAX_LEGACY_FILE_BYTES;
    const ENTITY: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn canonical_bytes(root: &Path) -> u64 {
        fn walk(path: &Path) -> u64 {
            fs::read_dir(path)
                .expect("canonical directory")
                .map(|entry| entry.expect("canonical entry"))
                .map(|entry| {
                    let kind = entry.file_type().expect("canonical file type");
                    if kind.is_dir() {
                        walk(&entry.path())
                    } else {
                        entry.metadata().expect("canonical metadata").len()
                    }
                })
                .sum()
        }

        ["batches", "events", "journal"]
            .into_iter()
            .map(|name| root.join(name))
            .filter(|path| path.exists())
            .map(|path| walk(&path))
            .sum()
    }

    fn high_water_bytes() -> u64 {
        let status = fs::read_to_string("/proc/self/status").expect("procfs status");
        status
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .expect("VmHWM value")
            .parse::<u64>()
            .expect("VmHWM integer")
            * 1024
    }

    let fixture = fixture("exact-gib-tip");
    let clone = fixture.root.0.join("exact-gib-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    let base_bytes = canonical_bytes(&clone);
    let mut remaining = EXACT_BYTES
        .checked_sub(base_bytes)
        .expect("base below limit");
    let directory = clone.join(format!("events/{ENTITY}"));
    fs::create_dir_all(&directory).expect("legacy directory");
    let mut ordinal = 0_u64;
    while remaining > 0 {
        let length = usize::try_from(remaining.min(FILE_BYTES as u64)).expect("file length");
        let mut bytes = vec![b'x'; length];
        let marker = ordinal.to_be_bytes();
        let marker_length = length.min(marker.len());
        bytes[..marker_length].copy_from_slice(&marker[..marker_length]);
        let record = format!("00000000-0000-7000-8000-{ordinal:012x}.json");
        fs::write(directory.join(record), bytes).expect("legacy payload");
        remaining -= length as u64;
        ordinal += 1;
    }
    assert_eq!(canonical_bytes(&clone), EXACT_BYTES);
    run(&clone, &["add", "events"]);
    run(&clone, &["commit", "-m", "exact 1 GiB tip"]);
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);
    let before_high_water = high_water_bytes();

    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("exact 1 GiB sync"),
        GitSyncOutcome::Advanced { .. }
    ));

    assert_eq!(canonical_bytes(&fixture.local), EXACT_BYTES);
    assert_eq!(
        oid(&fixture.local, "refs/heads/main"),
        oid(&fixture.remote, "refs/heads/main")
    );
    let high_water_growth = high_water_bytes().saturating_sub(before_high_water);
    eprintln!("exact-1-GiB Git sync VmHWM growth: {high_water_growth} bytes");
    assert!(
        high_water_growth < 256 * 1024 * 1024,
        "exact-1-GiB Git sync retained {high_water_growth} bytes"
    );
}

fn canonical_payload_bytes(root: &Path) -> u64 {
    fn walk(path: &Path) -> u64 {
        fs::read_dir(path)
            .expect("canonical directory")
            .map(|entry| entry.expect("canonical entry"))
            .map(|entry| {
                if entry.file_type().expect("canonical type").is_dir() {
                    walk(&entry.path())
                } else {
                    entry.metadata().expect("canonical metadata").len()
                }
            })
            .sum()
    }
    ["batches", "events", "journal"]
        .into_iter()
        .map(|name| root.join(name))
        .filter(|path| path.exists())
        .map(|path| walk(&path))
        .sum()
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "explicit exact-1-GiB valid journal-tip bounded-memory gate"]
fn exact_one_gib_journal_tip_sync_stays_below_256_mib() {
    const EXACT_BYTES: u64 = 1024 * 1024 * 1024;
    let registry = wayjournal_domain_registry_with(BULK_REGISTRATION).expect("bulk registry");
    let fixture = fixture_with_registry("exact-gib-journal-tip", registry, Arc::new(NoLegacy));
    let clone = fixture.root.0.join("exact-gib-journal-clone");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            clone.to_str().expect("clone"),
        ],
    );
    configure(&clone);
    let mut remaining = EXACT_BYTES
        .checked_sub(canonical_payload_bytes(&clone))
        .expect("genesis below capacity");
    let mut ordinal = 0_usize;
    while remaining > 0 {
        let record_id = format!(
            "01913f1d-8e2a-7c30-8f4a-{:012x}",
            0x6266_1417_4100 + ordinal * 3
        );
        let batch_id = format!(
            "01913f1d-8e2a-7c30-8f4a-{:012x}",
            0x6266_1417_4101 + ordinal * 3
        );
        let entity_id = format!(
            "01913f1d-8e2a-7c30-8f4a-{:012x}",
            0x6266_1417_4102 + ordinal * 3
        );
        let empty = prepare_batch(
            &[bulk_record(&record_id, &batch_id, &entity_id, 0)],
            &format!("bulk-{ordinal}"),
            &registry,
        )
        .expect("empty bulk shape");
        let empty_bytes = empty.manifest_bytes().len() + empty.records()[0].bytes().len();
        let maximum_blob = wayjournal_core::MAX_RECORD_BYTES - empty.records()[0].bytes().len();
        let maximum = prepare_batch(
            &[bulk_record(&record_id, &batch_id, &entity_id, maximum_blob)],
            &format!("bulk-{ordinal}"),
            &registry,
        )
        .expect("maximum bulk shape");
        let maximum_bytes = maximum.manifest_bytes().len() + maximum.records()[0].bytes().len();
        let chosen = if remaining > maximum_bytes as u64 + empty_bytes as u64 {
            maximum
        } else {
            let blob = usize::try_from(remaining)
                .expect("remaining usize")
                .checked_sub(empty_bytes)
                .expect("final bulk payload is representable");
            prepare_batch(
                &[bulk_record(&record_id, &batch_id, &entity_id, blob)],
                &format!("bulk-{ordinal}"),
                &registry,
            )
            .expect("final bulk shape")
        };
        let bytes = chosen.manifest_bytes().len() + chosen.records()[0].bytes().len();
        assert!(bytes as u64 <= remaining);
        write_prepared(&clone, &chosen);
        remaining -= bytes as u64;
        ordinal += 1;
    }
    assert_eq!(canonical_payload_bytes(&clone), EXACT_BYTES);
    run(&clone, &["add", "journal"]);
    run(&clone, &["commit", "-m", "exact 1 GiB valid journal tip"]);
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);
    let before = process_high_water_bytes();
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("exact journal sync"),
        GitSyncOutcome::Advanced { .. }
    ));
    assert_eq!(canonical_payload_bytes(&fixture.local), EXACT_BYTES);
    let growth = process_high_water_bytes().saturating_sub(before);
    eprintln!("exact-1-GiB journal-tip VmHWM growth: {growth} bytes");
    assert!(
        growth < 256 * 1024 * 1024,
        "exact journal replay retained {growth} bytes"
    );
}
