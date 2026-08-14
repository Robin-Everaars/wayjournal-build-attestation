#[allow(dead_code)]
mod support;

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use serde_json::json;
use wayjournal_core::{
    ActorId, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, GitQuarantineReason, GitSyncError,
    GitSyncOutcome, GitSyncRequest, LegacyEntry, LegacyEntrySource, LegacyStoreAdapter,
    LegacyStreamRequirement, LegacyStreamingError, LocalTrustBinding, Record, Store, prepare_batch,
    wayjournal_domain_registry,
};

use support::BoundedNoLegacy as NoLegacy;

#[derive(Debug)]
struct CollectingLegacy;
impl LegacyStoreAdapter for CollectingLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
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
fn request(remote: &Path) -> GitSyncRequest {
    GitSyncRequest::new(
        git(),
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

fn profile(record: &str, batch: &str, value: &str, second: u8) -> Record {
    Record {
        record_schema: "wayjournal.profile/v1".parse().expect("schema"),
        domain: "wayjournal.profile".parse().expect("domain"),
        kind: "profile.display_name.set".parse().expect("kind"),
        record_id: record.parse().expect("record"),
        entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010"
            .parse()
            .expect("entity"),
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
    let root = TestDir::new(label);
    let remote = root.0.join("remote.git");
    run(
        &root.0,
        &["init", "--bare", remote.to_str().expect("remote")],
    );
    let local = root.0.join("local");
    fs::create_dir(&local).expect("local");
    let registry = wayjournal_domain_registry().expect("registry");
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
