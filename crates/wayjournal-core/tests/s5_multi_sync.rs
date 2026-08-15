#[allow(dead_code)]
mod support;

use std::{
    fs,
    mem::MaybeUninit,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use serde_json::json;
use wayjournal_core::{
    ActorId, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, AuthorizedGitSyncError,
    CapabilityId, CapabilityOffer, DependencyStore, GitQuarantineReason, GitSyncError,
    GitSyncOutcome, GitSyncRequest, HandshakeRequirements, LocalTrustBinding, LogicalStoreId,
    MultiStoreSyncError, NegotiatedHandshake, ProofCache, ProofCacheDisposition, ProofCacheLookup,
    QualifiedEntityRef, Record, Store, StoreSyncTarget, negotiate_handshake, prepare_batch,
    sync_stores, wayjournal_domain_registry,
};

use support::BoundedNoLegacy as NoLegacy;

const TRUST: &str = "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15";
const SYNC: &str = "wayjournal.sync/git-union-cas-v1";
const JSON: &str = "wayjournal.json/v1";
static SERIAL: Mutex<()> = Mutex::new(());

fn is_git_command_failure(result: &Result<GitSyncOutcome, AuthorizedGitSyncError>) -> bool {
    matches!(
        result,
        Err(AuthorizedGitSyncError::Sync(GitSyncError::Git(_)))
    )
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wayjournal-s5-multi-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    root: TestDir,
    remote: PathBuf,
    local: PathBuf,
    store: Store,
    request: GitSyncRequest,
    logical_store: LogicalStoreId,
    store_uuid: &'static str,
}

fn git() -> PathBuf {
    PathBuf::from(std::env::var_os("WAYJOURNAL_TEST_GIT").expect("native Git"))
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

fn configure(cwd: &Path) {
    run(cwd, &["config", "user.name", "Wayjournal Test"]);
    run(cwd, &["config", "user.email", "wayjournal@example.invalid"]);
}

fn request(remote: &Path) -> GitSyncRequest {
    request_with_git(remote, git())
}

fn request_with_git(remote: &Path, executable: PathBuf) -> GitSyncRequest {
    GitSyncRequest::new(
        executable,
        LocalTrustBinding::parse(TRUST).expect("trust"),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(
                url::Url::from_file_path(remote)
                    .expect("remote URL")
                    .as_str(),
            )
            .expect("approved locator"),
            ApprovedRef::parse("refs/heads/main").expect("approved ref"),
        ),
    )
    .expect("request")
}

fn genesis(store_uuid: &str, record_id: &str, batch_id: &str) -> Record {
    Record {
        record_schema: "wayjournal.identity/v1".parse().expect("schema"),
        domain: "wayjournal.identity".parse().expect("domain"),
        kind: "store.genesis".parse().expect("kind"),
        record_id: record_id.parse().expect("record"),
        entity_id: store_uuid.parse().expect("entity"),
        batch_id: batch_id.parse().expect("batch"),
        actor: ActorId::parse("human:s5-multi").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: Vec::new(),
        payload: json!({"store_kind": "wayjournal.personal", "store_uuid": store_uuid}),
    }
}

fn profile(store_uuid: &str, record_id: &str, batch_id: &str) -> Record {
    Record {
        record_schema: "wayjournal.profile/v1".parse().expect("schema"),
        domain: "wayjournal.profile".parse().expect("domain"),
        kind: "profile.display_name.set".parse().expect("kind"),
        record_id: record_id.parse().expect("record"),
        entity_id: store_uuid.parse().expect("entity"),
        batch_id: batch_id.parse().expect("batch"),
        actor: ActorId::parse("human:s5-multi").expect("actor"),
        occurred_at: "2026-08-12T13:01:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:01:01Z".parse().expect("time"),
        parents: Vec::new(),
        payload: json!({"value": "advanced"}),
    }
}

fn fixture(
    label: &str,
    store_uuid: &'static str,
    genesis_record: &str,
    genesis_batch: &str,
) -> Fixture {
    let root = TestDir::new(label);
    let remote = root.0.join("remote.git");
    run(
        &root.0,
        &["init", "--bare", remote.to_str().expect("remote")],
    );
    let local = root.0.join("local");
    fs::create_dir(&local).expect("local");
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(&local, registry, Arc::new(NoLegacy)).expect("store");
    let batch = prepare_batch(
        &[genesis(store_uuid, genesis_record, genesis_batch)],
        "genesis",
        &registry,
    )
    .expect("genesis batch");
    store
        .append(&batch, store.read().expect("empty").revision())
        .expect("append genesis");
    let logical_store = store
        .read()
        .expect("initialized")
        .identity()
        .expect("identity")
        .logical_id()
        .clone();
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
    store
        .bootstrap_git_admission(&request)
        .expect("bootstrap checkpoint");
    Fixture {
        root,
        remote,
        local,
        store,
        request,
        logical_store,
        store_uuid,
    }
}

fn capability(value: &str) -> CapabilityId {
    CapabilityId::parse(value).expect("capability")
}

fn handshake(fixture: &Fixture, with_sync: bool) -> NegotiatedHandshake {
    let value = if with_sync { SYNC } else { JSON };
    let local =
        HandshakeRequirements::new(Vec::new(), Vec::new(), vec![capability(value)], Vec::new())
            .expect("local requirements");
    let remote = CapabilityOffer::new(
        fixture.logical_store.clone(),
        Vec::new(),
        Vec::new(),
        vec![capability(value)],
        Vec::new(),
    )
    .expect("remote offer");
    negotiate_handshake(
        &fixture.store,
        &fixture.logical_store,
        LocalTrustBinding::parse(TRUST).expect("trust"),
        &local,
        &remote,
    )
    .expect("handshake")
}

fn advance_remote(fixture: &Fixture, suffix: &str) {
    let writer = fixture.root.0.join(format!("writer-{suffix}"));
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().expect("remote"),
            writer.to_str().expect("writer"),
        ],
    );
    configure(&writer);
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(&writer, registry, Arc::new(NoLegacy)).expect("writer store");
    let record_id = uuid::Uuid::now_v7().hyphenated().to_string();
    let batch_id = uuid::Uuid::now_v7().hyphenated().to_string();
    let batch = prepare_batch(
        &[profile(fixture.store_uuid, &record_id, &batch_id)],
        "remote-advance",
        &registry,
    )
    .expect("profile batch");
    store
        .append(&batch, store.read().expect("writer read").revision())
        .expect("writer append");
    run(&writer, &["add", "events", "batches", "journal"]);
    run(&writer, &["commit", "-m", "remote advance"]);
    run(&writer, &["push", "origin", "HEAD:refs/heads/main"]);
}

struct TransferProbe {
    descriptor: rustix::fd::OwnedFd,
    watch: i32,
}

fn install_transfer_probe(remote: &Path) -> TransferProbe {
    use rustix::fs::inotify;

    let path = remote.join("objects/info/alternates");
    fs::write(&path, b"wayjournal-contact-probe\n").expect("probe file");
    let descriptor = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)
        .expect("probe descriptor");
    let watch =
        inotify::add_watch(&descriptor, &path, inotify::WatchFlags::OPEN).expect("probe watch");
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

#[test]
#[allow(clippy::too_many_lines)]
fn complete_preflight_and_sync_capability_failures_touch_no_target_probe() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let first = fixture(
        "preflight-a",
        "01913f1d-8e2a-7c30-8f4a-426614174010",
        "01913f1d-8e2a-7c30-8f4a-426614174011",
        "01913f1d-8e2a-7c30-8f4a-426614174012",
    );
    let second = fixture(
        "preflight-b",
        "01913f1d-8e2a-7c30-8f4a-426614174020",
        "01913f1d-8e2a-7c30-8f4a-426614174021",
        "01913f1d-8e2a-7c30-8f4a-426614174022",
    );
    let first_handshake = handshake(&first, true);
    let second_handshake = handshake(&second, true);
    let no_sync = handshake(&first, false);
    let first_probe = install_transfer_probe(&first.remote);
    let second_probe = install_transfer_probe(&second.remote);

    let first_target = || StoreSyncTarget {
        expected_store: first.logical_store.clone(),
        store: &first.store,
        request: &first.request,
        handshake: &first_handshake,
    };
    let second_target = || StoreSyncTarget {
        expected_store: second.logical_store.clone(),
        store: &second.store,
        request: &second.request,
        handshake: &second_handshake,
    };
    assert!(matches!(
        sync_stores(&[], None),
        Err(MultiStoreSyncError::Empty)
    ));
    assert!(matches!(
        sync_stores(&[first_target(), first_target()], None),
        Err(MultiStoreSyncError::DuplicateTarget)
    ));
    assert!(matches!(
        sync_stores(&[second_target(), first_target()], None),
        Err(MultiStoreSyncError::UnsortedTargets)
    ));
    let oversized = (0..257).map(|_| first_target()).collect::<Vec<_>>();
    assert!(matches!(
        sync_stores(&oversized, None),
        Err(MultiStoreSyncError::TooManyTargets)
    ));
    assert!(matches!(
        sync_stores(
            &[StoreSyncTarget {
                expected_store: first.logical_store.clone(),
                store: &second.store,
                request: &first.request,
                handshake: &first_handshake,
            }],
            None,
        ),
        Err(MultiStoreSyncError::TargetStoreIdentityMismatch { .. })
    ));
    assert!(matches!(
        sync_stores(
            &[StoreSyncTarget {
                expected_store: first.logical_store.clone(),
                store: &first.store,
                request: &second.request,
                handshake: &first_handshake,
            }],
            None,
        ),
        Err(MultiStoreSyncError::RequestAuthorityMismatch { .. })
    ));
    assert!(matches!(
        sync_stores(
            &[StoreSyncTarget {
                expected_store: first.logical_store.clone(),
                store: &first.store,
                request: &first.request,
                handshake: &no_sync,
            }],
            None,
        ),
        Err(MultiStoreSyncError::MissingSyncCapability { .. })
    ));

    let mut checkpoint: serde_json::Value = serde_json::from_slice(
        &fs::read(
            second
                .local
                .join(".wayjournal-local/checkpoints/admission-v1.json"),
        )
        .expect("checkpoint"),
    )
    .expect("checkpoint JSON");
    checkpoint["accepted_commit"] = serde_json::Value::String("f".repeat(40));
    let mut bytes = serde_json::to_vec_pretty(&checkpoint).expect("checkpoint JSON");
    bytes.push(b'\n');
    fs::write(
        second
            .local
            .join(".wayjournal-local/checkpoints/admission-v1.json"),
        bytes,
    )
    .expect("stale checkpoint");

    let targets = [
        StoreSyncTarget {
            expected_store: first.logical_store.clone(),
            store: &first.store,
            request: &first.request,
            handshake: &first_handshake,
        },
        StoreSyncTarget {
            expected_store: second.logical_store.clone(),
            store: &second.store,
            request: &second.request,
            handshake: &second_handshake,
        },
    ];
    assert!(matches!(
        sync_stores(&targets, None),
        Err(MultiStoreSyncError::HandshakeCheckpointMismatch { .. })
    ));
    assert!(!transfer_probe_contacted(&first_probe));
    assert!(!transfer_probe_contacted(&second_probe));

    fs::remove_file(
        first
            .local
            .join(".wayjournal-local/checkpoints/admission-v1.json"),
    )
    .expect("remove checkpoint");
    assert!(matches!(
        sync_stores(&[first_target()], None),
        Err(MultiStoreSyncError::MissingCheckpoint { .. })
    ));
    assert!(!transfer_probe_contacted(&first_probe));
}

#[test]
fn checkpoint_advance_between_preflight_and_locked_authorization_is_zero_transfer() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if std::env::var_os("WAYJOURNAL_S5_MULTI_RACE_CHILD").is_some() {
        let barrier = PathBuf::from(
            std::env::var_os("WAYJOURNAL_INTERNAL_S5_MULTI_BARRIER").expect("child barrier path"),
        );
        checkpoint_race_body(&barrier);
        return;
    }

    let barrier_root = TestDir::new("race-barrier");
    let barrier = barrier_root.0.join("barrier");
    fs::create_dir(&barrier).expect("barrier directory");
    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "checkpoint_advance_between_preflight_and_locked_authorization_is_zero_transfer",
            "--nocapture",
        ])
        .env("WAYJOURNAL_S5_MULTI_RACE_CHILD", "1")
        .env("WAYJOURNAL_INTERNAL_S5_MULTI_BARRIER", &barrier)
        .status()
        .expect("race child");
    assert!(status.success(), "race child failed: {status}");
}

fn checkpoint_race_body(barrier: &Path) {
    let fixture = fixture(
        "race",
        "01913f1d-8e2a-7c30-8f4a-426614174030",
        "01913f1d-8e2a-7c30-8f4a-426614174031",
        "01913f1d-8e2a-7c30-8f4a-426614174032",
    );
    let handshake = handshake(&fixture, true);
    let before = fixture
        .store
        .admission_checkpoint()
        .expect("checkpoint")
        .expect("checkpoint")
        .accepted_revision();
    advance_remote(&fixture, "30");

    let result = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            sync_stores(
                &[StoreSyncTarget {
                    expected_store: fixture.logical_store.clone(),
                    store: &fixture.store,
                    request: &fixture.request,
                    handshake: &handshake,
                }],
                None,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !barrier.join("ready").is_file() {
            assert!(
                Instant::now() < deadline,
                "preflight barrier was not reached"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(
            fixture
                .store
                .sync_git_union(&fixture.request)
                .expect("advance"),
            GitSyncOutcome::Advanced { .. }
        ));
        let probe = install_transfer_probe(&fixture.remote);
        fs::write(barrier.join("release"), b"").expect("release barrier");
        let result = worker.join().expect("multi-sync thread");
        assert!(!transfer_probe_contacted(&probe));
        result
    });

    let results = result.expect("successful call preflight");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].store, fixture.logical_store);
    assert_eq!(results[0].before, before);
    assert!(matches!(
        results[0].sync_result,
        Err(AuthorizedGitSyncError::StaleHandshake)
    ));
    let after = results[0].after.as_ref().expect("post checkpoint");
    assert_ne!(*after, before);
    assert_eq!(
        results[0].cache_disposition,
        ProofCacheDisposition::Unavailable
    );
}

#[test]
fn mixed_runtime_outcomes_remain_independent_ordered_and_observed() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let failed = fixture(
        "mixed-error",
        "01913f1d-8e2a-7c30-8f4a-426614174040",
        "01913f1d-8e2a-7c30-8f4a-426614174041",
        "01913f1d-8e2a-7c30-8f4a-426614174042",
    );
    let advanced = fixture(
        "mixed-advanced",
        "01913f1d-8e2a-7c30-8f4a-426614174050",
        "01913f1d-8e2a-7c30-8f4a-426614174051",
        "01913f1d-8e2a-7c30-8f4a-426614174052",
    );
    let unchanged = fixture(
        "mixed-unchanged",
        "01913f1d-8e2a-7c30-8f4a-426614174060",
        "01913f1d-8e2a-7c30-8f4a-426614174061",
        "01913f1d-8e2a-7c30-8f4a-426614174062",
    );
    let quarantined = fixture(
        "mixed-quarantined",
        "01913f1d-8e2a-7c30-8f4a-426614174070",
        "01913f1d-8e2a-7c30-8f4a-426614174071",
        "01913f1d-8e2a-7c30-8f4a-426614174072",
    );
    advance_remote(&unchanged, "60");
    assert!(matches!(
        unchanged
            .store
            .sync_git_union(&unchanged.request)
            .expect("establish up-to-date checkpoint"),
        GitSyncOutcome::Advanced { .. }
    ));
    let handshakes = [
        handshake(&failed, true),
        handshake(&advanced, true),
        handshake(&unchanged, true),
        handshake(&quarantined, true),
    ];
    advance_remote(&advanced, "50");
    let unavailable = failed.root.0.join("remote-unavailable");
    fs::rename(&failed.remote, unavailable).expect("hide failed remote");
    run(
        &quarantined.remote,
        &["update-ref", "-d", "refs/heads/main"],
    );

    let fixtures = [&failed, &advanced, &unchanged, &quarantined];
    let targets = fixtures
        .iter()
        .zip(&handshakes)
        .map(|(fixture, handshake)| StoreSyncTarget {
            expected_store: fixture.logical_store.clone(),
            store: &fixture.store,
            request: &fixture.request,
            handshake,
        })
        .collect::<Vec<_>>();
    let results = sync_stores(&targets, None).expect("all-target preflight");
    assert_eq!(results.len(), fixtures.len());
    for (result, fixture) in results.iter().zip(fixtures) {
        assert_eq!(result.store, fixture.logical_store);
        assert!(result.after.is_ok());
    }
    assert!(is_git_command_failure(&results[0].sync_result));
    assert!(matches!(
        results[1].sync_result,
        Ok(GitSyncOutcome::Advanced { .. })
    ));
    assert!(
        matches!(results[2].sync_result, Ok(GitSyncOutcome::UpToDate { .. })),
        "unexpected unchanged outcome: {:?}",
        results[2].sync_result
    );
    assert!(matches!(
        results[3].sync_result,
        Ok(GitSyncOutcome::Quarantined {
            reason: GitQuarantineReason::MissingApprovedRef,
            ..
        })
    ));
    assert_eq!(
        results[0].after.as_ref().expect("after"),
        &results[0].before
    );
    assert_ne!(
        results[1].after.as_ref().expect("after"),
        &results[1].before
    );
    assert_eq!(
        results[2].after.as_ref().expect("after"),
        &results[2].before
    );
    assert_eq!(
        results[3].after.as_ref().expect("after"),
        &results[3].before
    );
}

#[test]
fn durable_error_checkpoint_change_is_observed_and_invalidates_old_cache_dependencies() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = fixture(
        "cache-invalidation",
        "01913f1d-8e2a-7c30-8f4a-426614174075",
        "01913f1d-8e2a-7c30-8f4a-426614174076",
        "01913f1d-8e2a-7c30-8f4a-426614174077",
    );
    let proof = fixture
        .store
        .verified_proof(
            &QualifiedEntityRef {
                store: fixture.logical_store.clone(),
                domain: "wayjournal.identity".parse().expect("domain"),
                entity_id: fixture.store_uuid.parse().expect("entity"),
            },
            "01913f1d-8e2a-7c30-8f4a-426614174076"
                .parse()
                .expect("record"),
            "2026-08-12T13:02:00Z".parse().expect("observation"),
        )
        .expect("proof");
    let cache = ProofCache::open(fixture.root.0.join("proof-cache")).expect("cache");
    let authorities = [DependencyStore {
        expected_store: fixture.logical_store.clone(),
        store: &fixture.store,
    }];
    cache.insert(&proof, &authorities).expect("cache insert");
    let handshake = handshake(&fixture, true);
    advance_remote(&fixture, "75");

    let tools = fixture.root.0.join("failing-push-tools");
    fs::create_dir(&tools).expect("tools");
    let source = tools.join("wrapper.rs");
    let wrapper = tools.join("git-wrapper");
    let checkpoint_path = fixture
        .local
        .join(".wayjournal-local/checkpoints/admission-v1.json");
    let old_digest = proof.source_revision().digest().to_string();
    fs::write(
        &source,
        format!(
            r"use std::{{env, fs, process::Command}};
fn main() {{
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if !fs::read_to_string({checkpoint_path:?}).unwrap().contains({old_digest:?}) {{
        std::process::exit(41);
    }}
    let status = Command::new({git:?}).args(&args).status().unwrap();
    std::process::exit(status.code().unwrap_or(127));
}}
",
            checkpoint_path = checkpoint_path,
            old_digest = old_digest,
            git = git(),
        ),
    )
    .expect("wrapper source");
    assert!(
        Command::new("rustc")
            .args([source.as_os_str(), "-o".as_ref(), wrapper.as_os_str()])
            .status()
            .expect("rustc")
            .success()
    );
    let failing_request = request_with_git(&fixture.remote, wrapper);

    let results = sync_stores(
        &[StoreSyncTarget {
            expected_store: fixture.logical_store.clone(),
            store: &fixture.store,
            request: &failing_request,
            handshake: &handshake,
        }],
        Some(&cache),
    )
    .expect("multi sync");
    assert!(
        is_git_command_failure(&results[0].sync_result),
        "unexpected post-checkpoint error: {:?}",
        results[0].sync_result
    );
    assert_ne!(
        results[0]
            .after
            .as_ref()
            .expect("durable pending checkpoint"),
        &results[0].before
    );
    assert_eq!(
        results[0].cache_disposition,
        ProofCacheDisposition::Invalidated
    );
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &authorities)
            .expect("lookup"),
        ProofCacheLookup::Unavailable
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn first_git_invocation_remains_inside_the_revalidated_transfer_lock() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = fixture(
        "locked-core",
        "01913f1d-8e2a-7c30-8f4a-426614174080",
        "01913f1d-8e2a-7c30-8f4a-426614174081",
        "01913f1d-8e2a-7c30-8f4a-426614174082",
    );
    advance_remote(&fixture, "80");
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("establish up-to-date checkpoint"),
        GitSyncOutcome::Advanced { .. }
    ));
    let handshake = handshake(&fixture, true);
    let tools = fixture.root.0.join("tools");
    fs::create_dir(&tools).expect("tools");
    let source = tools.join("wrapper.rs");
    let wrapper = tools.join("git-wrapper");
    let ready = tools.join("ready");
    let release = tools.join("release");
    fs::write(
        &source,
        format!(
            r#"use std::{{env, fs, process::Command, thread, time::Duration}};
fn main() {{
    if !std::path::Path::new({ready:?}).exists() {{
        fs::write({ready:?}, b"").unwrap();
        while !std::path::Path::new({release:?}).exists() {{
            thread::sleep(Duration::from_millis(10));
        }}
    }}
    let status = Command::new({git:?}).args(env::args_os().skip(1)).status().unwrap();
    std::process::exit(status.code().unwrap_or(127));
}}
"#,
            ready = ready,
            release = release,
            git = git(),
        ),
    )
    .expect("wrapper source");
    assert!(
        Command::new("rustc")
            .args([source.as_os_str(), "-o".as_ref(), wrapper.as_os_str()])
            .status()
            .expect("rustc")
            .success()
    );
    let blocked_request = request_with_git(&fixture.remote, wrapper);
    let expected = fixture.store.read().expect("before append").revision();
    let registry = wayjournal_domain_registry().expect("registry");
    let batch = prepare_batch(
        &[profile(
            fixture.store_uuid,
            "01913f1d-8e2a-7c30-8f4a-426614174091",
            "01913f1d-8e2a-7c30-8f4a-426614174092",
        )],
        "blocked-append",
        &registry,
    )
    .expect("append batch");

    let store = &fixture.store;
    let logical_store = &fixture.logical_store;
    std::thread::scope(|scope| {
        let sync = scope.spawn(move || {
            sync_stores(
                &[StoreSyncTarget {
                    expected_store: logical_store.clone(),
                    store,
                    request: &blocked_request,
                    handshake: &handshake,
                }],
                None,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.is_file() {
            assert!(Instant::now() < deadline, "Git wrapper was not invoked");
            std::thread::sleep(Duration::from_millis(10));
        }
        let (send, receive) = mpsc::channel();
        let append = scope.spawn(move || {
            let result = store.append(&batch, expected);
            send.send(()).expect("append signal");
            result
        });
        assert!(
            receive.recv_timeout(Duration::from_millis(250)).is_err(),
            "append acquired the retained transfer lock while Git was running"
        );
        fs::write(&release, b"").expect("release wrapper");
        let results = sync.join().expect("sync thread").expect("sync call");
        assert!(
            matches!(
                results[0].sync_result,
                Ok(GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. })
            ),
            "unexpected locked-core outcome: {:?}",
            results[0].sync_result
        );
        append
            .join()
            .expect("append thread")
            .expect("append after sync");
    });
}
