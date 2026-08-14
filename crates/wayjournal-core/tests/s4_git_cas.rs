#[allow(dead_code)]
mod support;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use serde_json::json;
use wayjournal_core::{
    ActorId, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, GitAdmissionError, GitSyncOutcome,
    GitSyncRequest, LocalTrustBinding, Record, Store, StoreError, StoreRevisionRef, prepare_batch,
    wayjournal_domain_registry,
};

use support::BoundedNoLegacy as NoLegacy;
struct TestDir(PathBuf);
impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wayjournal-s4b-cas-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&path).expect("dir");
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
    let out = Command::new(git())
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("Git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}
fn configure(path: &Path) {
    run(path, &["config", "user.name", "Wayjournal Test"]);
    run(
        path,
        &["config", "user.email", "wayjournal@example.invalid"],
    );
}
fn genesis() -> Record {
    Record {
        record_schema: "wayjournal.identity/v1".parse().unwrap(),
        domain: "wayjournal.identity".parse().unwrap(),
        kind: "store.genesis".parse().unwrap(),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174011".parse().unwrap(),
        entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010".parse().unwrap(),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174012".parse().unwrap(),
        actor: ActorId::parse("human:robin").unwrap(),
        occurred_at: "2026-08-12T13:00:00Z".parse().unwrap(),
        recorded_at: "2026-08-12T13:00:01Z".parse().unwrap(),
        parents: vec![],
        payload: json!({"store_kind":"wayjournal.personal","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"}),
    }
}
fn profile(record: &str, batch: &str, value: &str) -> Record {
    Record {
        record_schema: "wayjournal.profile/v1".parse().unwrap(),
        domain: "wayjournal.profile".parse().unwrap(),
        kind: "profile.display_name.set".parse().unwrap(),
        record_id: record.parse().unwrap(),
        entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010".parse().unwrap(),
        batch_id: batch.parse().unwrap(),
        actor: ActorId::parse("human:robin").unwrap(),
        occurred_at: "2026-08-12T13:01:00Z".parse().unwrap(),
        recorded_at: "2026-08-12T13:01:01Z".parse().unwrap(),
        parents: vec![],
        payload: json!({"value":value}),
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
        .unwrap(),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(url::Url::from_file_path(remote).unwrap().as_str())
                .unwrap(),
            ApprovedRef::parse("refs/heads/main").unwrap(),
        ),
    )
    .unwrap()
}
struct Fixture {
    root: TestDir,
    remote: PathBuf,
    local: PathBuf,
    store: Store,
    request: GitSyncRequest,
}
fn fixture(label: &str) -> Fixture {
    fixture_with_remote(label, true, false)
}

fn fixture_with_remote(label: &str, bare: bool, configured_non_bare: bool) -> Fixture {
    let root = TestDir::new(label);
    let remote = root.0.join(if bare { "remote.git" } else { "remote" });
    if bare {
        run(&root.0, &["init", "--bare", remote.to_str().unwrap()]);
    } else {
        run(&root.0, &["init", "-b", "main", remote.to_str().unwrap()]);
        configure(&remote);
        // Permit fixture genesis publication, then restore the default refusal for that matrix
        // row before exercising S4b.
        run(
            &remote,
            &["config", "receive.denyCurrentBranch", "updateInstead"],
        );
    }
    let local = root.0.join("local");
    fs::create_dir(&local).unwrap();
    let registry = wayjournal_domain_registry().unwrap();
    let store = Store::open(&local, registry, Arc::new(NoLegacy)).unwrap();
    let batch = prepare_batch(&[genesis()], "genesis", &registry).unwrap();
    store
        .append(&batch, store.read().unwrap().revision())
        .unwrap();
    run(&local, &["init", "-b", "main"]);
    configure(&local);
    run(&local, &["add", "journal", "events", "batches"]);
    run(&local, &["commit", "-m", "genesis"]);
    run(
        &local,
        &["push", remote.to_str().unwrap(), "HEAD:refs/heads/main"],
    );
    if bare {
        run(
            &root.0,
            &[
                "--git-dir",
                remote.to_str().unwrap(),
                "symbolic-ref",
                "HEAD",
                "refs/heads/main",
            ],
        );
    } else if !configured_non_bare {
        run(&remote, &["config", "--unset", "receive.denyCurrentBranch"]);
    }
    let request = request(&remote);
    store.bootstrap_git_admission(&request).unwrap();
    Fixture {
        root,
        remote,
        local,
        store,
        request,
    }
}
fn clone_store(f: &Fixture, name: &str) -> (PathBuf, Store, GitSyncRequest) {
    run(&f.root.0, &["clone", f.remote.to_str().unwrap(), name]);
    let path = f.root.0.join(name);
    configure(&path);
    run(&path, &["remote", "remove", "origin"]);
    let store = Store::open(
        &path,
        wayjournal_domain_registry().unwrap(),
        Arc::new(NoLegacy),
    )
    .unwrap();
    let req = request(&f.remote);
    store.bootstrap_git_admission(&req).unwrap();
    (path, store, req)
}
fn append(store: &Store, path: &Path, record: Record, key: &str) {
    let registry = wayjournal_domain_registry().unwrap();
    let batch = prepare_batch(&[record], key, &registry).unwrap();
    store
        .append(&batch, store.read().unwrap().revision())
        .unwrap();
    run(path, &["add", "journal"]);
    run(path, &["commit", "-m", key]);
}

fn child_sync(root: &Path, remote: &Path, fault: &str) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("fault_child_entry")
        .arg("--nocapture")
        .env("WAYJOURNAL_S4B_CHILD_MODE", "sync")
        .env("WAYJOURNAL_S4B_ROOT", root)
        .env("WAYJOURNAL_S4B_REMOTE", remote)
        .env("WAYJOURNAL_INTERNAL_S4B_FAULT", fault)
        .status()
        .expect("spawn sync child")
}

fn child_api_probe_mode(root: &Path, remote: &Path, mode: &str) {
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("fault_child_entry")
        .arg("--nocapture")
        .env("WAYJOURNAL_S4B_CHILD_MODE", mode)
        .env("WAYJOURNAL_S4B_ROOT", root)
        .env("WAYJOURNAL_S4B_REMOTE", remote)
        .status()
        .expect("spawn API child");
    assert!(status.success(), "fresh-process API probe failed: {status}");
}

fn child_api_probe(root: &Path, remote: &Path) {
    child_api_probe_mode(root, remote, "apis");
}

fn probe_five_apis(root: &Path, remote: &Path) {
    let registry = wayjournal_domain_registry().unwrap();
    let store = Store::open(root, registry, Arc::new(NoLegacy)).unwrap();
    let batch = prepare_batch(
        &[profile(
            "01913f1d-8e2a-7c30-8f4a-426614174091",
            "01913f1d-8e2a-7c30-8f4a-426614174092",
            "blocked",
        )],
        "blocked",
        &registry,
    )
    .unwrap();
    let bogus = StoreRevisionRef::parse(
        "wayjournal.store/blake3-framed-v1",
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert!(matches!(
        store.read(),
        Err(StoreError::GitSyncPending { .. })
    ));
    assert!(matches!(
        store.append(&batch, bogus),
        Err(StoreError::GitSyncPending { .. })
    ));
    assert!(matches!(
        store.exclusive_snapshot(),
        Err(StoreError::GitSyncPending { .. })
    ));
    assert!(matches!(
        store.admission_checkpoint(),
        Err(GitAdmissionError::Store(StoreError::GitSyncPending { .. }))
    ));
    // Bootstrap is the fifth API. It may return read-only UpToDate once every local surface is
    // candidate, or remain pending before then; it must not perform recovery.
    let before = fs::read_dir(root.join(".wayjournal-local/sync-pending"))
        .unwrap()
        .count();
    let bootstrap = store.bootstrap_git_admission(&request(remote));
    assert!(
        bootstrap.is_ok()
            || matches!(
                bootstrap,
                Err(GitAdmissionError::Store(StoreError::GitSyncPending { .. }))
            ),
        "unexpected bootstrap result: {bootstrap:?}"
    );
    assert_eq!(
        fs::read_dir(root.join(".wayjournal-local/sync-pending"))
            .unwrap()
            .count(),
        before,
        "bootstrap changed pending state"
    );
}

fn probe_five_apis_without_pending(root: &Path, remote: &Path) {
    let registry = wayjournal_domain_registry().unwrap();
    let store = Store::open(root, registry, Arc::new(NoLegacy)).unwrap();
    let expected = store.read().unwrap().revision();
    let batch = prepare_batch(
        &[profile(
            "01913f1d-8e2a-7c30-8f4a-426614174093",
            "01913f1d-8e2a-7c30-8f4a-426614174094",
            "probe",
        )],
        "probe",
        &registry,
    )
    .unwrap();
    let wrong = StoreRevisionRef::parse(
        "wayjournal.store/blake3-framed-v1",
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert!(matches!(
        store.append(&batch, wrong),
        Err(StoreError::RevisionMismatch { .. })
    ));
    store.exclusive_snapshot().unwrap();
    store.admission_checkpoint().unwrap();
    store.bootstrap_git_admission(&request(remote)).unwrap();
    assert_eq!(store.read().unwrap().revision(), expected);
}

#[test]
fn fault_child_entry() {
    let Some(mode) = std::env::var_os("WAYJOURNAL_S4B_CHILD_MODE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("WAYJOURNAL_S4B_ROOT").unwrap());
    let remote = PathBuf::from(std::env::var_os("WAYJOURNAL_S4B_REMOTE").unwrap());
    if mode == "apis" {
        probe_five_apis(&root, &remote);
        return;
    }
    if mode == "clean-apis" {
        probe_five_apis_without_pending(&root, &remote);
        return;
    }
    let store = Store::open(
        &root,
        wayjournal_domain_registry().unwrap(),
        Arc::new(NoLegacy),
    )
    .unwrap();
    let _ = store.sync_git_union(&request(&remote));
    panic!("configured fault was not reached");
}

#[test]
fn every_pre_root_fault_is_disposable_for_five_fresh_handle_process_apis() {
    for barrier in [
        "operation-directory-durable",
        "disposable-fetch-complete",
        "compact-repository-durable",
        "disposable-fetch-retired",
        "repository-and-additions-durable",
    ] {
        let f = fixture(&format!("pre-root-fault-{barrier}"));
        run(&f.local, &["commit", "--allow-empty", "-m", "advance"]);
        assert_eq!(child_sync(&f.local, &f.remote, barrier).code(), Some(86));
        probe_five_apis_without_pending(&f.local, &f.remote);
        child_api_probe_mode(&f.local, &f.remote, "clean-apis");
        assert_eq!(
            fs::read_dir(f.local.join(".wayjournal-local/sync-pending"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[test]
fn every_normal_durability_fault_recovers_and_gates_five_fresh_handle_process_apis() {
    let barriers = [
        "pending-root-file-durable",
        "pending-root-durable",
        "canonical-files-durable",
        "phase-temporary-durable",
        "phase-renamed",
        "phase-parent-durable",
        "files-phase-durable",
        "local-ref-durable",
        "local-ref-phase-durable",
        "checkpoint-temporary-durable",
        "checkpoint-renamed",
        "checkpoint-parent-durable",
        "checkpoint-durable",
        "checkpoint-phase-durable",
        "push-response-lost",
        "remote-confirmed-phase-durable",
        "internal-candidate-removed",
        "pending-directory-unlinked",
    ];
    for barrier in barriers {
        let f = fixture(&format!("fault-{barrier}"));
        run(&f.local, &["commit", "--allow-empty", "-m", "advance"]);
        let status = child_sync(&f.local, &f.remote, barrier);
        assert_eq!(status.code(), Some(86), "fault not reached: {barrier}");
        let pending_count = fs::read_dir(f.local.join(".wayjournal-local/sync-pending"))
            .unwrap()
            .count();
        if barrier == "pending-directory-unlinked" {
            assert_eq!(pending_count, 0);
        } else {
            assert!(pending_count > 0, "no durable pending at {barrier}");
            probe_five_apis(&f.local, &f.remote);
            child_api_probe(&f.local, &f.remote);
            let fresh = Store::open(
                &f.local,
                wayjournal_domain_registry().unwrap(),
                Arc::new(NoLegacy),
            )
            .unwrap();
            assert!(matches!(
                fresh.sync_git_union(&request(&f.remote)).unwrap(),
                GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. }
            ));
        }
        let resumed = Store::open(
            &f.local,
            wayjournal_domain_registry().unwrap(),
            Arc::new(NoLegacy),
        )
        .unwrap();
        resumed.read().expect("APIs resume after durable cleanup");
    }
}

#[test]
fn prepared_recovery_uses_constant_git_processes_for_many_additions() {
    let f = fixture("constant-process-recovery");
    let registry = wayjournal_domain_registry().unwrap();
    let records = (0..16)
        .map(|index| {
            profile(
                &format!("01913f1d-8e2a-7c30-8f4a-4266141741{index:02}"),
                "01913f1d-8e2a-7c30-8f4a-426614174200",
                &format!("value-{index}"),
            )
        })
        .collect::<Vec<_>>();
    let batch = prepare_batch(&records, "many-additions", &registry).unwrap();
    let (writer_path, writer, _) = clone_store(&f, "many-additions-writer");
    writer
        .append(&batch, writer.read().unwrap().revision())
        .unwrap();
    run(&writer_path, &["add", "journal"]);
    run(&writer_path, &["commit", "-m", "many additions"]);
    run(
        &writer_path,
        &[
            "push",
            url::Url::from_file_path(&f.remote).unwrap().as_str(),
            "HEAD:refs/heads/main",
        ],
    );
    assert_eq!(
        child_sync(&f.local, &f.remote, "pending-root-durable").code(),
        Some(86)
    );

    let wrapper = f.root.0.join("counting-git");
    let wrapper_source = f.root.0.join("counting-git.rs");
    let log = f.root.0.join("git-invocations");
    fs::write(
        &wrapper_source,
        format!(
            r#"use std::{{env, fs::OpenOptions, io::Write, process::Command}};
fn main() {{
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let mut log = OpenOptions::new().create(true).append(true).open({log:?}).unwrap();
    writeln!(log, "{{}}", args.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>().join(" ")).unwrap();
    let status = Command::new({git:?}).args(&args).status().unwrap();
    std::process::exit(status.code().unwrap_or(127));
}}
"#,
            log = log,
            git = git(),
        ),
    )
    .unwrap();
    let compiled = Command::new("rustc")
        .args([
            wrapper_source.as_os_str(),
            "-o".as_ref(),
            wrapper.as_os_str(),
        ])
        .status()
        .unwrap();
    assert!(compiled.success(), "compile counting Git wrapper");
    let outcome = f
        .store
        .sync_git_union(&request_with_git(&f.remote, wrapper))
        .unwrap();
    assert!(matches!(outcome, GitSyncOutcome::Advanced { .. }));

    let invocations = fs::read_to_string(log).unwrap();
    assert_eq!(
        invocations
            .lines()
            .filter(|line| line.contains(" cat-file -e "))
            .count(),
        0,
        "recovery must not spawn cat-file -e per staged path:\n{invocations}"
    );
    assert_eq!(
        invocations
            .lines()
            .filter(|line| line.contains(" cat-file blob "))
            .count(),
        0,
        "recovery must use one persistent cat-file batch:\n{invocations}"
    );
    assert!(
        invocations.lines().count() < 80,
        "recovery process count must be independent of additions:\n{invocations}"
    );
}

#[test]
fn unreachable_remote_objects_are_removed_before_pending_root_is_durable() {
    let f = fixture("reachable-only");
    let hostile = run(&f.remote, &["hash-object", "-w", "--stdin"]);
    let hostile = String::from_utf8(hostile).unwrap().trim().to_owned();
    run(&f.local, &["commit", "--allow-empty", "-m", "advance"]);
    assert_eq!(
        child_sync(&f.local, &f.remote, "pending-root-durable").code(),
        Some(86)
    );
    let pending = fs::read_dir(f.local.join(".wayjournal-local/sync-pending"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("repo.git");
    let status = Command::new(git())
        .args([
            "--git-dir",
            pending.to_str().unwrap(),
            "cat-file",
            "-e",
            &hostile,
        ])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "unreachable hostile object became durable"
    );
}

#[test]
fn sha256_advancing_union_cas_is_exercised_when_supported() {
    let probe = Command::new(git())
        .args(["init", "-h"])
        .output()
        .expect("Git probe");
    if !String::from_utf8_lossy(&probe.stdout).contains("object-format")
        && !String::from_utf8_lossy(&probe.stderr).contains("object-format")
    {
        return;
    }
    let root = TestDir::new("sha256-advance");
    let remote = root.0.join("remote.git");
    run(
        &root.0,
        &[
            "init",
            "--bare",
            "--object-format=sha256",
            remote.to_str().unwrap(),
        ],
    );
    let local = root.0.join("local");
    fs::create_dir(&local).unwrap();
    let registry = wayjournal_domain_registry().unwrap();
    let store = Store::open(&local, registry, Arc::new(NoLegacy)).unwrap();
    let batch = prepare_batch(&[genesis()], "genesis", &registry).unwrap();
    store
        .append(&batch, store.read().unwrap().revision())
        .unwrap();
    run(&local, &["init", "-b", "main", "--object-format=sha256"]);
    configure(&local);
    run(&local, &["add", "journal", "events", "batches"]);
    run(&local, &["commit", "-m", "genesis"]);
    run(
        &local,
        &["push", remote.to_str().unwrap(), "HEAD:refs/heads/main"],
    );
    run(
        &root.0,
        &[
            "--git-dir",
            remote.to_str().unwrap(),
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ],
    );
    let req = request(&remote);
    store.bootstrap_git_admission(&req).unwrap();
    append(
        &store,
        &local,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174081",
            "01913f1d-8e2a-7c30-8f4a-426614174082",
            "sha256",
        ),
        "sha256",
    );
    let GitSyncOutcome::Advanced { commit, .. } = store.sync_git_union(&req).unwrap() else {
        panic!("SHA-256 advancing sync did not advance")
    };
    assert_eq!(commit.as_hex().len(), 64);
    assert!(matches!(
        commit.format(),
        wayjournal_core::GitObjectFormat::Sha256
    ));
}

#[test]
fn bare_and_explicitly_configured_non_bare_advance_but_default_non_bare_refuses() {
    for (label, bare, configured) in [("bare", true, false), ("nonbare-ok", false, true)] {
        let f = fixture_with_remote(label, bare, configured);
        run(&f.local, &["commit", "--allow-empty", "-m", "advance"]);
        assert!(matches!(
            f.store.sync_git_union(&f.request).unwrap(),
            GitSyncOutcome::Advanced { .. }
        ));
    }
    let f = fixture_with_remote("nonbare-refused", false, false);
    run(&f.local, &["commit", "--allow-empty", "-m", "advance"]);
    let error = f
        .store
        .sync_git_union(&f.request)
        .expect_err("default non-bare must reject checked-out ref push");
    assert!(matches!(error, wayjournal_core::GitSyncError::Git(_)));
}

#[test]
fn push_updates_only_approved_ref_with_exact_lease() {
    let f = fixture("one-ref");
    run(
        &f.root.0,
        &[
            "--git-dir",
            f.remote.to_str().unwrap(),
            "branch",
            "other",
            "refs/heads/main",
        ],
    );
    let before = run(
        &f.root.0,
        &[
            "--git-dir",
            f.remote.to_str().unwrap(),
            "rev-parse",
            "refs/heads/other",
        ],
    );
    run(&f.local, &["commit", "--allow-empty", "-m", "advance"]);
    assert!(matches!(
        f.store.sync_git_union(&f.request).unwrap(),
        GitSyncOutcome::Advanced { .. }
    ));
    let after = run(
        &f.root.0,
        &[
            "--git-dir",
            f.remote.to_str().unwrap(),
            "rev-parse",
            "refs/heads/other",
        ],
    );
    assert_eq!(before, after);
}

#[test]
fn lost_push_response_is_resolved_by_observation() {
    let f = fixture("idempotent-observe");
    run(&f.local, &["commit", "--allow-empty", "-m", "advance"]);
    let status = child_sync(&f.local, &f.remote, "push-response-lost");
    assert_eq!(status.code(), Some(86), "push response was not lost");
    let remote_after_lost_response = run(
        &f.root.0,
        &[
            "--git-dir",
            f.remote.to_str().unwrap(),
            "rev-parse",
            "refs/heads/main",
        ],
    );
    let recovered = f.store.sync_git_union(&f.request).unwrap();
    assert!(matches!(
        recovered,
        GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. }
    ));
    assert_eq!(
        remote_after_lost_response,
        run(
            &f.root.0,
            &[
                "--git-dir",
                f.remote.to_str().unwrap(),
                "rev-parse",
                "refs/heads/main",
            ],
        ),
        "recovery pushed a second value rather than resolving by observation"
    );
}

fn stale_fault_fixture(label: &str) -> (TestDir, PathBuf, PathBuf) {
    let f = fixture(label);
    let (path_a, store_a, req_a) = clone_store(&f, "a");
    let (path_b, store_b, _req_b) = clone_store(&f, "b");
    append(
        &store_a,
        &path_a,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174021",
            "01913f1d-8e2a-7c30-8f4a-426614174022",
            "A",
        ),
        "a",
    );
    append(
        &store_b,
        &path_b,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174031",
            "01913f1d-8e2a-7c30-8f4a-426614174032",
            "B",
        ),
        "b",
    );
    // Freeze B after its old-remote observation is durably bound, then let A win that exact
    // lease. Reopening B must observe the third value and durably publish a stale predecessor.
    assert_eq!(
        child_sync(&path_b, &f.remote, "checkpoint-phase-durable").code(),
        Some(86),
        "failed to establish pre-CAS predecessor"
    );
    assert!(matches!(
        store_a.sync_git_union(&req_a).unwrap(),
        GitSyncOutcome::Advanced { .. }
    ));
    assert_eq!(
        child_sync(&path_b, &f.remote, "remote-stale-phase-durable").code(),
        Some(86),
        "failed to establish durable stale predecessor"
    );
    (f.root, f.remote, path_b)
}

#[test]
fn every_stale_successor_fault_gates_five_fresh_handle_process_apis() {
    let barriers = [
        "operation-directory-durable",
        "disposable-fetch-complete",
        "compact-repository-durable",
        "disposable-fetch-retired",
        "repository-and-additions-durable",
        "pending-root-file-durable",
        "pending-root-durable",
        "successor-before-predecessor-retirement",
        "pending-directory-unlinked",
        "predecessor-retired-durable",
        "canonical-files-durable",
        "phase-temporary-durable",
        "phase-renamed",
        "phase-parent-durable",
        "files-phase-durable",
        "local-ref-updated",
        "local-git-durable",
        "local-ref-durable",
        "local-ref-phase-durable",
        "checkpoint-temporary-durable",
        "checkpoint-renamed",
        "checkpoint-parent-durable",
        "checkpoint-durable",
        "checkpoint-phase-durable",
        "push-response-lost",
        "remote-confirmed-phase-durable",
        "internal-candidate-removed",
        "pending-retired-durable",
    ];
    for barrier in barriers {
        let (_root, remote, local) = stale_fault_fixture(&format!("stale-fault-{barrier}"));
        let status = child_sync(&local, &remote, barrier);
        assert_eq!(status.code(), Some(86), "fault not reached: {barrier}");
        let pending_count = fs::read_dir(local.join(".wayjournal-local/sync-pending"))
            .unwrap()
            .count();
        if barrier == "pending-retired-durable" {
            assert_eq!(pending_count, 0);
            probe_five_apis_without_pending(&local, &remote);
            child_api_probe_mode(&local, &remote, "clean-apis");
        } else {
            assert!(
                pending_count > 0,
                "availability barrier missing at {barrier}"
            );
            probe_five_apis(&local, &remote);
            child_api_probe(&local, &remote);
            let fresh = Store::open(
                &local,
                wayjournal_domain_registry().unwrap(),
                Arc::new(NoLegacy),
            )
            .unwrap();
            assert!(matches!(
                fresh.sync_git_union(&request(&remote)).unwrap(),
                GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. }
            ));
            probe_five_apis_without_pending(&local, &remote);
            child_api_probe_mode(&local, &remote, "clean-apis");
        }
    }
}

#[test]
fn stale_successor_handoff_is_old_or_new() {
    let f = fixture("stale-successor");
    let (path_a, store_a, req_a) = clone_store(&f, "a");
    let (path_b, store_b, req_b) = clone_store(&f, "b");
    append(
        &store_a,
        &path_a,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174021",
            "01913f1d-8e2a-7c30-8f4a-426614174022",
            "A",
        ),
        "a",
    );
    append(
        &store_b,
        &path_b,
        profile(
            "01913f1d-8e2a-7c30-8f4a-426614174031",
            "01913f1d-8e2a-7c30-8f4a-426614174032",
            "B",
        ),
        "b",
    );
    assert!(matches!(
        store_a.sync_git_union(&req_a).unwrap(),
        GitSyncOutcome::Advanced { .. }
    ));
    assert!(matches!(
        store_b.sync_git_union(&req_b).unwrap(),
        GitSyncOutcome::Advanced { .. }
    ));
    let pending = path_b.join(".wayjournal-local/sync-pending");
    assert_eq!(fs::read_dir(pending).unwrap().count(), 0);
}
