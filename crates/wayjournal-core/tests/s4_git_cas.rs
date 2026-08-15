#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod support;

use std::{
    fs,
    mem::MaybeUninit,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use serde_json::json;
use wayjournal_core::{
    ActorId, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, GitAdmissionError,
    GitQuarantineReason, GitSyncError, GitSyncOutcome, GitSyncRequest, LocalTrustBinding,
    MAX_RECORD_BYTES, Record, Store, StoreError, StoreRevisionRef, prepare_batch,
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
struct TransferProbe {
    descriptor: rustix::fd::OwnedFd,
    watch: i32,
}

fn install_open_probe(path: &Path) -> TransferProbe {
    use rustix::fs::inotify;

    let descriptor = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)
        .expect("create open probe");
    let watch =
        inotify::add_watch(&descriptor, path, inotify::WatchFlags::OPEN).expect("watch open probe");
    TransferProbe { descriptor, watch }
}

fn install_transfer_probe(remote: &Path) -> TransferProbe {
    let path = remote.join("objects/info/alternates");
    fs::write(&path, b"wayjournal-contact-probe\n").expect("install transfer probe");
    install_open_probe(&path)
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

fn linked_fixture(label: &str) -> Fixture {
    let mut fixture = fixture(label);
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
    let store = Store::open(
        &linked,
        wayjournal_domain_registry().unwrap(),
        Arc::new(NoLegacy),
    )
    .unwrap();
    store.bootstrap_git_admission(&fixture.request).unwrap();
    fixture.local = linked;
    fixture.store = store;
    fixture
}

fn linked_admin_and_common(linked: &Path) -> (PathBuf, PathBuf) {
    let gitfile = fs::read(linked.join(".git")).unwrap();
    let raw = gitfile
        .strip_prefix(b"gitdir: ")
        .unwrap()
        .strip_suffix(b"\n")
        .unwrap_or_else(|| gitfile.strip_prefix(b"gitdir: ").unwrap());
    let admin = PathBuf::from(std::ffi::OsString::from_vec(raw.to_vec()));
    let common_raw = fs::read(admin.join("commondir")).unwrap();
    let common_raw = common_raw.strip_suffix(b"\n").unwrap_or(&common_raw);
    let common =
        fs::canonicalize(admin.join(std::ffi::OsString::from_vec(common_raw.to_vec()))).unwrap();
    (admin, common)
}

#[allow(clippy::unnecessary_debug_formatting)] // Debug produces escaped Rust path literals.
fn replacement_request(
    fixture: &Fixture,
    label: &str,
    target: &Path,
    replacement: &Path,
) -> GitSyncRequest {
    let tools = fixture.root.0.join(format!("replacement-tools-{label}"));
    fs::create_dir(&tools).unwrap();
    let source = tools.join("git-wrapper.rs");
    let wrapper = tools.join("git-wrapper");
    let marker = tools.join("replaced");
    let retained = target.with_extension(format!("wayjournal-retained-{label}"));
    let marker_literal = format!("{marker:?}");
    let target_literal = format!("{target:?}");
    let retained_literal = format!("{retained:?}");
    let replacement_literal = format!("{replacement:?}");
    let git_path = git();
    let git_literal = format!("{git_path:?}");
    fs::write(
        &source,
        format!(
            r#"use std::{{env, fs, ffi::OsStr, process::Command}};
fn main() {{
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let standalone = args.iter().any(|arg| arg == OsStr::new("ls-remote"));
    if standalone {{
        assert_eq!(env::current_dir().unwrap(), std::path::Path::new("/"));
        assert_eq!(env::var_os("GIT_DIR").as_deref(), Some(OsStr::new("/dev/null")));
        assert!(env::var_os("GIT_COMMON_DIR").is_none());
        assert!(env::var_os("GIT_WORK_TREE").is_none());
    }}
    if !standalone && env::var_os("GIT_DIR").is_some() && !std::path::Path::new({marker_literal}).exists() {{
        fs::rename({target_literal}, {retained_literal}).unwrap();
        fs::rename({replacement_literal}, {target_literal}).unwrap();
        fs::write({marker_literal}, b"").unwrap();
    }}
    let status = Command::new({git_literal}).args(&args).status().unwrap();
    std::process::exit(status.code().unwrap_or(127));
}}
"#,
        ),
    )
    .unwrap();
    let status = Command::new("rustc")
        .args([source.as_os_str(), "-o".as_ref(), wrapper.as_os_str()])
        .status()
        .unwrap();
    assert!(status.success());
    request_with_git(&fixture.remote, wrapper)
}

fn advance_remote(fixture: &Fixture) {
    let writer = fixture
        .root
        .0
        .join(format!("writer-{}", uuid::Uuid::now_v7()));
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().unwrap(),
            writer.to_str().unwrap(),
        ],
    );
    configure(&writer);
    run(&writer, &["commit", "--allow-empty", "-m", "advance"]);
    run(&writer, &["push", "origin", "HEAD:refs/heads/main"]);
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
fn linked_worktree_recovers_every_durable_publication_phase() {
    for barrier in [
        "pending-root-durable",
        "files-phase-durable",
        "local-ref-updated",
        "local-ref-phase-durable",
        "remote-confirmed-phase-durable",
    ] {
        let fixture = linked_fixture(&format!("linked-recovery-{barrier}"));
        let writer = fixture.root.0.join("writer");
        run(
            &fixture.root.0,
            &[
                "clone",
                fixture.remote.to_str().unwrap(),
                writer.to_str().unwrap(),
            ],
        );
        configure(&writer);
        run(&writer, &["commit", "--allow-empty", "-m", "advance"]);
        run(&writer, &["push", "origin", "HEAD:refs/heads/main"]);
        let status = child_sync(&fixture.local, &fixture.remote, barrier);
        assert_eq!(status.code(), Some(86), "fault not reached: {barrier}");
        assert!(
            fs::read_dir(fixture.local.join(".wayjournal-local/sync-pending"))
                .unwrap()
                .count()
                > 0,
            "pending state missing at {barrier}"
        );
        let fresh = Store::open(
            &fixture.local,
            wayjournal_domain_registry().unwrap(),
            Arc::new(NoLegacy),
        )
        .unwrap();
        assert!(matches!(
            fresh.sync_git_union(&request(&fixture.remote)).unwrap(),
            GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. }
        ));
        assert_eq!(
            fs::read_dir(fixture.local.join(".wayjournal-local/sync-pending"))
                .unwrap()
                .count(),
            0,
            "pending state survived recovery at {barrier}"
        );
        let local =
            String::from_utf8(run(&fixture.local, &["rev-parse", "refs/heads/main"])).unwrap();
        let remote = String::from_utf8(run(
            &fixture.root.0,
            &[
                "--git-dir",
                fixture.remote.to_str().unwrap(),
                "rev-parse",
                "refs/heads/main",
            ],
        ))
        .unwrap();
        assert_eq!(local.trim(), remote.trim(), "ref mismatch at {barrier}");
        let candidate = Command::new(git())
            .current_dir(&fixture.local)
            .args(["rev-parse", "--verify", "refs/wayjournal/candidate"])
            .output()
            .unwrap();
        assert!(
            !candidate.status.success(),
            "candidate ref survived recovery at {barrier}"
        );
    }
}

#[test]
fn linked_pending_layout_failure_precedes_transfer_and_preserves_pending() {
    let fixture = linked_fixture("linked-pending-layout-failure");
    let writer = fixture.root.0.join("writer");
    run(
        &fixture.root.0,
        &[
            "clone",
            fixture.remote.to_str().unwrap(),
            writer.to_str().unwrap(),
        ],
    );
    configure(&writer);
    run(&writer, &["commit", "--allow-empty", "-m", "advance"]);
    run(&writer, &["push", "origin", "HEAD:refs/heads/main"]);
    assert_eq!(
        child_sync(&fixture.local, &fixture.remote, "files-phase-durable").code(),
        Some(86)
    );
    let pending = fixture.local.join(".wayjournal-local/sync-pending");
    let pending_before = fs::read_dir(&pending).unwrap().count();
    assert!(pending_before > 0);
    let probe = install_transfer_probe(&fixture.remote);
    let retained = fixture.local.join(".git.retained");
    fs::rename(fixture.local.join(".git"), &retained).unwrap();
    std::os::unix::fs::symlink(&retained, fixture.local.join(".git")).unwrap();

    let fresh = Store::open(
        &fixture.local,
        wayjournal_domain_registry().unwrap(),
        Arc::new(NoLegacy),
    )
    .unwrap();
    match fresh
        .sync_git_union(&request(&fixture.remote))
        .expect_err("hostile linked layout must stop recovery")
    {
        GitSyncError::Git(error) => assert_eq!(error.operation(), "resolve local Git layout"),
        other => panic!("unexpected recovery error: {other:?}"),
    }
    assert!(
        !transfer_probe_contacted(&probe),
        "recovery contacted remote"
    );
    assert_eq!(fs::read_dir(&pending).unwrap().count(), pending_before);

    fs::remove_file(fixture.local.join(".git")).unwrap();
    fs::rename(&retained, fixture.local.join(".git")).unwrap();
    assert!(matches!(
        fresh.sync_git_union(&request(&fixture.remote)).unwrap(),
        GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. }
    ));
}

#[test]
fn linked_admin_and_common_replacements_are_never_traversed() {
    for phase in ["initial", "files-published"] {
        for kind in ["admin", "common"] {
            let fixture = linked_fixture(&format!("linked-{phase}-{kind}-replacement"));
            advance_remote(&fixture);
            if phase == "files-published" {
                assert_eq!(
                    child_sync(&fixture.local, &fixture.remote, "files-phase-durable").code(),
                    Some(86)
                );
            }
            let (admin, common) = linked_admin_and_common(&fixture.local);
            let target = if kind == "admin" { &admin } else { &common };
            let replacement = fixture.root.0.join(format!("{phase}-{kind}-replacement"));
            fs::create_dir(&replacement).unwrap();
            let sentinel = replacement.join("sentinel");
            fs::write(&sentinel, b"must remain unopened").unwrap();
            let probe = install_open_probe(&sentinel);
            let replacement_request =
                replacement_request(&fixture, &format!("{phase}-{kind}"), target, &replacement);
            let store = Store::open(
                &fixture.local,
                wayjournal_domain_registry().unwrap(),
                Arc::new(NoLegacy),
            )
            .unwrap();
            let result = store.sync_git_union(&replacement_request);
            match result {
                Ok(GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. }) => {
                    assert_eq!(
                        fs::read_dir(fixture.local.join(".wayjournal-local/sync-pending"))
                            .unwrap()
                            .count(),
                        0
                    );
                }
                Err(GitSyncError::Git(error)) => {
                    assert_eq!(error.operation(), "resolve local Git layout");
                    assert!(
                        fs::read_dir(fixture.local.join(".wayjournal-local/sync-pending"))
                            .unwrap()
                            .count()
                            > 0,
                        "fail-closed replacement lost pending state"
                    );
                }
                other => panic!("unexpected {phase} {kind} result: {other:?}"),
            }
            assert!(
                !transfer_probe_contacted(&probe),
                "traversed {phase} {kind} replacement"
            );
            assert_eq!(
                fs::read(target.join("sentinel")).unwrap(),
                b"must remain unopened"
            );
        }
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

fn mutate_persisted_candidate_snapshot(fixture: &Fixture, label: &str, mutate: impl FnOnce(&Path)) {
    let pending = fs::read_dir(fixture.local.join(".wayjournal-local/sync-pending"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let document_path = pending.join("pending.json");
    let document = fs::read(&document_path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&document).unwrap();
    let candidate = value["candidate_commit"]["hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let repository = pending.join("repo.git");
    let corrupt = fixture.root.0.join(label);
    run(
        &fixture.root.0,
        &[
            "clone",
            "--no-checkout",
            repository.to_str().unwrap(),
            corrupt.to_str().unwrap(),
        ],
    );
    configure(&corrupt);
    run(&corrupt, &["checkout", "--detach", &candidate]);
    mutate(&corrupt);
    run(&corrupt, &["add", "-A"]);
    run(&corrupt, &["commit", "-m", label]);
    let corrupt_commit = String::from_utf8(run(&corrupt, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    run(
        &fixture.root.0,
        &[
            "--git-dir",
            repository.to_str().unwrap(),
            "fetch",
            "--no-write-fetch-head",
            corrupt.join(".git").to_str().unwrap(),
            &corrupt_commit,
        ],
    );
    let replaced = String::from_utf8(document)
        .unwrap()
        .replacen(&candidate, &corrupt_commit, 1);
    fs::write(&document_path, replaced).unwrap();
}

#[test]
fn persisted_candidate_snapshot_bounds_quarantine_as_hostile_publication() {
    for kind in ["overlong-tree-record", "oversized-canonical-blob"] {
        let fixture = fixture(&format!("persisted-{kind}"));
        advance_remote(&fixture);
        assert_eq!(
            child_sync(&fixture.local, &fixture.remote, "pending-root-durable").code(),
            Some(86)
        );
        mutate_persisted_candidate_snapshot(&fixture, kind, |corrupt| match kind {
            "overlong-tree-record" => {
                let component = "a".repeat(200);
                let path = corrupt
                    .join("journal/records")
                    .join(&component)
                    .join(&component)
                    .join(&component)
                    .join("entry.json");
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"{}\n").unwrap();
            }
            "oversized-canonical-blob" => {
                let paths =
                    String::from_utf8(run(corrupt, &["ls-tree", "-r", "--name-only", "HEAD"]))
                        .unwrap();
                let record = paths
                    .lines()
                    .find(|path| path.starts_with("journal/records/"))
                    .unwrap();
                fs::write(corrupt.join(record), vec![b'x'; MAX_RECORD_BYTES + 1]).unwrap();
            }
            _ => unreachable!(),
        });

        let first = fixture.store.sync_git_union(&fixture.request).unwrap();
        let GitSyncOutcome::Quarantined {
            incident_id,
            reason: GitQuarantineReason::HostilePublicationState,
        } = first
        else {
            panic!("{kind} was not quarantined: {first:?}")
        };
        assert!(matches!(
            fixture.store.sync_git_union(&fixture.request).unwrap(),
            GitSyncOutcome::Quarantined {
                incident_id: retry,
                reason: GitQuarantineReason::HostilePublicationState,
            } if retry == incident_id
        ));
    }
}

#[test]
fn corrupt_persisted_candidate_snapshot_quarantines_as_hostile_publication() {
    let fixture = fixture("corrupt-persisted-candidate");
    advance_remote(&fixture);
    assert_eq!(
        child_sync(&fixture.local, &fixture.remote, "pending-root-durable").code(),
        Some(86)
    );
    let pending = fs::read_dir(fixture.local.join(".wayjournal-local/sync-pending"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let document_path = pending.join("pending.json");
    let document = fs::read(&document_path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&document).unwrap();
    let candidate = value["candidate_commit"]["hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let repository = pending.join("repo.git");
    let corrupt = fixture.root.0.join("corrupt-candidate");
    run(
        &fixture.root.0,
        &[
            "clone",
            "--no-checkout",
            repository.to_str().unwrap(),
            corrupt.to_str().unwrap(),
        ],
    );
    configure(&corrupt);
    run(&corrupt, &["checkout", "--detach", &candidate]);
    let paths =
        String::from_utf8(run(&corrupt, &["ls-tree", "-r", "--name-only", "HEAD"])).unwrap();
    let manifest = paths
        .lines()
        .find(|path| path.starts_with("journal/batches/"))
        .unwrap();
    fs::write(corrupt.join(manifest), b"{}\n").unwrap();
    run(&corrupt, &["add", manifest]);
    run(&corrupt, &["commit", "-m", "corrupt candidate snapshot"]);
    let corrupt_commit = String::from_utf8(run(&corrupt, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    run(
        &fixture.root.0,
        &[
            "--git-dir",
            repository.to_str().unwrap(),
            "fetch",
            "--no-write-fetch-head",
            corrupt.join(".git").to_str().unwrap(),
            &corrupt_commit,
        ],
    );
    let mut replaced = String::from_utf8(document).unwrap();
    replaced = replaced.replacen(&candidate, &corrupt_commit, 1);
    fs::write(&document_path, replaced).unwrap();

    let first = fixture
        .store
        .sync_git_union(&fixture.request)
        .expect("closed hostile-publication outcome");
    let GitSyncOutcome::Quarantined {
        incident_id,
        reason: GitQuarantineReason::HostilePublicationState,
    } = first
    else {
        panic!("corrupt persisted candidate was not quarantined: {first:?}")
    };
    assert!(
        pending.exists(),
        "hostile recovery retired pending evidence"
    );
    assert!(matches!(
        fixture
            .store
            .sync_git_union(&fixture.request)
            .expect("durable quarantine retry"),
        GitSyncOutcome::Quarantined {
            incident_id: retry,
            reason: GitQuarantineReason::HostilePublicationState,
        } if retry == incident_id
    ));
}

#[test]
fn operational_recovery_snapshot_failure_preserves_pending_without_quarantine() {
    for failure in ["ls-tree", "cat-file-batch"] {
        let fixture = fixture(&format!("operational-recovery-{failure}"));
        advance_remote(&fixture);
        assert_eq!(
            child_sync(&fixture.local, &fixture.remote, "pending-root-durable").code(),
            Some(86)
        );
        let pending = fixture.local.join(".wayjournal-local/sync-pending");
        let pending_before = fs::read_dir(&pending).unwrap().count();
        let checkpoint_path = fixture
            .local
            .join(".wayjournal-local/checkpoints/admission-v1.json");
        let checkpoint_before = fs::read(&checkpoint_path).unwrap();
        let local_before =
            String::from_utf8(run(&fixture.local, &["rev-parse", "refs/heads/main"])).unwrap();

        let source = fixture
            .root
            .0
            .join(format!("git-recovery-{failure}-wrapper.rs"));
        let wrapper = fixture
            .root
            .0
            .join(format!("git-recovery-{failure}-wrapper"));
        let marker = fixture.root.0.join(format!("fail-recovery-{failure}"));
        let predicate = if failure == "ls-tree" {
            r#"args.iter().any(|arg| arg == OsStr::new("ls-tree"))"#
        } else {
            r#"args.iter().any(|arg| arg == OsStr::new("cat-file")) && args.iter().any(|arg| arg == OsStr::new("--batch"))"#
        };
        fs::write(&marker, b"fail\n").unwrap();
        fs::write(
            &source,
            format!(
                r"use std::{{env, ffi::OsStr, path::Path, process::Command}};
fn main() {{
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if Path::new({marker:?}).exists() && ({predicate}) {{
        std::process::exit(2);
    }}
    let status = Command::new({git:?}).args(&args).status().unwrap();
    std::process::exit(status.code().unwrap_or(127));
}}
",
                marker = marker,
                git = git(),
            ),
        )
        .unwrap();
        assert!(
            Command::new("rustc")
                .args([source.as_os_str(), "-o".as_ref(), wrapper.as_os_str()])
                .status()
                .unwrap()
                .success()
        );
        let request = request_with_git(&fixture.remote, wrapper);
        let result = fixture.store.sync_git_union(&request);
        assert!(
            matches!(
                result,
                Err(GitSyncError::Admission(GitAdmissionError::Git(_)))
            ),
            "unexpected operational {failure} recovery result: {result:?}"
        );
        assert_eq!(fs::read_dir(&pending).unwrap().count(), pending_before);
        assert_eq!(
            fs::read_dir(fixture.local.join(".wayjournal-local/quarantine"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(fs::read(&checkpoint_path).unwrap(), checkpoint_before);
        assert_eq!(
            String::from_utf8(run(&fixture.local, &["rev-parse", "refs/heads/main"])).unwrap(),
            local_before
        );
        fs::remove_file(marker).unwrap();
        assert!(matches!(
            fixture.store.sync_git_union(&request).unwrap(),
            GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. }
        ));
    }
}

#[test]
fn deferred_recovery_revalidation_failures_stay_operational_and_retryable() {
    for failure in ["diff-tree", "fifth-cat-file-batch"] {
        let fixture = fixture(&format!("deferred-revalidation-{failure}"));
        advance_remote(&fixture);
        assert_eq!(
            child_sync(&fixture.local, &fixture.remote, "pending-root-durable").code(),
            Some(86)
        );
        let pending = fixture.local.join(".wayjournal-local/sync-pending");
        let pending_before = fs::read_dir(&pending).unwrap().count();
        let checkpoint_path = fixture
            .local
            .join(".wayjournal-local/checkpoints/admission-v1.json");
        let checkpoint_before = fs::read(&checkpoint_path).unwrap();
        let local_before =
            String::from_utf8(run(&fixture.local, &["rev-parse", "refs/heads/main"])).unwrap();

        let source = fixture
            .root
            .0
            .join(format!("git-deferred-{failure}-wrapper.rs"));
        let wrapper = fixture
            .root
            .0
            .join(format!("git-deferred-{failure}-wrapper"));
        let marker = fixture.root.0.join(format!("fail-deferred-{failure}"));
        let count = fixture.root.0.join(format!("deferred-{failure}-count"));
        fs::write(&marker, b"fail\n").unwrap();
        fs::write(
            &source,
            format!(
                r#"use std::{{env, ffi::OsStr, fs, path::Path, process::Command}};
fn main() {{
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let is_batch = args.iter().any(|arg| arg == OsStr::new("cat-file"))
        && args.iter().any(|arg| arg == OsStr::new("--batch"));
    let batch_number = if is_batch {{
        let prior = fs::read_to_string({count:?})
            .ok().and_then(|value| value.parse::<usize>().ok()).unwrap_or(0);
        let next = prior + 1;
        fs::write({count:?}, next.to_string()).unwrap();
        next
    }} else {{ 0 }};
    let should_fail = if {failure:?} == "diff-tree" {{
        args.iter().any(|arg| arg == OsStr::new("diff-tree"))
    }} else {{
        is_batch && batch_number == 5
    }};
    if Path::new({marker:?}).exists() && should_fail {{
        std::process::exit(2);
    }}
    let status = Command::new({git:?}).args(&args).status().unwrap();
    std::process::exit(status.code().unwrap_or(127));
}}
"#,
                count = count,
                failure = failure,
                marker = marker,
                git = git(),
            ),
        )
        .unwrap();
        assert!(
            Command::new("rustc")
                .args([source.as_os_str(), "-o".as_ref(), wrapper.as_os_str()])
                .status()
                .unwrap()
                .success()
        );
        let request = request_with_git(&fixture.remote, wrapper);
        let result = fixture.store.sync_git_union(&request);
        assert!(
            matches!(
                result,
                Err(GitSyncError::Admission(GitAdmissionError::Git(_)))
            ),
            "unexpected deferred {failure} recovery result: {result:?}"
        );
        assert_eq!(fs::read_dir(&pending).unwrap().count(), pending_before);
        assert_eq!(
            fs::read_dir(fixture.local.join(".wayjournal-local/quarantine"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(fs::read(&checkpoint_path).unwrap(), checkpoint_before);
        assert_eq!(
            String::from_utf8(run(&fixture.local, &["rev-parse", "refs/heads/main"])).unwrap(),
            local_before
        );
        fs::remove_file(marker).unwrap();
        assert!(matches!(
            fixture.store.sync_git_union(&request).unwrap(),
            GitSyncOutcome::Advanced { .. } | GitSyncOutcome::UpToDate { .. }
        ));
    }
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
