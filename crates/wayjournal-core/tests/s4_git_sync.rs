#![cfg(target_os = "linux")]

use std::{
    ffi::OsString,
    fs,
    mem::MaybeUninit,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use serde_json::json;
use wayjournal_core::{
    ADMISSION_CHECKPOINT_FILENAME, ActorId, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator,
    GitAdmissionError, GitAdmissionOutcome, GitObjectFormat, GitSyncRequest, LegacyEntry,
    LegacyStoreAdapter, LocalTrustBinding, Record, Store, decode_admission_checkpoint,
    encode_admission_checkpoint, prepare_batch, wayjournal_domain_registry,
};

#[derive(Debug)]
struct NoLegacy;
impl LegacyStoreAdapter for NoLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
    }
}
struct TestDir(PathBuf);
impl TestDir {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("wayjournal-s4-{label}-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).expect("directory");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn git() -> PathBuf {
    PathBuf::from(
        std::env::var_os("WAYJOURNAL_TEST_GIT").expect("WAYJOURNAL_TEST_GIT absolute path"),
    )
}
fn run(cwd: &Path, args: &[&str]) {
    let output = Command::new(git())
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn trust(hex: &str) -> LocalTrustBinding {
    LocalTrustBinding::parse(hex).expect("trust binding")
}

struct AdmissionFixture {
    local: TestDir,
    _remote_parent: TestDir,
    remote: PathBuf,
    store: Store,
    request: GitSyncRequest,
}

fn admission_fixture(label: &str) -> AdmissionFixture {
    let local = TestDir::new(&format!("{label}-local"));
    let remote_parent = TestDir::new(&format!("{label}-remote"));
    let remote = remote_parent.path().join("store.git");
    run(
        remote_parent.path(),
        &["init", "--bare", remote.to_str().expect("UTF-8 remote")],
    );
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(local.path(), registry, Arc::new(NoLegacy)).expect("store");
    let batch = prepare_batch(&[genesis()], label, &registry).expect("genesis");
    store
        .append(&batch, store.read().expect("empty").revision())
        .expect("append");
    run(local.path(), &["init", "-b", "main"]);
    run(local.path(), &["config", "user.name", "Wayjournal Test"]);
    run(
        local.path(),
        &["config", "user.email", "wayjournal@example.invalid"],
    );
    run(local.path(), &["add", "events", "batches", "journal"]);
    run(local.path(), &["commit", "-m", "genesis"]);
    run(
        local.path(),
        &[
            "push",
            remote.to_str().expect("UTF-8 remote"),
            "HEAD:refs/heads/main",
        ],
    );
    run(
        remote_parent.path(),
        &[
            "--git-dir",
            remote.to_str().expect("UTF-8 remote"),
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ],
    );
    let locator =
        ApprovedRemoteLocator::parse(url::Url::from_file_path(&remote).expect("URL").as_str())
            .expect("locator");
    let request = GitSyncRequest::new(
        git(),
        trust("3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"),
        ApprovedRemote::new(locator, ApprovedRef::parse("refs/heads/main").expect("ref")),
    )
    .expect("request");
    AdmissionFixture {
        local,
        _remote_parent: remote_parent,
        remote,
        store,
        request,
    }
}

fn checkpoint_path(fixture: &AdmissionFixture) -> PathBuf {
    fixture
        .local
        .path()
        .join(".wayjournal-local/checkpoints/admission-v1.json")
}

fn linked_fixture(label: &str) -> (AdmissionFixture, TestDir, PathBuf) {
    let fixture = admission_fixture(label);
    run(fixture.local.path(), &["checkout", "--detach"]);
    let linked = TestDir::new(&format!("{label}-linked"));
    fs::remove_dir(linked.path()).expect("remove linked-worktree destination");
    run(
        fixture.local.path(),
        &[
            "worktree",
            "add",
            linked.path().to_str().expect("UTF-8 linked worktree"),
            "main",
        ],
    );
    let gitfile = fs::read(linked.path().join(".git")).expect("gitfile");
    let admin = PathBuf::from(OsString::from_vec(
        gitfile
            .strip_prefix(b"gitdir: ")
            .expect("gitfile prefix")
            .strip_suffix(b"\n")
            .unwrap_or_else(|| gitfile.strip_prefix(b"gitdir: ").expect("gitfile prefix"))
            .to_vec(),
    ));
    (fixture, linked, admin)
}

#[test]
fn malformed_linked_topology_and_symlink_components_fail_closed() {
    for case in ["backlink", "commondir", "common-redirect", "symlink"] {
        let (fixture, linked, admin) = linked_fixture(&format!("linked-topology-{case}"));
        match case {
            "backlink" => {
                let other = linked.path().join("other-gitfile");
                fs::write(&other, b"not authority\n").expect("other gitfile");
                fs::write(admin.join("gitdir"), format!("{}\n", other.display()))
                    .expect("replace backlink");
            }
            "commondir" => {
                fs::write(admin.join("commondir"), b".\n").expect("replace commondir");
            }
            "common-redirect" => {
                fs::write(fixture.local.path().join(".git/commondir"), b"elsewhere\n")
                    .expect("redirect common");
            }
            "symlink" => {
                let symlink = linked.path().with_extension("admin-link");
                std::os::unix::fs::symlink(&admin, &symlink).expect("admin symlink");
                fs::write(
                    linked.path().join(".git"),
                    format!("gitdir: {}\n", symlink.display()),
                )
                .expect("symlink gitfile");
            }
            _ => unreachable!(),
        }
        let store = Store::open(
            linked.path(),
            wayjournal_domain_registry().expect("registry"),
            Arc::new(NoLegacy),
        )
        .expect("linked store");
        let error = store
            .bootstrap_git_admission(&fixture.request)
            .expect_err("hostile topology must fail");
        match error {
            GitAdmissionError::Git(error) => {
                assert_eq!(error.operation(), "resolve local Git layout", "{case}");
            }
            other => panic!("unexpected {case} error: {other:?}"),
        }
    }
}

#[test]
fn fifo_git_control_files_fail_promptly_before_remote_contact() {
    for control in ["gitfile", "gitdir", "commondir", "HEAD", "config"] {
        let (fixture, linked, admin) = linked_fixture(&format!("fifo-control-{control}"));
        let target = match control {
            "gitfile" => {
                let retained = linked.path().join(".git.retained");
                fs::rename(linked.path().join(".git"), retained).expect("retain gitfile");
                linked.path().join(".git")
            }
            "config" => {
                let target = fixture.local.path().join(".git/config");
                fs::remove_file(&target).expect("remove config");
                target
            }
            name => {
                let target = admin.join(name);
                fs::remove_file(&target).expect("remove admin control");
                target
            }
        };
        let status = Command::new("mkfifo")
            .arg(&target)
            .status()
            .expect("mkfifo");
        assert!(status.success(), "mkfifo {control}");
        let store = Store::open(
            linked.path(),
            wayjournal_domain_registry().expect("registry"),
            Arc::new(NoLegacy),
        )
        .expect("linked store");
        let probe = install_transfer_probe(&fixture);
        let started = Instant::now();
        let error = store
            .bootstrap_git_admission(&fixture.request)
            .expect_err("FIFO control must fail");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "blocked on {control}"
        );
        match error {
            GitAdmissionError::Git(error) => {
                let expected = if matches!(control, "HEAD" | "config") {
                    "audit repository metadata"
                } else {
                    "resolve local Git layout"
                };
                assert_eq!(error.operation(), expected, "{control}");
            }
            other => panic!("unexpected {control} error: {other:?}"),
        }
        assert!(
            !transfer_probe_contacted(&probe),
            "remote contacted for {control}"
        );
    }
}

#[test]
fn malformed_gitfiles_fail_closed_before_remote_contact() {
    let cases = [
        ("empty", Vec::new()),
        ("prefix", b"wrong: target\n".to_vec()),
        ("target", b"gitdir: \n".to_vec()),
        ("nul", b"gitdir: target\0suffix\n".to_vec()),
        ("crlf", b"gitdir: target\r\n".to_vec()),
        ("lines", b"gitdir: target\nsecond\n".to_vec()),
        ("oversize", vec![b'x'; 4097]),
    ];
    for (label, bytes) in cases {
        let fixture = admission_fixture(&format!("malformed-gitfile-{label}"));
        fs::rename(
            fixture.local.path().join(".git"),
            fixture.local.path().join("admin.git"),
        )
        .expect("retain original Git directory");
        fs::write(fixture.local.path().join(".git"), bytes).expect("malformed gitfile");
        let probe = install_transfer_probe(&fixture);
        let error = fixture
            .store
            .bootstrap_git_admission(&fixture.request)
            .expect_err("malformed gitfile must fail");
        match error {
            GitAdmissionError::Git(error) => {
                assert_eq!(error.operation(), "resolve local Git layout", "{label}");
            }
            other => panic!("unexpected {label} error: {other:?}"),
        }
        assert!(
            !transfer_probe_contacted(&probe),
            "remote contacted for {label}"
        );
    }
}

#[test]
fn local_git_commands_remain_bound_after_gitfile_replacement() {
    let (fixture, linked, _) = linked_fixture("linked-gitfile-race");
    let tools = TestDir::new("linked-gitfile-race-tools");
    let wrapper = tools.path().join("git-wrapper");
    let log = tools.path().join("git.log");
    let marker = tools.path().join("replaced");
    let retained = linked.path().join(".git.retained");
    let source = tools.path().join("git-wrapper.rs");
    fs::write(
        &source,
        format!(
            r#"use std::{{env, fs, fs::OpenOptions, io::Write, process::Command}};
fn main() {{
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if env::var_os("GIT_DIR").is_some() && !std::path::Path::new({marker:?}).exists() {{
        fs::rename({gitfile:?}, {retained:?}).unwrap();
        fs::write({gitfile:?}, b"hostile-gitfile").unwrap();
        fs::write({marker:?}, b"").unwrap();
    }}
    let mut log = OpenOptions::new().create(true).append(true).open({log:?}).unwrap();
    // The store keeps a cat-file batch child alive while it streams ls-tree, so two wrappers
    // append here at once; one write per line keeps their records from interleaving.
    let mut line = format!("D={{}} C={{}} W={{}}", env::var("GIT_DIR").unwrap_or_default(), env::var("GIT_COMMON_DIR").unwrap_or_default(), env::var("GIT_WORK_TREE").unwrap_or_default());
    for arg in &args {{ line.push_str(&format!(" <{{}}>", arg.to_string_lossy())); }}
    line.push('\n');
    log.write_all(line.as_bytes()).unwrap();
    let status = Command::new({git:?}).args(&args).status().unwrap();
    std::process::exit(status.code().unwrap_or(127));
}}
"#,
            marker = marker,
            gitfile = linked.path().join(".git"),
            retained = retained,
            log = log,
            git = git(),
        ),
    )
    .expect("wrapper source");
    let compiled = Command::new("rustc")
        .args([source.as_os_str(), "-o".as_ref(), wrapper.as_os_str()])
        .status()
        .expect("compile wrapper");
    assert!(compiled.success(), "compile wrapper");
    let request = GitSyncRequest::new(
        wrapper,
        fixture.request.local_trust(),
        fixture.request.approved_remote().clone(),
    )
    .expect("wrapper request");
    let store = Store::open(
        linked.path(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    )
    .expect("linked store");

    let outcome = store.bootstrap_git_admission(&request);
    assert!(
        matches!(outcome, Ok(GitAdmissionOutcome::GenesisValidated { .. })),
        "replacement outcome: {outcome:?}"
    );
    assert_eq!(
        fs::read(linked.path().join(".git")).expect("replacement gitfile"),
        b"hostile-gitfile"
    );
    let invocations = fs::read_to_string(log).expect("invocation log");
    let local = invocations
        .lines()
        .filter(|line| !line.starts_with("D= C= W="))
        .collect::<Vec<_>>();
    assert!(!local.is_empty());
    for line in local {
        let fields = line.split_whitespace().take(3).collect::<Vec<_>>();
        assert_eq!(fields.len(), 3, "{line}");
        assert!(
            fields
                .iter()
                .all(|field| field.contains("=/proc/") && field.contains("/fd/")),
            "{line}"
        );
        assert!(!line.contains("<--git-dir=.>"), "{line}");
        assert!(
            !line.contains(&linked.path().join(".git").display().to_string()),
            "{line}"
        );
    }
}

#[test]
fn authentic_admission_checkpoint_roundtrips_through_the_public_codec() {
    let fixture = admission_fixture("public-checkpoint-codec");
    let store = Store::open(
        fixture.local.path(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    )
    .expect("store");
    assert!(matches!(
        store.bootstrap_git_admission(&fixture.request),
        Ok(GitAdmissionOutcome::GenesisValidated { .. })
    ));

    let checkpoint = store
        .admission_checkpoint()
        .expect("read checkpoint")
        .expect("checkpoint present");
    let bytes = fs::read(
        fixture
            .local
            .path()
            .join(".wayjournal-local/checkpoints")
            .join(ADMISSION_CHECKPOINT_FILENAME),
    )
    .expect("checkpoint bytes");
    assert_eq!(
        encode_admission_checkpoint(&checkpoint).expect("encode checkpoint"),
        bytes
    );
    assert_eq!(
        decode_admission_checkpoint(&bytes).expect("decode checkpoint"),
        checkpoint
    );
}

#[test]
fn relative_gitfile_target_preserves_linked_worktree_topology() {
    let fixture = admission_fixture("relative-linked-worktree");
    run(fixture.local.path(), &["checkout", "--detach"]);
    let linked = TestDir::new("relative-linked-worktree-store");
    fs::remove_dir(linked.path()).expect("remove linked-worktree destination");
    run(
        fixture.local.path(),
        &[
            "worktree",
            "add",
            linked.path().to_str().expect("UTF-8 linked worktree"),
            "main",
        ],
    );
    let local_name = fixture
        .local
        .path()
        .file_name()
        .expect("local basename")
        .to_string_lossy();
    let linked_name = linked
        .path()
        .file_name()
        .expect("linked basename")
        .to_string_lossy();
    fs::write(
        linked.path().join(".git"),
        format!("gitdir: ../{local_name}/.git/worktrees/{linked_name}\n"),
    )
    .expect("relative gitfile");
    let store = Store::open(
        linked.path(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    )
    .expect("linked-worktree store");

    assert!(matches!(
        store.bootstrap_git_admission(&fixture.request),
        Ok(GitAdmissionOutcome::GenesisValidated { .. })
    ));
}

#[test]
fn real_linked_worktree_bootstrap_uses_the_common_repository() {
    let fixture = admission_fixture("linked-worktree");
    run(fixture.local.path(), &["checkout", "--detach"]);
    let linked = TestDir::new("linked-worktree-store");
    fs::remove_dir(linked.path()).expect("remove linked-worktree destination");
    run(
        fixture.local.path(),
        &[
            "worktree",
            "add",
            linked.path().to_str().expect("UTF-8 linked worktree"),
            "main",
        ],
    );
    let store = Store::open(
        linked.path(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    )
    .expect("linked-worktree store");

    assert!(matches!(
        store.bootstrap_git_admission(&fixture.request),
        Ok(GitAdmissionOutcome::GenesisValidated { .. })
    ));
    assert!(matches!(
        store.bootstrap_git_admission(&fixture.request),
        Ok(GitAdmissionOutcome::UpToDate { .. })
    ));
}

fn git_output(cwd: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new(git())
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("Git output");
    assert!(
        output.status.success(),
        "Git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn rewrite_checkpoint(fixture: &AdmissionFixture, mutate: impl FnOnce(&mut serde_json::Value)) {
    let path = checkpoint_path(fixture);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("checkpoint bytes"))
            .expect("checkpoint JSON");
    mutate(&mut value);
    let mut bytes = serde_json::to_vec_pretty(&value).expect("canonical JSON");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("rewrite checkpoint");
}

struct TransferProbe {
    descriptor: rustix::fd::OwnedFd,
    watch: i32,
}

fn install_transfer_probe(fixture: &AdmissionFixture) -> TransferProbe {
    install_remote_transfer_probe(&fixture.remote)
}

fn install_remote_transfer_probe(remote: &Path) -> TransferProbe {
    use rustix::fs::inotify;

    let path = remote.join("objects/info/alternates");
    fs::write(&path, b"wayjournal-contact-probe\n").expect("install transfer probe");
    let descriptor = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)
        .expect("create transfer probe");
    let watch = inotify::add_watch(&descriptor, &path, inotify::WatchFlags::OPEN)
        .expect("watch transfer probe");
    let probe = TransferProbe { descriptor, watch };
    assert!(!transfer_probe_contacted(&probe));
    probe
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
fn transfer_probe_observes_a_real_fetch() {
    let fixture = admission_fixture("transfer-probe-positive");
    let probe = install_transfer_probe(&fixture);
    let destination = TestDir::new("transfer-probe-destination");
    run(destination.path(), &["init", "--bare"]);
    let output = Command::new(git())
        .arg(format!("--git-dir={}", destination.path().display()))
        .args([
            "fetch",
            fixture.request.approved_remote().locator().as_str(),
            "refs/heads/main:refs/wayjournal/probe",
        ])
        .output()
        .expect("positive transfer probe");
    assert!(
        output.status.success(),
        "positive transfer: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        transfer_probe_contacted(&probe),
        "positive control did not observe transfer"
    );
}

fn profile_record() -> Record {
    Record {
        record_schema: "wayjournal.profile/v1".parse().expect("schema"),
        domain: "wayjournal.profile".parse().expect("domain"),
        kind: "profile.display_name.set".parse().expect("kind"),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174021"
            .parse()
            .expect("record"),
        entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010"
            .parse()
            .expect("entity"),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174022"
            .parse()
            .expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:01:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:01:01Z".parse().expect("time"),
        parents: Vec::new(),
        payload: json!({"value":"Robin"}),
    }
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

#[test]
fn bootstrap_binds_validated_tip_then_reports_up_to_date() {
    let local = TestDir::new("local");
    let remote_parent = TestDir::new("remote");
    let remote = remote_parent.path().join("store.git");
    run(
        remote_parent.path(),
        &["init", "--bare", remote.to_str().expect("utf8")],
    );
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(local.path(), registry, Arc::new(NoLegacy)).expect("store");
    let batch = prepare_batch(&[genesis()], "bootstrap", &registry).expect("genesis");
    store
        .append(&batch, store.read().expect("empty").revision())
        .expect("append");
    run(local.path(), &["init", "-b", "main"]);
    run(local.path(), &["config", "user.name", "Wayjournal Test"]);
    run(
        local.path(),
        &["config", "user.email", "wayjournal@example.invalid"],
    );
    run(local.path(), &["add", "events", "batches", "journal"]);
    run(local.path(), &["commit", "-m", "genesis"]);
    run(
        local.path(),
        &[
            "push",
            remote.to_str().expect("utf8"),
            "HEAD:refs/heads/main",
        ],
    );

    let locator =
        ApprovedRemoteLocator::parse(url::Url::from_file_path(&remote).expect("url").as_str())
            .expect("locator");
    let request = GitSyncRequest::new(
        git(),
        LocalTrustBinding::parse(
            "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        )
        .expect("trust"),
        ApprovedRemote::new(locator, ApprovedRef::parse("refs/heads/main").expect("ref")),
    )
    .expect("request");
    let first = store
        .bootstrap_git_admission(&request)
        .expect("bootstrap sync");
    assert!(matches!(
        first,
        GitAdmissionOutcome::GenesisValidated { .. }
    ));
    let checkpoint = store
        .admission_checkpoint()
        .expect("checkpoint read")
        .expect("checkpoint");
    assert_eq!(
        checkpoint.logical_store_id(),
        store
            .read()
            .expect("read")
            .identity()
            .expect("identity")
            .logical_id()
    );
    assert_eq!(checkpoint.local_trust_binding(), &request.local_trust());
    assert_eq!(checkpoint.approved_remote(), request.approved_remote());

    let second = store
        .bootstrap_git_admission(&request)
        .expect("up to date sync");
    assert!(matches!(second, GitAdmissionOutcome::UpToDate { .. }));
    assert_eq!(
        fs::metadata(
            local
                .path()
                .join(".wayjournal-local/checkpoints/admission-v1.json")
        )
        .expect("checkpoint metadata")
        .permissions()
        .mode()
            & 0o777,
        0o600,
    );
}

#[test]
fn checkpoint_binding_is_read_and_validated_under_one_exclusive_lock() {
    let fixture = admission_fixture("checkpoint-lock");
    let first_store = fixture.store.clone();
    let first_request = fixture.request.clone();
    let first = thread::spawn(move || first_store.bootstrap_git_admission(&first_request));
    let attempts = fixture
        .local
        .path()
        .join(".wayjournal-local/admission-attempts");
    let deadline = Instant::now() + Duration::from_secs(10);
    while fs::read_dir(&attempts)
        .expect("attempt directory")
        .next()
        .is_none()
    {
        assert!(
            Instant::now() < deadline,
            "first admission never reached fetch"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let second = GitSyncRequest::new(
        git(),
        trust("4c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"),
        fixture.request.approved_remote().clone(),
    )
    .expect("second request");
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&second),
        Err(GitAdmissionError::LocalTrustMismatch)
    ));
    assert!(matches!(
        first
            .join()
            .expect("first thread")
            .expect("first admission"),
        GitAdmissionOutcome::GenesisValidated { .. }
    ));
    assert_eq!(
        fixture
            .store
            .admission_checkpoint()
            .expect("checkpoint")
            .expect("present")
            .local_trust_binding(),
        &fixture.request.local_trust()
    );
}

#[test]
fn checkpoint_approval_mismatches_fail_before_contacting_remote() {
    let fixture = admission_fixture("checkpoint-approval");
    fixture
        .store
        .bootstrap_git_admission(&fixture.request)
        .expect("bootstrap");
    let marker_root = TestDir::new("checkpoint-approval-marker");
    let marker_remote = marker_root.path().join("wrong-remote.git");
    run(
        marker_root.path(),
        &[
            "clone",
            "--bare",
            fixture.remote.to_str().expect("remote"),
            marker_remote.to_str().expect("marker remote"),
        ],
    );
    let probe = install_transfer_probe(&fixture);
    let wrong_locator_probe = install_remote_transfer_probe(&marker_remote);

    let wrong_trust = GitSyncRequest::new(
        git(),
        trust("4c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"),
        fixture.request.approved_remote().clone(),
    )
    .expect("wrong trust");
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&wrong_trust),
        Err(GitAdmissionError::LocalTrustMismatch)
    ));
    assert!(
        !transfer_probe_contacted(&probe),
        "trust mismatch contacted transfer"
    );

    let wrong_locator = GitSyncRequest::new(
        git(),
        fixture.request.local_trust(),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(
                url::Url::from_file_path(&marker_remote)
                    .expect("marker URL")
                    .as_str(),
            )
            .expect("marker locator"),
            ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
    )
    .expect("wrong locator");
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&wrong_locator),
        Err(GitAdmissionError::UnapprovedRemote)
    ));
    assert!(
        !transfer_probe_contacted(&wrong_locator_probe),
        "locator mismatch contacted transfer"
    );

    run(
        marker_root.path(),
        &[
            "--git-dir",
            fixture.remote.to_str().expect("remote"),
            "branch",
            "other",
            "refs/heads/main",
        ],
    );
    let probe = install_transfer_probe(&fixture);
    let wrong_ref = GitSyncRequest::new(
        git(),
        fixture.request.local_trust(),
        ApprovedRemote::new(
            fixture.request.approved_remote().locator().clone(),
            ApprovedRef::parse("refs/heads/other").expect("other ref"),
        ),
    )
    .expect("wrong ref");
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&wrong_ref),
        Err(GitAdmissionError::UnapprovedRef)
    ));
    assert!(
        !transfer_probe_contacted(&probe),
        "ref mismatch contacted transfer"
    );
}

#[test]
fn existing_checkpoint_semantics_are_revalidated_before_network() {
    for (label, mutate, expected) in [
        (
            "identity",
            (|value: &mut serde_json::Value| {
                value["store_uuid"] =
                    serde_json::Value::String("01913f1d-8e2a-7c30-8f4a-426614174020".to_owned());
            }) as fn(&mut serde_json::Value),
            "identity",
        ),
        (
            "revision",
            |value: &mut serde_json::Value| {
                value["accepted_revision_digest"] = serde_json::Value::String(
                    "4c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15".to_owned(),
                );
            },
            "revision",
        ),
        (
            "object-format",
            |value: &mut serde_json::Value| {
                value["accepted_git_object_format"] =
                    serde_json::Value::String("sha256".to_owned());
                value["accepted_commit"] = serde_json::Value::String("0".repeat(64));
            },
            "object format",
        ),
    ] {
        let fixture = admission_fixture(&format!("checkpoint-{label}"));
        fixture
            .store
            .bootstrap_git_admission(&fixture.request)
            .expect("bootstrap");
        let probe = install_transfer_probe(&fixture);
        rewrite_checkpoint(&fixture, mutate);
        let result = fixture.store.bootstrap_git_admission(&fixture.request);
        match expected {
            "identity" => assert!(matches!(
                result,
                Err(GitAdmissionError::CheckpointIdentityMismatch)
            )),
            "revision" => assert!(matches!(
                result,
                Err(GitAdmissionError::CheckpointRevisionMismatch)
            )),
            "object format" => assert!(matches!(
                result,
                Err(GitAdmissionError::CheckpointObjectFormatMismatch)
            )),
            _ => unreachable!(),
        }
        assert!(
            !transfer_probe_contacted(&probe),
            "{label} mismatch contacted transfer"
        );
    }
}

#[test]
fn checkpoint_accepted_oid_must_name_a_commit_object() {
    for case in ["tree", "blob", "tag", "missing"] {
        let fixture = admission_fixture(&format!("checkpoint-object-{case}"));
        fixture
            .store
            .bootstrap_git_admission(&fixture.request)
            .expect("bootstrap");
        let oid = match case {
            "tree" => String::from_utf8(git_output(
                fixture.local.path(),
                &["rev-parse", "HEAD^{tree}"],
            ))
            .expect("tree OID")
            .trim()
            .to_owned(),
            "blob" => {
                let path = fixture.local.path().join("blob-input");
                fs::write(&path, b"blob").expect("blob input");
                String::from_utf8(git_output(
                    fixture.local.path(),
                    &["hash-object", "-w", path.to_str().expect("path")],
                ))
                .expect("blob OID")
                .trim()
                .to_owned()
            }
            "tag" => {
                run(
                    fixture.local.path(),
                    &["tag", "-a", "object-tag", "-m", "tag"],
                );
                String::from_utf8(git_output(
                    fixture.local.path(),
                    &["rev-parse", "refs/tags/object-tag"],
                ))
                .expect("tag OID")
                .trim()
                .to_owned()
            }
            "missing" => "0".repeat(40),
            _ => unreachable!(),
        };
        let probe = install_transfer_probe(&fixture);
        rewrite_checkpoint(&fixture, |value| {
            value["accepted_commit"] = serde_json::Value::String(oid);
        });
        assert!(matches!(
            fixture.store.bootstrap_git_admission(&fixture.request),
            Err(GitAdmissionError::CheckpointCommitUnavailable)
        ));
        assert!(
            !transfer_probe_contacted(&probe),
            "{case} checkpoint contacted transfer"
        );
    }
}

#[test]
fn approved_local_and_remote_refs_are_required_to_name_commits() {
    let local = admission_fixture("local-ref-object");
    let tree = String::from_utf8(git_output(
        local.local.path(),
        &["rev-parse", "HEAD^{tree}"],
    ))
    .expect("tree")
    .trim()
    .to_owned();
    fs::write(
        local.local.path().join(".git/refs/heads/main"),
        format!("{tree}\n"),
    )
    .expect("write non-commit local branch ref");
    assert!(matches!(
        local.store.bootstrap_git_admission(&local.request),
        Err(GitAdmissionError::Git(error))
            if error.operation() == "validate commit object"
    ));

    let remote = admission_fixture("remote-ref-object");
    let remote_tree = String::from_utf8(git_output(
        remote.local.path(),
        &["rev-parse", "HEAD^{tree}"],
    ))
    .expect("remote tree")
    .trim()
    .to_owned();
    fs::write(
        remote.remote.join("refs/heads/main"),
        format!("{remote_tree}\n"),
    )
    .expect("write non-commit remote branch ref");
    assert!(matches!(
        remote.store.bootstrap_git_admission(&remote.request),
        Err(GitAdmissionError::Git(error))
            if error.operation() == "validate commit object"
    ));
}

#[test]
fn local_advance_required_does_not_create_or_recover_attempts_or_fetch() {
    let fixture = admission_fixture("local-advance");
    fixture
        .store
        .bootstrap_git_admission(&fixture.request)
        .expect("bootstrap");
    run(
        fixture.local.path(),
        &["commit", "--allow-empty", "-m", "local advance"],
    );
    let attempts = fixture
        .local
        .path()
        .join(".wayjournal-local/admission-attempts");
    let stale = attempts.join("01913f1d-8e2a-7c30-8f4a-426614174099");
    fs::create_dir(&stale).expect("stale attempt");
    fs::write(stale.join("retained"), b"for S4b recovery").expect("stale evidence");
    let outcome = fixture
        .store
        .bootstrap_git_admission(&fixture.request)
        .expect("advance required");
    assert!(matches!(
        outcome,
        GitAdmissionOutcome::AdvanceRequired { remote: None, .. }
    ));
    assert_eq!(
        fs::read(stale.join("retained")).expect("stale evidence"),
        b"for S4b recovery"
    );
}

#[test]
fn divergent_remote_reports_advance_required_without_mutation() {
    let fixture = admission_fixture("divergence");
    fixture
        .store
        .bootstrap_git_admission(&fixture.request)
        .expect("bootstrap");
    let checkpoint_before = fs::read(checkpoint_path(&fixture)).expect("checkpoint");
    let revision_before = fixture.store.read().expect("snapshot").revision();
    let local_tip_before = Command::new(git())
        .current_dir(fixture.local.path())
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("local tip")
        .stdout;

    let other = TestDir::new("divergence-other");
    run(
        other.path(),
        &["clone", fixture.remote.to_str().expect("remote"), "clone"],
    );
    let clone = other.path().join("clone");
    run(&clone, &["config", "user.name", "Wayjournal Test"]);
    run(
        &clone,
        &["config", "user.email", "wayjournal@example.invalid"],
    );
    run(&clone, &["commit", "--allow-empty", "-m", "remote advance"]);
    run(&clone, &["push", "origin", "HEAD:refs/heads/main"]);
    let remote_tip_before = Command::new(git())
        .args([
            "--git-dir",
            fixture.remote.to_str().expect("remote"),
            "rev-parse",
            "refs/heads/main",
        ])
        .output()
        .expect("remote tip")
        .stdout;

    assert!(matches!(
        fixture.store.bootstrap_git_admission(&fixture.request),
        Ok(GitAdmissionOutcome::AdvanceRequired { .. })
    ));
    assert_eq!(
        fs::read(checkpoint_path(&fixture)).expect("checkpoint"),
        checkpoint_before
    );
    assert_eq!(
        fixture.store.read().expect("snapshot").revision(),
        revision_before
    );
    assert_eq!(
        Command::new(git())
            .current_dir(fixture.local.path())
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("local tip")
            .stdout,
        local_tip_before
    );
    assert_eq!(
        Command::new(git())
            .args([
                "--git-dir",
                fixture.remote.to_str().expect("remote"),
                "rev-parse",
                "refs/heads/main",
            ])
            .output()
            .expect("remote tip")
            .stdout,
        remote_tip_before
    );
}

#[test]
fn hostile_inherited_and_global_git_configuration_is_inert() {
    const CHILD: &str = "WAYJOURNAL_HOSTILE_CONFIG_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let local = PathBuf::from(std::env::var_os("WAYJOURNAL_HOSTILE_LOCAL").expect("local"));
        let remote = PathBuf::from(std::env::var_os("WAYJOURNAL_HOSTILE_REMOTE").expect("remote"));
        let registry = wayjournal_domain_registry().expect("registry");
        let store = Store::open(&local, registry, Arc::new(NoLegacy)).expect("child store");
        let request = GitSyncRequest::new(
            git(),
            trust("3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"),
            ApprovedRemote::new(
                ApprovedRemoteLocator::parse(
                    url::Url::from_file_path(&remote)
                        .expect("remote URL")
                        .as_str(),
                )
                .expect("locator"),
                ApprovedRef::parse("refs/heads/main").expect("ref"),
            ),
        )
        .expect("request");
        assert!(matches!(
            store.bootstrap_git_admission(&request),
            Ok(GitAdmissionOutcome::GenesisValidated { .. })
        ));
        return;
    }

    let fixture = admission_fixture("hostile-global");
    let hostile = TestDir::new("hostile-config");
    let marker = hostile.path().join("marker");
    let marker_script = hostile.path().join("marker-script");
    fs::write(
        &marker_script,
        format!(
            "#!/bin/sh\nprintf marker > '{}'\nexit 1\n",
            marker.display()
        ),
    )
    .expect("marker script");
    fs::set_permissions(&marker_script, fs::Permissions::from_mode(0o700)).expect("marker mode");
    let approved = fixture.request.approved_remote().locator().as_str();
    let rewrite = format!("ext::{}", marker_script.display());
    let included = hostile.path().join("included.gitconfig");
    fs::write(
        &included,
        format!(
            "[url \"{rewrite}\"]\n\tinsteadOf = {approved}\n[protocol \"ext\"]\n\tallow = always\n"
        ),
    )
    .expect("included config");
    let global = hostile.path().join("global.gitconfig");
    fs::write(
        &global,
        format!("[include]\n\tpath = {}\n[credential]\n\thelper = !{}\n[core]\n\tsshCommand = {}\n[http]\n\tproxy = http://SENTINEL_SECRET.invalid\n", included.display(), marker_script.display(), marker_script.display()),
    )
    .expect("global config");
    let system = hostile.path().join("system.gitconfig");
    fs::copy(&global, &system).expect("system config");
    let home = hostile.path().join("home");
    let xdg = hostile.path().join("xdg");
    fs::create_dir(&home).expect("home");
    fs::create_dir(&xdg).expect("xdg");
    fs::create_dir(xdg.join("git")).expect("XDG Git directory");
    fs::copy(&global, home.join(".gitconfig")).expect("home config");
    fs::copy(&global, xdg.join("git/config")).expect("XDG Git config");

    let status = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "hostile_inherited_and_global_git_configuration_is_inert",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("WAYJOURNAL_HOSTILE_LOCAL", fixture.local.path())
        .env("WAYJOURNAL_HOSTILE_REMOTE", &fixture.remote)
        .env("WAYJOURNAL_TEST_GIT", git())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("GIT_CONFIG_SYSTEM", &system)
        .env("GIT_CONFIG_GLOBAL", &global)
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", format!("url.{rewrite}.insteadOf"))
        .env("GIT_CONFIG_VALUE_0", approved)
        .env("GIT_CONFIG_KEY_1", "protocol.ext.allow")
        .env("GIT_CONFIG_VALUE_1", "always")
        .env("GIT_ASKPASS", &marker_script)
        .env("SSH_ASKPASS", &marker_script)
        .env("GIT_SSH_COMMAND", &marker_script)
        .env("http_proxy", "http://SENTINEL_SECRET.invalid")
        .env("https_proxy", "http://SENTINEL_SECRET.invalid")
        .status()
        .expect("child test");
    assert!(status.success(), "hostile child failed");
    assert!(!marker.exists(), "ambient Git authority executed a marker");
    let checkpoint = fs::read(checkpoint_path(&fixture)).expect("checkpoint");
    assert!(
        !checkpoint
            .windows(b"SENTINEL_SECRET".len())
            .any(|window| window == b"SENTINEL_SECRET")
    );
}

#[test]
fn every_dangerous_local_git_config_key_is_rejected_before_transfer() {
    let marker_root = TestDir::new("local-config-markers");
    let marker = marker_root.path().join("marker");
    let marker_script = marker_root.path().join("marker-script");
    fs::write(
        &marker_script,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
    )
    .expect("marker script");
    fs::set_permissions(&marker_script, fs::Permissions::from_mode(0o700)).expect("mode");
    let cases = [
        ("include.path", marker_script.to_string_lossy().into_owned()),
        ("url.ext::evil.insteadof", "file:///".to_owned()),
        ("credential.helper", format!("!{}", marker_script.display())),
        ("http.proxy", "http://SENTINEL_SECRET.invalid".to_owned()),
        (
            "remote.origin.proxy",
            "http://SENTINEL_SECRET.invalid".to_owned(),
        ),
        (
            "remote.origin.uploadpack",
            marker_script.to_string_lossy().into_owned(),
        ),
        (
            "remote.origin.receivepack",
            marker_script.to_string_lossy().into_owned(),
        ),
        (
            "core.sshcommand",
            marker_script.to_string_lossy().into_owned(),
        ),
        ("protocol.ext.allow", "always".to_owned()),
        (
            "core.hookspath",
            marker_root.path().to_string_lossy().into_owned(),
        ),
        (
            "filter.evil.clean",
            marker_script.to_string_lossy().into_owned(),
        ),
        (
            "filter.evil.smudge",
            marker_script.to_string_lossy().into_owned(),
        ),
        (
            "filter.evil.process",
            marker_script.to_string_lossy().into_owned(),
        ),
        (
            "core.fsmonitor",
            marker_script.to_string_lossy().into_owned(),
        ),
        (
            "diff.evil.command",
            marker_script.to_string_lossy().into_owned(),
        ),
        (
            "merge.evil.driver",
            marker_script.to_string_lossy().into_owned(),
        ),
    ];
    for (index, (key, value)) in cases.into_iter().enumerate() {
        let fixture = admission_fixture(&format!("local-config-{index}"));
        run(fixture.local.path(), &["config", key, &value]);
        let error = fixture
            .store
            .bootstrap_git_admission(&fixture.request)
            .expect_err(key);
        let text = error.to_string();
        assert!(text.contains("audit local config"), "{key}: {text}");
        assert!(!text.contains("SENTINEL_SECRET"), "{key}: leaked value");
        assert!(!marker.exists(), "{key}: marker executed");
        assert_eq!(
            fixture.store.admission_checkpoint().expect("checkpoint"),
            None
        );
    }
}

#[test]
fn restrictive_umask_still_creates_a_private_reopenable_checkpoint() {
    const CHILD: &str = "WAYJOURNAL_UMASK_BOOTSTRAP_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let local = PathBuf::from(std::env::var_os("WAYJOURNAL_UMASK_LOCAL").expect("local"));
        let remote = PathBuf::from(std::env::var_os("WAYJOURNAL_UMASK_REMOTE").expect("remote"));
        let registry = wayjournal_domain_registry().expect("registry");
        let store = Store::open(&local, registry, Arc::new(NoLegacy)).expect("child store");
        let request = GitSyncRequest::new(
            git(),
            trust("3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"),
            ApprovedRemote::new(
                ApprovedRemoteLocator::parse(
                    url::Url::from_file_path(&remote)
                        .expect("remote URL")
                        .as_str(),
                )
                .expect("locator"),
                ApprovedRef::parse("refs/heads/main").expect("ref"),
            ),
        )
        .expect("request");
        let first = store.bootstrap_git_admission(&request);
        assert!(
            matches!(first, Ok(GitAdmissionOutcome::GenesisValidated { .. })),
            "first bootstrap under restrictive umask: {first:?}"
        );
        let second = store.bootstrap_git_admission(&request);
        assert!(
            matches!(second, Ok(GitAdmissionOutcome::UpToDate { .. })),
            "second bootstrap under restrictive umask: {second:?}"
        );
        let mode = fs::metadata(local.join(".wayjournal-local/checkpoints/admission-v1.json"))
            .expect("checkpoint")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        return;
    }
    let fixture = admission_fixture("umask");
    let status = Command::new("/bin/sh")
        .args([
            "-c",
            "umask 0777; exec \"$WAYJOURNAL_TEST_BINARY\" restrictive_umask_still_creates_a_private_reopenable_checkpoint --nocapture",
        ])
        .env(CHILD, "1")
        .env("WAYJOURNAL_UMASK_LOCAL", fixture.local.path())
        .env("WAYJOURNAL_UMASK_REMOTE", &fixture.remote)
        .env("WAYJOURNAL_TEST_GIT", git())
        .env(
            "WAYJOURNAL_TEST_BINARY",
            std::env::current_exe().expect("test executable"),
        )
        .status()
        .expect("umask child");
    assert!(status.success());
}

#[test]
fn git_failures_do_not_persist_or_report_locator_path_secrets() {
    let fixture = admission_fixture("redaction");
    let missing = fixture
        .remote
        .parent()
        .expect("remote parent")
        .join("SENTINEL_SECRET-missing.git");
    let request = GitSyncRequest::new(
        git(),
        fixture.request.local_trust(),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(
                url::Url::from_file_path(missing)
                    .expect("missing URL")
                    .as_str(),
            )
            .expect("locator"),
            ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
    )
    .expect("request");
    let error = fixture
        .store
        .bootstrap_git_admission(&request)
        .expect_err("missing remote");
    assert!(!error.to_string().contains("SENTINEL_SECRET"));
    assert_eq!(
        fixture.store.admission_checkpoint().expect("checkpoint"),
        None
    );
    assert!(
        fs::read_dir(
            fixture
                .local
                .path()
                .join(".wayjournal-local/admission-attempts")
        )
        .expect("attempts")
        .next()
        .is_none()
    );
}

#[test]
fn retained_git_executable_inode_survives_path_substitution() {
    let fixture = admission_fixture("git-inode");
    let executable = fixture.local.path().join("pinned-git");
    fs::copy(git(), &executable).expect("copy Git executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("Git mode");
    let request = GitSyncRequest::new(
        executable.clone(),
        fixture.request.local_trust(),
        fixture.request.approved_remote().clone(),
    )
    .expect("request");
    fs::rename(&executable, fixture.local.path().join("retained-git"))
        .expect("rename retained Git");
    fs::copy(
        std::env::current_exe().expect("test executable"),
        &executable,
    )
    .expect("hostile replacement");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("replacement mode");
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&request),
        Ok(GitAdmissionOutcome::GenesisValidated { .. })
    ));
}

#[test]
fn retained_root_and_non_utf8_attempt_paths_are_not_reopened_ambiently() {
    let fixture = admission_fixture("retained-root");
    let moved = fixture.local.path().with_extension("retained");
    fs::rename(fixture.local.path(), &moved).expect("move bound root");
    fs::create_dir(fixture.local.path()).expect("hostile replacement root");
    fs::write(fixture.local.path().join("marker"), b"outside").expect("outside marker");
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&fixture.request),
        Ok(GitAdmissionOutcome::GenesisValidated { .. })
    ));
    assert_eq!(
        fs::read(fixture.local.path().join("marker")).expect("outside marker"),
        b"outside"
    );
    fs::remove_dir_all(&moved).expect("remove retained root");

    let mut bytes = format!("wayjournal-s4-nonutf8-{}-", uuid::Uuid::now_v7()).into_bytes();
    bytes.push(0xff);
    let non_utf8 = std::env::temp_dir().join(OsString::from_vec(bytes));
    fs::create_dir(&non_utf8).expect("non-UTF-8 root");
    let local = TestDir(non_utf8);
    let remote_parent = TestDir::new("nonutf8-remote");
    let remote = remote_parent.path().join("store.git");
    run(
        remote_parent.path(),
        &["init", "--bare", remote.to_str().expect("remote")],
    );
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(local.path(), registry, Arc::new(NoLegacy)).expect("store");
    let batch = prepare_batch(&[genesis()], "nonutf8", &registry).expect("genesis");
    store
        .append(&batch, store.read().expect("empty").revision())
        .expect("append");
    run(local.path(), &["init", "-b", "main"]);
    run(local.path(), &["config", "user.name", "Wayjournal Test"]);
    run(
        local.path(),
        &["config", "user.email", "wayjournal@example.invalid"],
    );
    run(local.path(), &["add", "events", "batches", "journal"]);
    run(local.path(), &["commit", "-m", "genesis"]);
    run(
        local.path(),
        &[
            "push",
            remote.to_str().expect("remote"),
            "HEAD:refs/heads/main",
        ],
    );
    let request = GitSyncRequest::new(
        git(),
        trust("3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(
                url::Url::from_file_path(&remote)
                    .expect("remote URL")
                    .as_str(),
            )
            .expect("locator"),
            ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
    )
    .expect("request");
    assert!(matches!(
        store.bootstrap_git_admission(&request),
        Ok(GitAdmissionOutcome::GenesisValidated { .. })
    ));
}

#[test]
fn bootstrap_rejects_a_filesystem_revision_not_committed_at_local_head() {
    let fixture = admission_fixture("hostile-revision");
    let before = fixture.store.read().expect("before").revision();
    let registry = wayjournal_domain_registry().expect("registry");
    let batch = prepare_batch(&[profile_record()], "uncommitted", &registry).expect("profile");
    fixture
        .store
        .append(&batch, before)
        .expect("uncommitted canonical append");
    let changed = fixture.store.read().expect("changed").revision();
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&fixture.request),
        Err(GitAdmissionError::CandidateRevisionMismatch)
    ));
    assert_eq!(fixture.store.read().expect("after").revision(), changed);
    assert_eq!(
        fixture.store.admission_checkpoint().expect("checkpoint"),
        None
    );
}

#[test]
fn bootstrap_rejects_a_tracked_noncanonical_path() {
    let fixture = admission_fixture("hostile-noncanonical");
    fs::write(fixture.local.path().join("README.bad"), b"not canonical")
        .expect("noncanonical file");
    run(fixture.local.path(), &["add", "README.bad"]);
    run(fixture.local.path(), &["commit", "-m", "noncanonical"]);
    run(
        fixture.local.path(),
        &[
            "push",
            "--force",
            fixture.remote.to_str().expect("remote"),
            "HEAD:refs/heads/main",
        ],
    );
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&fixture.request),
        Err(GitAdmissionError::NonCanonicalTrackedPath)
    ));
    assert_eq!(
        fixture.store.admission_checkpoint().expect("checkpoint"),
        None
    );
}

#[test]
fn bootstrap_rejects_an_executable_canonical_blob() {
    let fixture = admission_fixture("hostile-mode");
    let record = fixture.local.path().join(
        "journal/records/wayjournal.identity/01913f1d-8e2a-7c30-8f4a-426614174010/01913f1d-8e2a-7c30-8f4a-426614174011.json",
    );
    fs::set_permissions(&record, fs::Permissions::from_mode(0o700)).expect("executable mode");
    run(fixture.local.path(), &["add", "journal"]);
    run(fixture.local.path(), &["commit", "-m", "executable record"]);
    run(
        fixture.local.path(),
        &[
            "push",
            "--force",
            fixture.remote.to_str().expect("remote"),
            "HEAD:refs/heads/main",
        ],
    );
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&fixture.request),
        Err(GitAdmissionError::InvalidTreeEntry)
    ));
    assert_eq!(
        fixture.store.admission_checkpoint().expect("checkpoint"),
        None
    );
}

#[test]
fn bootstrap_rejects_a_git_tree_with_a_different_logical_identity() {
    let fixture = admission_fixture("hostile-identity");
    let other = TestDir::new("other-identity");
    let registry = wayjournal_domain_registry().expect("registry");
    let other_store = Store::open(other.path(), registry, Arc::new(NoLegacy)).expect("store");
    let mut other_genesis = genesis();
    other_genesis.record_id = "01913f1d-8e2a-7c30-8f4a-426614174031"
        .parse()
        .expect("record");
    other_genesis.entity_id = "01913f1d-8e2a-7c30-8f4a-426614174030"
        .parse()
        .expect("entity");
    other_genesis.batch_id = "01913f1d-8e2a-7c30-8f4a-426614174032"
        .parse()
        .expect("batch");
    other_genesis.payload = json!({
        "store_kind":"wayjournal.personal",
        "store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174030"
    });
    let other_batch = prepare_batch(&[other_genesis], "other", &registry).expect("genesis");
    other_store
        .append(&other_batch, other_store.read().expect("empty").revision())
        .expect("append");
    run(other.path(), &["init", "-b", "main"]);
    run(other.path(), &["config", "user.name", "Wayjournal Test"]);
    run(
        other.path(),
        &["config", "user.email", "wayjournal@example.invalid"],
    );
    run(other.path(), &["add", "events", "batches", "journal"]);
    run(other.path(), &["commit", "-m", "other identity"]);
    run(
        fixture.local.path(),
        &["fetch", other.path().to_str().expect("other"), "HEAD"],
    );
    run(
        fixture.local.path(),
        &["update-ref", "refs/heads/main", "FETCH_HEAD"],
    );
    run(
        fixture.local.path(),
        &[
            "push",
            "--force",
            fixture.remote.to_str().expect("remote"),
            "refs/heads/main:refs/heads/main",
        ],
    );
    assert!(matches!(
        fixture.store.bootstrap_git_admission(&fixture.request),
        Err(GitAdmissionError::IdentityMismatch)
    ));
    assert_eq!(
        fixture.store.admission_checkpoint().expect("checkpoint"),
        None
    );
}

#[test]
fn sha256_repository_bootstrap_returns_a_tagged_sha256_commit_when_supported() {
    let local = TestDir::new("sha256-local");
    let remote_parent = TestDir::new("sha256-remote");
    let remote = remote_parent.path().join("store.git");
    let probe = Command::new(git())
        .current_dir(remote_parent.path())
        .args([
            "init",
            "--bare",
            "--object-format=sha256",
            remote.to_str().expect("remote"),
        ])
        .output()
        .expect("SHA-256 probe");
    if !probe.status.success() {
        return;
    }
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(local.path(), registry, Arc::new(NoLegacy)).expect("store");
    let batch = prepare_batch(&[genesis()], "sha256", &registry).expect("genesis");
    store
        .append(&batch, store.read().expect("empty").revision())
        .expect("append");
    run(
        local.path(),
        &["init", "-b", "main", "--object-format=sha256"],
    );
    run(local.path(), &["config", "user.name", "Wayjournal Test"]);
    run(
        local.path(),
        &["config", "user.email", "wayjournal@example.invalid"],
    );
    run(local.path(), &["add", "events", "batches", "journal"]);
    run(local.path(), &["commit", "-m", "genesis"]);
    run(
        local.path(),
        &[
            "push",
            remote.to_str().expect("remote"),
            "HEAD:refs/heads/main",
        ],
    );
    let request = GitSyncRequest::new(
        git(),
        trust("3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(
                url::Url::from_file_path(&remote)
                    .expect("remote URL")
                    .as_str(),
            )
            .expect("locator"),
            ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
    )
    .expect("request");
    let outcome = store
        .bootstrap_git_admission(&request)
        .expect("SHA-256 bootstrap");
    match outcome {
        GitAdmissionOutcome::GenesisValidated { commit, .. } => {
            assert_eq!(commit.format(), GitObjectFormat::Sha256);
            assert_eq!(commit.as_hex().len(), 64);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn dangerous_local_git_config_is_rejected_before_contacting_remote() {
    let local = TestDir::new("hostile-local");
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(local.path(), registry, Arc::new(NoLegacy)).expect("store");
    let batch = prepare_batch(&[genesis()], "hostile", &registry).expect("genesis");
    store
        .append(&batch, store.read().expect("empty").revision())
        .expect("append");
    run(local.path(), &["init", "-b", "main"]);
    run(local.path(), &["config", "user.name", "Wayjournal Test"]);
    run(
        local.path(),
        &["config", "user.email", "wayjournal@example.invalid"],
    );
    run(local.path(), &["add", "events", "batches", "journal"]);
    run(local.path(), &["commit", "-m", "genesis"]);
    run(
        local.path(),
        &["config", "credential.helper", "!touch should-not-run"],
    );
    let marker_remote = local.path().join("remote-contacted");
    let remote_script = local.path().join("remote-marker");
    fs::write(
        &remote_script,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker_remote.display()),
    )
    .expect("remote marker");
    fs::set_permissions(&remote_script, fs::Permissions::from_mode(0o700)).expect("mode");
    let request = GitSyncRequest::new(
        git(),
        LocalTrustBinding::parse(
            "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        )
        .expect("trust"),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(
                url::Url::from_file_path(&remote_script)
                    .expect("url")
                    .as_str(),
            )
            .expect("locator"),
            ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
    )
    .expect("request");
    assert!(store.bootstrap_git_admission(&request).is_err());
    assert!(
        !marker_remote.exists(),
        "unsafe local config was not rejected before transfer"
    );
    assert_eq!(store.admission_checkpoint().expect("checkpoint"), None);
}
