use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use wayjournal_core::{
    ADMISSION_CHECKPOINT_FILENAME, ApprovalError, ApprovedRef, ApprovedRemote,
    ApprovedRemoteLocator, CheckpointError, GitAdmissionError, GitObjectFormat, GitOid,
    GitSyncRequest, LegacyEntry, LegacyStoreAdapter, LocalTrustBinding,
    MAX_ADMISSION_CHECKPOINT_BYTES, Store, decode_admission_checkpoint,
    encode_admission_checkpoint, wayjournal_domain_registry,
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
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("wayjournal-s4-checkpoint-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).expect("create test directory");
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

#[test]
fn checked_admission_inputs_reject_ambient_or_credential_bearing_authority() {
    let git = std::env::current_exe().expect("absolute executable");
    let locator = ApprovedRemoteLocator::parse("file:///srv/git/store.git").expect("file URL");
    let reference = ApprovedRef::parse("refs/heads/main").expect("branch ref");
    let remote = ApprovedRemote::new(locator, reference);
    let trust = LocalTrustBinding::parse(
        "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
    )
    .expect("binding");
    let request = GitSyncRequest::new(git.clone(), trust, remote.clone()).expect("request");
    assert_eq!(request.git_executable(), git);
    assert_eq!(request.local_trust(), trust);
    assert_eq!(request.approved_remote(), &remote);

    for rejected in [
        "http://example.invalid/store.git",
        "ssh://example.invalid/store.git",
        "file://user@example.invalid/store.git",
        "https://user@example.invalid/store.git",
        "https://example.invalid/store.git?token=secret",
        "https://example.invalid/store.git#fragment",
        "file:///tmp/a%2fb/store.git",
        "file:///tmp/%252e%252e/etc/store.git",
        "file:///tmp/a%00b/store.git",
        "https://example.invalid/a%2fb.git",
        "example.invalid:store.git",
        "ext::sh -c marker",
    ] {
        assert!(
            ApprovedRemoteLocator::parse(rejected).is_err(),
            "{rejected}"
        );
    }
    for rejected in [
        "main",
        "refs/tags/main",
        "refs/heads/a..b",
        "refs/heads/a b",
    ] {
        assert_eq!(ApprovedRef::parse(rejected), Err(ApprovalError::InvalidRef));
    }
    assert!(GitSyncRequest::new(PathBuf::from("git"), trust, remote).is_err());
}

#[test]
fn git_executable_is_an_opened_executable_inode_not_a_followed_path() {
    let git = std::env::current_exe().expect("absolute executable");
    let remote = ApprovedRemote::new(
        ApprovedRemoteLocator::parse("file:///srv/git/store.git").expect("file URL"),
        ApprovedRef::parse("refs/heads/main").expect("branch ref"),
    );
    let trust = LocalTrustBinding::parse(
        "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
    )
    .expect("binding");
    let directory = TestDir::new();
    let symlink_path = directory.path().join("git-link");
    symlink(&git, &symlink_path).expect("Git symlink");
    assert!(GitSyncRequest::new(symlink_path, trust, remote.clone()).is_err());
    let non_executable = directory.path().join("git-non-executable");
    fs::write(&non_executable, b"not executable").expect("non-executable fixture");
    fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o600))
        .expect("non-executable mode");
    assert!(GitSyncRequest::new(non_executable, trust, remote).is_err());
}

#[test]
fn checked_types_cannot_be_deserialized_around_their_constructors() {
    assert!(
        serde_json::from_str::<ApprovedRemoteLocator>("\"ssh://evil.invalid/store.git\"").is_err()
    );
    assert!(
        serde_json::from_str::<ApprovedRemoteLocator>(
            "\"https://user:secret@example.invalid/store.git\""
        )
        .is_err()
    );
    assert!(serde_json::from_str::<ApprovedRef>("\"refs/tags/evil\"").is_err());
    assert!(
        serde_json::from_value::<GitOid>(serde_json::json!({"format":"sha1","hex":"x"})).is_err()
    );
}

#[test]
fn git_oids_are_tagged_and_canonical() {
    let sha1 = GitOid::parse(
        GitObjectFormat::Sha1,
        "0123456789abcdef0123456789abcdef01234567",
    )
    .expect("sha1");
    let sha256 = GitOid::parse(
        GitObjectFormat::Sha256,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .expect("sha256");
    assert_eq!(sha1.format(), GitObjectFormat::Sha1);
    assert_eq!(sha1.as_hex(), "0123456789abcdef0123456789abcdef01234567");
    assert_eq!(sha256.format(), GitObjectFormat::Sha256);
    assert_eq!(sha256.as_hex().len(), 64);
    assert!(GitOid::parse(GitObjectFormat::Sha1, sha256.as_hex()).is_err());
    assert!(GitOid::parse(GitObjectFormat::Sha1, "ABCDEF").is_err());
    assert!(GitObjectFormat::from_str("sha384").is_err());
}

#[test]
fn missing_checkpoint_is_absent_but_corruption_is_fatal() {
    let directory = TestDir::new();
    let store = Store::open(
        directory.path(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    )
    .expect("store");
    assert_eq!(
        store.admission_checkpoint().expect("absent checkpoint"),
        None
    );

    fs::write(
        directory
            .path()
            .join(".wayjournal-local/checkpoints/admission-v1.json"),
        b"{}\n",
    )
    .expect("corrupt checkpoint");
    assert!(matches!(
        store.admission_checkpoint(),
        Err(GitAdmissionError::Checkpoint(_))
    ));
}

fn open_store(directory: &TestDir) -> Store {
    Store::open(
        directory.path(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    )
    .expect("store")
}

fn canonical_checkpoint() -> &'static [u8] {
    b"{\n  \"accepted_commit\": \"0123456789abcdef0123456789abcdef01234567\",\n  \"accepted_git_object_format\": \"sha1\",\n  \"accepted_revision_algorithm\": \"wayjournal.store/blake3-framed-v1\",\n  \"accepted_revision_digest\": \"3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15\",\n  \"genesis_fingerprint\": \"7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447\",\n  \"local_trust_binding\": \"3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15\",\n  \"remote_locator\": \"file:///srv/git/store.git\",\n  \"remote_ref\": \"refs/heads/main\",\n  \"schema\": \"wayjournal.admission-checkpoint/v1\",\n  \"store_uuid\": \"01913f1d-8e2a-7c30-8f4a-426614174010\"\n}\n"
}

#[test]
fn public_checkpoint_codec_has_the_stable_closed_wire_contract() {
    assert_eq!(ADMISSION_CHECKPOINT_FILENAME, "admission-v1.json");
    assert_eq!(MAX_ADMISSION_CHECKPOINT_BYTES, 8 * 1024);

    let checkpoint = decode_admission_checkpoint(canonical_checkpoint()).expect("canonical");
    assert_eq!(
        encode_admission_checkpoint(&checkpoint).expect("encode"),
        canonical_checkpoint()
    );

    let text = std::str::from_utf8(canonical_checkpoint()).expect("fixture text");
    let invalid = [
        (
            "unknown field",
            text.replacen(
                "  \"store_uuid\":",
                "  \"unknown\": true,\n  \"store_uuid\":",
                1,
            )
            .into_bytes(),
        ),
        (
            "noncanonical bytes",
            serde_json::to_vec(
                &serde_json::from_slice::<serde_json::Value>(canonical_checkpoint())
                    .expect("fixture JSON"),
            )
            .expect("compact JSON"),
        ),
        (
            "object format",
            text.replacen(
                "\"accepted_git_object_format\": \"sha1\"",
                "\"accepted_git_object_format\": \"sha256\"",
                1,
            )
            .into_bytes(),
        ),
        (
            "revision algorithm",
            text.replacen(
                "wayjournal.store/blake3-framed-v1",
                "wayjournal.store/unknown-v1",
                1,
            )
            .into_bytes(),
        ),
    ];
    for (label, bytes) in invalid {
        assert!(
            matches!(
                decode_admission_checkpoint(&bytes),
                Err(CheckpointError::Invalid(_))
            ),
            "{label}"
        );
    }
    assert!(matches!(
        decode_admission_checkpoint(&vec![b'x'; MAX_ADMISSION_CHECKPOINT_BYTES + 1]),
        Err(CheckpointError::Oversized)
    ));
}

#[test]
fn checkpoint_codec_is_canonical_closed_and_bounded() {
    let text = std::str::from_utf8(canonical_checkpoint()).expect("fixture text");
    let cases = [
        ("canonical", canonical_checkpoint().to_vec(), true),
        ("duplicate", text.replacen("  \"schema\": \"wayjournal.admission-checkpoint/v1\",", "  \"schema\": \"wayjournal.admission-checkpoint/v1\",\n  \"schema\": \"wayjournal.admission-checkpoint/v1\",", 1).into_bytes(), false),
        ("unknown", text.replacen("  \"store_uuid\":", "  \"unknown\": true,\n  \"store_uuid\":", 1).into_bytes(), false),
        ("missing", format!("{}\n", text.lines().filter(|line| !line.contains("\"remote_ref\"")).collect::<Vec<_>>().join("\n")).into_bytes(), false),
        ("trailing", [canonical_checkpoint(), b" "].concat(), false),
        ("float", text.replacen("\"wayjournal.admission-checkpoint/v1\"", "1.5", 1).into_bytes(), false),
        ("oversized", vec![b'x'; 8193], false),
    ];
    for (label, bytes, valid) in cases {
        let directory = TestDir::new();
        let store = open_store(&directory);
        let path = directory
            .path()
            .join(".wayjournal-local/checkpoints/admission-v1.json");
        fs::write(&path, bytes).expect("write case");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("checkpoint mode");
        let result = store.admission_checkpoint();
        assert_eq!(result.is_ok(), valid, "{label}: {result:?}");
        if valid {
            let parsed = result.expect("valid").expect("present");
            assert_eq!(
                parsed.accepted_commit().as_hex(),
                "0123456789abcdef0123456789abcdef01234567"
            );
            assert_eq!(
                parsed.approved_remote().reference().as_str(),
                "refs/heads/main"
            );
        }
    }
}

#[test]
fn checkpoint_residue_cleanup_is_narrow_and_symlinks_fail_closed() {
    let clean = TestDir::new();
    let clean_store = open_store(&clean);
    let temporary = clean.path().join(
        ".wayjournal-local/checkpoints/.admission-v1.json.tmp-01913f1d-8e2a-7c30-8f4a-426614174099",
    );
    fs::write(&temporary, b"stale").expect("temporary");
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).expect("temporary mode");
    assert_eq!(clean_store.admission_checkpoint().expect("cleanup"), None);
    assert!(!temporary.exists());

    let unknown = TestDir::new();
    let unknown_store = open_store(&unknown);
    fs::write(
        unknown
            .path()
            .join(".wayjournal-local/checkpoints/other.json"),
        b"{}\n",
    )
    .expect("unknown");
    assert!(matches!(
        unknown_store.admission_checkpoint(),
        Err(GitAdmissionError::Checkpoint(_))
    ));

    let linked = TestDir::new();
    let linked_store = open_store(&linked);
    std::os::unix::fs::symlink(
        "/dev/null",
        linked
            .path()
            .join(".wayjournal-local/checkpoints/admission-v1.json"),
    )
    .expect("symlink");
    assert!(matches!(
        linked_store.admission_checkpoint(),
        Err(GitAdmissionError::Checkpoint(_))
    ));

    let target_directory = TestDir::new();
    let target_directory_store = open_store(&target_directory);
    fs::create_dir(
        target_directory
            .path()
            .join(".wayjournal-local/checkpoints/admission-v1.json"),
    )
    .expect("target directory");
    assert!(matches!(
        target_directory_store.admission_checkpoint(),
        Err(GitAdmissionError::Checkpoint(_))
    ));

    let temporary_symlink = TestDir::new();
    let temporary_symlink_store = open_store(&temporary_symlink);
    symlink(
        "/dev/null",
        temporary_symlink.path().join(
            ".wayjournal-local/checkpoints/.admission-v1.json.tmp-01913f1d-8e2a-7c30-8f4a-426614174099",
        ),
    )
    .expect("temporary symlink");
    assert!(matches!(
        temporary_symlink_store.admission_checkpoint(),
        Err(GitAdmissionError::Checkpoint(_))
    ));

    let multiple = TestDir::new();
    let multiple_store = open_store(&multiple);
    for suffix in [
        "01913f1d-8e2a-7c30-8f4a-426614174098",
        "01913f1d-8e2a-7c30-8f4a-426614174099",
    ] {
        let temporary = multiple.path().join(format!(
            ".wayjournal-local/checkpoints/.admission-v1.json.tmp-{suffix}"
        ));
        fs::write(&temporary, b"stale").expect("temporary");
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).expect("temporary mode");
    }
    assert!(matches!(
        multiple_store.admission_checkpoint(),
        Err(GitAdmissionError::Checkpoint(_))
    ));

    let oversized = TestDir::new();
    let oversized_store = open_store(&oversized);
    let oversized_temporary = oversized.path().join(
        ".wayjournal-local/checkpoints/.admission-v1.json.tmp-01913f1d-8e2a-7c30-8f4a-426614174099",
    );
    fs::write(&oversized_temporary, vec![b'x'; 8193]).expect("oversized temporary");
    fs::set_permissions(&oversized_temporary, fs::Permissions::from_mode(0o600))
        .expect("temporary mode");
    assert!(matches!(
        oversized_store.admission_checkpoint(),
        Err(GitAdmissionError::Checkpoint(_))
    ));
}

#[test]
fn checkpoint_target_requires_private_mode() {
    let directory = TestDir::new();
    let store = open_store(&directory);
    let path = directory
        .path()
        .join(".wayjournal-local/checkpoints/admission-v1.json");
    fs::write(&path, canonical_checkpoint()).expect("checkpoint");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("public mode");
    assert!(matches!(
        store.admission_checkpoint(),
        Err(GitAdmissionError::Checkpoint(_))
    ));
}
