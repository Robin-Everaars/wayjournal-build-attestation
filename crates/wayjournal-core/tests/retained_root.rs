#[allow(dead_code)]
mod support;

use std::{
    fs,
    fs::File,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[cfg(target_os = "linux")]
use std::os::unix::fs::symlink;

use serde_json::{Value, json};
use support::BoundedNoLegacy;
use wayjournal_core::{
    ActorId, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, CommitOutcome, DomainRegistration,
    DomainRegistry, GitAdmissionError, GitCommandFailureKind, GitQuarantineReason, GitSyncOutcome,
    GitSyncRequest, KindId, LegacyEntry, LegacyStoreAdapter, LocalTrustBinding,
    MAX_LEGACY_FILE_BYTES, Record, Store, StoreCorruption, StoreError, prepare_batch,
    wayjournal_domain_registry,
};

fn validate_note(kind: &KindId, payload: &Value) -> Result<(), String> {
    if kind.as_str() != "note.created" {
        return Err("unsupported note kind".to_owned());
    }
    payload
        .as_object()
        .filter(|object| object.len() == 1 && object.contains_key("title"))
        .map(|_| ())
        .ok_or_else(|| "payload must contain exactly one title".to_owned())
}

static NOTE_KINDS: &[&str] = &["note.created"];
static EXAMPLE_DOMAINS: &[DomainRegistration] = &[DomainRegistration::new(
    "example.notes",
    "example.notes/v1",
    NOTE_KINDS,
    validate_note,
)];

/// A registry without the sealed identity/profile/catalog built-ins.
fn example_registry() -> DomainRegistry {
    DomainRegistry::new(EXAMPLE_DOMAINS).expect("example registry")
}

struct TestDir(PathBuf);
impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wayjournal-retained-root-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        // Hostile-permission cases leave a child that remove_dir_all cannot recurse into.
        if let Ok(entries) = fs::read_dir(&self.0) {
            for entry in entries.flatten() {
                let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700));
            }
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct RejectingLegacy;
impl LegacyStoreAdapter for RejectingLegacy {
    fn validate(&self, entries: &[LegacyEntry<'_>]) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }
        Err(format!("frozen legacy set of {} rejected", entries.len()))
    }
}

#[derive(Debug, Default)]
struct CountingLegacy {
    calls: AtomicUsize,
    entries: AtomicUsize,
}
impl LegacyStoreAdapter for CountingLegacy {
    fn validate(&self, entries: &[LegacyEntry<'_>]) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.entries.store(entries.len(), Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Debug)]
struct NoLegacy;
impl LegacyStoreAdapter for NoLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
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
        payload: json!({
            "store_kind": "wayjournal.personal",
            "store_uuid": "01913f1d-8e2a-7c30-8f4a-426614174010"
        }),
    }
}

/// A diagnostic path that must never be opened, created, or canonicalized.
fn unopenable_diagnostic() -> PathBuf {
    PathBuf::from("/nonexistent/wayjournal-retained-root-diagnostic")
}

#[test]
fn retained_root_store_operates_descriptor_relative_after_rename() {
    let directory = TestDir::new("rename");
    let original = directory.path().join("store-root");
    fs::create_dir(&original).expect("store root");
    let descriptor = File::open(&original).expect("retain root descriptor");

    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open_strict_retained_root(
        descriptor,
        unopenable_diagnostic(),
        registry,
        Arc::new(NoLegacy),
    )
    .expect("open retained root");

    // Reserved children were derived descriptor-relatively into the real root.
    assert!(original.join("events").is_dir());
    assert!(original.join("journal").is_dir());
    assert!(!unopenable_diagnostic().exists());

    // Rename the root out from under the diagnostic path. The retained
    // descriptor must keep addressing the same store.
    let renamed = directory.path().join("store-root-renamed");
    fs::rename(&original, &renamed).expect("rename store root");

    let empty = store.read().expect("read after rename");
    assert!(empty.records().is_empty());
    let prepared = prepare_batch(&[genesis()], "genesis", &registry).expect("prepare");
    let published = store
        .append(&prepared, empty.revision())
        .expect("publish after rename");
    assert!(matches!(published, CommitOutcome::Published { .. }));

    let visible = store.read().expect("read publication");
    assert_eq!(visible.records().len(), 1);
    assert!(!original.exists());
    assert!(renamed.join("events").is_dir());
    assert!(!unopenable_diagnostic().exists());
}

#[test]
fn retained_root_descriptors_share_one_store_across_rename() {
    let directory = TestDir::new("shared");
    let original = directory.path().join("store-root");
    fs::create_dir(&original).expect("store root");
    let registry = wayjournal_domain_registry().expect("registry");

    let first = Store::open_strict_retained_root(
        File::open(&original).expect("first descriptor"),
        unopenable_diagnostic(),
        registry,
        Arc::new(NoLegacy),
    )
    .expect("open first");

    let renamed = directory.path().join("store-root-renamed");
    fs::rename(&original, &renamed).expect("rename store root");

    let second = Store::open_strict_retained_root(
        File::open(&renamed).expect("second descriptor"),
        unopenable_diagnostic(),
        registry,
        Arc::new(NoLegacy),
    )
    .expect("open second");

    let empty = first.read().expect("first read");
    let prepared = prepare_batch(&[genesis()], "genesis", &registry).expect("prepare");
    first
        .append(&prepared, empty.revision())
        .expect("publish through first");

    // The second handle addresses the same store: it sees the publication and
    // enforces revision compare-and-swap against it.
    let observed = second.read().expect("second read");
    assert_eq!(observed.records().len(), 1);
    assert!(matches!(
        second.append(&prepared, empty.revision()),
        Ok(CommitOutcome::Replay { .. }) | Err(StoreError::RevisionMismatch { .. })
    ));
}

#[test]
fn retained_root_ignores_a_resolvable_decoy_diagnostic_path() {
    let directory = TestDir::new("decoy");
    let real = directory.path().join("store-root");
    let decoy = directory.path().join("decoy-root");
    fs::create_dir(&real).expect("store root");
    fs::create_dir(&decoy).expect("decoy root");
    let descriptor = File::open(&real).expect("retain root descriptor");

    let registry = wayjournal_domain_registry().expect("registry");
    let store =
        Store::open_strict_retained_root(descriptor, decoy.clone(), registry, Arc::new(NoLegacy))
            .expect("open retained root");

    // An openable diagnostic path stays inert: every reserved child is derived
    // from the descriptor, and nothing at all is created in the decoy.
    assert!(real.join("events").is_dir());
    assert!(real.join("journal").is_dir());
    assert_eq!(fs::read_dir(&decoy).expect("read decoy").count(), 0);

    let empty = store.read().expect("read");
    let prepared = prepare_batch(&[genesis()], "genesis", &registry).expect("prepare");
    assert!(matches!(
        store.append(&prepared, empty.revision()).expect("publish"),
        CommitOutcome::Published { .. }
    ));
    assert_eq!(store.read().expect("read publication").records().len(), 1);
    assert_eq!(fs::read_dir(&decoy).expect("read decoy").count(), 0);
}

/// Writes one frozen legacy S1/S2 event file into a store root.
fn write_legacy_event(root: &Path, bytes: &[u8]) {
    let event = root.join("events/123e4567-e89b-42d3-a456-426614174000");
    fs::create_dir_all(&event).expect("legacy event directory");
    fs::write(
        event.join("01913f1d-8e2a-7c30-8f4a-426614174001.json"),
        bytes,
    )
    .expect("legacy event");
}

fn retained_store(root: &Path, legacy: Arc<dyn LegacyStoreAdapter>) -> Result<Store, StoreError> {
    Store::open_strict_retained_root(
        File::open(root).expect("retain root descriptor"),
        unopenable_diagnostic(),
        wayjournal_domain_registry().expect("registry"),
        legacy,
    )
}

#[test]
fn retained_root_enforces_the_bounded_legacy_scan() {
    // The adapter's rejection of a frozen legacy set is enforced through the retained root.
    let rejecting = TestDir::new("legacy-reject");
    let reject_root = rejecting.path().join("store-root");
    fs::create_dir(&reject_root).expect("store root");
    let store = retained_store(&reject_root, Arc::new(RejectingLegacy)).expect("open rejecting");
    write_legacy_event(&reject_root, b"legacy event\n");
    assert!(
        matches!(
            store.read(),
            Err(StoreError::Corrupt {
                issue: StoreCorruption::InvalidLegacy { .. },
                ..
            })
        ),
        "retained root must enforce the legacy adapter"
    );

    // A permissive adapter is handed exactly the frozen entry the scan found under the
    // retained descriptor, which proves the scan reaches it at all.
    let counting = TestDir::new("legacy-count");
    let count_root = counting.path().join("store-root");
    fs::create_dir(&count_root).expect("store root");
    let counter = Arc::new(CountingLegacy::default());
    let store = retained_store(&count_root, counter.clone()).expect("open counting");
    write_legacy_event(&count_root, b"legacy event\n");
    let snapshot = store.read().expect("permissive legacy scan");
    assert_eq!(snapshot.legacy_entries().len(), 1);
    assert_eq!(counter.entries.load(Ordering::Relaxed), 1);
    assert!(counter.calls.load(Ordering::Relaxed) >= 1);

    // The byte bound refuses an oversized legacy file before anything is allocated for it,
    // so the adapter is never consulted.
    let oversized = TestDir::new("legacy-oversized");
    let over_root = oversized.path().join("store-root");
    fs::create_dir(&over_root).expect("store root");
    let counter = Arc::new(CountingLegacy::default());
    let store = retained_store(&over_root, counter.clone()).expect("open oversized");
    write_legacy_event(&over_root, &vec![b'x'; MAX_LEGACY_FILE_BYTES + 1]);
    assert!(
        matches!(store.read(), Err(StoreError::InvalidLayout { .. })),
        "oversized legacy file must be refused by the bound"
    );
    assert_eq!(counter.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn retained_root_fails_closed_on_a_removed_directory() {
    let directory = TestDir::new("removed");
    let root = directory.path().join("store-root");
    fs::create_dir(&root).expect("store root");
    let descriptor = File::open(&root).expect("retain root descriptor");
    fs::remove_dir(&root).expect("remove store root");

    // The inode is still alive through the descriptor, but it is unlinked, so no reserved
    // child can be created. That must fail closed rather than half-open a store.
    let Err(error) = Store::open_strict_retained_root(
        descriptor,
        unopenable_diagnostic(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    ) else {
        panic!("removed root must be rejected");
    };
    assert!(
        matches!(error, StoreError::Io { .. }),
        "removed root gave {error:?}"
    );
    assert!(!root.exists());
}

#[test]
fn retained_root_ignores_a_replacement_directory_at_the_original_path() {
    let directory = TestDir::new("replaced");
    let original = directory.path().join("store-root");
    fs::create_dir(&original).expect("store root");
    let descriptor = File::open(&original).expect("retain root descriptor");

    // Move the retained directory aside and drop a fresh directory at the original path.
    let moved = directory.path().join("store-root-moved");
    fs::rename(&original, &moved).expect("move store root");
    fs::create_dir(&original).expect("replacement directory");

    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open_strict_retained_root(
        descriptor,
        original.clone(),
        registry,
        Arc::new(NoLegacy),
    )
    .expect("open retained root");

    // Every reserved child and every publication belongs to the retained inode. The
    // replacement standing at the diagnostic path must stay untouched.
    assert!(moved.join("events").is_dir());
    assert!(moved.join("journal").is_dir());
    assert_eq!(
        fs::read_dir(&original).expect("read replacement").count(),
        0
    );

    let empty = store.read().expect("read");
    let prepared = prepare_batch(&[genesis()], "genesis", &registry).expect("prepare");
    assert!(matches!(
        store.append(&prepared, empty.revision()).expect("publish"),
        CommitOutcome::Published { .. }
    ));
    assert_eq!(store.read().expect("read publication").records().len(), 1);
    assert_eq!(
        fs::read_dir(&original).expect("read replacement").count(),
        0
    );
}

#[test]
fn retained_root_rejects_a_non_directory_descriptor() {
    let directory = TestDir::new("nondir");
    let file_path = directory.path().join("regular-file");
    fs::write(&file_path, b"not a directory").expect("regular file");
    let descriptor = File::open(&file_path).expect("file descriptor");

    let registry = wayjournal_domain_registry().expect("registry");
    let Err(error) = Store::open_strict_retained_root(
        descriptor,
        unopenable_diagnostic(),
        registry,
        Arc::new(NoLegacy),
    ) else {
        panic!("regular file must be rejected");
    };
    assert!(matches!(error, StoreError::InvalidLayout { .. }));
}

#[cfg(target_os = "linux")]
#[test]
fn retained_root_rejects_a_symlink_descriptor() {
    let directory = TestDir::new("symlink");
    let target = directory.path().join("store-root");
    let link = directory.path().join("store-link");
    fs::create_dir(&target).expect("store root");
    symlink(&target, &link).expect("symlink to store root");

    // O_PATH with O_NOFOLLOW retains the link itself rather than its target, so
    // fstat reports a symlink and the descriptor is refused before the layout
    // could be created through it.
    let descriptor = File::from(
        rustix::fs::open(
            &link,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("symlink descriptor"),
    );
    let Err(error) = Store::open_strict_retained_root(
        descriptor,
        unopenable_diagnostic(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    ) else {
        panic!("symlink descriptor must be rejected");
    };
    assert!(matches!(error, StoreError::InvalidLayout { .. }));
    assert_eq!(
        fs::read_dir(&target).expect("read symlink target").count(),
        0
    );
}

#[test]
fn retained_root_fails_closed_on_a_root_it_cannot_populate() {
    if rustix::process::geteuid().is_root() {
        return; // The DAC override makes these permission bits meaningless.
    }
    // Read without write, and read-write without search: neither can carry the
    // reserved layout, so both must fail closed with nothing created.
    for (label, mode) in [("no-write", 0o500), ("no-search", 0o600)] {
        let directory = TestDir::new(label);
        let root = directory.path().join("store-root");
        fs::create_dir(&root).expect("store root");
        let descriptor = File::open(&root).expect("retain root descriptor");
        fs::set_permissions(&root, fs::Permissions::from_mode(mode)).expect("restrict store root");

        let result = Store::open_strict_retained_root(
            descriptor,
            unopenable_diagnostic(),
            wayjournal_domain_registry().expect("registry"),
            Arc::new(NoLegacy),
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("restore store root");
        let Err(error) = result else {
            panic!("{label} root must be rejected");
        };
        assert!(
            matches!(error, StoreError::Io { .. }),
            "{label} root gave {error:?}"
        );
        assert_eq!(fs::read_dir(&root).expect("read store root").count(), 0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn retained_root_rejects_a_descriptor_it_cannot_make_durable() {
    let directory = TestDir::new("o-path");
    let root = directory.path().join("store-root");
    fs::create_dir(&root).expect("store root");

    // An O_PATH handle satisfies fstat and is a legal mkdirat target, so without
    // the durability probe it would populate the root and only fail on the
    // closing fsync, leaving the reserved layout behind.
    let descriptor = File::from(
        rustix::fs::open(
            &root,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("O_PATH descriptor"),
    );
    let Err(error) = Store::open_strict_retained_root(
        descriptor,
        unopenable_diagnostic(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    ) else {
        panic!("an O_PATH descriptor must be rejected");
    };
    assert!(
        matches!(
            error,
            StoreError::Io {
                operation: "sync directory descriptor",
                ..
            }
        ),
        "O_PATH descriptor gave {error:?}"
    );
    assert_eq!(fs::read_dir(&root).expect("read store root").count(), 0);
}

#[test]
fn retained_root_rejects_a_root_it_could_never_lock() {
    if rustix::process::geteuid().is_root() {
        return; // The DAC override makes these permission bits meaningless.
    }
    let directory = TestDir::new("no-read");
    let root = directory.path().join("store-root");
    fs::create_dir(&root).expect("store root");
    let descriptor = File::open(&root).expect("retain root descriptor");
    // Write and search without read. Every root lock reopens the root itself
    // read-only, so a store here could be created but never read.
    fs::set_permissions(&root, fs::Permissions::from_mode(0o300)).expect("restrict store root");

    let result = Store::open_strict_retained_root(
        descriptor,
        unopenable_diagnostic(),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("restore store root");
    let Err(error) = result else {
        panic!("a root without read permission must be rejected");
    };
    assert!(
        matches!(
            error,
            StoreError::Io {
                operation: "open independent root lock descriptor",
                ..
            }
        ),
        "unreadable root gave {error:?}"
    );
    assert_eq!(fs::read_dir(&root).expect("read store root").count(), 0);
}

#[test]
fn retained_root_fails_closed_on_a_descriptor_that_cannot_host_a_store() {
    // A procfs directory passes the fstat gate: it is an ordinary directory and
    // the root descriptor is exempt from the cross-device rule its children get.
    // Nothing can be created in it, so the open must still fail closed.
    let Ok(descriptor) = File::open("/proc/self/fd") else {
        return; // No procfs in this sandbox.
    };
    let Err(error) = Store::open_strict_retained_root(
        descriptor,
        PathBuf::from("/proc/self/fd"),
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    ) else {
        panic!("a procfs descriptor must be rejected");
    };
    assert!(
        matches!(error, StoreError::Io { .. }),
        "procfs descriptor gave {error:?}"
    );
    assert!(!Path::new("/proc/self/fd/events").exists());
}

const TRUST_BINDING: &str = "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15";
const RETAINED_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const REPLACEMENT_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const CHECKPOINTS: &str = ".wayjournal-local/checkpoints";
const QUARANTINE: &str = ".wayjournal-local/quarantine";
const RESIDUE: &str = ".admission-v1.json.tmp-01913f1d-8e2a-7c30-8f4a-426614174099";
const RETAINED_INCIDENT: &str = "01913f1d-8e2a-7c30-8f4a-426614174091";
const REPLACEMENT_INCIDENT: &str = "01913f1d-8e2a-7c30-8f4a-426614174090";
const ANCESTRY_REFUSAL: &str =
    "Git resolve local Git layout failed: ambient store ancestry no longer names the retained root";

/// The canonical admission checkpoint, byte-identical to the `s4_checkpoint`
/// fixture and matching the identity that [`genesis`] publishes.
const CANONICAL_CHECKPOINT: &str = r#"{
  "accepted_commit": "0123456789abcdef0123456789abcdef01234567",
  "accepted_git_object_format": "sha1",
  "accepted_revision_algorithm": "wayjournal.store/blake3-framed-v1",
  "accepted_revision_digest": "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
  "genesis_fingerprint": "7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447",
  "local_trust_binding": "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
  "remote_locator": "file:///srv/git/store.git",
  "remote_ref": "refs/heads/main",
  "schema": "wayjournal.admission-checkpoint/v1",
  "store_uuid": "01913f1d-8e2a-7c30-8f4a-426614174010"
}
"#;

/// Writes one 0600 local-state fixture, the mode every reader demands.
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private fixture mode");
}

fn git_executable() -> PathBuf {
    PathBuf::from(std::env::var_os("WAYJOURNAL_TEST_GIT").expect("Git"))
}

/// The one request the canonical checkpoint above admits.
fn sync_request() -> GitSyncRequest {
    GitSyncRequest::new(
        git_executable(),
        LocalTrustBinding::parse(TRUST_BINDING).expect("trust"),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse("file:///srv/git/store.git").expect("locator"),
            ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
    )
    .expect("request")
}

fn incident_json(incident_id: &str, request: &GitSyncRequest, reason: &str) -> Vec<u8> {
    let value = json!({
        "schema": "wayjournal.git-quarantine/v1",
        "incident_id": incident_id,
        "reason": reason,
        "logical_store_id": {
            "store_uuid": "01913f1d-8e2a-7c30-8f4a-426614174010",
            "genesis_fingerprint": "7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447"
        },
        "local_trust_binding": TRUST_BINDING,
        "approved_remote": request.approved_remote(),
        "checkpoint_commit": {"format": "sha1", "hex": "1".repeat(40)},
        "checkpoint_revision": {
            "algorithm": "wayjournal.store/blake3-framed-v1",
            "digest": "1c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
        },
        "observed_commit": null,
        "evidence_digest": "5c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
    });
    let mut bytes = serde_json::to_vec_pretty(&value).expect("incident JSON");
    bytes.push(b'\n');
    bytes
}

/// Opens a retained-root store on `root` whose diagnostic path is `diagnostic`.
fn retained_federation_store(root: &Path, diagnostic: PathBuf) -> Store {
    Store::open_strict_retained_root(
        File::open(root).expect("retain root descriptor"),
        diagnostic,
        wayjournal_domain_registry().expect("registry"),
        Arc::new(BoundedNoLegacy),
    )
    .expect("open retained root")
}

#[test]
fn retained_root_checkpoint_io_stays_on_the_retained_inode() {
    let directory = TestDir::new("checkpoint");
    let real = directory.path().join("store-root");
    let replacement = directory.path().join("replacement-root");
    fs::create_dir(&real).expect("store root");
    fs::create_dir(&replacement).expect("replacement root");
    let store = retained_federation_store(&real, replacement.clone());
    assert_eq!(
        fs::read_dir(&replacement)
            .expect("read replacement")
            .count(),
        0
    );

    // Give the replacement a complete, plausible checkpoint carrying a different
    // accepted commit, so a redirected read would be visible in the result.
    fs::create_dir_all(replacement.join(CHECKPOINTS)).expect("replacement checkpoints");
    let replacement_bytes = CANONICAL_CHECKPOINT.replace(RETAINED_COMMIT, REPLACEMENT_COMMIT);
    let replacement_checkpoint = replacement.join(CHECKPOINTS).join("admission-v1.json");
    write_private(
        &real.join(CHECKPOINTS).join("admission-v1.json"),
        CANONICAL_CHECKPOINT.as_bytes(),
    );
    write_private(&replacement_checkpoint, replacement_bytes.as_bytes());

    // Reading also writes: residue recovery unlinks a stale temporary. Plant one
    // on both sides so a redirected write is visible too.
    let real_residue = real.join(CHECKPOINTS).join(RESIDUE);
    let replacement_residue = replacement.join(CHECKPOINTS).join(RESIDUE);
    write_private(&real_residue, b"stale");
    write_private(&replacement_residue, b"stale");

    let checkpoint = store
        .admission_checkpoint()
        .expect("read checkpoint")
        .expect("checkpoint present");
    assert_eq!(checkpoint.accepted_commit().as_hex(), RETAINED_COMMIT);
    assert!(!real_residue.exists(), "retained residue must be recovered");
    assert!(
        replacement_residue.exists(),
        "residue recovery reached the diagnostic path"
    );
    assert_eq!(
        fs::read(&replacement_checkpoint).expect("replacement checkpoint"),
        replacement_bytes.as_bytes()
    );
}

#[test]
fn retained_root_quarantine_is_read_from_the_retained_inode() {
    let directory = TestDir::new("quarantine");
    let real = directory.path().join("store-root");
    let replacement = directory.path().join("replacement-root");
    fs::create_dir(&real).expect("store root");
    fs::create_dir(&replacement).expect("replacement root");
    let store = retained_federation_store(&real, replacement.clone());
    let request = sync_request();

    // Only the lexicographically first incident is examined, so the replacement
    // holds the lower identifier: a redirected scan would report it, not ours.
    fs::create_dir_all(replacement.join(QUARANTINE)).expect("replacement quarantine");
    write_private(
        &real
            .join(QUARANTINE)
            .join(format!("{RETAINED_INCIDENT}.json")),
        &incident_json(RETAINED_INCIDENT, &request, "malformed_history"),
    );
    let replacement_incident = replacement
        .join(QUARANTINE)
        .join(format!("{REPLACEMENT_INCIDENT}.json"));
    let replacement_bytes =
        incident_json(REPLACEMENT_INCIDENT, &request, "unsafe_repository_state");
    write_private(&replacement_incident, &replacement_bytes);

    // Quarantine is consulted before every other piece of federation state, so
    // it is the earliest point a redirected read could surface.
    assert!(matches!(
        store.sync_git_union(&request).expect("typed quarantine"),
        GitSyncOutcome::Quarantined {
            incident_id,
            reason: GitQuarantineReason::MalformedHistory
        } if incident_id.to_string() == RETAINED_INCIDENT
    ));
    assert_eq!(
        fs::read(&replacement_incident).expect("replacement incident"),
        replacement_bytes
    );
    assert_eq!(
        fs::read_dir(replacement.join(QUARANTINE))
            .expect("read replacement quarantine")
            .count(),
        1
    );
}

#[test]
fn retained_root_git_sync_refuses_an_ambient_ancestry_swap() {
    let directory = TestDir::new("ancestry");
    let root = directory.path().join("store-root");
    let admin = directory.path().join("git-admin");
    fs::create_dir(&root).expect("store root");
    fs::create_dir(&admin).expect("Git admin directory");
    let registry = wayjournal_domain_registry().expect("registry");
    let store = retained_federation_store(&root, root.clone());

    // Genesis plus the canonical checkpoint is the minimum durable state that
    // reaches local Git inspection at all.
    let empty = store.read().expect("read");
    let prepared = prepare_batch(&[genesis()], "genesis", &registry).expect("prepare");
    store
        .append(&prepared, empty.revision())
        .expect("publish genesis");
    write_private(
        &root.join(CHECKPOINTS).join("admission-v1.json"),
        CANONICAL_CHECKPOINT.as_bytes(),
    );
    // A .git regular file is a linked Git worktree, the single shape where the
    // diagnostic bytes are resolved ambiently before being checked back against
    // the retained inode.
    fs::write(root.join(".git"), format!("gitdir: {}\n", admin.display())).expect("gitfile");
    let request = sync_request();

    // Control: while the diagnostic path still names the retained root the
    // ancestry walk passes and the refusal comes from further downstream.
    let Err(GitAdmissionError::Git(intact)) = store.bootstrap_git_admission(&request) else {
        panic!("an incomplete worktree admin directory must be rejected");
    };
    assert_eq!(intact.operation(), "resolve local Git layout");
    assert_ne!(intact.to_string(), ANCESTRY_REFUSAL);

    // Move the retained root aside and leave a plausible replacement store, with
    // its own checkpoint, standing at the diagnostic pathname.
    let moved = directory.path().join("store-root-moved");
    fs::rename(&root, &moved).expect("move store root");
    fs::create_dir(&root).expect("replacement directory");
    fs::create_dir_all(root.join(CHECKPOINTS)).expect("replacement checkpoints");
    fs::create_dir_all(root.join(QUARANTINE)).expect("replacement quarantine");
    write_private(
        &root.join(CHECKPOINTS).join("admission-v1.json"),
        CANONICAL_CHECKPOINT
            .replace(RETAINED_COMMIT, REPLACEMENT_COMMIT)
            .as_bytes(),
    );
    fs::write(root.join(".git"), format!("gitdir: {}\n", admin.display()))
        .expect("replacement gitfile");

    let Err(GitAdmissionError::Git(swapped)) = store.bootstrap_git_admission(&request) else {
        panic!("an ambient ancestry swap must be rejected");
    };
    assert_eq!(swapped.operation(), "resolve local Git layout");
    assert_eq!(swapped.kind(), GitCommandFailureKind::Io);
    assert_eq!(swapped.to_string(), ANCESTRY_REFUSAL);

    // The union path classifies the same layout refusal as a hostile repository
    // state. The incident it durably records belongs to the retained inode.
    assert!(matches!(
        store.sync_git_union(&request).expect("typed quarantine"),
        GitSyncOutcome::Quarantined {
            reason: GitQuarantineReason::UnsafeRepositoryState,
            ..
        }
    ));
    assert_eq!(
        fs::read_dir(moved.join(QUARANTINE))
            .expect("read retained quarantine")
            .count(),
        1
    );
    assert_eq!(
        fs::read_dir(root.join(QUARANTINE))
            .expect("read replacement quarantine")
            .count(),
        0
    );
}

#[test]
fn retained_root_requires_sealed_builtins_like_open_strict() {
    let directory = TestDir::new("builtins");
    let root = directory.path().join("store-root");
    fs::create_dir(&root).expect("store root");
    let descriptor = File::open(&root).expect("descriptor");

    // The example registry carries no sealed identity/profile/catalog
    // built-ins, so the strict gate must refuse it exactly as open_strict does.
    let Err(error) = Store::open_strict_retained_root(
        descriptor,
        unopenable_diagnostic(),
        example_registry(),
        Arc::new(NoLegacy),
    ) else {
        panic!("registry without sealed built-ins must be rejected");
    };
    assert!(matches!(error, StoreError::InvalidLayout { .. }));
}
