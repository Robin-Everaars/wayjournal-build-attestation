use std::{
    fs,
    fs::File,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use serde_json::{Value, json};
use wayjournal_core::{
    ActorId, CommitOutcome, DomainRegistration, DomainRegistry, KindId, LegacyEntry,
    LegacyStoreAdapter, MAX_LEGACY_FILE_BYTES, Record, Store, StoreCorruption, StoreError,
    prepare_batch, wayjournal_domain_registry,
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
