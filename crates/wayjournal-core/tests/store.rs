mod support;

use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    sync::{Arc, Barrier, mpsc},
    thread,
    time::Duration,
};

use support::{BATCH_ID, RECORD_A, RECORD_B, note_record, registry};
use wayjournal_core::{
    AppendPreview, CommitOutcome, ExclusiveStoreOperation, LegacyEntry, LegacyStoreAdapter,
    PathClass, PreparedBatch, Store, StoreCorruption, StoreError, StoreRevisionRef, prepare_batch,
};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wayjournal-store-{label}-{}-{}",
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
struct FixtureLegacy;

impl LegacyStoreAdapter for FixtureLegacy {
    fn validate(&self, entries: &[LegacyEntry<'_>]) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }
        if entries.len() != 2
            || entries[0].class() != PathClass::LegacyBatch
            || entries[0].bytes() != b"legacy batch\n"
            || entries[1].class() != PathClass::LegacyEvent
            || entries[1].bytes() != b"legacy event\n"
        {
            return Err("frozen legacy pair is incomplete or malformed".to_owned());
        }
        Ok(())
    }
}

fn store(root: &Path) -> Result<Store, StoreError> {
    Store::open_legacy_s1_s2(root, registry(), Arc::new(FixtureLegacy))
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    fs::write(path, bytes).expect("write fixture");
}

#[test]
fn opens_reads_and_appends_with_expected_revision_and_replay() {
    let directory = TestDir::new("append");
    let store = store(directory.path()).expect("open");
    let empty = store.read().expect("read empty");
    assert!(empty.records().is_empty());
    assert!(empty.manifests().is_empty());

    let records = [
        note_record(
            RECORD_A,
            "123e4567-e89b-42d3-a456-426614174000",
            "stored first",
        ),
        note_record(
            RECORD_B,
            "123e4567-e89b-42d3-a456-426614174001",
            "stored second",
        ),
    ];
    let prepared = prepare_batch(&records, "append-key", &registry()).expect("prepare");
    let published = store
        .append(&prepared, empty.revision())
        .expect("publish complete batch");
    let CommitOutcome::Published { revision, .. } = published else {
        panic!("first append must publish");
    };
    let visible = store.read().expect("read publication");
    assert_eq!(visible.revision(), revision);
    assert_eq!(visible.records().len(), 2);
    assert_eq!(visible.manifests().len(), 1);

    assert!(matches!(
        store.append(&prepared, empty.revision()),
        Err(StoreError::RevisionMismatch { .. })
    ));
    assert!(matches!(
        store.append(&prepared, visible.revision()),
        Ok(CommitOutcome::Replay { .. })
    ));
}

#[test]
fn strict_scan_validates_generic_ownership_and_frozen_legacy_adapter() {
    let orphan = TestDir::new("orphan");
    let orphan_store = store(orphan.path()).expect("open");
    let prepared = prepare_batch(
        &[note_record(
            RECORD_A,
            "123e4567-e89b-42d3-a456-426614174000",
            "orphan",
        )],
        "orphan-key",
        &registry(),
    )
    .expect("prepare");
    write(
        orphan.path(),
        prepared.records()[0].path(),
        prepared.records()[0].bytes(),
    );
    assert!(matches!(
        orphan_store.read(),
        Err(StoreError::Corrupt {
            issue: StoreCorruption::GenericOwnership(_),
            ..
        })
    ));

    let legacy = TestDir::new("legacy");
    let legacy_store = store(legacy.path()).expect("open");
    write(
        legacy.path(),
        "events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json",
        b"legacy event\n",
    );
    assert!(matches!(
        legacy_store.read(),
        Err(StoreError::Corrupt {
            issue: StoreCorruption::InvalidLegacy { .. },
            ..
        })
    ));
    write(
        legacy.path(),
        &format!("batches/{BATCH_ID}.json"),
        b"legacy batch\n",
    );
    let snapshot = legacy_store.read().expect("complete frozen legacy pair");
    assert_eq!(snapshot.legacy_entries().len(), 2);
}

#[test]
fn hostile_reserved_layout_and_publication_collisions_fail_closed() {
    let symlinked = TestDir::new("symlink-root");
    let outside = symlinked.path().join("outside");
    fs::create_dir(&outside).expect("outside");
    symlink(&outside, symlinked.path().join("journal")).expect("symlink");
    assert!(matches!(
        store(symlinked.path()),
        Err(StoreError::InvalidLayout { .. })
    ));

    let unknown = TestDir::new("unknown");
    let unknown_store = store(unknown.path()).expect("open");
    fs::create_dir(unknown.path().join("journal/unknown-empty"))
        .expect("unknown empty reserved directory");
    assert!(matches!(
        unknown_store.read(),
        Err(StoreError::Corrupt {
            issue: StoreCorruption::InvalidCanonicalPath { .. },
            ..
        })
    ));

    let nonregular = TestDir::new("nonregular");
    let nonregular_store = store(nonregular.path()).expect("open");
    let outside_file = nonregular.path().join("outside-file");
    fs::write(&outside_file, b"outside").expect("outside file");
    symlink(
        &outside_file,
        nonregular
            .path()
            .join(format!("journal/batches/{BATCH_ID}.json")),
    )
    .expect("canonical symlink");
    assert!(matches!(
        nonregular_store.read(),
        Err(StoreError::Corrupt {
            issue: StoreCorruption::NonRegularPath { .. },
            ..
        })
    ));

    let collision = TestDir::new("collision");
    let collision_store = store(collision.path()).expect("open");
    let prepared = prepare_batch(
        &[note_record(
            RECORD_A,
            "123e4567-e89b-42d3-a456-426614174000",
            "collision",
        )],
        "collision-key",
        &registry(),
    )
    .expect("prepare");
    write(
        collision.path(),
        prepared.records()[0].path(),
        b"hostile bytes",
    );
    let expected = collision_store
        .read()
        .expect_err("orphan collision is corruption");
    assert!(matches!(expected, StoreError::Corrupt { .. }));
}

#[test]
fn post_open_namespace_replacement_cannot_redirect_retained_anchors() {
    for relative in [
        "events",
        "batches",
        "journal",
        ".wayjournal-local/stages",
        ".wayjournal-local/recovery",
    ] {
        let directory = TestDir::new(&relative.replace('/', "-"));
        let retained = store(directory.path()).expect("open");
        let path = directory.path().join(relative);
        let original = directory
            .path()
            .join(format!("replaced-{}", relative.replace('/', "-")));
        fs::rename(&path, &original).expect("move reserved directory");
        let outside = directory.path().join("hostile-outside");
        fs::create_dir_all(&outside).expect("outside");
        symlink(&outside, &path).expect("replace with symlink");
        retained
            .read()
            .expect("retained descriptor remains confined to original inode");
        assert!(matches!(
            store(directory.path()),
            Err(StoreError::InvalidLayout { .. })
        ));
    }

    let directory = TestDir::new("no-lock-name");
    let retained = store(directory.path()).expect("open");
    assert!(!directory.path().join(".wayjournal-local/lock").exists());
    retained
        .read()
        .expect("root inode itself is the lock authority");
}

#[test]
fn oversized_canonical_and_legacy_files_are_rejected_before_allocation() {
    for (label, relative, size) in [
        (
            "oversized-batch",
            format!("journal/batches/{BATCH_ID}.json"),
            wayjournal_core::MAX_BATCH_BYTES + 1,
        ),
        (
            "oversized-record",
            format!(
                "journal/records/notes.domain/123e4567-e89b-42d3-a456-426614174000/{RECORD_A}.json"
            ),
            wayjournal_core::MAX_RECORD_BYTES + 1,
        ),
        (
            "oversized-legacy",
            format!("batches/{BATCH_ID}.json"),
            wayjournal_core::MAX_LEGACY_FILE_BYTES + 1,
        ),
    ] {
        let directory = TestDir::new(label);
        let store = store(directory.path()).expect("open");
        write(directory.path(), &relative, &vec![b'x'; size]);
        assert!(matches!(
            store.read(),
            Err(StoreError::InvalidLayout { .. })
        ));
    }
}

#[test]
fn duplicate_record_identity_across_canonical_paths_fails_globally() {
    let directory = TestDir::new("duplicate-global-id");
    let store = store(directory.path()).expect("open");
    let first = prepare_batch(
        &[note_record(
            RECORD_A,
            "123e4567-e89b-42d3-a456-426614174000",
            "first",
        )],
        "first-key",
        &registry(),
    )
    .expect("first");
    let mut second_record = note_record(RECORD_A, "123e4567-e89b-42d3-a456-426614174001", "second");
    second_record.batch_id = "01913f1d-8e2a-7c30-8f4a-426614174100"
        .parse()
        .expect("second batch");
    let second = prepare_batch(&[second_record], "second-key", &registry()).expect("second");
    for prepared in [&first, &second] {
        write(
            directory.path(),
            prepared.records()[0].path(),
            prepared.records()[0].bytes(),
        );
        write(
            directory.path(),
            prepared.manifest_path(),
            prepared.manifest_bytes(),
        );
    }
    assert!(matches!(
        store.read(),
        Err(StoreError::Corrupt {
            issue: StoreCorruption::DuplicateGlobalRecordId { .. },
            ..
        })
    ));
}

#[test]
fn exclusive_snapshot_serializes_writers() {
    let directory = TestDir::new("exclusive");
    let reader = store(directory.path()).expect("reader open");
    let writer = store(directory.path()).expect("writer open");
    let expected = reader.read().expect("read").revision();
    let prepared = prepare_batch(
        &[note_record(
            RECORD_A,
            "123e4567-e89b-42d3-a456-426614174000",
            "exclusive",
        )],
        "exclusive-key",
        &registry(),
    )
    .expect("prepare");
    let guard = reader.exclusive_snapshot().expect("exclusive snapshot");
    let started = Arc::new(Barrier::new(2));
    let child_started = Arc::clone(&started);
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        child_started.wait();
        sender
            .send(writer.append(&prepared, expected))
            .expect("send");
    });
    started.wait();
    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(guard);
    let result = receiver.recv_timeout(Duration::from_secs(2));
    assert!(
        matches!(result, Ok(Ok(CommitOutcome::Published { .. }))),
        "writer result: {result:?}"
    );
    handle.join().expect("writer join");
}

#[test]
fn local_state_is_excluded_from_revision() {
    let directory = TestDir::new("local-revision");
    let store = store(directory.path()).expect("open");
    let before = store.read().expect("read").revision();
    write(
        directory.path(),
        ".wayjournal-local/checkpoints/admission.json",
        b"not in S2 semantics",
    );
    let after = store.read().expect("read after local file").revision();
    assert_eq!(before, after);
}

#[allow(dead_code)]
fn exclusive_operation_compile_contract<'store>(
    store: &'store Store,
    prepared: &PreparedBatch,
    expected: StoreRevisionRef,
) -> Result<(CommitOutcome, StoreRevisionRef), StoreError> {
    let mut operation: ExclusiveStoreOperation<'store> = store.begin_exclusive_operation()?;
    operation.recover_locked()?;
    let _root = operation.retained_root().duplicate_descriptor()?;
    let _snapshot: &wayjournal_core::StoreSnapshot = operation.snapshot_locked()?;
    let _preview: AppendPreview = operation.preview_append_locked(prepared, expected)?;
    let (outcome, snapshot) = operation.append_locked(prepared, expected)?;
    Ok((outcome, snapshot.revision()))
}

#[test]
fn locked_operation_previews_publishes_and_replays_without_reacquiring() {
    let directory = TestDir::new("exclusive-operation");
    let store = store(directory.path()).expect("open");
    let prepared = prepare_batch(
        &[note_record(
            RECORD_A,
            "123e4567-e89b-42d3-a456-426614174000",
            "locked",
        )],
        "locked-key",
        &registry(),
    )
    .expect("prepare");

    let mut operation = store.begin_exclusive_operation().expect("begin operation");
    operation.recover_locked().expect("recover");
    let expected = operation.snapshot_locked().expect("snapshot").revision();
    let AppendPreview::Publish {
        revision: previewed,
    } = operation
        .preview_append_locked(&prepared, expected)
        .expect("preview publish")
    else {
        panic!("new batch must preview publication");
    };
    assert_ne!(previewed, expected);

    let (outcome, committed) = operation
        .append_locked(&prepared, expected)
        .expect("append under same operation");
    assert!(matches!(
        outcome,
        CommitOutcome::Published { revision, .. } if revision == previewed
    ));
    assert_eq!(committed.revision(), previewed);

    assert!(matches!(
        operation
            .preview_append_locked(&prepared, previewed)
            .expect("preview replay"),
        AppendPreview::Replay { revision, .. } if revision == previewed
    ));
    assert!(matches!(
        operation.preview_append_locked(&prepared, expected),
        Err(StoreError::RevisionMismatch { actual, .. }) if actual == previewed
    ));
}
