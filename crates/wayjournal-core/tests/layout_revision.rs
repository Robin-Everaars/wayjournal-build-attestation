use wayjournal_core::{
    CanonicalPath, PathClass, RevisionAlgorithm, RevisionEntry, RevisionError, StoreRevisionRef,
    classify_path, compute_store_revision,
};

const LEGACY_EVENT: &str =
    "events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json";
const LEGACY_BATCH: &str = "batches/01913f1d-8e2a-7c30-8f4a-426614174099.json";
const JOURNAL_RECORD: &str = "journal/records/example.notes/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174002.json";
const JOURNAL_BATCH: &str = "journal/batches/01913f1d-8e2a-7c30-8f4a-426614174100.json";

#[test]
fn reserved_paths_cover_frozen_legacy_and_generic_roots() {
    let cases = [
        (LEGACY_EVENT.as_bytes(), PathClass::LegacyEvent),
        (LEGACY_BATCH.as_bytes(), PathClass::LegacyBatch),
        (JOURNAL_RECORD.as_bytes(), PathClass::JournalRecord),
        (JOURNAL_BATCH.as_bytes(), PathClass::JournalBatch),
        (b"README.md".as_slice(), PathClass::NonCanonical),
    ];
    for (path, expected) in cases {
        assert_eq!(classify_path(path), expected, "path {path:?}");
    }

    for path in [
        b"events".as_slice(),
        b"events//x.json",
        b"events/123e4567-e89b-42d3-2456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json",
        b"events/../x.json",
        b"batches/x/y.json",
        b"journal/records/example/entity.json",
        b"journal/records/Example.notes/entity/id.json",
        b"journal/records/example.notes/entity/id",
        b"journal/batches/nested/id.json",
        b"journal/unknown/x.json",
        b"journal/records/\xff/entity/id.json",
    ] {
        assert_eq!(
            classify_path(path),
            PathClass::InvalidReserved,
            "path {path:?}"
        );
    }
}

#[test]
fn canonical_path_parser_exposes_closed_identity_components() {
    let path = CanonicalPath::parse(JOURNAL_RECORD.as_bytes()).expect("valid record path");
    assert_eq!(path.class(), PathClass::JournalRecord);
    assert_eq!(path.as_bytes(), JOURNAL_RECORD.as_bytes());
}

fn all_roots() -> [RevisionEntry; 4] {
    [
        RevisionEntry::regular(LEGACY_EVENT, b"legacy-event"),
        RevisionEntry::regular(LEGACY_BATCH, b"legacy-batch"),
        RevisionEntry::regular(JOURNAL_RECORD, b"generic-record"),
        RevisionEntry::regular(JOURNAL_BATCH, b"generic-batch"),
    ]
}

#[test]
fn revision_sorts_raw_paths_covers_all_roots_and_has_exact_digest() {
    let mut entries = all_roots().to_vec();
    entries.push(RevisionEntry::regular("README.md", b"not authoritative"));
    let forward = compute_store_revision(entries.clone()).expect("revision");
    let reverse = compute_store_revision(entries.into_iter().rev()).expect("revision");
    assert_eq!(forward, reverse);
    assert_eq!(
        forward.algorithm(),
        RevisionAlgorithm::WayjournalBlake3FramedV1
    );
    assert_eq!(
        forward.digest().to_string(),
        "ee86c8bd5c2f29dd8fa3b3eb4574244cbb4fe5f2b5a44c74dc7a0278522c06f1"
    );

    for omitted in [LEGACY_EVENT, LEGACY_BATCH, JOURNAL_RECORD, JOURNAL_BATCH] {
        let changed = compute_store_revision(
            all_roots()
                .into_iter()
                .filter(|entry| entry.path() != omitted.as_bytes()),
        )
        .expect("revision");
        assert_ne!(forward, changed, "omitting {omitted} must change digest");
    }
}

#[test]
fn revision_rejects_duplicates_invalid_reserved_and_nonregular_paths() {
    assert!(matches!(
        compute_store_revision([
            RevisionEntry::regular(LEGACY_EVENT, b"one"),
            RevisionEntry::regular(LEGACY_EVENT, b"two"),
        ]),
        Err(RevisionError::DuplicatePath(_))
    ));
    assert!(matches!(
        compute_store_revision([RevisionEntry::regular("journal/unknown/x", b"x")]),
        Err(RevisionError::InvalidCanonicalPath(_))
    ));
    assert!(matches!(
        compute_store_revision([RevisionEntry::nonregular(JOURNAL_BATCH)]),
        Err(RevisionError::NonRegularCanonicalPath(_))
    ));
    compute_store_revision([RevisionEntry::nonregular("docs/link")])
        .expect("noncanonical nonregular paths are not authoritative");
}

#[test]
fn typed_revision_reference_keeps_legacy_algorithm_distinct() {
    let digest = "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15";
    let generic = StoreRevisionRef::parse("wayjournal.store/blake3-framed-v1", digest)
        .expect("generic revision");
    let legacy =
        StoreRevisionRef::parse("waytask.store/blake3-framed-v1", digest).expect("legacy revision");
    assert_ne!(generic, legacy);
    assert_eq!(legacy.algorithm(), RevisionAlgorithm::WaytaskBlake3FramedV1);
    assert!(StoreRevisionRef::parse("wayjournal.store/blake3-framed-v2", digest).is_err());
    assert!(
        StoreRevisionRef::parse("wayjournal.store/blake3-framed-v1", &digest.to_uppercase())
            .is_err()
    );
}
