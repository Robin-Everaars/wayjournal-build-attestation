use wayjournal_core::{
    RevisionEntry, RevisionError, StoreRevisionAccumulator, compute_store_revision,
};

#[test]
fn public_streaming_accumulator_matches_owned_revision_without_retaining_bytes() {
    let paths = [
        b"batches/01913f1d-8e2a-7c30-8f4a-426614174012.json".as_slice(),
        b"events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json"
            .as_slice(),
    ];
    let expected = compute_store_revision([
        RevisionEntry::regular(paths[0], b"batch"),
        RevisionEntry::regular(paths[1], b"event"),
    ])
    .expect("owned revision");

    let mut accumulator = StoreRevisionAccumulator::new();
    for (path, content) in [
        (paths[0], b"batch".as_slice()),
        (paths[1], b"event".as_slice()),
    ] {
        let bytes = content.to_vec();
        accumulator
            .push(path, &bytes)
            .expect("push borrowed canonical bytes");
    }

    assert_eq!(accumulator.finish(), expected);
}

#[test]
fn public_streaming_accumulator_rejects_invalid_duplicate_and_unordered_paths() {
    let later =
        b"events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174002.json";
    let earlier = b"batches/01913f1d-8e2a-7c30-8f4a-426614174012.json";

    let mut invalid = StoreRevisionAccumulator::new();
    assert!(matches!(
        invalid.push(b"README.md", b"ignored elsewhere"),
        Err(RevisionError::InvalidCanonicalPath(_))
    ));

    let mut duplicate = StoreRevisionAccumulator::new();
    duplicate.push(later, b"one").expect("first entry");
    assert!(matches!(
        duplicate.push(later, b"two"),
        Err(RevisionError::DuplicatePath(_))
    ));

    let mut unordered = StoreRevisionAccumulator::new();
    unordered.push(later, b"one").expect("later entry");
    assert!(matches!(
        unordered.push(earlier, b"two"),
        Err(RevisionError::NonCanonicalOrder(_))
    ));
}
