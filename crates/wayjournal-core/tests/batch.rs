mod support;

use support::{BATCH_ID, RECORD_A, RECORD_B, note_record, registry};
use wayjournal_core::{
    BatchError, IdempotencyDecision, StoredMember, classify_idempotency, decode_batch_manifest,
    prepare_batch, validate_batch_members, validate_batch_ownership,
};

fn prepared() -> wayjournal_core::PreparedBatch {
    prepare_batch(
        &[
            note_record(RECORD_B, "123e4567-e89b-42d3-a456-426614174001", "B"),
            note_record(RECORD_A, "123e4567-e89b-42d3-a456-426614174000", "A"),
        ],
        "retry-key",
        &registry(),
    )
    .expect("batch should prepare")
}

#[test]
fn prepared_batch_is_sorted_digest_bound_and_matches_golden() {
    let prepared = prepared();
    assert_eq!(
        prepared.manifest_path(),
        format!("journal/batches/{BATCH_ID}.json")
    );
    assert_eq!(
        prepared
            .records()
            .iter()
            .map(wayjournal_core::PreparedRecord::path)
            .collect::<Vec<_>>(),
        vec![
            format!(
                "journal/records/example.notes/123e4567-e89b-42d3-a456-426614174000/{RECORD_A}.json"
            ),
            format!(
                "journal/records/example.notes/123e4567-e89b-42d3-a456-426614174001/{RECORD_B}.json"
            ),
        ]
    );
    assert_eq!(
        prepared.manifest_bytes(),
        include_bytes!("../../../fixtures/wayjournal.batch.v1.json")
    );
    assert_eq!(
        decode_batch_manifest(prepared.manifest_bytes()).expect("manifest decode"),
        *prepared.manifest()
    );
    assert_eq!(
        prepared.manifest().idempotency_key_digest().to_string(),
        "d6c4a90c21434312d0f18d97c404b10ee920fd734b07626797dadcd4c9bf10d9"
    );
    assert_eq!(
        prepared.manifest().request_digest().to_string(),
        "94fd055c016454a93bb8ababa843f5b8f8f2123acb12de69da7b55a00c275119"
    );
    assert_eq!(
        prepared.manifest().members()[0]
            .content_digest()
            .to_string(),
        "5d567d7c343072ec77e6daf0fad3e102588b39616973ddfc7d9184cbc1c9b7df"
    );
    assert!(!String::from_utf8_lossy(prepared.manifest_bytes()).contains("retry-key"));

    let reversed = prepare_batch(
        &[
            note_record(RECORD_A, "123e4567-e89b-42d3-a456-426614174000", "A"),
            note_record(RECORD_B, "123e4567-e89b-42d3-a456-426614174001", "B"),
        ],
        "retry-key",
        &registry(),
    )
    .expect("order-independent batch");
    assert_eq!(prepared.manifest_bytes(), reversed.manifest_bytes());
}

#[test]
fn manifest_decoder_is_closed_canonical_and_identity_bound() {
    let canonical = String::from_utf8(prepared().manifest_bytes().to_vec()).expect("UTF-8");
    let duplicate = canonical.replacen(
        "  \"actor\": \"human:robin\",\n",
        "  \"actor\": \"human:robin\",\n  \"actor\": \"agent:other\",\n",
        1,
    );
    assert!(matches!(
        decode_batch_manifest(duplicate.as_bytes()),
        Err(BatchError::InvalidJson(message)) if message.contains("duplicate JSON object key")
    ));

    let unknown = canonical.replacen(
        "  \"schema\": \"wayjournal.batch/v1\"\n",
        "  \"schema\": \"wayjournal.batch/v1\",\n  \"unknown\": true\n",
        1,
    );
    assert!(matches!(
        decode_batch_manifest(unknown.as_bytes()),
        Err(BatchError::InvalidManifest(_))
    ));

    let compact: serde_json::Value = serde_json::from_slice(canonical.as_bytes()).expect("JSON");
    assert_eq!(
        decode_batch_manifest(&serde_json::to_vec(&compact).expect("compact")),
        Err(BatchError::NonCanonical)
    );

    let mismatched_id = canonical.replacen(RECORD_A, RECORD_B, 1);
    assert!(matches!(
        decode_batch_manifest(mismatched_id.as_bytes()),
        Err(BatchError::InvalidManifest(_) | BatchError::UnsortedMembers)
    ));

    let mismatched_schema_domain = canonical.replacen(
        "\"record_schema\": \"example.notes/v1\"",
        "\"record_schema\": \"other.notes/v1\"",
        1,
    );
    assert!(matches!(
        decode_batch_manifest(mismatched_schema_domain.as_bytes()),
        Err(BatchError::InvalidManifest(_))
    ));
}

#[test]
fn manifest_and_members_reject_missing_extra_duplicate_and_mismatch() {
    let prepared = prepared();
    let members = prepared
        .records()
        .iter()
        .map(|record| StoredMember::new(record.path().as_bytes(), record.bytes()))
        .collect::<Vec<_>>();
    validate_batch_members(prepared.manifest(), &members, &registry())
        .expect("complete members should validate");

    assert!(matches!(
        validate_batch_members(prepared.manifest(), &members[..1], &registry()),
        Err(BatchError::MissingMember { .. })
    ));

    let mut extra = members.clone();
    extra.push(StoredMember::new(b"journal/records/extra", b"{}"));
    assert!(matches!(
        validate_batch_members(prepared.manifest(), &extra, &registry()),
        Err(BatchError::ExtraMember { .. })
    ));

    let mut duplicate = members.clone();
    duplicate.push(members[0]);
    assert!(matches!(
        validate_batch_members(prepared.manifest(), &duplicate, &registry()),
        Err(BatchError::DuplicateStoredPath { .. })
    ));

    let mut replaced = members.clone();
    replaced[0] = StoredMember::new(members[0].path(), members[1].bytes());
    assert!(matches!(
        validate_batch_members(prepared.manifest(), &replaced, &registry()),
        Err(BatchError::MemberIdentityMismatch { .. } | BatchError::MemberDigestMismatch { .. })
    ));
}

#[test]
fn ownership_requires_every_generic_record_exactly_once() {
    let one = prepared();
    let records = one
        .records()
        .iter()
        .map(|record| StoredMember::new(record.path().as_bytes(), record.bytes()))
        .collect::<Vec<_>>();

    validate_batch_ownership(&records, &[one.manifest()], &registry())
        .expect("single manifest should own every record");
    assert!(matches!(
        validate_batch_ownership(&records, &[], &registry()),
        Err(BatchError::UnownedRecord { .. })
    ));
    assert!(matches!(
        validate_batch_ownership(&records, &[one.manifest(), one.manifest()], &registry()),
        Err(BatchError::MultiplyOwnedRecord { .. })
    ));
}

#[test]
fn idempotency_is_actor_scoped_and_detects_replay_conflicts() {
    let one = prepared();
    let manifest = one.manifest();
    assert!(matches!(
        classify_idempotency(
            [manifest],
            manifest.actor(),
            "retry-key",
            manifest.request_digest()
        ),
        Ok(IdempotencyDecision::Replay(found)) if found == manifest
    ));
    assert!(matches!(
        classify_idempotency(
            [manifest],
            manifest.actor(),
            "different-key",
            manifest.request_digest()
        ),
        Ok(IdempotencyDecision::New)
    ));

    let different = prepare_batch(
        &[note_record(
            "01913f1d-8e2a-7c30-8f4a-426614174003",
            "123e4567-e89b-42d3-a456-426614174002",
            "different",
        )],
        "retry-key",
        &registry(),
    )
    .expect("second batch");
    assert!(matches!(
        classify_idempotency(
            [manifest],
            manifest.actor(),
            "retry-key",
            different.manifest().request_digest()
        ),
        Err(BatchError::IdempotencyRequestMismatch { .. })
    ));
    assert!(matches!(
        classify_idempotency(
            [manifest, different.manifest()],
            manifest.actor(),
            "retry-key",
            manifest.request_digest()
        ),
        Err(BatchError::DuplicateIdempotencyOwnership { .. })
    ));
}

#[test]
fn batch_rejects_mixed_actor_batch_and_duplicate_record_id() {
    let mut mixed_batch = note_record(RECORD_B, "123e4567-e89b-42d3-a456-426614174001", "B");
    mixed_batch.batch_id = "01913f1d-8e2a-7c30-8f4a-426614174100"
        .parse()
        .expect("batch id");
    assert!(matches!(
        prepare_batch(
            &[
                note_record(RECORD_A, "123e4567-e89b-42d3-a456-426614174000", "A"),
                mixed_batch,
            ],
            "key",
            &registry()
        ),
        Err(BatchError::MixedBatchId { .. })
    ));

    let mut mixed_actor = note_record(RECORD_B, "123e4567-e89b-42d3-a456-426614174001", "B");
    mixed_actor.actor = wayjournal_core::ActorId::parse("agent:other").expect("actor");
    assert!(matches!(
        prepare_batch(
            &[
                note_record(RECORD_A, "123e4567-e89b-42d3-a456-426614174000", "A"),
                mixed_actor,
            ],
            "key",
            &registry()
        ),
        Err(BatchError::MixedActor { .. })
    ));

    assert!(matches!(
        prepare_batch(
            &[
                note_record(RECORD_A, "123e4567-e89b-42d3-a456-426614174000", "A"),
                note_record(RECORD_A, "123e4567-e89b-42d3-a456-426614174001", "B"),
            ],
            "key",
            &registry()
        ),
        Err(BatchError::DuplicateRecordId { .. })
    ));
}
