use serde_json::json;
use wayjournal_core::{
    ActorId, BatchId, EntityId, GenesisError, IdentityRelation, LogicalStoreId, Record,
    RecordTimestamp, StoreUuid, StoredMember, classify_logical_identity, genesis_fingerprint,
    prepare_batch, validate_store_identity, wayjournal_domain_registry,
};

const STORE_UUID: &str = "01913f1d-8e2a-7c30-8f4a-426614174010";
const GENESIS_RECORD: &str = "01913f1d-8e2a-7c30-8f4a-426614174011";
const FIRST_BATCH: &str = "01913f1d-8e2a-7c30-8f4a-426614174012";

fn record(kind: &str, record_id: &str, batch_id: &str, payload: serde_json::Value) -> Record {
    Record {
        record_schema: "wayjournal.identity/v1".parse().expect("schema"),
        domain: "wayjournal.identity".parse().expect("domain"),
        kind: kind.parse().expect("kind"),
        record_id: record_id.parse().expect("record"),
        entity_id: STORE_UUID.parse::<EntityId>().expect("entity"),
        batch_id: batch_id.parse::<BatchId>().expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z"
            .parse::<RecordTimestamp>()
            .expect("timestamp"),
        recorded_at: "2026-08-12T13:00:01Z"
            .parse::<RecordTimestamp>()
            .expect("timestamp"),
        parents: Vec::new(),
        payload,
    }
}

fn genesis(record_id: &str, batch_id: &str) -> Record {
    record(
        "store.genesis",
        record_id,
        batch_id,
        json!({"store_kind": "wayjournal.personal", "store_uuid": STORE_UUID}),
    )
}

fn identity_for(
    records: &[Record],
    key: &str,
) -> Result<wayjournal_core::StoreIdentity, GenesisError> {
    let registry = wayjournal_domain_registry().expect("built-in registry");
    let prepared = prepare_batch(records, key, &registry).expect("prepare");
    let members = prepared
        .records()
        .iter()
        .map(|item| StoredMember::new(item.path().as_bytes(), item.bytes()))
        .collect::<Vec<_>>();
    validate_store_identity(&[prepared.manifest().clone()], &members, &registry)
        .map(|identity| identity.expect("initialized"))
}

#[test]
fn genesis_golden_has_path_byte_bound_fingerprint_and_logical_identity() {
    let registry = wayjournal_domain_registry().expect("registry");
    let record = genesis(GENESIS_RECORD, FIRST_BATCH);
    let prepared = prepare_batch(&[record], "genesis", &registry).expect("prepare");
    assert_eq!(
        prepared.records()[0].bytes(),
        include_bytes!("../../../fixtures/wayjournal.identity.genesis.v1.json")
    );
    let members = [StoredMember::new(
        prepared.records()[0].path().as_bytes(),
        prepared.records()[0].bytes(),
    )];
    let identity = validate_store_identity(&[prepared.manifest().clone()], &members, &registry)
        .expect("valid genesis")
        .expect("initialized identity");
    assert_eq!(identity.logical_id().store_uuid().to_string(), STORE_UUID);
    assert_eq!(
        identity.logical_id().genesis_fingerprint(),
        genesis_fingerprint(
            prepared.records()[0].path().as_bytes(),
            prepared.records()[0].bytes()
        )
    );
    assert_eq!(
        identity.logical_id().genesis_fingerprint().to_string(),
        "7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447"
    );
    assert!(identity.fork_provenance().is_none());
}

#[test]
fn logical_fork_mints_identity_and_preserves_exact_parent_provenance() {
    let parent = identity_for(&[genesis(GENESIS_RECORD, FIRST_BATCH)], "parent").expect("parent");
    let child_uuid = "01913f1d-8e2a-7c30-8f4a-426614174020";
    let child = Record {
        entity_id: child_uuid.parse().expect("entity"),
        payload: json!({
            "forked_from": {
                "parent": parent.logical_id(),
                "parent_revision": {
                    "algorithm": "wayjournal.store/blake3-framed-v1",
                    "digest": "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
                }
            },
            "store_kind": "wayjournal.personal",
            "store_uuid": child_uuid
        }),
        ..genesis(
            "01913f1d-8e2a-7c30-8f4a-426614174021",
            "01913f1d-8e2a-7c30-8f4a-426614174022",
        )
    };
    let fork = identity_for(&[child], "fork").expect("valid fork");
    assert_ne!(
        fork.logical_id().store_uuid(),
        parent.logical_id().store_uuid()
    );
    assert_eq!(
        fork.fork_provenance().expect("provenance").parent,
        *parent.logical_id()
    );
    assert_eq!(
        fork.fork_provenance()
            .expect("provenance")
            .parent_revision
            .algorithm(),
        wayjournal_core::RevisionAlgorithm::WayjournalBlake3FramedV1
    );
}

#[test]
fn genesis_is_exactly_once_and_in_the_first_generic_batch() {
    let registry = wayjournal_domain_registry().expect("registry");
    let first_non_genesis = Record {
        record_schema: "wayjournal.profile/v1".parse().expect("schema"),
        domain: "wayjournal.profile".parse().expect("domain"),
        kind: "profile.display_name.set".parse().expect("kind"),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174001".parse().expect("id"),
        entity_id: STORE_UUID.parse().expect("entity"),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174002"
            .parse()
            .expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: Vec::new(),
        payload: json!({"value": "before genesis"}),
    };
    let first = prepare_batch(&[first_non_genesis], "first", &registry).expect("first");
    let second = prepare_batch(&[genesis(GENESIS_RECORD, FIRST_BATCH)], "second", &registry)
        .expect("second");
    let mut members = Vec::new();
    for batch in [&first, &second] {
        members.extend(
            batch
                .records()
                .iter()
                .map(|item| StoredMember::new(item.path().as_bytes(), item.bytes())),
        );
    }
    assert_eq!(
        validate_store_identity(
            &[first.manifest().clone(), second.manifest().clone()],
            &members,
            &registry,
        ),
        Err(GenesisError::GenesisNotFirst)
    );

    let duplicate = genesis("01913f1d-8e2a-7c30-8f4a-426614174013", FIRST_BATCH);
    assert_eq!(
        identity_for(
            &[genesis(GENESIS_RECORD, FIRST_BATCH), duplicate],
            "duplicate"
        ),
        Err(GenesisError::DuplicateGenesis)
    );

    let mixed_profile = Record {
        batch_id: FIRST_BATCH.parse().expect("batch"),
        ..first.records()[0].record().clone()
    };
    assert_eq!(
        identity_for(
            &[genesis(GENESIS_RECORD, FIRST_BATCH), mixed_profile],
            "mixed-first",
        ),
        Err(GenesisError::GenesisNotFirst)
    );

    let profile_only = prepare_batch(
        &[Record {
            batch_id: FIRST_BATCH.parse().expect("batch"),
            ..first.records()[0].record().clone()
        }],
        "missing",
        &registry,
    )
    .expect("profile batch");
    let profile_members = [StoredMember::new(
        profile_only.records()[0].path().as_bytes(),
        profile_only.records()[0].bytes(),
    )];
    assert_eq!(
        validate_store_identity(
            &[profile_only.manifest().clone()],
            &profile_members,
            &registry
        ),
        Err(GenesisError::MissingGenesis)
    );
}

#[test]
fn identity_validation_rejects_incomplete_fake_path_and_nested_duplicate_payload() {
    let registry = wayjournal_domain_registry().expect("registry");
    let prepared = prepare_batch(
        &[genesis(GENESIS_RECORD, FIRST_BATCH)],
        "hostile",
        &registry,
    )
    .expect("prepare");
    assert_eq!(
        validate_store_identity(&[prepared.manifest().clone()], &[], &registry),
        Err(GenesisError::IncompleteMembers)
    );
    let fake = [StoredMember::new(
        b"journal/records/wayjournal.identity/01913f1d-8e2a-7c30-8f4a-426614174010/01913f1d-8e2a-7c30-8f4a-426614174099.json",
        prepared.records()[0].bytes(),
    )];
    assert!(validate_store_identity(&[prepared.manifest().clone()], &fake, &registry).is_err());
    let duplicate = String::from_utf8(prepared.records()[0].bytes().to_vec())
        .expect("utf8")
        .replacen(
            "    \"store_uuid\":",
            "    \"store_uuid\": \"01913f1d-8e2a-7c30-8f4a-426614174010\",\n    \"store_uuid\":",
            1,
        );
    assert!(wayjournal_core::decode_record(duplicate.as_bytes(), &registry).is_err());
}

#[test]
fn replica_collision_and_fork_rules_use_only_immutable_identity() {
    let original = identity_for(&[genesis(GENESIS_RECORD, FIRST_BATCH)], "one").expect("identity");
    assert_eq!(
        classify_logical_identity(original.logical_id(), original.logical_id()),
        IdentityRelation::Replica
    );

    let changed = identity_for(
        &[record(
            "store.genesis",
            GENESIS_RECORD,
            FIRST_BATCH,
            json!({"store_kind": "wayjournal.catalog", "store_uuid": STORE_UUID}),
        )],
        "two",
    )
    .expect("changed identity");
    assert_eq!(
        classify_logical_identity(original.logical_id(), changed.logical_id()),
        IdentityRelation::UuidCollision
    );

    let other_uuid: StoreUuid = "01913f1d-8e2a-7c30-8f4a-426614174020"
        .parse()
        .expect("uuid");
    let other = LogicalStoreId::new(other_uuid, original.logical_id().genesis_fingerprint());
    assert_eq!(
        classify_logical_identity(original.logical_id(), &other),
        IdentityRelation::Distinct
    );

    let invalid_fork = record(
        "store.genesis",
        GENESIS_RECORD,
        FIRST_BATCH,
        json!({
            "forked_from": {
                "parent": original.logical_id(),
                "parent_revision": {
                    "algorithm": "wayjournal.store/blake3-framed-v1",
                    "digest": "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
                }
            },
            "store_kind": "wayjournal.personal",
            "store_uuid": STORE_UUID
        }),
    );
    let registry = wayjournal_domain_registry().expect("registry");
    assert!(prepare_batch(&[invalid_fork], "fork", &registry).is_err());
}

#[test]
fn identity_derivation_is_order_independent_and_rejects_duplicate_or_tampered_ownership() {
    let registry = wayjournal_domain_registry().expect("registry");
    let genesis_batch = prepare_batch(
        &[genesis(GENESIS_RECORD, FIRST_BATCH)],
        "identity-order",
        &registry,
    )
    .expect("genesis");
    let profile = Record {
        record_schema: "wayjournal.profile/v1".parse().expect("schema"),
        domain: "wayjournal.profile".parse().expect("domain"),
        kind: "profile.display_name.set".parse().expect("kind"),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174021".parse().expect("id"),
        entity_id: STORE_UUID.parse().expect("entity"),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174022"
            .parse()
            .expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: vec![],
        payload: json!({"value":"Robin"}),
    };
    let profile_batch = prepare_batch(&[profile], "identity-profile", &registry).expect("profile");
    let members = [
        StoredMember::new(
            genesis_batch.records()[0].path().as_bytes(),
            genesis_batch.records()[0].bytes(),
        ),
        StoredMember::new(
            profile_batch.records()[0].path().as_bytes(),
            profile_batch.records()[0].bytes(),
        ),
    ];
    let forward = validate_store_identity(
        &[
            genesis_batch.manifest().clone(),
            profile_batch.manifest().clone(),
        ],
        &members,
        &registry,
    )
    .expect("forward");
    let reverse = validate_store_identity(
        &[
            profile_batch.manifest().clone(),
            genesis_batch.manifest().clone(),
        ],
        &members,
        &registry,
    )
    .expect("reverse manifests");
    let reversed_members = [members[1], members[0]];
    let member_reverse = validate_store_identity(
        &[
            genesis_batch.manifest().clone(),
            profile_batch.manifest().clone(),
        ],
        &reversed_members,
        &registry,
    )
    .expect("reverse members");
    assert_eq!(forward, reverse);
    assert_eq!(forward, member_reverse);
    assert_eq!(
        validate_store_identity(
            &[
                genesis_batch.manifest().clone(),
                genesis_batch.manifest().clone()
            ],
            &members[..1],
            &registry
        ),
        Err(GenesisError::IncompleteMembers)
    );
    let mut tampered = genesis_batch.records()[0].bytes().to_vec();
    let index = tampered
        .iter()
        .position(|byte| *byte == b'r')
        .expect("byte");
    tampered[index] = b's';
    assert!(
        validate_store_identity(
            &[genesis_batch.manifest().clone()],
            &[StoredMember::new(
                genesis_batch.records()[0].path().as_bytes(),
                &tampered
            )],
            &registry,
        )
        .is_err()
    );
}
