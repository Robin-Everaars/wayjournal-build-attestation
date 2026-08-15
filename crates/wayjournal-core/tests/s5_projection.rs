use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde_json::{Value, json};
use wayjournal_core::{
    ActorId, ContradictionRef, LegacyEntry, LegacyStoreAdapter, LocalTrustBinding, LogicalStoreId,
    MAX_PROJECTION_BYTES, MAX_PROOFS, MAX_VECTOR_STORES, PROOF_VECTOR_SCHEMA_V1, ProofError,
    ProofVector, QualifiedEntityRef, REVISION_ALGORITHM_V1, REVISION_VECTOR_SCHEMA_V1, Record,
    RevisionVector, RevisionVectorEntry, Store, StoreRevisionRef, StoreUuid,
    VERIFIED_PROOF_SCHEMA_V1, decode_proof_vector, decode_revision_vector, decode_verified_proof,
    encode_proof_vector, encode_revision_vector, encode_verified_proof, prepare_batch,
    wayjournal_domain_registry,
};

const STORE_UUID: &str = "01913f1d-8e2a-7c30-8f4a-426614174010";
const STORE_UUID_2: &str = "01913f1d-8e2a-7c30-8f4a-426614174020";
const GENESIS_FP: &str = "7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447";
const REVISION_DIGEST: &str = "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15";
const TRUST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const FIXTURE_PROOF_ID: &str = "99bf2caf35a7b5e12d6b82ae2948ec627098e9a11152533cfdfcd711fd214922";
const RECORD_ID: &str = "01913f1d-8e2a-7c30-8f4a-426614174011";
const ENTITY_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
const OBSERVED_AT: &str = "2026-08-12T13:00:01Z";

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
            std::env::temp_dir().join(format!("wayjournal-s5-projection-{}", uuid::Uuid::now_v7()));
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

fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("JSON");
    bytes.push(b'\n');
    bytes
}

fn decode_hex(input: &str) -> Vec<u8> {
    let input = input.trim();
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex UTF-8"), 16).expect("hex byte")
        })
        .collect()
}

fn proof_preimage(observed_at: &str) -> Vec<u8> {
    let fields = [
        VERIFIED_PROOF_SCHEMA_V1.as_bytes(),
        STORE_UUID.as_bytes(),
        GENESIS_FP.as_bytes(),
        b"wayjournal.profile",
        ENTITY_ID.as_bytes(),
        RECORD_ID.as_bytes(),
        REVISION_ALGORITHM_V1.as_bytes(),
        REVISION_DIGEST.as_bytes(),
        TRUST.as_bytes(),
        observed_at.as_bytes(),
    ];
    let mut bytes = b"wayjournal-proof-v1\0".to_vec();
    for field in fields {
        bytes.extend_from_slice(
            &u64::try_from(field.len())
                .expect("bounded fixture")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(field);
    }
    bytes
}

fn fixture_proof_value() -> Value {
    json!({
        "local_trust_binding": TRUST,
        "observed_at": OBSERVED_AT,
        "proof_id": FIXTURE_PROOF_ID,
        "record_id": RECORD_ID,
        "schema": VERIFIED_PROOF_SCHEMA_V1,
        "source_revision": {
            "algorithm": REVISION_ALGORITHM_V1,
            "digest": REVISION_DIGEST
        },
        "subject": {
            "domain": "wayjournal.profile",
            "entity_id": ENTITY_ID,
            "store": {
                "genesis_fingerprint": GENESIS_FP,
                "store_uuid": STORE_UUID
            }
        }
    })
}

fn fixture_proof_bytes() -> Vec<u8> {
    include_bytes!("../../../fixtures/wayjournal.verified-proof.v1.json").to_vec()
}

fn store_id(uuid: &str, digest: &str) -> LogicalStoreId {
    LogicalStoreId::new(
        uuid.parse::<StoreUuid>().expect("store UUID"),
        digest.parse().expect("genesis fingerprint"),
    )
}

fn revision(digest: &str) -> StoreRevisionRef {
    StoreRevisionRef::parse(REVISION_ALGORITHM_V1, digest).expect("revision")
}

#[test]
fn proof_preimage_fixture_and_digest_are_exact() {
    let checked = decode_hex(include_str!(
        "../../../fixtures/wayjournal.verified-proof.v1.preimage.hex"
    ));
    let independently_framed = proof_preimage(OBSERVED_AT);
    assert_eq!(checked, independently_framed);
    assert_eq!(checked.len(), 499);
    assert_eq!(blake3::hash(&checked).to_hex().as_str(), FIXTURE_PROOF_ID);

    let bytes = fixture_proof_bytes();
    assert_eq!(bytes, canonical(&fixture_proof_value()));
    let proof = decode_verified_proof(&bytes).expect("checked proof");
    assert_eq!(proof.proof_id().to_string(), FIXTURE_PROOF_ID);
    assert_eq!(proof.subject().store, store_id(STORE_UUID, GENESIS_FP));
    assert_eq!(proof.source_revision(), revision(REVISION_DIGEST));
    assert_eq!(proof.local_trust_binding().as_digest().to_string(), TRUST);
    assert_eq!(proof.observed_at().to_string(), OBSERVED_AT);
    assert_eq!(encode_verified_proof(&proof).expect("encode"), bytes);

    let contradiction = ContradictionRef::new(
        proof.proof_id(),
        proof.subject().store.clone(),
        proof.source_revision(),
    );
    assert_eq!(contradiction.proof_id(), proof.proof_id());
    assert_eq!(contradiction.source_store(), &proof.subject().store);
    assert_eq!(contradiction.source_revision(), proof.source_revision());
}

#[test]
fn verified_proof_codec_rejects_open_duplicate_noncanonical_float_and_changed_preimages() {
    let canonical_bytes = fixture_proof_bytes();
    let text = String::from_utf8(canonical_bytes.clone()).expect("fixture text");
    let duplicate = text.replacen(
        "  \"proof_id\":",
        &format!("  \"proof_id\": \"{FIXTURE_PROOF_ID}\",\n  \"proof_id\":"),
        1,
    );
    assert!(decode_verified_proof(duplicate.as_bytes()).is_err());

    let mut unknown = fixture_proof_value();
    unknown["unknown"] = json!(true);
    assert!(decode_verified_proof(&canonical(&unknown)).is_err());
    let mut nested_unknown = fixture_proof_value();
    nested_unknown["subject"]["store"]["unknown"] = json!(true);
    assert!(decode_verified_proof(&canonical(&nested_unknown)).is_err());

    let compact = serde_json::to_vec(&fixture_proof_value()).expect("compact");
    assert!(decode_verified_proof(&compact).is_err());
    let trailing = [canonical_bytes.as_slice(), b" "].concat();
    assert!(decode_verified_proof(&trailing).is_err());

    let float = text.replacen("{\n", "{\n  \"floating\": 1.5,\n", 1);
    assert!(decode_verified_proof(float.as_bytes()).is_err());

    let mut missing = fixture_proof_value();
    missing
        .as_object_mut()
        .expect("proof object")
        .remove("record_id");
    assert!(decode_verified_proof(&canonical(&missing)).is_err());
    let mut schema = fixture_proof_value();
    schema["schema"] = json!("wayjournal.verified-proof/v2");
    assert!(decode_verified_proof(&canonical(&schema)).is_err());
    let mut algorithm = fixture_proof_value();
    algorithm["source_revision"]["algorithm"] = json!("example.unknown/v1");
    assert!(decode_verified_proof(&canonical(&algorithm)).is_err());

    let mutations = [
        (vec!["proof_id"], "0".repeat(64)),
        (
            vec!["record_id"],
            "01913f1d-8e2a-7c30-8f4a-426614174012".to_owned(),
        ),
        (vec!["source_revision", "digest"], "4".repeat(64)),
        (vec!["local_trust_binding"], "e".repeat(64)),
        (vec!["observed_at"], "2026-08-12T13:00:02Z".to_owned()),
        (vec!["subject", "domain"], "wayjournal.catalog".to_owned()),
        (
            vec!["subject", "entity_id"],
            "123e4567-e89b-42d3-a456-426614174001".to_owned(),
        ),
        (
            vec!["subject", "store", "store_uuid"],
            STORE_UUID_2.to_owned(),
        ),
        (
            vec!["subject", "store", "genesis_fingerprint"],
            "5".repeat(64),
        ),
    ];
    for (path, replacement) in mutations {
        let mut value = fixture_proof_value();
        let mut cursor = &mut value;
        for component in &path[..path.len() - 1] {
            cursor = &mut cursor[*component];
        }
        cursor[path[path.len() - 1]] = Value::String(replacement);
        assert!(
            decode_verified_proof(&canonical(&value)).is_err(),
            "changed preimage field {path:?}"
        );
    }
}

#[test]
fn revision_vector_wire_is_closed_ordered_unique_and_bounded() {
    let first =
        RevisionVectorEntry::new(store_id(STORE_UUID, GENESIS_FP), revision(REVISION_DIGEST));
    let second = RevisionVectorEntry::new(
        store_id(STORE_UUID_2, &"4".repeat(64)),
        revision(&"5".repeat(64)),
    );
    let vector = RevisionVector::new(vec![first.clone(), second.clone()]).expect("ordered");
    let bytes = encode_revision_vector(&vector).expect("encode");
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).expect("JSON"),
        json!({
            "entries": [
                {
                    "revision": {"algorithm": REVISION_ALGORITHM_V1, "digest": REVISION_DIGEST},
                    "store": {"genesis_fingerprint": GENESIS_FP, "store_uuid": STORE_UUID}
                },
                {
                    "revision": {"algorithm": REVISION_ALGORITHM_V1, "digest": "5".repeat(64)},
                    "store": {"genesis_fingerprint": "4".repeat(64), "store_uuid": STORE_UUID_2}
                }
            ],
            "schema": REVISION_VECTOR_SCHEMA_V1
        })
    );
    assert_eq!(decode_revision_vector(&bytes).expect("decode"), vector);
    assert!(RevisionVector::new(vec![second.clone(), first.clone()]).is_err());
    assert!(RevisionVector::new(vec![first.clone(), first.clone()]).is_err());

    let mut unsorted = serde_json::from_slice::<Value>(&bytes).expect("value");
    unsorted["entries"]
        .as_array_mut()
        .expect("entries")
        .reverse();
    assert!(decode_revision_vector(&canonical(&unsorted)).is_err());

    let mut same_property = serde_json::from_slice::<Value>(&bytes).expect("value");
    same_property["entries"][1]["store"] = same_property["entries"][0]["store"].clone();
    same_property["entries"][1]["revision"]["digest"] = json!("6".repeat(64));
    assert!(decode_revision_vector(&canonical(&same_property)).is_err());

    let mut unknown = serde_json::from_slice::<Value>(&bytes).expect("value");
    unknown["entries"][0]["unknown"] = json!(false);
    assert!(decode_revision_vector(&canonical(&unknown)).is_err());
    let mut root_unknown = serde_json::from_slice::<Value>(&bytes).expect("value");
    root_unknown["unknown"] = json!(false);
    assert!(decode_revision_vector(&canonical(&root_unknown)).is_err());
    let mut missing = serde_json::from_slice::<Value>(&bytes).expect("value");
    missing.as_object_mut().expect("root").remove("entries");
    assert!(decode_revision_vector(&canonical(&missing)).is_err());
    let mut schema = serde_json::from_slice::<Value>(&bytes).expect("value");
    schema["schema"] = json!("wayjournal.revision-vector/v2");
    assert!(decode_revision_vector(&canonical(&schema)).is_err());
    let mut unknown_algorithm = serde_json::from_slice::<Value>(&bytes).expect("value");
    unknown_algorithm["entries"][0]["revision"]["algorithm"] = json!("unknown/v1");
    assert!(decode_revision_vector(&canonical(&unknown_algorithm)).is_err());

    let duplicate_key = String::from_utf8(bytes.clone()).expect("text").replacen(
        "  \"schema\":",
        &format!("  \"schema\": \"{REVISION_VECTOR_SCHEMA_V1}\",\n  \"schema\":"),
        1,
    );
    assert!(decode_revision_vector(duplicate_key.as_bytes()).is_err());
    let float = String::from_utf8(bytes.clone()).expect("text").replacen(
        "{\n",
        "{\n  \"float\": 1.5,\n",
        1,
    );
    assert!(decode_revision_vector(float.as_bytes()).is_err());
    assert!(decode_revision_vector(&serde_json::to_vec(&vector.entries().len()).unwrap()).is_err());
    assert!(decode_revision_vector(&serde_json::to_vec(&root_unknown).unwrap()).is_err());

    let entry = serde_json::from_slice::<Value>(&bytes).expect("value")["entries"][0].clone();
    let too_many = canonical(&json!({
        "entries": vec![entry; MAX_VECTOR_STORES + 1],
        "schema": REVISION_VECTOR_SCHEMA_V1
    }));
    assert!(decode_revision_vector(&too_many).is_err());
    assert!(RevisionVector::new(vec![first; MAX_VECTOR_STORES + 1]).is_err());
}

fn proof_with_observed_at(observed_at: &str) -> Value {
    let mut value = fixture_proof_value();
    value["observed_at"] = json!(observed_at);
    value["proof_id"] = json!(
        blake3::hash(&proof_preimage(observed_at))
            .to_hex()
            .to_string()
    );
    value
}

#[test]
fn proof_vector_wire_is_closed_ordered_unique_hash_checked_and_bounded() {
    let first = decode_verified_proof(&canonical(&proof_with_observed_at(OBSERVED_AT)))
        .expect("first proof");
    let second = decode_verified_proof(&canonical(&proof_with_observed_at("2026-08-12T13:00:02Z")))
        .expect("second proof");
    let mut proofs = vec![first.clone(), second.clone()];
    proofs.sort_by_key(wayjournal_core::VerifiedProof::proof_id);
    let vector = ProofVector::new(proofs.clone()).expect("ordered vector");
    let bytes = encode_proof_vector(&vector).expect("encode");
    let root: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(root["schema"], PROOF_VECTOR_SCHEMA_V1);
    assert_eq!(root["proofs"].as_array().expect("proofs").len(), 2);
    assert_eq!(decode_proof_vector(&bytes).expect("decode"), vector);

    let mut reversed = proofs.clone();
    reversed.reverse();
    assert!(ProofVector::new(reversed).is_err());
    assert!(ProofVector::new(vec![first.clone(), first.clone()]).is_err());

    let mut unsorted = root.clone();
    unsorted["proofs"].as_array_mut().expect("proofs").reverse();
    assert!(decode_proof_vector(&canonical(&unsorted)).is_err());
    let mut duplicate_property = root.clone();
    duplicate_property["proofs"][1]["proof_id"] =
        duplicate_property["proofs"][0]["proof_id"].clone();
    assert!(decode_proof_vector(&canonical(&duplicate_property)).is_err());
    let mut unknown = root.clone();
    unknown["proofs"][0]["extra"] = json!(true);
    assert!(decode_proof_vector(&canonical(&unknown)).is_err());
    let mut root_unknown = root.clone();
    root_unknown["extra"] = json!(true);
    assert!(decode_proof_vector(&canonical(&root_unknown)).is_err());
    let mut missing = root.clone();
    missing.as_object_mut().expect("root").remove("proofs");
    assert!(decode_proof_vector(&canonical(&missing)).is_err());
    let mut schema = root.clone();
    schema["schema"] = json!("wayjournal.proof-vector/v2");
    assert!(decode_proof_vector(&canonical(&schema)).is_err());
    let duplicate_key = String::from_utf8(bytes.clone()).expect("text").replacen(
        "  \"schema\":",
        &format!("  \"schema\": \"{PROOF_VECTOR_SCHEMA_V1}\",\n  \"schema\":"),
        1,
    );
    assert!(decode_proof_vector(duplicate_key.as_bytes()).is_err());
    let float = String::from_utf8(bytes.clone()).expect("text").replacen(
        "{\n",
        "{\n  \"float\": 1.5,\n",
        1,
    );
    assert!(decode_proof_vector(float.as_bytes()).is_err());
    assert!(decode_proof_vector(&serde_json::to_vec(&root_unknown).unwrap()).is_err());

    let proof = root["proofs"][0].clone();
    let too_many = canonical(&json!({
        "proofs": vec![proof; MAX_PROOFS + 1],
        "schema": PROOF_VECTOR_SCHEMA_V1
    }));
    assert!(decode_proof_vector(&too_many).is_err());
    assert!(ProofVector::new(vec![first; MAX_PROOFS + 1]).is_err());
}

#[test]
fn every_projection_decoder_rejects_limit_plus_one_before_parsing() {
    let oversized = vec![b' '; MAX_PROJECTION_BYTES + 1];
    assert!(decode_revision_vector(&oversized).is_err());
    assert!(decode_verified_proof(&oversized).is_err());
    assert!(decode_proof_vector(&oversized).is_err());
}

fn record(domain: &str, kind: &str, record_id: &str, batch_id: &str, payload: Value) -> Record {
    Record {
        record_schema: format!("{domain}/v1").parse().expect("schema"),
        domain: domain.parse().expect("domain"),
        kind: kind.parse().expect("kind"),
        record_id: record_id.parse().expect("record id"),
        entity_id: STORE_UUID.parse().expect("entity id"),
        batch_id: batch_id.parse().expect("batch id"),
        actor: ActorId::parse("human:projection-test").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("timestamp"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("timestamp"),
        parents: Vec::new(),
        payload,
    }
}

fn genesis() -> Record {
    record(
        "wayjournal.identity",
        "store.genesis",
        "01913f1d-8e2a-7c30-8f4a-426614174011",
        "01913f1d-8e2a-7c30-8f4a-426614174012",
        json!({"store_kind": "wayjournal.personal", "store_uuid": STORE_UUID}),
    )
}

fn write_checkpoint(root: &Path, store: &LogicalStoreId, revision: StoreRevisionRef, trust: &str) {
    let bytes = canonical(&json!({
        "accepted_commit": "0123456789abcdef0123456789abcdef01234567",
        "accepted_git_object_format": "sha1",
        "accepted_revision_algorithm": revision.algorithm().as_str(),
        "accepted_revision_digest": revision.digest().to_string(),
        "genesis_fingerprint": store.genesis_fingerprint().to_string(),
        "local_trust_binding": trust,
        "remote_locator": "file:///srv/git/approved.git",
        "remote_ref": "refs/heads/approved",
        "schema": "wayjournal.admission-checkpoint/v1",
        "store_uuid": store.store_uuid().to_string()
    }));
    let path = root.join(".wayjournal-local/checkpoints/admission-v1.json");
    fs::write(&path, bytes).expect("checkpoint");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("checkpoint mode");
}

struct StoreFixture {
    directory: TestDir,
    store: Store,
    logical_store: LogicalStoreId,
    profile_id: wayjournal_core::RecordId,
    catalog_id: wayjournal_core::RecordId,
}

fn initialized_store() -> StoreFixture {
    let directory = TestDir::new();
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(directory.path(), registry, Arc::new(NoLegacy)).expect("store");
    let genesis_batch =
        prepare_batch(&[genesis()], "projection-genesis", &registry).expect("batch");
    store
        .append(&genesis_batch, store.read().expect("empty").revision())
        .expect("genesis append");
    let initialized = store.read().expect("initialized");
    let logical_store = initialized
        .identity()
        .expect("identity")
        .logical_id()
        .clone();
    let profile_id: wayjournal_core::RecordId = "01913f1d-8e2a-7c30-8f4a-426614174021"
        .parse()
        .expect("profile id");
    let catalog_id: wayjournal_core::RecordId = "01913f1d-8e2a-7c30-8f4a-426614174022"
        .parse()
        .expect("catalog id");
    let advisory = [
        record(
            "wayjournal.profile",
            "profile.remote.add",
            &profile_id.to_string(),
            "01913f1d-8e2a-7c30-8f4a-426614174030",
            json!({
                "key": "authority-looking",
                "value": {"locator": "ssh://unapproved.invalid/repo", "requires_identity_validation": true}
            }),
        ),
        record(
            "wayjournal.catalog",
            "catalog.remote.add",
            &catalog_id.to_string(),
            "01913f1d-8e2a-7c30-8f4a-426614174030",
            json!({
                "key": "authority-looking",
                "target": logical_store,
                "value": {"locator": "https://unapproved.invalid/repo", "requires_identity_validation": true}
            }),
        ),
    ];
    let advisory_batch =
        prepare_batch(&advisory, "projection-advisory", &registry).expect("advisory batch");
    store
        .append(&advisory_batch, initialized.revision())
        .expect("advisory append");
    StoreFixture {
        directory,
        store,
        logical_store,
        profile_id,
        catalog_id,
    }
}

fn subject(store: &LogicalStoreId, domain: &str) -> QualifiedEntityRef {
    QualifiedEntityRef {
        store: store.clone(),
        domain: domain.parse().expect("domain"),
        entity_id: STORE_UUID.parse().expect("entity"),
    }
}

#[test]
fn proof_creation_uses_only_current_locked_checkpoint_and_presence() {
    let fixture = initialized_store();
    let observed_at = "1999-01-01T00:00:00Z".parse().expect("old provenance");
    assert!(matches!(
        fixture.store.verified_proof(
            &subject(&fixture.logical_store, "wayjournal.profile"),
            fixture.profile_id,
            observed_at,
        ),
        Err(ProofError::MissingCheckpoint)
    ));

    let snapshot = fixture.store.read().expect("snapshot");
    write_checkpoint(
        fixture.directory.path(),
        &fixture.logical_store,
        snapshot.revision(),
        TRUST,
    );
    for (domain, record_id) in [
        ("wayjournal.profile", fixture.profile_id),
        ("wayjournal.catalog", fixture.catalog_id),
    ] {
        let proof = fixture
            .store
            .verified_proof(
                &subject(&fixture.logical_store, domain),
                record_id,
                observed_at,
            )
            .expect("presence proof");
        assert_eq!(proof.subject(), &subject(&fixture.logical_store, domain));
        assert_eq!(proof.record_id(), record_id);
        assert_eq!(proof.source_revision(), snapshot.revision());
        assert_eq!(
            proof.local_trust_binding(),
            LocalTrustBinding::parse(TRUST).unwrap()
        );
        assert_eq!(proof.observed_at(), observed_at);
        decode_verified_proof(&encode_verified_proof(&proof).expect("encode")).expect("round trip");
    }

    let missing = "01913f1d-8e2a-7c30-8f4a-426614174099"
        .parse()
        .expect("missing record id");
    assert!(matches!(
        fixture.store.verified_proof(
            &subject(&fixture.logical_store, "wayjournal.profile"),
            missing,
            observed_at,
        ),
        Err(ProofError::RecordNotFound)
    ));
    assert!(matches!(
        fixture.store.verified_proof(
            &subject(&fixture.logical_store, "wayjournal.catalog"),
            fixture.profile_id,
            observed_at,
        ),
        Err(ProofError::SubjectMismatch)
    ));
    let other_store = store_id(STORE_UUID_2, GENESIS_FP);
    assert!(matches!(
        fixture.store.verified_proof(
            &subject(&other_store, "wayjournal.profile"),
            fixture.profile_id,
            observed_at,
        ),
        Err(ProofError::IdentityMismatch)
    ));
}

#[test]
fn advanced_checkpoint_cannot_prove_restored_old_canonical_bytes() {
    let fixture = initialized_store();
    let old = fixture.store.read().expect("R");
    write_checkpoint(
        fixture.directory.path(),
        &fixture.logical_store,
        old.revision(),
        TRUST,
    );
    fixture
        .store
        .verified_proof(
            &subject(&fixture.logical_store, "wayjournal.profile"),
            fixture.profile_id,
            OBSERVED_AT.parse().expect("time"),
        )
        .expect("proof at R");
    let retained_old_checkpoint = fs::read(
        fixture
            .directory
            .path()
            .join(".wayjournal-local/checkpoints/admission-v1.json"),
    )
    .expect("retained checkpoint R");

    let registry = wayjournal_domain_registry().expect("registry");
    let advance_record = record(
        "wayjournal.profile",
        "profile.description.set",
        "01913f1d-8e2a-7c30-8f4a-426614174041",
        "01913f1d-8e2a-7c30-8f4a-426614174042",
        json!({"value": "checkpoint R2"}),
    );
    let advance_path = advance_record.canonical_path();
    let advance = prepare_batch(&[advance_record], "projection-R2", &registry).expect("advance");
    let manifest_path = advance.manifest().canonical_path();
    fixture
        .store
        .append(&advance, old.revision())
        .expect("advance canonical state");
    let new = fixture.store.read().expect("R2");
    assert_ne!(old.revision(), new.revision());
    write_checkpoint(
        fixture.directory.path(),
        &fixture.logical_store,
        new.revision(),
        TRUST,
    );

    fs::remove_file(fixture.directory.path().join(advance_path)).expect("restore R record set");
    fs::remove_file(fixture.directory.path().join(manifest_path)).expect("restore R manifests");
    assert_eq!(
        fixture.store.read().expect("restored R").revision(),
        old.revision()
    );
    assert!(matches!(
        fixture.store.verified_proof(
            &subject(&fixture.logical_store, "wayjournal.profile"),
            fixture.profile_id,
            OBSERVED_AT.parse().expect("time"),
        ),
        Err(ProofError::RevisionMismatch)
    ));
    assert_ne!(
        fs::read(
            fixture
                .directory
                .path()
                .join(".wayjournal-local/checkpoints/admission-v1.json")
        )
        .expect("checkpoint R2"),
        retained_old_checkpoint,
        "the retained checkpoint R bytes cannot replace current authority"
    );
}

#[test]
fn checkpoint_identity_revision_and_pending_gates_fail_closed() {
    let fixture = initialized_store();
    let current = fixture.store.read().expect("current");
    write_checkpoint(
        fixture.directory.path(),
        &fixture.logical_store,
        revision(&"a".repeat(64)),
        TRUST,
    );
    assert!(matches!(
        fixture.store.verified_proof(
            &subject(&fixture.logical_store, "wayjournal.profile"),
            fixture.profile_id,
            OBSERVED_AT.parse().expect("time"),
        ),
        Err(ProofError::RevisionMismatch)
    ));

    let other = store_id(STORE_UUID_2, &"b".repeat(64));
    write_checkpoint(fixture.directory.path(), &other, current.revision(), TRUST);
    assert!(matches!(
        fixture.store.verified_proof(
            &subject(&fixture.logical_store, "wayjournal.profile"),
            fixture.profile_id,
            OBSERVED_AT.parse().expect("time"),
        ),
        Err(ProofError::IdentityMismatch)
    ));

    write_checkpoint(
        fixture.directory.path(),
        &fixture.logical_store,
        current.revision(),
        TRUST,
    );
    fs::write(
        fixture
            .directory
            .path()
            .join(".wayjournal-local/sync-pending/unknown"),
        b"hostile pending state",
    )
    .expect("pending residue");
    assert!(matches!(
        fixture.store.verified_proof(
            &subject(&fixture.logical_store, "wayjournal.profile"),
            fixture.profile_id,
            OBSERVED_AT.parse().expect("time"),
        ),
        Err(ProofError::Store(_))
    ));
}
