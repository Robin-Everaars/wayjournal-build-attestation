use std::{env, fs, path::Path};

use serde_json::{Value, json};
use wayjournal_core::{
    ActorId, CapabilityId, CapabilityOffer, DomainRegistration, DomainRegistry, KindId,
    LogicalStoreId, PROJECTION_CACHE_ENTRY_SCHEMA_V1, PROOF_VECTOR_PROJECTION_ID, ProofVector,
    REVISION_ALGORITHM_V1, REVISION_VECTOR_PROJECTION_ID, Record, RevisionVector,
    RevisionVectorEntry, S5_CAPABILITIES, S5_CAPABILITY_MANIFEST, S5_PROJECTIONS, StoreRevisionRef,
    StoreUuid, VERIFIED_PROOF_PROJECTION_ID, VERIFIED_PROOF_SCHEMA_V1, all_generated_schemas,
    decode_verified_proof, encode_capability_offer, encode_proof_vector, encode_record,
    encode_revision_vector, prepare_batch, wayjournal_domain_registry,
};

const RECORD_A: &str = "01913f1d-8e2a-7c30-8f4a-426614174001";
const RECORD_B: &str = "01913f1d-8e2a-7c30-8f4a-426614174002";
const BATCH: &str = "01913f1d-8e2a-7c30-8f4a-426614174099";
const S5_STORE_UUID: &str = "01913f1d-8e2a-7c30-8f4a-426614174010";
const S5_GENESIS: &str = "7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447";
const S5_REVISION: &str = "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15";
const S5_TRUST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const S5_ENTITY: &str = "123e4567-e89b-42d3-a456-426614174000";
const S5_RECORD: &str = "01913f1d-8e2a-7c30-8f4a-426614174011";
const S5_OBSERVED: &str = "2026-08-12T13:00:01Z";

fn validate_note(kind: &KindId, payload: &Value) -> Result<(), String> {
    if kind.as_str() != "note.created" {
        return Err("unsupported note kind".to_owned());
    }
    let object = payload.as_object().ok_or("payload must be an object")?;
    if object.len() != 1
        || !matches!(object.get("title"), Some(Value::String(title)) if !title.is_empty())
    {
        return Err("payload must contain exactly one nonempty title".to_owned());
    }
    Ok(())
}

static KINDS: &[&str] = &["note.created"];
static DOMAINS: &[DomainRegistration] = &[DomainRegistration::new(
    "example.notes",
    "example.notes/v1",
    KINDS,
    validate_note,
)];

fn canonical(value: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(value)
        .map(|mut bytes| {
            bytes.push(b'\n');
            bytes
        })
        .expect("canonical fixture")
}

fn proof_preimage() -> Vec<u8> {
    let fields = [
        VERIFIED_PROOF_SCHEMA_V1.as_bytes(),
        S5_STORE_UUID.as_bytes(),
        S5_GENESIS.as_bytes(),
        b"wayjournal.profile".as_slice(),
        S5_ENTITY.as_bytes(),
        S5_RECORD.as_bytes(),
        REVISION_ALGORITHM_V1.as_bytes(),
        S5_REVISION.as_bytes(),
        S5_TRUST.as_bytes(),
        S5_OBSERVED.as_bytes(),
    ];
    let mut bytes = b"wayjournal-proof-v1\0".to_vec();
    for field in fields {
        bytes.extend_from_slice(
            &u64::try_from(field.len())
                .expect("bounded proof field")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(field);
    }
    bytes
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = Vec::with_capacity(bytes.len() * 2 + 1);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)]);
        output.push(DIGITS[usize::from(byte & 0x0f)]);
    }
    output.push(b'\n');
    output
}

fn s5_store() -> LogicalStoreId {
    LogicalStoreId::new(
        S5_STORE_UUID.parse::<StoreUuid>().expect("S5 store UUID"),
        S5_GENESIS.parse().expect("S5 genesis fingerprint"),
    )
}

fn s5_revision() -> StoreRevisionRef {
    StoreRevisionRef::parse(REVISION_ALGORITHM_V1, S5_REVISION).expect("S5 revision")
}

#[allow(clippy::too_many_lines)]
fn s5_artifacts() -> Vec<(String, Vec<u8>)> {
    let preimage = proof_preimage();
    let proof_id = blake3::hash(&preimage).to_hex().to_string();
    assert_eq!(
        proof_id, "99bf2caf35a7b5e12d6b82ae2948ec627098e9a11152533cfdfcd711fd214922",
        "frozen proof preimage"
    );
    let proof_bytes = canonical(&json!({
        "local_trust_binding": S5_TRUST,
        "observed_at": S5_OBSERVED,
        "proof_id": proof_id,
        "record_id": S5_RECORD,
        "schema": VERIFIED_PROOF_SCHEMA_V1,
        "source_revision": {
            "algorithm": REVISION_ALGORITHM_V1,
            "digest": S5_REVISION
        },
        "subject": {
            "domain": "wayjournal.profile",
            "entity_id": S5_ENTITY,
            "store": {
                "genesis_fingerprint": S5_GENESIS,
                "store_uuid": S5_STORE_UUID
            }
        }
    }));
    let proof = decode_verified_proof(&proof_bytes).expect("generated proof");
    let revision_vector =
        RevisionVector::new(vec![RevisionVectorEntry::new(s5_store(), s5_revision())])
            .expect("revision vector");
    let revision_vector_bytes = encode_revision_vector(&revision_vector).expect("revision vector");
    let proof_vector = ProofVector::new(vec![proof.clone()]).expect("proof vector");
    let proof_vector_bytes = encode_proof_vector(&proof_vector).expect("proof vector");

    let mut capabilities = S5_CAPABILITIES
        .into_iter()
        .map(|value| CapabilityId::parse(value).expect("S5 capability"))
        .collect::<Vec<_>>();
    capabilities.sort();
    let mut projections = S5_PROJECTIONS
        .into_iter()
        .map(|value| value.parse().expect("S5 projection"))
        .collect::<Vec<_>>();
    projections.sort();
    let offer = CapabilityOffer::new(
        s5_store(),
        vec![CapabilityId::parse("wayjournal.sync/git-union-cas-v1").expect("sync")],
        vec![
            REVISION_VECTOR_PROJECTION_ID
                .parse()
                .expect("revision projection"),
        ],
        capabilities,
        projections,
    )
    .expect("capability offer");
    let offer_bytes = encode_capability_offer(&offer).expect("capability offer");

    let dependencies: Value =
        serde_json::from_slice(&revision_vector_bytes).expect("revision-vector value");
    let proof_value: Value = serde_json::from_slice(&proof_bytes).expect("proof value");
    let cache_entry_bytes = canonical(&json!({
        "dependencies": dependencies,
        "proof": proof_value,
        "schema": PROJECTION_CACHE_ENTRY_SCHEMA_V1
    }));
    let manifest_bytes = canonical(&json!({
        "capabilities": S5_CAPABILITY_MANIFEST.capabilities,
        "schema": S5_CAPABILITY_MANIFEST.schema
    }));

    // Keep the exact public projection IDs visible in this independently generated offer fixture.
    assert!(
        [
            PROOF_VECTOR_PROJECTION_ID,
            REVISION_VECTOR_PROJECTION_ID,
            VERIFIED_PROOF_PROJECTION_ID,
        ]
        .iter()
        .all(|projection| offer
            .supported_projections()
            .iter()
            .any(|id| id.as_str() == *projection))
    );

    vec![
        (
            "fixtures/wayjournal.revision-vector.v1.json".to_owned(),
            revision_vector_bytes,
        ),
        (
            "fixtures/wayjournal.verified-proof.v1.json".to_owned(),
            proof_bytes,
        ),
        (
            "fixtures/wayjournal.proof-vector.v1.json".to_owned(),
            proof_vector_bytes,
        ),
        (
            "fixtures/wayjournal.capability-offer.v1.json".to_owned(),
            offer_bytes,
        ),
        (
            "fixtures/wayjournal.projection-cache-entry.v1.json".to_owned(),
            cache_entry_bytes,
        ),
        (
            "fixtures/wayjournal.verified-proof.v1.preimage.hex".to_owned(),
            hex(&preimage),
        ),
        (
            "fixtures/wayjournal.capabilities.v2.json".to_owned(),
            manifest_bytes,
        ),
    ]
}

fn note(record_id: &str, entity_id: &str, title: &str) -> Record {
    Record {
        record_schema: "example.notes/v1".parse().expect("schema"),
        domain: "example.notes".parse().expect("domain"),
        kind: "note.created".parse().expect("kind"),
        record_id: record_id.parse().expect("record id"),
        entity_id: entity_id.parse().expect("entity id"),
        batch_id: BATCH.parse().expect("batch id"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("timestamp"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("timestamp"),
        parents: Vec::new(),
        payload: json!({"title": title}),
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    let check = env::args().skip(1).any(|argument| argument == "--check");
    let registry = DomainRegistry::new(DOMAINS).expect("registry");
    let record = note(
        RECORD_A,
        "123e4567-e89b-42d3-a456-426614174000",
        "First note",
    );
    let batch = prepare_batch(
        &[
            note(RECORD_B, "123e4567-e89b-42d3-a456-426614174001", "B"),
            note(RECORD_A, "123e4567-e89b-42d3-a456-426614174000", "A"),
        ],
        "retry-key",
        &registry,
    )
    .expect("batch");

    let mut artifacts = all_generated_schemas()
        .map(|(name, contents)| (format!("schemas/{name}"), contents.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    artifacts.push((
        "fixtures/wayjournal.record.v1.json".to_owned(),
        encode_record(&record, &registry).expect("record"),
    ));
    artifacts.push((
        "fixtures/wayjournal.batch.v1.json".to_owned(),
        batch.manifest_bytes().to_vec(),
    ));
    let genesis = Record {
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
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("timestamp"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("timestamp"),
        parents: Vec::new(),
        payload: json!({
            "store_kind": "wayjournal.personal",
            "store_uuid": "01913f1d-8e2a-7c30-8f4a-426614174010"
        }),
    };
    artifacts.push((
        "fixtures/wayjournal.identity.genesis.v1.json".to_owned(),
        encode_record(
            &genesis,
            &wayjournal_domain_registry().expect("built-in registry"),
        )
        .expect("genesis"),
    ));
    artifacts.push((
        "fixtures/wayjournal.profile.v1.json".to_owned(),
        serde_json::to_vec_pretty(&json!({
            "kind": "profile.display_name.set",
            "payload": {"value": "Robin"}
        }))
        .map(|mut bytes| {
            bytes.push(b'\n');
            bytes
        })
        .expect("profile fixture"),
    ));
    artifacts.push((
        "fixtures/wayjournal.catalog.v1.json".to_owned(),
        serde_json::to_vec_pretty(&json!({
            "kind": "catalog.remote.add",
            "payload": {
                "key": "origin",
                "target": {
                    "genesis_fingerprint": "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
                    "store_uuid": "01913f1d-8e2a-7c30-8f4a-426614174010"
                },
                "value": {
                    "locator": "ssh://example/repo",
                    "requires_identity_validation": true
                }
            }
        }))
        .map(|mut bytes| { bytes.push(b'\n'); bytes })
        .expect("catalog fixture"),
    ));
    artifacts.extend(s5_artifacts());

    let mut drift = false;
    for (path, contents) in artifacts {
        if check {
            if fs::read(&path).ok().as_deref() != Some(contents.as_slice()) {
                eprintln!("artifact drift: {path}");
                drift = true;
            }
        } else {
            if let Some(parent) = Path::new(&path).parent() {
                fs::create_dir_all(parent).expect("create artifact directory");
            }
            fs::write(&path, contents).expect("write artifact");
        }
    }
    assert!(!drift, "checked artifacts differ from generated output");
}
