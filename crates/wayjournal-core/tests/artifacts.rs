use wayjournal_core::{
    BATCH_SCHEMA_V1, CAPABILITY_MANIFEST, JSON_CODEC_V1, RECORD_SCHEMA_V1, REVISION_ALGORITHM_V1,
};

#[test]
fn capability_manifest_is_exactly_the_s1_surface() {
    assert_eq!(CAPABILITY_MANIFEST.schema, "wayjournal.capabilities/v1");
    assert_eq!(
        CAPABILITY_MANIFEST.capabilities,
        [
            JSON_CODEC_V1,
            RECORD_SCHEMA_V1,
            BATCH_SCHEMA_V1,
            "wayjournal.layout/v1",
            REVISION_ALGORITHM_V1,
            "waytask.layout/v1",
            "waytask.store/blake3-framed-v1"
        ]
    );
}

#[test]
fn checked_schemas_match_generated_schemas() {
    for (name, generated) in wayjournal_core::generated_schemas() {
        let checked = match name {
            "wayjournal.record.v1.json" => {
                include_str!("../../../schemas/wayjournal.record.v1.json")
            }
            "wayjournal.batch.v1.json" => include_str!("../../../schemas/wayjournal.batch.v1.json"),
            other => panic!("unexpected generated schema {other}"),
        };
        assert_eq!(checked, generated, "schema drift for {name}");
    }
}

#[test]
fn schemas_independently_accept_goldens_and_reject_hostile_values() {
    let record_schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/wayjournal.record.v1.json"))
            .expect("record schema JSON");
    let record_validator = jsonschema::validator_for(&record_schema).expect("record schema");
    let record: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../fixtures/wayjournal.record.v1.json"
    ))
    .expect("record golden");
    assert!(record_validator.is_valid(&record));
    let mut noncanonical_timestamp = record.clone();
    noncanonical_timestamp["occurred_at"] = serde_json::json!("2026-08-12T13:00:00.000Z");
    assert!(!record_validator.is_valid(&noncanonical_timestamp));
    let mut float_payload = record;
    float_payload["payload"]["title"] = serde_json::json!(1.5);
    assert!(!record_validator.is_valid(&float_payload));

    let batch_schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/wayjournal.batch.v1.json"))
            .expect("batch schema JSON");
    let batch_validator = jsonschema::validator_for(&batch_schema).expect("batch schema");
    let batch: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../fixtures/wayjournal.batch.v1.json"))
            .expect("batch golden");
    assert!(batch_validator.is_valid(&batch));
    let mut hostile_path = batch.clone();
    hostile_path["members"][0]["path"] =
        serde_json::json!("journal/records/example.notes/not-a-uuid/not-a-v7.json");
    assert!(!batch_validator.is_valid(&hostile_path));

    let mut version_two_entity = batch.clone();
    version_two_entity["members"][0]["path"] = serde_json::json!(
        "journal/records/example.notes/123e4567-e89b-22d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json"
    );
    assert!(!batch_validator.is_valid(&version_two_entity));

    let mut boundary_domain = batch.clone();
    let exactly_128 = format!("{}.{}.a", "a".repeat(62), "b".repeat(63));
    assert_eq!(exactly_128.len(), 128);
    boundary_domain["members"][0]["path"] = serde_json::json!(format!(
        "journal/records/{exactly_128}/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json"
    ));
    assert!(batch_validator.is_valid(&boundary_domain));

    let mut overlong_domain = batch;
    let over_128 = format!("{}.{}.aa", "a".repeat(62), "b".repeat(63));
    assert_eq!(over_128.len(), 129);
    overlong_domain["members"][0]["path"] = serde_json::json!(format!(
        "journal/records/{over_128}/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json"
    ));
    assert!(!batch_validator.is_valid(&overlong_domain));
}
