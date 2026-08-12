use wayjournal_core::{
    BATCH_SCHEMA_V1, CAPABILITY_MANIFEST, CATALOG_SCHEMA_V1, IDENTITY_SCHEMA_V1, JSON_CODEC_V1,
    PROFILE_SCHEMA_V1, RECORD_SCHEMA_V1, REVISION_ALGORITHM_V1,
};

#[test]
fn capability_manifest_is_exactly_the_s3_surface() {
    assert_eq!(CAPABILITY_MANIFEST.schema, "wayjournal.capabilities/v1");
    assert_eq!(
        CAPABILITY_MANIFEST.capabilities,
        [
            JSON_CODEC_V1,
            RECORD_SCHEMA_V1,
            BATCH_SCHEMA_V1,
            "wayjournal.layout/v1",
            REVISION_ALGORITHM_V1,
            IDENTITY_SCHEMA_V1,
            PROFILE_SCHEMA_V1,
            CATALOG_SCHEMA_V1,
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
            "wayjournal.identity.v1.json" => {
                include_str!("../../../schemas/wayjournal.identity.v1.json")
            }
            "wayjournal.profile.v1.json" => {
                include_str!("../../../schemas/wayjournal.profile.v1.json")
            }
            "wayjournal.catalog.v1.json" => {
                include_str!("../../../schemas/wayjournal.catalog.v1.json")
            }
            other => panic!("unexpected generated schema {other}"),
        };
        assert_eq!(checked, generated, "schema drift for {name}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
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
    let mut version_two = record.clone();
    version_two["entity_id"] = serde_json::json!("123e4567-e89b-22d3-a456-426614174000");
    assert!(!record_validator.is_valid(&version_two));
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

    let identity_schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/wayjournal.identity.v1.json"))
            .expect("identity schema");
    let identity_validator = jsonschema::validator_for(&identity_schema).expect("identity schema");
    let identity_record: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/wayjournal.identity.genesis.v1.json"
    ))
    .expect("identity record");
    assert!(record_validator.is_valid(&identity_record));
    let identity_bytes = include_bytes!("../../../fixtures/wayjournal.identity.genesis.v1.json");
    assert!(
        wayjournal_core::decode_record(
            identity_bytes,
            &wayjournal_core::wayjournal_domain_registry().expect("registry")
        )
        .is_ok()
    );
    let identity_domain = serde_json::json!({
        "kind": identity_record["kind"],
        "payload": identity_record["payload"],
    });
    assert!(identity_validator.is_valid(&identity_domain));
    let mut wrong_algorithm = identity_domain;
    wrong_algorithm["payload"]["forked_from"] = serde_json::json!({
        "parent": {
            "genesis_fingerprint": "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
            "store_uuid": "01913f1d-8e2a-7c30-8f4a-426614174020"
        },
        "parent_revision": {
            "algorithm": "wayjournal.store/blake3-framed-v2",
            "digest": "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
        }
    });
    assert!(!identity_validator.is_valid(&wrong_algorithm));

    for (schema, fixture) in [
        (
            include_str!("../../../schemas/wayjournal.profile.v1.json"),
            include_str!("../../../fixtures/wayjournal.profile.v1.json"),
        ),
        (
            include_str!("../../../schemas/wayjournal.catalog.v1.json"),
            include_str!("../../../fixtures/wayjournal.catalog.v1.json"),
        ),
    ] {
        let schema: serde_json::Value = serde_json::from_str(schema).expect("domain schema");
        let validator = jsonschema::validator_for(&schema).expect("domain validator");
        let fixture: serde_json::Value = serde_json::from_str(fixture).expect("domain fixture");
        assert!(validator.is_valid(&fixture));
        let mut hostile = fixture.clone();
        hostile["payload"]["unknown"] = serde_json::json!(true);
        assert!(!validator.is_valid(&hostile));
        let mut control = fixture.clone();
        if control["payload"].get("key").is_some() {
            for hostile_control in ['\u{0001}', '\u{007f}', '\u{0085}'] {
                control["payload"]["key"] = serde_json::json!(format!("bad{hostile_control}key"));
                assert!(!validator.is_valid(&control));
            }
        }
        if fixture["kind"] == "catalog.remote.add" {
            let mut false_validation = fixture;
            false_validation["payload"]["value"]["requires_identity_validation"] =
                serde_json::json!(false);
            assert!(!validator.is_valid(&false_validation));
        }
    }
}

fn schema_sample(schema: &serde_json::Value) -> serde_json::Value {
    if let Some(value) = schema.get("const") {
        return value.clone();
    }
    if let Some(first) = schema
        .get("oneOf")
        .and_then(|v| v.as_array())
        .and_then(|v| v.first())
    {
        return schema_sample(first);
    }
    match schema.get("type").and_then(|v| v.as_str()) {
        Some("object") => {
            let properties = schema["properties"].as_object().expect("properties");
            schema["required"]
                .as_array()
                .expect("required")
                .iter()
                .map(|name| {
                    let name = name.as_str().expect("name");
                    (name.to_owned(), schema_sample(&properties[name]))
                })
                .collect::<serde_json::Map<_, _>>()
                .into()
        }
        Some("array") => serde_json::json!([schema_sample(&schema["items"])]),
        Some("boolean") => serde_json::json!(true),
        Some("string") => {
            let pattern = schema.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            if pattern.contains("{64}") {
                serde_json::json!(
                    "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
                )
            } else if pattern.contains("-7[") {
                serde_json::json!("01913f1d-8e2a-7c30-8f4a-426614174010")
            } else if pattern.contains("[1345678]") {
                serde_json::json!("123e4567-e89b-42d3-a456-426614174000")
            } else if pattern.contains("\\.") {
                serde_json::json!("example.token")
            } else {
                serde_json::json!("x")
            }
        }
        _ => panic!("unsupported sample schema {schema}"),
    }
}

#[test]
fn every_closed_s3_operation_schema_has_valid_and_closed_hostile_vector() {
    let mut count = 0;
    for checked in [
        include_str!("../../../schemas/wayjournal.profile.v1.json"),
        include_str!("../../../schemas/wayjournal.catalog.v1.json"),
    ] {
        let schema: serde_json::Value = serde_json::from_str(checked).expect("schema");
        for variant in schema["oneOf"].as_array().expect("variants") {
            count += 1;
            let validator = jsonschema::validator_for(variant).expect("variant");
            let sample = schema_sample(variant);
            assert!(validator.is_valid(&sample), "valid {sample}");
            let domain = if sample["kind"]
                .as_str()
                .expect("kind")
                .starts_with("profile.")
            {
                "wayjournal.profile"
            } else {
                "wayjournal.catalog"
            };
            let runtime = wayjournal_core::Record {
                record_schema: format!("{domain}/v1").parse().expect("schema"),
                domain: domain.parse().expect("domain"),
                kind: sample["kind"]
                    .as_str()
                    .expect("kind")
                    .parse()
                    .expect("kind"),
                record_id: "01913f1d-8e2a-7c30-8f4a-426614174001".parse().expect("id"),
                entity_id: "123e4567-e89b-42d3-a456-426614174000"
                    .parse()
                    .expect("entity"),
                batch_id: "01913f1d-8e2a-7c30-8f4a-426614174002"
                    .parse()
                    .expect("batch"),
                actor: wayjournal_core::ActorId::parse("test:schema").expect("actor"),
                occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
                recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
                parents: Vec::new(),
                payload: sample["payload"].clone(),
            };
            let registry = wayjournal_core::wayjournal_domain_registry().expect("registry");
            assert!(wayjournal_core::encode_record(&runtime, &registry).is_ok());
            let mut hostile = sample;
            hostile["payload"]["unknown"] = serde_json::json!(true);
            assert!(!validator.is_valid(&hostile));
            let hostile_runtime = wayjournal_core::Record {
                payload: hostile["payload"].clone(),
                ..runtime
            };
            assert!(wayjournal_core::encode_record(&hostile_runtime, &registry).is_err());
        }
    }
    assert_eq!(count, 30);
}

#[test]
fn reference_array_and_bounded_string_schema_edges_are_exact() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/wayjournal.profile.v1.json"))
            .expect("schema");
    let resolve = &schema["oneOf"][1];
    let validator = jsonschema::validator_for(resolve).expect("resolve");
    let mut sample = schema_sample(resolve);
    let id = serde_json::json!("01913f1d-8e2a-7c30-8f4a-426614174010");
    sample["payload"]["candidates"] = serde_json::json!([]);
    assert!(!validator.is_valid(&sample));
    sample["payload"]["candidates"] = serde_json::json!([id.clone()]);
    assert!(validator.is_valid(&sample));
    sample["payload"]["candidates"] = serde_json::Value::Array(vec![id.clone(); 2]);
    assert!(!validator.is_valid(&sample));
    sample["payload"]["candidates"] = serde_json::Value::Array(
        (0..4096)
            .map(|i| serde_json::json!(format!("01913f1d-8e2a-7c30-8f4a-{i:012}")))
            .collect(),
    );
    assert!(validator.is_valid(&sample));
    sample["payload"]["candidates"]
        .as_array_mut()
        .expect("array")
        .push(serde_json::json!("01913f1d-8e2a-7c30-8f4a-426614184096"));
    assert!(!validator.is_valid(&sample));
    sample["payload"]["candidates"] = serde_json::json!([id]);
    for (length, expected) in [(0, false), (1, true), (4096, true), (4097, false)] {
        sample["payload"]["value"] = serde_json::json!("x".repeat(length));
        assert_eq!(
            validator.is_valid(&sample),
            expected,
            "text length {length}"
        );
    }
}

fn runtime_record(domain: &str, sample: &serde_json::Value) -> wayjournal_core::Record {
    wayjournal_core::Record {
        record_schema: format!("{domain}/v1").parse().expect("schema"),
        domain: domain.parse().expect("domain"),
        kind: sample["kind"]
            .as_str()
            .expect("kind")
            .parse()
            .expect("kind"),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174001".parse().expect("id"),
        entity_id: "123e4567-e89b-42d3-a456-426614174000"
            .parse()
            .expect("entity"),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174002"
            .parse()
            .expect("batch"),
        actor: wayjournal_core::ActorId::parse("test:parity").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: Vec::new(),
        payload: sample["payload"].clone(),
    }
}

#[test]
fn all_65_control_scalars_have_schema_runtime_parity_for_text_key_and_locator() {
    let checked: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/wayjournal.profile.v1.json"))
            .expect("schema");
    let cases = [(0, "value"), (6, "key"), (6, "locator")];
    let controls = (0..=0x1f)
        .chain([0x7f])
        .chain(0x80..=0x9f)
        .map(|value| char::from_u32(value).expect("scalar"))
        .collect::<Vec<_>>();
    assert_eq!(controls.len(), 65);
    let registry = wayjournal_core::wayjournal_domain_registry().expect("registry");
    for (variant_index, field) in cases {
        let variant = &checked["oneOf"][variant_index];
        let validator = jsonschema::validator_for(variant).expect("validator");
        for control in &controls {
            let mut sample = schema_sample(variant);
            if field == "locator" {
                sample["payload"]["value"]["locator"] = serde_json::json!(format!("x{control}"));
            } else {
                sample["payload"][field] = serde_json::json!(format!("x{control}"));
            }
            assert!(
                !validator.is_valid(&sample),
                "schema accepted U+{:04X} in {field}",
                *control as u32
            );
            assert!(
                wayjournal_core::encode_record(
                    &runtime_record("wayjournal.profile", &sample),
                    &registry
                )
                .is_err(),
                "runtime accepted U+{:04X} in {field}",
                *control as u32
            );
        }
        for printable in [' ', '~', '\u{00a0}'] {
            let mut sample = schema_sample(variant);
            if field == "locator" {
                sample["payload"]["value"]["locator"] = serde_json::json!(format!("x{printable}"));
            } else {
                sample["payload"][field] = serde_json::json!(format!("x{printable}"));
            }
            assert!(
                validator.is_valid(&sample),
                "schema rejected printable in {field}"
            );
            assert!(
                wayjournal_core::encode_record(
                    &runtime_record("wayjournal.profile", &sample),
                    &registry
                )
                .is_ok(),
                "runtime rejected printable in {field}"
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn text_key_locator_and_reference_bounds_match_schema_and_runtime() {
    let checked: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/wayjournal.profile.v1.json"))
            .expect("schema");
    let registry = wayjournal_core::wayjournal_domain_registry().expect("registry");
    for (variant_index, path, maximum) in [
        (0, "value", 4096_usize),
        (6, "key", 128),
        (6, "locator", 2048),
    ] {
        let variant = &checked["oneOf"][variant_index];
        let validator = jsonschema::validator_for(variant).expect("validator");
        for (length, accepted) in [(0, false), (1, true), (maximum, true), (maximum + 1, false)] {
            let mut sample = schema_sample(variant);
            if path == "locator" {
                sample["payload"]["value"]["locator"] = serde_json::json!("x".repeat(length));
            } else {
                sample["payload"][path] = serde_json::json!("x".repeat(length));
            }
            assert_eq!(
                validator.is_valid(&sample),
                accepted,
                "schema {path} {length}"
            );
            assert_eq!(
                wayjournal_core::encode_record(
                    &runtime_record("wayjournal.profile", &sample),
                    &registry
                )
                .is_ok(),
                accepted,
                "runtime {path} {length}"
            );
        }
    }
    for variant_index in [1_usize, 11] {
        let variant = &checked["oneOf"][variant_index];
        let validator = jsonschema::validator_for(variant).expect("validator");
        for (length, accepted) in [(0, false), (1, true), (4096, true), (4097, false)] {
            let mut sample = schema_sample(variant);
            sample["payload"][if variant_index == 1 {
                "candidates"
            } else {
                "adds"
            }] = serde_json::Value::Array(
                (0..length)
                    .map(|i| serde_json::json!(format!("01913f1d-8e2a-7c30-8f4a-{i:012}")))
                    .collect(),
            );
            assert_eq!(
                validator.is_valid(&sample),
                accepted,
                "schema refs {length}"
            );
            assert_eq!(
                wayjournal_core::encode_record(
                    &runtime_record("wayjournal.profile", &sample),
                    &registry
                )
                .is_ok(),
                accepted,
                "runtime refs {length}"
            );
        }
        let mut duplicate = schema_sample(variant);
        duplicate["payload"][if variant_index == 1 {
            "candidates"
        } else {
            "adds"
        }] = serde_json::json!([
            "01913f1d-8e2a-7c30-8f4a-426614174001",
            "01913f1d-8e2a-7c30-8f4a-426614174001"
        ]);
        assert!(!validator.is_valid(&duplicate));
        assert!(
            wayjournal_core::encode_record(
                &runtime_record("wayjournal.profile", &duplicate),
                &registry
            )
            .is_err()
        );
        let mut unsorted = schema_sample(variant);
        unsorted["payload"][if variant_index == 1 {
            "candidates"
        } else {
            "adds"
        }] = serde_json::json!([
            "01913f1d-8e2a-7c30-8f4a-426614174002",
            "01913f1d-8e2a-7c30-8f4a-426614174001"
        ]);
        assert!(
            validator.is_valid(&unsorted),
            "standard JSON Schema treats x-wayjournal-sorted as an annotation"
        );
        assert!(
            wayjournal_core::encode_record(
                &runtime_record("wayjournal.profile", &unsorted),
                &registry
            )
            .is_err()
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn uuid_version_and_variant_matrix_matches_entity_and_store_types() {
    let record_schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/wayjournal.record.v1.json"))
            .expect("record schema");
    let record_validator = jsonschema::validator_for(&record_schema).expect("record validator");
    let base: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/wayjournal.record.v1.json"))
            .expect("record");
    for version in 1..=8 {
        let uuid = format!("123e4567-e89b-{version}2d3-a456-426614174000");
        let mut sample = base.clone();
        sample["entity_id"] = serde_json::json!(uuid);
        let accepted = version != 2;
        assert_eq!(
            record_validator.is_valid(&sample),
            accepted,
            "entity schema v{version}"
        );
        assert_eq!(
            uuid.parse::<wayjournal_core::EntityId>().is_ok(),
            accepted,
            "entity runtime v{version}"
        );
        assert_eq!(
            uuid.parse::<wayjournal_core::StoreUuid>().is_ok(),
            version == 7,
            "store runtime v{version}"
        );
    }
    for variant in ['0', 'c'] {
        let uuid = format!("123e4567-e89b-42d3-{variant}456-426614174000");
        let mut sample = base.clone();
        sample["entity_id"] = serde_json::json!(uuid.clone());
        assert!(!record_validator.is_valid(&sample));
        assert!(uuid.parse::<wayjournal_core::EntityId>().is_err());
    }
    let registry = wayjournal_core::wayjournal_domain_registry().expect("registry");
    let identity_schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/wayjournal.identity.v1.json"))
            .expect("identity schema");
    let identity_validator =
        jsonschema::validator_for(&identity_schema).expect("identity validator");
    let identity_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/wayjournal.identity.genesis.v1.json"
    ))
    .expect("identity fixture");
    for version in 1..=8 {
        let mut full = identity_fixture.clone();
        full["payload"]["store_uuid"] =
            serde_json::json!(format!("01913f1d-8e2a-{version}c30-8f4a-426614174010"));
        assert!(
            record_validator.is_valid(&full),
            "generic envelope remains valid v{version}"
        );
        let projected = serde_json::json!({"kind":full["kind"],"payload":full["payload"]});
        let accepted = version == 7;
        assert_eq!(
            identity_validator.is_valid(&projected),
            accepted,
            "identity store schema v{version}"
        );
        let bytes = serde_json::to_vec_pretty(&full)
            .map(|mut bytes| {
                bytes.push(b'\n');
                bytes
            })
            .expect("bytes");
        assert_eq!(
            wayjournal_core::decode_record(&bytes, &registry).is_ok(),
            accepted,
            "identity store runtime v{version}"
        );
    }
    for variant in ['0', 'c', 'e'] {
        let mut full = identity_fixture.clone();
        let uuid = format!("01913f1d-8e2a-7c30-{variant}f4a-426614174010");
        assert_ne!(
            uuid::Uuid::parse_str(&uuid).expect("uuid").get_variant(),
            uuid::Variant::RFC4122
        );
        full["payload"]["store_uuid"] = serde_json::json!(uuid);
        let projected = serde_json::json!({"kind":full["kind"],"payload":full["payload"]});
        assert!(!identity_validator.is_valid(&projected));
        let bytes = serde_json::to_vec_pretty(&full)
            .map(|mut bytes| {
                bytes.push(b'\n');
                bytes
            })
            .expect("bytes");
        assert!(wayjournal_core::decode_record(&bytes, &registry).is_err());
    }
    for (domain, checked) in [
        (
            "wayjournal.profile",
            include_str!("../../../schemas/wayjournal.profile.v1.json"),
        ),
        (
            "wayjournal.catalog",
            include_str!("../../../schemas/wayjournal.catalog.v1.json"),
        ),
    ] {
        let schema: serde_json::Value = serde_json::from_str(checked).expect("relation schema");
        let relation = &schema["oneOf"][7];
        let validator = jsonschema::validator_for(relation).expect("relation");
        for version in 1..=8 {
            let mut store_sample = schema_sample(relation);
            let value = if domain == "wayjournal.profile" {
                &mut store_sample["payload"]["value"]
            } else {
                &mut store_sample["payload"]["value"]["reference"]
            };
            value["entity_id"] = serde_json::json!("123e4567-e89b-72d3-a456-426614174000");
            value["store"]["store_uuid"] =
                serde_json::json!(format!("01913f1d-8e2a-{version}c30-8f4a-426614174010"));
            let store_accepted = version == 7;
            assert_eq!(
                validator.is_valid(&store_sample),
                store_accepted,
                "{domain} store v{version}"
            );
            assert_eq!(
                wayjournal_core::encode_record(&runtime_record(domain, &store_sample), &registry)
                    .is_ok(),
                store_accepted,
                "{domain} store runtime v{version}"
            );

            let mut entity_sample = schema_sample(relation);
            let value = if domain == "wayjournal.profile" {
                &mut entity_sample["payload"]["value"]
            } else {
                &mut entity_sample["payload"]["value"]["reference"]
            };
            value["store"]["store_uuid"] =
                serde_json::json!("01913f1d-8e2a-7c30-8f4a-426614174010");
            value["entity_id"] =
                serde_json::json!(format!("123e4567-e89b-{version}2d3-a456-426614174000"));
            let entity_accepted = version != 2;
            assert_eq!(
                validator.is_valid(&entity_sample),
                entity_accepted,
                "{domain} entity v{version}"
            );
            assert_eq!(
                wayjournal_core::encode_record(&runtime_record(domain, &entity_sample), &registry)
                    .is_ok(),
                entity_accepted,
                "{domain} entity runtime v{version}"
            );
        }
        for variant in ['0', 'c', 'e'] {
            let uuid = format!("01913f1d-8e2a-7c30-{variant}f4a-426614174010");
            assert_ne!(
                uuid::Uuid::parse_str(&uuid).expect("uuid").get_variant(),
                uuid::Variant::RFC4122
            );
            let mut store_sample = schema_sample(relation);
            let value = if domain == "wayjournal.profile" {
                &mut store_sample["payload"]["value"]
            } else {
                &mut store_sample["payload"]["value"]["reference"]
            };
            value["entity_id"] = serde_json::json!("123e4567-e89b-72d3-a456-426614174000");
            value["store"]["store_uuid"] = serde_json::json!(uuid);
            assert!(!validator.is_valid(&store_sample));
            assert!(
                wayjournal_core::encode_record(&runtime_record(domain, &store_sample), &registry)
                    .is_err()
            );

            let uuid = format!("123e4567-e89b-42d3-{variant}456-426614174000");
            assert_ne!(
                uuid::Uuid::parse_str(&uuid).expect("uuid").get_variant(),
                uuid::Variant::RFC4122
            );
            let mut entity_sample = schema_sample(relation);
            let value = if domain == "wayjournal.profile" {
                &mut entity_sample["payload"]["value"]
            } else {
                &mut entity_sample["payload"]["value"]["reference"]
            };
            value["store"]["store_uuid"] =
                serde_json::json!("01913f1d-8e2a-7c30-8f4a-426614174010");
            value["entity_id"] = serde_json::json!(uuid);
            assert!(!validator.is_valid(&entity_sample));
            assert!(
                wayjournal_core::encode_record(&runtime_record(domain, &entity_sample), &registry)
                    .is_err()
            );
        }
    }
}
