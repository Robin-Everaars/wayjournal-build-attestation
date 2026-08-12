use serde_json::{Value, json};
use wayjournal_core::{
    ActorId, BatchId, DomainId, DomainRegistration, DomainRegistry, EntityId, KindId, Record,
    RecordCodecError, RecordId, RecordSchemaId, RecordTimestamp, decode_record, encode_record,
};

const RECORD_ID: &str = "01913f1d-8e2a-7c30-8f4a-426614174001";
const BATCH_ID: &str = "01913f1d-8e2a-7c30-8f4a-426614174099";
const ENTITY_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

fn validate_note(kind: &KindId, payload: &Value) -> Result<(), String> {
    if kind.as_str() != "note.created" {
        return Err("unsupported note kind".to_owned());
    }
    let object = payload
        .as_object()
        .ok_or_else(|| "payload must be an object".to_owned())?;
    if object.len() != 1
        || !matches!(object.get("title"), Some(Value::String(title)) if !title.is_empty())
    {
        return Err("payload must contain exactly one nonempty title".to_owned());
    }
    Ok(())
}

static NOTE_KINDS: &[&str] = &["note.created"];
static DOMAINS: &[DomainRegistration] = &[DomainRegistration::new(
    "example.notes",
    "example.notes/v1",
    NOTE_KINDS,
    validate_note,
)];

fn registry() -> DomainRegistry {
    DomainRegistry::new(DOMAINS).expect("static domain registry should be valid")
}

fn record() -> Record {
    Record {
        record_schema: "example.notes/v1".parse().expect("schema"),
        domain: "example.notes".parse().expect("domain"),
        kind: "note.created".parse().expect("kind"),
        record_id: RECORD_ID.parse().expect("record id"),
        entity_id: ENTITY_ID.parse().expect("entity id"),
        batch_id: BATCH_ID.parse().expect("batch id"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("timestamp"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("timestamp"),
        parents: Vec::new(),
        payload: json!({"title": "First note"}),
    }
}

#[test]
fn canonical_record_matches_golden_and_round_trips() {
    let expected = include_bytes!("../../../fixtures/wayjournal.record.v1.json");
    let encoded = encode_record(&record(), &registry()).expect("record should encode");
    assert_eq!(encoded, expected);
    assert_eq!(
        decode_record(expected, &registry()).expect("golden should decode"),
        record()
    );
}

#[test]
fn hostile_json_is_rejected_before_domain_validation() {
    let canonical = String::from_utf8(encode_record(&record(), &registry()).expect("encode"))
        .expect("canonical JSON is UTF-8");

    let duplicate = canonical.replacen(
        "  \"actor\": \"human:robin\",\n",
        "  \"actor\": \"human:robin\",\n  \"actor\": \"agent:other\",\n",
        1,
    );
    assert!(matches!(
        decode_record(duplicate.as_bytes(), &registry()),
        Err(RecordCodecError::DuplicateKey(key)) if key == "actor"
    ));

    let unknown = canonical.replacen(
        "  \"schema\": \"wayjournal.record/v1\"\n",
        "  \"schema\": \"wayjournal.record/v1\",\n  \"unknown\": true\n",
        1,
    );
    assert!(matches!(
        decode_record(unknown.as_bytes(), &registry()),
        Err(RecordCodecError::UnknownField(field)) if field == "unknown"
    ));

    let compact: Value = serde_json::from_slice(canonical.as_bytes()).expect("fixture JSON");
    let compact = serde_json::to_vec(&compact).expect("compact JSON");
    assert_eq!(
        decode_record(&compact, &registry()),
        Err(RecordCodecError::NonCanonical)
    );

    let float = canonical.replacen("\"title\": \"First note\"", "\"title\": 1.5", 1);
    assert!(matches!(
        decode_record(float.as_bytes(), &registry()),
        Err(RecordCodecError::FloatNotAllowed | RecordCodecError::InvalidJson(_))
    ));
}

#[test]
fn typed_identifiers_timestamps_and_parents_are_strict() {
    assert!(
        "01913f1d-8e2a-4c30-8f4a-426614174001"
            .parse::<RecordId>()
            .is_err()
    );
    assert!(
        "01913F1D-8E2A-7C30-8F4A-426614174001"
            .parse::<BatchId>()
            .is_err()
    );
    assert!(
        "00000000-0000-0000-0000-000000000000"
            .parse::<EntityId>()
            .is_err()
    );
    assert!("notes".parse::<DomainId>().is_err());
    assert!("Example.notes".parse::<DomainId>().is_err());
    assert!("example.notes/../v1".parse::<RecordSchemaId>().is_err());
    assert!("created".parse::<KindId>().is_err());
    assert!(ActorId::parse("root").is_err());
    assert!(ActorId::parse("human:has whitespace").is_err());
    assert!(
        "2026-08-12T15:00:00+02:00"
            .parse::<RecordTimestamp>()
            .is_err()
    );
    assert!(
        "2026-08-12T13:00:00.000Z"
            .parse::<RecordTimestamp>()
            .is_err()
    );

    let mut unsorted = record();
    unsorted.parents = vec![
        "01913f1d-8e2a-7c30-8f4a-426614174010".parse().expect("id"),
        "01913f1d-8e2a-7c30-8f4a-426614174009".parse().expect("id"),
    ];
    assert_eq!(
        encode_record(&unsorted, &registry()),
        Err(RecordCodecError::InvalidParents)
    );

    let mut duplicate = record();
    duplicate.parents = vec![
        "01913f1d-8e2a-7c30-8f4a-426614174010".parse().expect("id"),
        "01913f1d-8e2a-7c30-8f4a-426614174010".parse().expect("id"),
    ];
    assert_eq!(
        encode_record(&duplicate, &registry()),
        Err(RecordCodecError::InvalidParents)
    );

    let mut self_parent = record();
    self_parent.parents = vec![self_parent.record_id];
    assert_eq!(
        encode_record(&self_parent, &registry()),
        Err(RecordCodecError::InvalidParents)
    );
}

#[test]
fn registry_is_closed_and_payload_validation_is_compiled_in() {
    static MISMATCHED: &[DomainRegistration] = &[DomainRegistration::new(
        "other.notes",
        "example.notes/v1",
        NOTE_KINDS,
        validate_note,
    )];
    assert!(DomainRegistry::new(MISMATCHED).is_err());

    let mut wrong_schema = record();
    wrong_schema.record_schema = "example.notes/v2".parse().expect("schema token");
    assert!(matches!(
        encode_record(&wrong_schema, &registry()),
        Err(RecordCodecError::UnknownDomainSchema { .. })
    ));

    let mut wrong_domain = record();
    wrong_domain.domain = "other.notes".parse().expect("domain token");
    assert!(matches!(
        encode_record(&wrong_domain, &registry()),
        Err(RecordCodecError::UnknownDomainSchema { .. })
    ));

    let mut wrong_kind = record();
    wrong_kind.kind = "note.deleted".parse().expect("kind token");
    assert!(matches!(
        encode_record(&wrong_kind, &registry()),
        Err(RecordCodecError::UnknownKind { .. })
    ));

    let mut open_payload = record();
    open_payload.payload = json!({"title": "ok", "extension": true});
    assert!(matches!(
        encode_record(&open_payload, &registry()),
        Err(RecordCodecError::InvalidPayload(_))
    ));
}
