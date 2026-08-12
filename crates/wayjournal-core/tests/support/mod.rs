use serde_json::{Value, json};
use wayjournal_core::{
    ActorId, DomainRegistration, DomainRegistry, KindId, Record, RecordTimestamp,
};

pub const RECORD_A: &str = "01913f1d-8e2a-7c30-8f4a-426614174001";
pub const RECORD_B: &str = "01913f1d-8e2a-7c30-8f4a-426614174002";
pub const BATCH_ID: &str = "01913f1d-8e2a-7c30-8f4a-426614174099";

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

static NOTE_KINDS: &[&str] = &["note.created"];
static DOMAINS: &[DomainRegistration] = &[DomainRegistration::new(
    "example.notes",
    "example.notes/v1",
    NOTE_KINDS,
    validate_note,
)];

pub fn registry() -> DomainRegistry {
    DomainRegistry::new(DOMAINS).expect("registry")
}

pub fn note_record(record: &str, entity: &str, title: &str) -> Record {
    Record {
        record_schema: "example.notes/v1".parse().expect("schema"),
        domain: "example.notes".parse().expect("domain"),
        kind: "note.created".parse().expect("kind"),
        record_id: record.parse().expect("record id"),
        entity_id: entity.parse().expect("entity id"),
        batch_id: BATCH_ID.parse().expect("batch id"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z"
            .parse::<RecordTimestamp>()
            .expect("timestamp"),
        recorded_at: "2026-08-12T13:00:01Z"
            .parse::<RecordTimestamp>()
            .expect("timestamp"),
        parents: Vec::new(),
        payload: json!({"title": title}),
    }
}
