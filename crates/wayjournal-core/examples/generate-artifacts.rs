use std::{env, fs, path::Path};

use serde_json::{Value, json};
use wayjournal_core::{
    ActorId, DomainRegistration, DomainRegistry, KindId, Record, encode_record, generated_schemas,
    prepare_batch,
};

const RECORD_A: &str = "01913f1d-8e2a-7c30-8f4a-426614174001";
const RECORD_B: &str = "01913f1d-8e2a-7c30-8f4a-426614174002";
const BATCH: &str = "01913f1d-8e2a-7c30-8f4a-426614174099";

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

    let mut artifacts = generated_schemas()
        .into_iter()
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
