use crate::{BATCH_SCHEMA_V1, JSON_CODEC_V1, RECORD_SCHEMA_V1, REVISION_ALGORITHM_V1};

pub struct CapabilityManifest {
    pub schema: &'static str,
    pub capabilities: [&'static str; 7],
}

pub const CAPABILITY_MANIFEST: CapabilityManifest = CapabilityManifest {
    schema: "wayjournal.capabilities/v1",
    capabilities: [
        JSON_CODEC_V1,
        RECORD_SCHEMA_V1,
        BATCH_SCHEMA_V1,
        "wayjournal.layout/v1",
        REVISION_ALGORITHM_V1,
        "waytask.layout/v1",
        "waytask.store/blake3-framed-v1",
    ],
};

const RECORD_SCHEMA: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://wayjournal.dev/schemas/wayjournal.record.v1.json",
  "title": "wayjournal.record/v1",
  "$defs": {
    "canonicalValue": {
      "anyOf": [
        {"type": ["null", "boolean", "string", "integer"]},
        {"type": "array", "items": {"$ref": "#/$defs/canonicalValue"}},
        {"type": "object", "additionalProperties": {"$ref": "#/$defs/canonicalValue"}}
      ]
    }
  },
  "type": "object",
  "additionalProperties": false,
  "required": ["actor", "batch_id", "domain", "entity_id", "kind", "occurred_at", "parents", "payload", "record_id", "record_schema", "recorded_at", "schema"],
  "properties": {
    "actor": {"type": "string", "maxLength": 129, "pattern": "^[a-z][a-z0-9_-]{0,31}:[^\\s\\p{Cc}]{1,96}$"},
    "batch_id": {"type": "string", "format": "uuid", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},
    "domain": {"type": "string", "maxLength": 128, "pattern": "^[a-z][a-z0-9_-]{0,62}(\\.[a-z][a-z0-9_-]{0,62})+$"},
    "entity_id": {"type": "string", "format": "uuid", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},
    "kind": {"type": "string", "maxLength": 128, "pattern": "^[a-z][a-z0-9_-]{0,62}(\\.[a-z][a-z0-9_-]{0,62})+$"},
    "occurred_at": {"type": "string", "format": "date-time", "maxLength": 33, "pattern": "^(?:[0-9]{4}|[+-][0-9]{6})-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{0,8}[1-9])?Z$"},
    "parents": {"type": "array", "items": {"type": "string", "format": "uuid", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"}, "uniqueItems": true, "x-wayjournal-sorted": true},
    "payload": {"$ref": "#/$defs/canonicalValue"},
    "record_id": {"type": "string", "format": "uuid", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},
    "record_schema": {"type": "string", "maxLength": 128, "pattern": "^[a-z][a-z0-9_-]{0,62}(\\.[a-z][a-z0-9_-]{0,62})+/[a-z][a-z0-9_-]{0,62}$"},
    "recorded_at": {"type": "string", "format": "date-time", "maxLength": 33, "pattern": "^(?:[0-9]{4}|[+-][0-9]{6})-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{0,8}[1-9])?Z$"},
    "schema": {"const": "wayjournal.record/v1"}
  }
}
"##;

const BATCH_SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://wayjournal.dev/schemas/wayjournal.batch.v1.json",
  "title": "wayjournal.batch/v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["actor", "batch_id", "idempotency_key_digest", "members", "request_digest", "schema"],
  "properties": {
    "actor": {"type": "string", "maxLength": 129, "pattern": "^[a-z][a-z0-9_-]{0,31}:[^\\s\\p{Cc}]{1,96}$"},
    "batch_id": {"type": "string", "format": "uuid", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},
    "idempotency_key_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "members": {
      "type": "array",
      "minItems": 1,
      "uniqueItems": true,
      "x-wayjournal-sorted-by": "path",
      "x-wayjournal-path-domain-maxLength": 128,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["content_digest", "path", "record_id", "record_schema"],
        "properties": {
          "content_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
          "path": {"type": "string", "maxLength": 240, "pattern": "^journal/records/(?=.{3,128}/)[a-z][a-z0-9_-]{0,62}(\\.[a-z][a-z0-9_-]{0,62})+/[0-9a-f]{8}-[0-9a-f]{4}-[1345678][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.json$"},
          "record_id": {"type": "string", "format": "uuid", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},
          "record_schema": {"type": "string", "maxLength": 128, "pattern": "^[a-z][a-z0-9_-]{0,62}(\\.[a-z][a-z0-9_-]{0,62})+/[a-z][a-z0-9_-]{0,62}$", "x-wayjournal-matches-path-domain": true}
        }
      }
    },
    "request_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "schema": {"const": "wayjournal.batch/v1"}
  }
}
"#;

#[must_use]
pub fn generated_schemas() -> [(&'static str, &'static str); 2] {
    [
        ("wayjournal.record.v1.json", RECORD_SCHEMA),
        ("wayjournal.batch.v1.json", BATCH_SCHEMA),
    ]
}
