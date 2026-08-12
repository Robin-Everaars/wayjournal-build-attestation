use std::collections::BTreeSet;

use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    ActorId, BatchId, DomainId, EntityId, KindId, RecordId, RecordSchemaId, RecordTimestamp,
    json::{StrictJsonError, decode_strict, encode_pretty},
};

pub const RECORD_SCHEMA_V1: &str = "wayjournal.record/v1";
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
const ENVELOPE_FIELDS: [&str; 11] = [
    "actor",
    "batch_id",
    "domain",
    "entity_id",
    "kind",
    "occurred_at",
    "parents",
    "payload",
    "record_id",
    "record_schema",
    "recorded_at",
];

pub type DomainValidator = fn(&KindId, &Value) -> Result<(), String>;

#[derive(Debug, Clone, Copy)]
pub struct DomainRegistration {
    domain: &'static str,
    schema: &'static str,
    kinds: &'static [&'static str],
    validator: DomainValidator,
}

impl DomainRegistration {
    #[must_use]
    pub const fn new(
        domain: &'static str,
        schema: &'static str,
        kinds: &'static [&'static str],
        validator: DomainValidator,
    ) -> Self {
        Self {
            domain,
            schema,
            kinds,
            validator,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RegistryError {
    #[error("invalid compile-time domain registration {0}: {1}")]
    InvalidRegistration(&'static str, String),
    #[error("duplicate domain/schema registration: {domain}/{schema}")]
    DuplicateRegistration {
        domain: &'static str,
        schema: &'static str,
    },
    #[error("domain registration has duplicate or invalid kind: {0}")]
    InvalidKind(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub struct DomainRegistry {
    registrations: &'static [DomainRegistration],
}

impl DomainRegistry {
    /// Constructs a registry from linked, static domain declarations.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if declarations are invalid or ambiguous.
    pub fn new(registrations: &'static [DomainRegistration]) -> Result<Self, RegistryError> {
        let mut pairs = BTreeSet::new();
        for registration in registrations {
            registration.domain.parse::<DomainId>().map_err(|error| {
                RegistryError::InvalidRegistration(registration.domain, error.to_string())
            })?;
            registration
                .schema
                .parse::<RecordSchemaId>()
                .map_err(|error| {
                    RegistryError::InvalidRegistration(registration.schema, error.to_string())
                })?;
            if registration
                .schema
                .split_once('/')
                .map(|(domain, _)| domain)
                != Some(registration.domain)
            {
                return Err(RegistryError::InvalidRegistration(
                    registration.schema,
                    "schema prefix must equal its registered domain".to_owned(),
                ));
            }
            if !pairs.insert((registration.domain, registration.schema)) {
                return Err(RegistryError::DuplicateRegistration {
                    domain: registration.domain,
                    schema: registration.schema,
                });
            }
            let mut kinds = BTreeSet::new();
            for kind in registration.kinds {
                if kind.parse::<KindId>().is_err() || !kinds.insert(*kind) {
                    return Err(RegistryError::InvalidKind(kind));
                }
            }
        }
        Ok(Self { registrations })
    }

    fn validate(
        &self,
        domain: &DomainId,
        schema: &RecordSchemaId,
        kind: &KindId,
        payload: &Value,
    ) -> Result<(), RecordCodecError> {
        let Some(registration) = self.registrations.iter().find(|registration| {
            registration.domain == domain.as_str() && registration.schema == schema.as_str()
        }) else {
            return Err(RecordCodecError::UnknownDomainSchema {
                domain: domain.to_string(),
                schema: schema.to_string(),
            });
        };
        if !registration.kinds.contains(&kind.as_str()) {
            return Err(RecordCodecError::UnknownKind {
                schema: schema.to_string(),
                kind: kind.to_string(),
            });
        }
        (registration.validator)(kind, payload).map_err(RecordCodecError::InvalidPayload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub record_schema: RecordSchemaId,
    pub domain: DomainId,
    pub kind: KindId,
    pub record_id: RecordId,
    pub entity_id: EntityId,
    pub batch_id: BatchId,
    pub actor: ActorId,
    pub occurred_at: RecordTimestamp,
    pub recorded_at: RecordTimestamp,
    pub parents: Vec<RecordId>,
    pub payload: Value,
}

impl Record {
    #[must_use]
    pub fn canonical_path(&self) -> String {
        format!(
            "journal/records/{}/{}/{}.json",
            self.domain, self.entity_id, self.record_id
        )
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RecordCodecError {
    #[error("record exceeds the {MAX_RECORD_BYTES}-byte limit")]
    RecordTooLarge,
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("duplicate JSON object key: {0}")]
    DuplicateKey(String),
    #[error("floating-point JSON numbers are not allowed")]
    FloatNotAllowed,
    #[error("record envelope must be a JSON object")]
    EnvelopeNotObject,
    #[error("missing record envelope field: {0}")]
    MissingField(&'static str),
    #[error("unknown record envelope field: {0}")]
    UnknownField(String),
    #[error("invalid record field {field}: {message}")]
    InvalidField {
        field: &'static str,
        message: String,
    },
    #[error("unsupported record envelope schema: {0}")]
    UnsupportedSchema(String),
    #[error("unknown domain/schema pair: {domain}/{schema}")]
    UnknownDomainSchema { domain: String, schema: String },
    #[error("unknown kind {kind} for schema {schema}")]
    UnknownKind { schema: String, kind: String },
    #[error("invalid domain payload: {0}")]
    InvalidPayload(String),
    #[error("causal parents must be sorted and duplicate-free")]
    InvalidParents,
    #[error("record JSON is not in canonical form")]
    NonCanonical,
}

impl From<StrictJsonError> for RecordCodecError {
    fn from(error: StrictJsonError) -> Self {
        match error {
            StrictJsonError::Invalid(message) => Self::InvalidJson(message),
            StrictJsonError::DuplicateKey(key) => Self::DuplicateKey(key),
            StrictJsonError::FloatNotAllowed => Self::FloatNotAllowed,
        }
    }
}

/// Encodes and validates a closed canonical `wayjournal.record/v1` envelope.
///
/// # Errors
/// Returns [`RecordCodecError`] for invalid types, domain payloads, bounds, or causal order.
pub fn encode_record(
    record: &Record,
    registry: &DomainRegistry,
) -> Result<Vec<u8>, RecordCodecError> {
    validate_record(record, registry)?;
    let mut object = Map::new();
    object.insert("actor".to_owned(), Value::String(record.actor.to_string()));
    object.insert(
        "batch_id".to_owned(),
        Value::String(record.batch_id.to_string()),
    );
    object.insert(
        "domain".to_owned(),
        Value::String(record.domain.to_string()),
    );
    object.insert(
        "entity_id".to_owned(),
        Value::String(record.entity_id.to_string()),
    );
    object.insert("kind".to_owned(), Value::String(record.kind.to_string()));
    object.insert(
        "occurred_at".to_owned(),
        Value::String(record.occurred_at.to_string()),
    );
    object.insert(
        "parents".to_owned(),
        Value::Array(
            record
                .parents
                .iter()
                .map(ToString::to_string)
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert("payload".to_owned(), record.payload.clone());
    object.insert(
        "record_id".to_owned(),
        Value::String(record.record_id.to_string()),
    );
    object.insert(
        "record_schema".to_owned(),
        Value::String(record.record_schema.to_string()),
    );
    object.insert(
        "recorded_at".to_owned(),
        Value::String(record.recorded_at.to_string()),
    );
    object.insert(
        "schema".to_owned(),
        Value::String(RECORD_SCHEMA_V1.to_owned()),
    );
    let bytes = encode_pretty(&Value::Object(object))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordCodecError::RecordTooLarge);
    }
    Ok(bytes)
}

/// Decodes a byte-identical canonical `wayjournal.record/v1` envelope.
///
/// # Errors
/// Returns [`RecordCodecError`] for malformed, open, unbounded, or unregistered data.
pub fn decode_record(bytes: &[u8], registry: &DomainRegistry) -> Result<Record, RecordCodecError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordCodecError::RecordTooLarge);
    }
    let value = decode_strict(bytes)?;
    let record = record_from_value(value)?;
    validate_record(&record, registry)?;
    if encode_record(&record, registry)? != bytes {
        return Err(RecordCodecError::NonCanonical);
    }
    Ok(record)
}

fn validate_record(record: &Record, registry: &DomainRegistry) -> Result<(), RecordCodecError> {
    if !record.parents.windows(2).all(|pair| pair[0] < pair[1])
        || record.parents.contains(&record.record_id)
    {
        return Err(RecordCodecError::InvalidParents);
    }
    registry.validate(
        &record.domain,
        &record.record_schema,
        &record.kind,
        &record.payload,
    )
}

fn record_from_value(value: Value) -> Result<Record, RecordCodecError> {
    let Value::Object(mut object) = value else {
        return Err(RecordCodecError::EnvelopeNotObject);
    };
    let schema = take_string(&mut object, "schema")?;
    if schema != RECORD_SCHEMA_V1 {
        return Err(RecordCodecError::UnsupportedSchema(schema));
    }
    if let Some(field) = object
        .keys()
        .find(|field| !ENVELOPE_FIELDS.contains(&field.as_str()) && field.as_str() != "schema")
    {
        return Err(RecordCodecError::UnknownField(field.clone()));
    }
    let record = Record {
        record_schema: parse_string(&mut object, "record_schema")?,
        domain: parse_string(&mut object, "domain")?,
        kind: parse_string(&mut object, "kind")?,
        record_id: parse_string(&mut object, "record_id")?,
        entity_id: parse_string(&mut object, "entity_id")?,
        batch_id: parse_string(&mut object, "batch_id")?,
        actor: ActorId::parse(&take_string(&mut object, "actor")?)
            .map_err(|error| invalid_field("actor", error.to_string()))?,
        occurred_at: parse_string(&mut object, "occurred_at")?,
        recorded_at: parse_string(&mut object, "recorded_at")?,
        parents: take_string_array(&mut object, "parents")?
            .into_iter()
            .map(|parent| {
                parent.parse().map_err(|error: crate::IdentifierError| {
                    invalid_field("parents", error.to_string())
                })
            })
            .collect::<Result<_, _>>()?,
        payload: object
            .remove("payload")
            .ok_or(RecordCodecError::MissingField("payload"))?,
    };
    Ok(record)
}

fn invalid_field(field: &'static str, message: impl Into<String>) -> RecordCodecError {
    RecordCodecError::InvalidField {
        field,
        message: message.into(),
    }
}

fn take_string(
    object: &mut Map<String, Value>,
    field: &'static str,
) -> Result<String, RecordCodecError> {
    match object
        .remove(field)
        .ok_or(RecordCodecError::MissingField(field))?
    {
        Value::String(value) => Ok(value),
        _ => Err(invalid_field(field, "expected a string")),
    }
}

fn parse_string<T>(
    object: &mut Map<String, Value>,
    field: &'static str,
) -> Result<T, RecordCodecError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    take_string(object, field)?
        .parse()
        .map_err(|error: T::Err| invalid_field(field, error.to_string()))
}

fn take_string_array(
    object: &mut Map<String, Value>,
    field: &'static str,
) -> Result<Vec<String>, RecordCodecError> {
    let Value::Array(values) = object
        .remove(field)
        .ok_or(RecordCodecError::MissingField(field))?
    else {
        return Err(invalid_field(field, "expected an array of strings"));
    };
    values
        .into_iter()
        .map(|value| match value {
            Value::String(value) => Ok(value),
            _ => Err(invalid_field(field, "expected an array of strings")),
        })
        .collect()
}
