use std::fmt;

use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use thiserror::Error;

pub const JSON_CODEC_V1: &str = "wayjournal.json/v1";
const DUPLICATE_KEY_MARKER: &str = "WAYJOURNAL_DUPLICATE_KEY:";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StrictJsonError {
    #[error("invalid JSON: {0}")]
    Invalid(String),
    #[error("duplicate JSON object key: {0}")]
    DuplicateKey(String),
    #[error("floating-point JSON numbers are not allowed")]
    FloatNotAllowed,
}

pub(crate) fn decode_strict(bytes: &[u8]) -> Result<Value, StrictJsonError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let StrictValue(value) =
        StrictValue::deserialize(&mut deserializer).map_err(|error| map_error(&error))?;
    deserializer.end().map_err(|error| map_error(&error))?;
    Ok(value)
}

pub(crate) fn encode_pretty(value: &Value) -> Result<Vec<u8>, StrictJsonError> {
    reject_floats(value)?;
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| StrictJsonError::Invalid(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn reject_floats(value: &Value) -> Result<(), StrictJsonError> {
    match value {
        Value::Number(number) if !number.is_i64() && !number.is_u64() => {
            Err(StrictJsonError::FloatNotAllowed)
        }
        Value::Array(values) => values.iter().try_for_each(reject_floats),
        Value::Object(values) => values.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

fn map_error(error: &serde_json::Error) -> StrictJsonError {
    let message = error.to_string();
    if let Some(marked) = message.strip_prefix(DUPLICATE_KEY_MARKER) {
        let encoded = marked
            .rsplit_once(" at line ")
            .map_or(marked, |(key, _)| key);
        if let Ok(key) = serde_json::from_str::<String>(encoded) {
            return StrictJsonError::DuplicateKey(key);
        }
    }
    if message.starts_with("floating-point JSON numbers are not allowed") {
        return StrictJsonError::FloatNotAllowed;
    }
    StrictJsonError::Invalid(message)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate keys or floating-point numbers")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point JSON numbers are not allowed"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if values.contains_key(&key) {
                let encoded = serde_json::to_string(&key).map_err(de::Error::custom)?;
                return Err(de::Error::custom(format_args!(
                    "{DUPLICATE_KEY_MARKER}{encoded}"
                )));
            }
            let StrictValue(value) = access.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}
