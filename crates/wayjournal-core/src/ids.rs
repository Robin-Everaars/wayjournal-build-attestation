use std::{fmt, str::FromStr};

use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use uuid::{Uuid, Variant};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentifierError {
    #[error("invalid {kind}: {value}")]
    InvalidUuid { kind: &'static str, value: String },
    #[error("invalid {kind}: {value}")]
    InvalidToken { kind: &'static str, value: String },
    #[error("invalid actor id: {0}")]
    InvalidActor(String),
    #[error("timestamp is not canonical RFC3339 UTC: {0}")]
    InvalidTimestamp(String),
}

fn parse_uuid(
    input: &str,
    kind: &'static str,
    accepted_versions: &[usize],
) -> Result<Uuid, IdentifierError> {
    let parsed = Uuid::parse_str(input).map_err(|_| IdentifierError::InvalidUuid {
        kind,
        value: input.to_owned(),
    })?;
    if input != parsed.hyphenated().to_string()
        || parsed.is_nil()
        || parsed.get_variant() != Variant::RFC4122
        || !accepted_versions.contains(&parsed.get_version_num())
    {
        return Err(IdentifierError::InvalidUuid {
            kind,
            value: input.to_owned(),
        });
    }
    Ok(parsed)
}

macro_rules! uuid_id {
    ($name:ident, $kind:literal, [$($version:literal),+ $(,)?]) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                parse_uuid(input, $kind, &[$($version),+]).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.hyphenated().fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(de::Error::custom)
            }
        }
    };
}

uuid_id!(RecordId, "record id", [7]);
uuid_id!(BatchId, "batch id", [7]);
uuid_id!(EntityId, "entity id", [1, 3, 4, 5, 6, 7, 8]);

fn valid_segment(input: &str, max: usize) -> bool {
    !input.is_empty()
        && input.len() <= max
        && input.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' => true,
            b'0'..=b'9' | b'_' | b'-' => index > 0,
            _ => false,
        })
}

fn parse_namespaced_token(
    input: &str,
    separator: char,
    kind: &'static str,
) -> Result<String, IdentifierError> {
    let valid = input.len() <= 128
        && input.split(separator).count() >= 2
        && input
            .split(separator)
            .all(|segment| valid_segment(segment, 63));
    if valid {
        Ok(input.to_owned())
    } else {
        Err(IdentifierError::InvalidToken {
            kind,
            value: input.to_owned(),
        })
    }
}

macro_rules! token_id {
    ($name:ident, $kind:literal, $separator:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                parse_namespaced_token(input, $separator, $kind).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(de::Error::custom)
            }
        }
    };
}

token_id!(DomainId, "domain id", '.');
token_id!(KindId, "kind id", '.');

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordSchemaId(String);

impl RecordSchemaId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RecordSchemaId {
    type Err = IdentifierError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let valid = input.len() <= 128
            && input.split_once('/').is_some_and(|(domain, version)| {
                !version.contains('/')
                    && domain.parse::<DomainId>().is_ok()
                    && valid_segment(version, 63)
            });
        if valid {
            Ok(Self(input.to_owned()))
        } else {
            Err(IdentifierError::InvalidToken {
                kind: "record schema id",
                value: input.to_owned(),
            })
        }
    }
}

impl fmt::Display for RecordSchemaId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for RecordSchemaId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RecordSchemaId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActorId(String);

impl ActorId {
    /// Parses a bounded, namespaced, self-asserted actor label.
    ///
    /// # Errors
    /// Returns [`IdentifierError`] for malformed or unbounded labels.
    pub fn parse(input: &str) -> Result<Self, IdentifierError> {
        let Some((namespace, value)) = input.split_once(':') else {
            return Err(IdentifierError::InvalidActor(input.to_owned()));
        };
        let valid_value = !value.is_empty()
            && value.chars().count() <= 96
            && value
                .chars()
                .all(|character| !character.is_control() && !character.is_whitespace());
        if !valid_segment(namespace, 32) || !valid_value || input.chars().count() > 129 {
            return Err(IdentifierError::InvalidActor(input.to_owned()));
        }
        Ok(Self(input.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActorId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for ActorId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ActorId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordTimestamp(Timestamp);

impl FromStr for RecordTimestamp {
    type Err = IdentifierError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let timestamp: Timestamp = input
            .parse()
            .map_err(|_| IdentifierError::InvalidTimestamp(input.to_owned()))?;
        if timestamp.to_string() != input || !input.ends_with('Z') {
            return Err(IdentifierError::InvalidTimestamp(input.to_owned()));
        }
        Ok(Self(timestamp))
    }
}

impl fmt::Display for RecordTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for RecordTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RecordTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}
