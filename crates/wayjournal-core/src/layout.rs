use thiserror::Error;

use crate::{BatchId, DomainId, EntityId, RecordId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    LegacyEvent,
    LegacyBatch,
    JournalRecord,
    JournalBatch,
    NonCanonical,
    InvalidReserved,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid reserved canonical path: {0:?}")]
pub struct PathError(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath(Vec<u8>, PathClass);

impl CanonicalPath {
    /// Parses one exact path beneath a frozen legacy or generic journal root.
    ///
    /// # Errors
    /// Returns [`PathError`] for noncanonical or malformed reserved paths.
    pub fn parse(path: &[u8]) -> Result<Self, PathError> {
        let class = classify_path(path);
        match class {
            PathClass::LegacyEvent
            | PathClass::LegacyBatch
            | PathClass::JournalRecord
            | PathClass::JournalBatch => Ok(Self(path.to_vec(), class)),
            PathClass::NonCanonical | PathClass::InvalidReserved => Err(PathError(path.to_vec())),
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[must_use]
    pub const fn class(&self) -> PathClass {
        self.1
    }
}

#[must_use]
pub fn classify_path(path: &[u8]) -> PathClass {
    let Ok(path) = std::str::from_utf8(path) else {
        return if reserved_prefix_bytes(path) {
            PathClass::InvalidReserved
        } else {
            PathClass::NonCanonical
        };
    };
    if path.starts_with("events/") {
        return if valid_legacy_event(path) {
            PathClass::LegacyEvent
        } else {
            PathClass::InvalidReserved
        };
    }
    if path == "events" {
        return PathClass::InvalidReserved;
    }
    if path.starts_with("batches/") {
        return if valid_legacy_batch(path) {
            PathClass::LegacyBatch
        } else {
            PathClass::InvalidReserved
        };
    }
    if path == "batches" {
        return PathClass::InvalidReserved;
    }
    if path.starts_with("journal/records/") {
        return if valid_journal_record(path) {
            PathClass::JournalRecord
        } else {
            PathClass::InvalidReserved
        };
    }
    if path.starts_with("journal/batches/") {
        return if valid_journal_batch(path) {
            PathClass::JournalBatch
        } else {
            PathClass::InvalidReserved
        };
    }
    if path == "journal" || path.starts_with("journal/") {
        return PathClass::InvalidReserved;
    }
    PathClass::NonCanonical
}

fn reserved_prefix_bytes(path: &[u8]) -> bool {
    path == b"events"
        || path.starts_with(b"events/")
        || path == b"batches"
        || path.starts_with(b"batches/")
        || path == b"journal"
        || path.starts_with(b"journal/")
}

fn valid_legacy_event(path: &str) -> bool {
    let parts = path.split('/').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0] == "events"
        && valid_legacy_uuid(parts[1], &[4, 5, 7])
        && parts[2]
            .strip_suffix(".json")
            .is_some_and(|id| id.parse::<RecordId>().is_ok())
}

fn valid_legacy_batch(path: &str) -> bool {
    let parts = path.split('/').collect::<Vec<_>>();
    parts.len() == 2
        && parts[0] == "batches"
        && parts[1]
            .strip_suffix(".json")
            .is_some_and(|id| id.parse::<BatchId>().is_ok())
}

fn valid_legacy_uuid(input: &str, versions: &[usize]) -> bool {
    uuid::Uuid::parse_str(input).is_ok_and(|id| {
        input == id.hyphenated().to_string()
            && !id.is_nil()
            && id.get_variant() == uuid::Variant::RFC4122
            && versions.contains(&id.get_version_num())
    })
}

fn valid_journal_record(path: &str) -> bool {
    validate_journal_record_path(path)
}

fn valid_journal_batch(path: &str) -> bool {
    let parts = path.split('/').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0] == "journal"
        && parts[1] == "batches"
        && parts[2]
            .strip_suffix(".json")
            .is_some_and(|id| id.parse::<BatchId>().is_ok())
}

pub(crate) fn validate_journal_record_path(path: &str) -> bool {
    let parts = path.split('/').collect::<Vec<_>>();
    parts.len() == 5
        && parts[0] == "journal"
        && parts[1] == "records"
        && parts[2].parse::<DomainId>().is_ok()
        && parts[3].parse::<EntityId>().is_ok()
        && parts[4]
            .strip_suffix(".json")
            .is_some_and(|id| id.parse::<RecordId>().is_ok())
}
