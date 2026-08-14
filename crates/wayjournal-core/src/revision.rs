use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

use crate::{Digest, DigestError, PathClass, classify_path, hash::update_frame};

pub const REVISION_ALGORITHM_V1: &str = "wayjournal.store/blake3-framed-v1";
pub const LEGACY_REVISION_ALGORITHM_V1: &str = "waytask.store/blake3-framed-v1";
const STORE_REVISION_DOMAIN: &[u8] = b"wayjournal-store-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevisionAlgorithm {
    WayjournalBlake3FramedV1,
    WaytaskBlake3FramedV1,
}

impl RevisionAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WayjournalBlake3FramedV1 => REVISION_ALGORITHM_V1,
            Self::WaytaskBlake3FramedV1 => LEGACY_REVISION_ALGORITHM_V1,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unsupported revision algorithm: {0}")]
pub struct RevisionAlgorithmError(String);

impl std::str::FromStr for RevisionAlgorithm {
    type Err = RevisionAlgorithmError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            REVISION_ALGORITHM_V1 => Ok(Self::WayjournalBlake3FramedV1),
            LEGACY_REVISION_ALGORITHM_V1 => Ok(Self::WaytaskBlake3FramedV1),
            _ => Err(RevisionAlgorithmError(input.to_owned())),
        }
    }
}

impl fmt::Display for RevisionAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

impl Serialize for RevisionAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RevisionAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRevisionRef {
    algorithm: RevisionAlgorithm,
    digest: Digest,
}

impl StoreRevisionRef {
    /// Parses a typed exact revision algorithm and canonical digest.
    ///
    /// # Errors
    /// Returns [`StoreRevisionParseError`] for unknown algorithms or noncanonical digests.
    pub fn parse(algorithm: &str, digest: &str) -> Result<Self, StoreRevisionParseError> {
        Ok(Self {
            algorithm: algorithm.parse()?,
            digest: Digest::parse(digest)?,
        })
    }

    #[must_use]
    pub const fn algorithm(self) -> RevisionAlgorithm {
        self.algorithm
    }
    #[must_use]
    pub const fn digest(self) -> Digest {
        self.digest
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoreRevisionParseError {
    #[error(transparent)]
    Algorithm(#[from] RevisionAlgorithmError),
    #[error(transparent)]
    Digest(#[from] DigestError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionEntry {
    path: Vec<u8>,
    bytes: Vec<u8>,
    regular: bool,
}

impl RevisionEntry {
    #[must_use]
    pub fn regular(path: impl Into<Vec<u8>>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            bytes: bytes.into(),
            regular: true,
        }
    }

    #[must_use]
    pub fn nonregular(path: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            bytes: Vec::new(),
            regular: false,
        }
    }

    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RevisionError {
    #[error("duplicate raw revision path: {0:?}")]
    DuplicatePath(Vec<u8>),
    #[error("invalid path below a reserved root: {0:?}")]
    InvalidCanonicalPath(Vec<u8>),
    #[error("nonregular path below a reserved root: {0:?}")]
    NonRegularCanonicalPath(Vec<u8>),
    #[error("canonical revision path is not strictly ordered: {0:?}")]
    NonCanonicalOrder(Vec<u8>),
}

pub(crate) struct CanonicalRevisionAccumulator {
    hasher: blake3::Hasher,
    previous_path: Option<Vec<u8>>,
}

impl CanonicalRevisionAccumulator {
    pub(crate) fn new() -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(STORE_REVISION_DOMAIN);
        Self {
            hasher,
            previous_path: None,
        }
    }

    pub(crate) fn push(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), RevisionError> {
        if !matches!(
            classify_path(path),
            PathClass::LegacyEvent
                | PathClass::LegacyBatch
                | PathClass::JournalRecord
                | PathClass::JournalBatch
        ) {
            return Err(RevisionError::InvalidCanonicalPath(path.to_vec()));
        }
        if let Some(previous) = self.previous_path.as_deref() {
            if previous == path {
                return Err(RevisionError::DuplicatePath(path.to_vec()));
            }
            if previous > path {
                return Err(RevisionError::NonCanonicalOrder(path.to_vec()));
            }
        }
        update_frame(&mut self.hasher, path);
        update_frame(&mut self.hasher, bytes);
        self.previous_path = Some(path.to_vec());
        Ok(())
    }

    pub(crate) fn finish(self) -> StoreRevisionRef {
        StoreRevisionRef {
            algorithm: RevisionAlgorithm::WayjournalBlake3FramedV1,
            digest: Digest::from_hash(self.hasher.finalize()),
        }
    }
}

/// Computes `wayjournal.store/blake3-framed-v1` over all four canonical roots.
///
/// Input order is ignored. Non-authoritative paths are excluded. Invalid or nonregular
/// reserved paths and duplicate raw paths fail closed.
///
/// # Errors
/// Returns [`RevisionError`] for duplicate, invalid, or nonregular canonical entries.
pub fn compute_store_revision(
    entries: impl IntoIterator<Item = RevisionEntry>,
) -> Result<StoreRevisionRef, RevisionError> {
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if let Some(path) = entries
        .windows(2)
        .find(|pair| pair[0].path == pair[1].path)
        .map(|pair| pair[0].path.clone())
    {
        return Err(RevisionError::DuplicatePath(path));
    }
    let mut accumulator = CanonicalRevisionAccumulator::new();
    for entry in &entries {
        match classify_path(&entry.path) {
            PathClass::InvalidReserved => {
                return Err(RevisionError::InvalidCanonicalPath(entry.path.clone()));
            }
            PathClass::LegacyEvent
            | PathClass::LegacyBatch
            | PathClass::JournalRecord
            | PathClass::JournalBatch => {
                if !entry.regular {
                    return Err(RevisionError::NonRegularCanonicalPath(entry.path.clone()));
                }
                accumulator.push(&entry.path, &entry.bytes)?;
            }
            PathClass::NonCanonical => {}
        }
    }
    Ok(accumulator.finish())
}

#[cfg(test)]
mod streaming_tests {
    use super::{CanonicalRevisionAccumulator, RevisionEntry, compute_store_revision};

    #[test]
    fn canonical_revision_accumulator_matches_sorted_revision_without_retaining_bytes() {
        let entries = [
            (
                b"batches/01913f1d-8e2a-7c30-8f4a-426614174012.json".as_slice(),
                b"batch".as_slice(),
            ),
            (
                b"events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json"
                    .as_slice(),
                b"event".as_slice(),
            ),
        ];
        let expected = compute_store_revision(
            entries
                .iter()
                .map(|(path, bytes)| RevisionEntry::regular(*path, *bytes)),
        )
        .expect("revision");
        let mut accumulator = CanonicalRevisionAccumulator::new();
        for (path, bytes) in entries {
            accumulator.push(path, bytes).expect("ordered entry");
        }

        assert_eq!(accumulator.finish(), expected);
    }

    #[test]
    fn canonical_revision_accumulator_rejects_duplicate_and_out_of_order_paths() {
        let later =
            b"events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174002.json";
        let earlier = b"batches/01913f1d-8e2a-7c30-8f4a-426614174012.json";
        let mut duplicate = CanonicalRevisionAccumulator::new();
        duplicate.push(later, b"one").expect("first");
        assert!(duplicate.push(later, b"two").is_err());
        let mut unordered = CanonicalRevisionAccumulator::new();
        unordered.push(later, b"one").expect("first");
        assert!(unordered.push(earlier, b"two").is_err());
    }
}
