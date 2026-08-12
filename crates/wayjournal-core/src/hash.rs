use std::{cmp::Ordering, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(blake3::Hash);

impl Digest {
    pub(crate) const fn from_hash(hash: blake3::Hash) -> Self {
        Self(hash)
    }

    /// Parses exactly 64 lowercase hexadecimal BLAKE3 digits.
    ///
    /// # Errors
    /// Returns [`DigestError`] for any other representation.
    pub fn parse(input: &str) -> Result<Self, DigestError> {
        if input.len() != 64
            || !input
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DigestError::NonCanonical(input.to_owned()));
        }
        blake3::Hash::from_hex(input)
            .map(Self)
            .map_err(|_| DigestError::NonCanonical(input.to_owned()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Digest {
    type Err = DigestError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl PartialOrd for Digest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Digest {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DigestError {
    #[error("digest is not 64 lowercase hexadecimal digits: {0}")]
    NonCanonical(String),
}

pub(crate) fn hash_bytes(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest::from_hash(hasher.finalize())
}

pub(crate) fn framed_hash<'a>(
    domain: &[u8],
    entries: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for (left, right) in entries {
        update_frame(&mut hasher, left);
        update_frame(&mut hasher, right);
    }
    Digest::from_hash(hasher.finalize())
}

pub(crate) fn update_frame(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let length =
        u64::try_from(bytes.len()).expect("usize always fits u64 on supported Rust targets");
    hasher.update(&length.to_be_bytes());
    hasher.update(bytes);
}
