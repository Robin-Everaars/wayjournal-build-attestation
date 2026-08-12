use std::fmt;

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
