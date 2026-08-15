use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

use crate::{
    Digest, DigestError, LocalTrustBinding, LogicalStoreId, QualifiedEntityRef, RecordId,
    RecordTimestamp, StoreRevisionRef,
    hash::update_frame,
    json::{StrictJsonError, decode_strict, encode_pretty},
};

pub const REVISION_VECTOR_SCHEMA_V1: &str = "wayjournal.revision-vector/v1";
pub const VERIFIED_PROOF_SCHEMA_V1: &str = "wayjournal.verified-proof/v1";
pub const PROOF_VECTOR_SCHEMA_V1: &str = "wayjournal.proof-vector/v1";
pub const MAX_VECTOR_STORES: usize = 256;
pub const MAX_PROOFS: usize = 4_096;
pub const MAX_PROJECTION_BYTES: usize = 8 * 1024 * 1024;

const PROOF_ID_DOMAIN: &[u8] = b"wayjournal-proof-v1\0";

/// One store revision in a canonical revision vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionVectorEntry {
    store: LogicalStoreId,
    revision: StoreRevisionRef,
}

impl RevisionVectorEntry {
    #[must_use]
    pub const fn new(store: LogicalStoreId, revision: StoreRevisionRef) -> Self {
        Self { store, revision }
    }

    #[must_use]
    pub const fn store(&self) -> &LogicalStoreId {
        &self.store
    }

    #[must_use]
    pub const fn revision(&self) -> StoreRevisionRef {
        self.revision
    }
}

/// Canonical, bounded wire data describing store revisions.
///
/// A revision vector is never evidence that any listed revision is current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionVector {
    entries: Vec<RevisionVectorEntry>,
}

impl RevisionVector {
    /// Validates a strictly store-ordered, duplicate-free revision vector.
    ///
    /// # Errors
    /// Returns [`ProjectionError`] when the count or ordering invariant is violated.
    pub fn new(entries: Vec<RevisionVectorEntry>) -> Result<Self, ProjectionError> {
        validate_revision_entries(&entries)?;
        Ok(Self { entries })
    }

    #[must_use]
    pub fn entries(&self) -> &[RevisionVectorEntry] {
        &self.entries
    }
}

/// Integrity identifier for one exact verified-proof preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofId(Digest);

impl ProofId {
    /// Parses exactly 64 lowercase hexadecimal BLAKE3 digits.
    ///
    /// # Errors
    /// Returns [`DigestError`] for every noncanonical representation.
    pub fn parse(input: &str) -> Result<Self, DigestError> {
        Digest::parse(input).map(Self)
    }

    #[must_use]
    pub const fn as_digest(self) -> Digest {
        self.0
    }
}

impl fmt::Display for ProofId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ProofId {
    type Err = DigestError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl Serialize for ProofId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ProofId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// A locally verified presence projection tied to one durable admission checkpoint.
///
/// This is an integrity-bound local observation, not a signature, claim, or freshness promise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    proof_id: ProofId,
    subject: QualifiedEntityRef,
    record_id: RecordId,
    source_revision: StoreRevisionRef,
    local_trust_binding: LocalTrustBinding,
    observed_at: RecordTimestamp,
}

impl VerifiedProof {
    #[must_use]
    pub const fn proof_id(&self) -> ProofId {
        self.proof_id
    }

    #[must_use]
    pub const fn subject(&self) -> &QualifiedEntityRef {
        &self.subject
    }

    #[must_use]
    pub const fn record_id(&self) -> RecordId {
        self.record_id
    }

    #[must_use]
    pub const fn source_revision(&self) -> StoreRevisionRef {
        self.source_revision
    }

    #[must_use]
    pub const fn local_trust_binding(&self) -> LocalTrustBinding {
        self.local_trust_binding
    }

    #[must_use]
    pub const fn observed_at(&self) -> RecordTimestamp {
        self.observed_at
    }

    pub(crate) fn from_checkpoint(
        subject: QualifiedEntityRef,
        record_id: RecordId,
        source_revision: StoreRevisionRef,
        local_trust_binding: LocalTrustBinding,
        observed_at: RecordTimestamp,
    ) -> Self {
        let proof_id = compute_proof_id(
            &subject,
            record_id,
            source_revision,
            local_trust_binding,
            observed_at,
        );
        Self {
            proof_id,
            subject,
            record_id,
            source_revision,
            local_trust_binding,
            observed_at,
        }
    }

    pub(crate) fn recomputed_proof_id(&self) -> ProofId {
        compute_proof_id(
            &self.subject,
            self.record_id,
            self.source_revision,
            self.local_trust_binding,
            self.observed_at,
        )
    }
}

/// A canonical proof-id-ordered collection of verified proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofVector {
    proofs: Vec<VerifiedProof>,
}

impl ProofVector {
    /// Validates a strictly proof-id-ordered, duplicate-free proof vector.
    ///
    /// # Errors
    /// Returns [`ProjectionError`] when the count or ordering invariant is violated.
    pub fn new(proofs: Vec<VerifiedProof>) -> Result<Self, ProjectionError> {
        validate_proofs(&proofs)?;
        Ok(Self { proofs })
    }

    #[must_use]
    pub fn proofs(&self) -> &[VerifiedProof] {
        &self.proofs
    }
}

/// Consumer-owned reference useful when recording a contradiction or invalidation.
///
/// This helper deliberately has no Serde implementation or Wayjournal wire schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContradictionRef {
    proof_id: ProofId,
    source_store: LogicalStoreId,
    source_revision: StoreRevisionRef,
}

impl ContradictionRef {
    #[must_use]
    pub const fn new(
        proof_id: ProofId,
        source_store: LogicalStoreId,
        source_revision: StoreRevisionRef,
    ) -> Self {
        Self {
            proof_id,
            source_store,
            source_revision,
        }
    }

    #[must_use]
    pub const fn proof_id(&self) -> ProofId {
        self.proof_id
    }

    #[must_use]
    pub const fn source_store(&self) -> &LogicalStoreId {
        &self.source_store
    }

    #[must_use]
    pub const fn source_revision(&self) -> StoreRevisionRef {
        self.source_revision
    }
}

#[derive(Debug, Error)]
pub enum ProofError {
    #[error(transparent)]
    Store(#[from] crate::StoreError),
    #[error(transparent)]
    Checkpoint(#[from] crate::CheckpointError),
    #[error("a current durable admission checkpoint is required")]
    MissingCheckpoint,
    #[error("a strict initialized store identity is required")]
    MissingIdentity,
    #[error("checkpoint, snapshot, and proof-subject identities do not match")]
    IdentityMismatch,
    #[error("checkpoint accepted revision does not equal the canonical snapshot revision")]
    RevisionMismatch,
    #[error("the requested record is absent from the canonical snapshot")]
    RecordNotFound,
    #[error("the requested record domain or entity does not match the proof subject")]
    SubjectMismatch,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    #[error("projection exceeds the {MAX_PROJECTION_BYTES}-byte limit")]
    TooLarge,
    #[error("revision vector exceeds the {MAX_VECTOR_STORES}-store limit")]
    TooManyStores,
    #[error("proof vector exceeds the {MAX_PROOFS}-proof limit")]
    TooManyProofs,
    #[error("invalid projection JSON: {0}")]
    InvalidJson(String),
    #[error("duplicate JSON object key: {0}")]
    DuplicateKey(String),
    #[error("floating-point JSON numbers are not allowed")]
    FloatNotAllowed,
    #[error("invalid closed projection document: {0}")]
    InvalidDocument(String),
    #[error("unsupported projection schema")]
    UnsupportedSchema,
    #[error("revision vector entries must be strictly ordered and unique by logical store")]
    InvalidRevisionOrder,
    #[error("proof vector entries must be strictly ordered and unique by proof id")]
    InvalidProofOrder,
    #[error("verified proof id does not equal its recomputed preimage hash")]
    ProofIdMismatch,
    #[error("projection JSON is not in canonical form")]
    NonCanonical,
}

impl From<StrictJsonError> for ProjectionError {
    fn from(error: StrictJsonError) -> Self {
        match error {
            StrictJsonError::Invalid(message) => Self::InvalidJson(message),
            StrictJsonError::DuplicateKey(key) => Self::DuplicateKey(key),
            StrictJsonError::FloatNotAllowed => Self::FloatNotAllowed,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRevisionVectorEntry {
    revision: StoreRevisionRef,
    store: LogicalStoreId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRevisionVector {
    entries: Vec<RawRevisionVectorEntry>,
    schema: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVerifiedProof {
    local_trust_binding: LocalTrustBinding,
    observed_at: RecordTimestamp,
    proof_id: ProofId,
    record_id: RecordId,
    schema: String,
    source_revision: StoreRevisionRef,
    subject: QualifiedEntityRef,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProofVector {
    proofs: Vec<RawVerifiedProof>,
    schema: String,
}

impl From<&RevisionVectorEntry> for RawRevisionVectorEntry {
    fn from(entry: &RevisionVectorEntry) -> Self {
        Self {
            revision: entry.revision,
            store: entry.store.clone(),
        }
    }
}

impl From<RawRevisionVectorEntry> for RevisionVectorEntry {
    fn from(entry: RawRevisionVectorEntry) -> Self {
        Self::new(entry.store, entry.revision)
    }
}

impl From<&VerifiedProof> for RawVerifiedProof {
    fn from(proof: &VerifiedProof) -> Self {
        Self {
            local_trust_binding: proof.local_trust_binding,
            observed_at: proof.observed_at,
            proof_id: proof.proof_id,
            record_id: proof.record_id,
            schema: VERIFIED_PROOF_SCHEMA_V1.to_owned(),
            source_revision: proof.source_revision,
            subject: proof.subject.clone(),
        }
    }
}

impl TryFrom<RawVerifiedProof> for VerifiedProof {
    type Error = ProjectionError;

    fn try_from(raw: RawVerifiedProof) -> Result<Self, Self::Error> {
        if raw.schema != VERIFIED_PROOF_SCHEMA_V1 {
            return Err(ProjectionError::UnsupportedSchema);
        }
        let proof = Self {
            proof_id: raw.proof_id,
            subject: raw.subject,
            record_id: raw.record_id,
            source_revision: raw.source_revision,
            local_trust_binding: raw.local_trust_binding,
            observed_at: raw.observed_at,
        };
        if proof.proof_id != proof.recomputed_proof_id() {
            return Err(ProjectionError::ProofIdMismatch);
        }
        Ok(proof)
    }
}

/// Encodes the exact canonical `wayjournal.revision-vector/v1` wire representation.
///
/// # Errors
/// Returns [`ProjectionError`] for invalid ordering, bounds, or serialization failures.
pub fn encode_revision_vector(vector: &RevisionVector) -> Result<Vec<u8>, ProjectionError> {
    validate_revision_entries(&vector.entries)?;
    encode_raw(&RawRevisionVector {
        entries: vector.entries.iter().map(Into::into).collect(),
        schema: REVISION_VECTOR_SCHEMA_V1.to_owned(),
    })
}

/// Decodes byte-identical canonical `wayjournal.revision-vector/v1` wire data.
///
/// # Errors
/// Rejects malformed, open, unbounded, noncanonical, unsorted, or duplicate data.
pub fn decode_revision_vector(bytes: &[u8]) -> Result<RevisionVector, ProjectionError> {
    require_size(bytes)?;
    let value = decode_strict(bytes)?;
    let raw: RawRevisionVector = serde_json::from_value(value)
        .map_err(|error| ProjectionError::InvalidDocument(error.to_string()))?;
    if raw.schema != REVISION_VECTOR_SCHEMA_V1 {
        return Err(ProjectionError::UnsupportedSchema);
    }
    if raw.entries.len() > MAX_VECTOR_STORES {
        return Err(ProjectionError::TooManyStores);
    }
    let vector = RevisionVector::new(raw.entries.into_iter().map(Into::into).collect())?;
    if encode_revision_vector(&vector)? != bytes {
        return Err(ProjectionError::NonCanonical);
    }
    Ok(vector)
}

/// Encodes the exact canonical `wayjournal.verified-proof/v1` wire representation.
///
/// # Errors
/// Returns [`ProjectionError`] if the proof hash or encoded size is invalid.
pub fn encode_verified_proof(proof: &VerifiedProof) -> Result<Vec<u8>, ProjectionError> {
    if proof.proof_id != proof.recomputed_proof_id() {
        return Err(ProjectionError::ProofIdMismatch);
    }
    encode_raw(&RawVerifiedProof::from(proof))
}

/// Decodes a byte-identical canonical `wayjournal.verified-proof/v1` proof.
///
/// The proof id is always recomputed from the other ten fields.
///
/// # Errors
/// Rejects malformed, open, unbounded, noncanonical, or hash-mismatched data.
pub fn decode_verified_proof(bytes: &[u8]) -> Result<VerifiedProof, ProjectionError> {
    require_size(bytes)?;
    let value = decode_strict(bytes)?;
    let raw: RawVerifiedProof = serde_json::from_value(value)
        .map_err(|error| ProjectionError::InvalidDocument(error.to_string()))?;
    let proof = VerifiedProof::try_from(raw)?;
    if encode_verified_proof(&proof)? != bytes {
        return Err(ProjectionError::NonCanonical);
    }
    Ok(proof)
}

/// Encodes the exact canonical `wayjournal.proof-vector/v1` wire representation.
///
/// # Errors
/// Returns [`ProjectionError`] for invalid ordering, proof hashes, bounds, or serialization.
pub fn encode_proof_vector(vector: &ProofVector) -> Result<Vec<u8>, ProjectionError> {
    validate_proofs(&vector.proofs)?;
    encode_raw(&RawProofVector {
        proofs: vector.proofs.iter().map(Into::into).collect(),
        schema: PROOF_VECTOR_SCHEMA_V1.to_owned(),
    })
}

/// Decodes byte-identical canonical `wayjournal.proof-vector/v1` wire data.
///
/// # Errors
/// Rejects malformed, open, unbounded, noncanonical, unsorted, duplicate, or hash-mismatched data.
pub fn decode_proof_vector(bytes: &[u8]) -> Result<ProofVector, ProjectionError> {
    require_size(bytes)?;
    let value = decode_strict(bytes)?;
    let raw: RawProofVector = serde_json::from_value(value)
        .map_err(|error| ProjectionError::InvalidDocument(error.to_string()))?;
    if raw.schema != PROOF_VECTOR_SCHEMA_V1 {
        return Err(ProjectionError::UnsupportedSchema);
    }
    if raw.proofs.len() > MAX_PROOFS {
        return Err(ProjectionError::TooManyProofs);
    }
    let proofs = raw
        .proofs
        .into_iter()
        .map(VerifiedProof::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let vector = ProofVector::new(proofs)?;
    if encode_proof_vector(&vector)? != bytes {
        return Err(ProjectionError::NonCanonical);
    }
    Ok(vector)
}

fn encode_raw(value: &impl Serialize) -> Result<Vec<u8>, ProjectionError> {
    let value = serde_json::to_value(value)
        .map_err(|error| ProjectionError::InvalidDocument(error.to_string()))?;
    let bytes = encode_pretty(&value)?;
    require_size(&bytes)?;
    Ok(bytes)
}

fn require_size(bytes: &[u8]) -> Result<(), ProjectionError> {
    if bytes.len() > MAX_PROJECTION_BYTES {
        Err(ProjectionError::TooLarge)
    } else {
        Ok(())
    }
}

fn validate_revision_entries(entries: &[RevisionVectorEntry]) -> Result<(), ProjectionError> {
    if entries.len() > MAX_VECTOR_STORES {
        return Err(ProjectionError::TooManyStores);
    }
    if !entries.windows(2).all(|pair| pair[0].store < pair[1].store) {
        return Err(ProjectionError::InvalidRevisionOrder);
    }
    Ok(())
}

fn validate_proofs(proofs: &[VerifiedProof]) -> Result<(), ProjectionError> {
    if proofs.len() > MAX_PROOFS {
        return Err(ProjectionError::TooManyProofs);
    }
    if !proofs
        .windows(2)
        .all(|pair| pair[0].proof_id < pair[1].proof_id)
    {
        return Err(ProjectionError::InvalidProofOrder);
    }
    if proofs
        .iter()
        .any(|proof| proof.proof_id != proof.recomputed_proof_id())
    {
        return Err(ProjectionError::ProofIdMismatch);
    }
    Ok(())
}

fn compute_proof_id(
    subject: &QualifiedEntityRef,
    record_id: RecordId,
    source_revision: StoreRevisionRef,
    local_trust_binding: LocalTrustBinding,
    observed_at: RecordTimestamp,
) -> ProofId {
    let store_uuid = subject.store.store_uuid().to_string();
    let genesis_fingerprint = subject.store.genesis_fingerprint().to_string();
    let entity_id = subject.entity_id.to_string();
    let record_id = record_id.to_string();
    let source_digest = source_revision.digest().to_string();
    let local_trust_binding = local_trust_binding.as_digest().to_string();
    let observed_at = observed_at.to_string();

    let mut hasher = blake3::Hasher::new();
    hasher.update(PROOF_ID_DOMAIN);
    for field in [
        VERIFIED_PROOF_SCHEMA_V1.as_bytes(),
        store_uuid.as_bytes(),
        genesis_fingerprint.as_bytes(),
        subject.domain.as_str().as_bytes(),
        entity_id.as_bytes(),
        record_id.as_bytes(),
        source_revision.algorithm().as_str().as_bytes(),
        source_digest.as_bytes(),
        local_trust_binding.as_bytes(),
        observed_at.as_bytes(),
    ] {
        update_frame(&mut hasher, field);
    }
    ProofId(Digest::from_hash(hasher.finalize()))
}
