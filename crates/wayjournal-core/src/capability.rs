use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

use crate::{
    AdmissionCheckpoint, GitAdmissionError, LocalTrustBinding, LogicalStoreId, Store,
    json::{StrictJsonError, decode_strict, encode_pretty},
};

pub const CAPABILITY_OFFER_SCHEMA_V1: &str = "wayjournal.capability-offer/v1";
pub const MAX_CAPABILITY_SET_ENTRIES: usize = 64;
pub const MAX_CAPABILITY_OFFER_BYTES: usize = 64 * 1024;

pub const REVISION_VECTOR_PROJECTION_ID: &str = "wayjournal.projection/revision-vector-v1";
pub const VERIFIED_PROOF_PROJECTION_ID: &str = "wayjournal.projection/verified-proof-v1";
pub const PROOF_VECTOR_PROJECTION_ID: &str = "wayjournal.projection/proof-vector-v1";

pub const GIT_UNION_CAS_CAPABILITY: &str = "wayjournal.sync/git-union-cas-v1";

/// The complete capability vocabulary implemented by S5.
pub const S5_CAPABILITIES: [&str; 16] = [
    "wayjournal.json/v1",
    "wayjournal.record/v1",
    "wayjournal.batch/v1",
    "wayjournal.layout/v1",
    "wayjournal.store/blake3-framed-v1",
    "wayjournal.identity/v1",
    "wayjournal.profile/v1",
    "wayjournal.catalog/v1",
    "wayjournal.admission-checkpoint/v1",
    GIT_UNION_CAS_CAPABILITY,
    "wayjournal.verified-proof/v1",
    "wayjournal.revision-vector/v1",
    "wayjournal.proof-vector/v1",
    "wayjournal.projection-cache/v1",
    "waytask.layout/v1",
    "waytask.store/blake3-framed-v1",
];

pub const S5_PROJECTIONS: [&str; 3] = [
    PROOF_VECTOR_PROJECTION_ID,
    REVISION_VECTOR_PROJECTION_ID,
    VERIFIED_PROOF_PROJECTION_ID,
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityIdError {
    #[error("invalid {kind}: {value}")]
    Invalid { kind: &'static str, value: String },
}

fn valid_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return false;
    }
    let Some((namespace, version)) = value.split_once('/') else {
        return false;
    };
    if version.contains('/')
        || version.is_empty()
        || version.len() > 64
        || !version.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index > 0,
            _ => false,
        })
    {
        return false;
    }
    let mut segments = namespace.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    let mut count = 1_usize;
    if !valid_namespace_segment(first) {
        return false;
    }
    for segment in segments {
        count += 1;
        if !valid_namespace_segment(segment) {
            return false;
        }
    }
    count >= 2
}

fn valid_namespace_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 63
        && segment.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' => true,
            b'0'..=b'9' | b'_' | b'-' => index > 0,
            _ => false,
        })
}

macro_rules! capability_identifier {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Parses one canonical bounded capability-style identifier.
            ///
            /// # Errors
            /// Returns [`CapabilityIdError`] unless the identifier matches the frozen grammar.
            pub fn parse(value: &str) -> Result<Self, CapabilityIdError> {
                if valid_identifier(value) {
                    Ok(Self(value.to_owned()))
                } else {
                    Err(CapabilityIdError::Invalid {
                        kind: $kind,
                        value: value.to_owned(),
                    })
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = CapabilityIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
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
                Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

capability_identifier!(CapabilityId, "capability id");
capability_identifier!(ProjectionId, "projection id");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProjectionKind {
    RevisionVector,
    VerifiedProof,
    ProofVector,
}

impl ProjectionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RevisionVector => REVISION_VECTOR_PROJECTION_ID,
            Self::VerifiedProof => VERIFIED_PROOF_PROJECTION_ID,
            Self::ProofVector => PROOF_VECTOR_PROJECTION_ID,
        }
    }

    #[must_use]
    pub fn id(self) -> ProjectionId {
        ProjectionId(self.as_str().to_owned())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityOfferError {
    #[error(transparent)]
    Identifier(#[from] CapabilityIdError),
    #[error("{set} exceeds the {MAX_CAPABILITY_SET_ENTRIES}-entry limit")]
    TooManyEntries { set: &'static str },
    #[error("{set} must be lexicographically byte-sorted and duplicate-free")]
    InvalidSetOrder { set: &'static str },
    #[error("capability offer exceeds the {MAX_CAPABILITY_OFFER_BYTES}-byte limit")]
    TooLarge,
    #[error("invalid capability-offer JSON: {0}")]
    InvalidJson(String),
    #[error("duplicate JSON object key: {0}")]
    DuplicateKey(String),
    #[error("floating-point JSON numbers are not allowed")]
    FloatNotAllowed,
    #[error("invalid closed capability offer: {0}")]
    InvalidDocument(String),
    #[error("unsupported capability-offer schema")]
    UnsupportedSchema,
    #[error("capability-offer JSON is not in canonical form")]
    NonCanonical,
    #[error("local supported capability is not part of the frozen S5 vocabulary: {0}")]
    UnknownLocalCapability(CapabilityId),
    #[error("local supported projection is not part of the frozen S5 vocabulary: {0}")]
    UnknownLocalProjection(ProjectionId),
}

impl From<StrictJsonError> for CapabilityOfferError {
    fn from(error: StrictJsonError) -> Self {
        match error {
            StrictJsonError::Invalid(message) => Self::InvalidJson(message),
            StrictJsonError::DuplicateKey(key) => Self::DuplicateKey(key),
            StrictJsonError::FloatNotAllowed => Self::FloatNotAllowed,
        }
    }
}

fn validate_set<T: Ord>(values: &[T], set: &'static str) -> Result<(), CapabilityOfferError> {
    if values.len() > MAX_CAPABILITY_SET_ENTRIES {
        return Err(CapabilityOfferError::TooManyEntries { set });
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CapabilityOfferError::InvalidSetOrder { set });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityOffer {
    logical_store_id: LogicalStoreId,
    required_capabilities: Vec<CapabilityId>,
    required_projections: Vec<ProjectionId>,
    supported_capabilities: Vec<CapabilityId>,
    supported_projections: Vec<ProjectionId>,
}

impl CapabilityOffer {
    /// Creates an exact offer without sorting or deduplicating caller input.
    ///
    /// # Errors
    /// Every set must already be strictly byte-sorted, duplicate-free, and bounded.
    pub fn new(
        logical_store_id: LogicalStoreId,
        required_capabilities: Vec<CapabilityId>,
        required_projections: Vec<ProjectionId>,
        supported_capabilities: Vec<CapabilityId>,
        supported_projections: Vec<ProjectionId>,
    ) -> Result<Self, CapabilityOfferError> {
        validate_offer_sets(
            &required_capabilities,
            &required_projections,
            &supported_capabilities,
            &supported_projections,
        )?;
        Ok(Self {
            logical_store_id,
            required_capabilities,
            required_projections,
            supported_capabilities,
            supported_projections,
        })
    }

    #[must_use]
    pub const fn logical_store_id(&self) -> &LogicalStoreId {
        &self.logical_store_id
    }

    #[must_use]
    pub fn required_capabilities(&self) -> &[CapabilityId] {
        &self.required_capabilities
    }

    #[must_use]
    pub fn required_projections(&self) -> &[ProjectionId] {
        &self.required_projections
    }

    #[must_use]
    pub fn supported_capabilities(&self) -> &[CapabilityId] {
        &self.supported_capabilities
    }

    #[must_use]
    pub fn supported_projections(&self) -> &[ProjectionId] {
        &self.supported_projections
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRequirements {
    required_capabilities: Vec<CapabilityId>,
    required_projections: Vec<ProjectionId>,
    supported_capabilities: Vec<CapabilityId>,
    supported_projections: Vec<ProjectionId>,
}

impl HandshakeRequirements {
    /// Creates validated local handshake inputs.
    ///
    /// Local supported sets are restricted to the frozen S5 vocabulary. Journal profile and
    /// catalog data therefore cannot augment these explicitly supplied sets.
    ///
    /// # Errors
    /// Every set must already be strictly byte-sorted, duplicate-free, and bounded; every local
    /// identifier must be one of the identifiers implemented by S5.
    pub fn new(
        required_capabilities: Vec<CapabilityId>,
        required_projections: Vec<ProjectionId>,
        supported_capabilities: Vec<CapabilityId>,
        supported_projections: Vec<ProjectionId>,
    ) -> Result<Self, CapabilityOfferError> {
        validate_offer_sets(
            &required_capabilities,
            &required_projections,
            &supported_capabilities,
            &supported_projections,
        )?;
        for capability in required_capabilities.iter().chain(&supported_capabilities) {
            if !known_capability(capability) {
                return Err(CapabilityOfferError::UnknownLocalCapability(
                    capability.clone(),
                ));
            }
        }
        for projection in required_projections.iter().chain(&supported_projections) {
            if !known_projection(projection) {
                return Err(CapabilityOfferError::UnknownLocalProjection(
                    projection.clone(),
                ));
            }
        }
        Ok(Self {
            required_capabilities,
            required_projections,
            supported_capabilities,
            supported_projections,
        })
    }

    #[must_use]
    pub fn required_capabilities(&self) -> &[CapabilityId] {
        &self.required_capabilities
    }

    #[must_use]
    pub fn required_projections(&self) -> &[ProjectionId] {
        &self.required_projections
    }

    #[must_use]
    pub fn supported_capabilities(&self) -> &[CapabilityId] {
        &self.supported_capabilities
    }

    #[must_use]
    pub fn supported_projections(&self) -> &[ProjectionId] {
        &self.supported_projections
    }
}

fn validate_offer_sets(
    required_capabilities: &[CapabilityId],
    required_projections: &[ProjectionId],
    supported_capabilities: &[CapabilityId],
    supported_projections: &[ProjectionId],
) -> Result<(), CapabilityOfferError> {
    validate_set(required_capabilities, "required_capabilities")?;
    validate_set(required_projections, "required_projections")?;
    validate_set(supported_capabilities, "supported_capabilities")?;
    validate_set(supported_projections, "supported_projections")
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapabilityOffer {
    logical_store_id: LogicalStoreId,
    required_capabilities: Vec<CapabilityId>,
    required_projections: Vec<ProjectionId>,
    schema: String,
    supported_capabilities: Vec<CapabilityId>,
    supported_projections: Vec<ProjectionId>,
}

/// Encodes the exact canonical `wayjournal.capability-offer/v1` wire representation.
///
/// # Errors
/// Returns [`CapabilityOfferError`] if any set invariant or encoded bound is violated.
pub fn encode_capability_offer(offer: &CapabilityOffer) -> Result<Vec<u8>, CapabilityOfferError> {
    validate_offer_sets(
        &offer.required_capabilities,
        &offer.required_projections,
        &offer.supported_capabilities,
        &offer.supported_projections,
    )?;
    let raw = RawCapabilityOffer {
        logical_store_id: offer.logical_store_id.clone(),
        required_capabilities: offer.required_capabilities.clone(),
        required_projections: offer.required_projections.clone(),
        schema: CAPABILITY_OFFER_SCHEMA_V1.to_owned(),
        supported_capabilities: offer.supported_capabilities.clone(),
        supported_projections: offer.supported_projections.clone(),
    };
    let value = serde_json::to_value(raw)
        .map_err(|error| CapabilityOfferError::InvalidDocument(error.to_string()))?;
    let bytes = encode_pretty(&value)?;
    if bytes.len() > MAX_CAPABILITY_OFFER_BYTES {
        return Err(CapabilityOfferError::TooLarge);
    }
    Ok(bytes)
}

/// Decodes byte-identical canonical `wayjournal.capability-offer/v1` wire data.
///
/// # Errors
/// Rejects malformed, open, noncanonical, unbounded, unsorted, and duplicate input.
pub fn decode_capability_offer(bytes: &[u8]) -> Result<CapabilityOffer, CapabilityOfferError> {
    if bytes.len() > MAX_CAPABILITY_OFFER_BYTES {
        return Err(CapabilityOfferError::TooLarge);
    }
    let value = decode_strict(bytes)?;
    let raw: RawCapabilityOffer = serde_json::from_value(value)
        .map_err(|error| CapabilityOfferError::InvalidDocument(error.to_string()))?;
    if raw.schema != CAPABILITY_OFFER_SCHEMA_V1 {
        return Err(CapabilityOfferError::UnsupportedSchema);
    }
    let offer = CapabilityOffer::new(
        raw.logical_store_id,
        raw.required_capabilities,
        raw.required_projections,
        raw.supported_capabilities,
        raw.supported_projections,
    )?;
    if encode_capability_offer(&offer)? != bytes {
        return Err(CapabilityOfferError::NonCanonical);
    }
    Ok(offer)
}

#[derive(Debug, Error)]
pub enum NegotiationError {
    #[error("failed to read current durable checkpoint authority: {0}")]
    CheckpointAuthority(#[source] GitAdmissionError),
    #[error("a current durable admission checkpoint is required")]
    MissingCheckpoint,
    #[error("expected store does not match the current durable checkpoint")]
    ExpectedStoreMismatch,
    #[error("remote offer identity does not match the expected store")]
    RemoteStoreMismatch,
    #[error("expected trust binding does not match the current durable checkpoint")]
    TrustMismatch,
    #[error("remote requires unknown capability: {0}")]
    UnknownRequiredCapability(CapabilityId),
    #[error("remote requires unknown projection: {0}")]
    UnknownRequiredProjection(ProjectionId),
    #[error("local required capability is not supported remotely: {0}")]
    LocalCapabilityRequirement(CapabilityId),
    #[error("remote required capability is not supported locally: {0}")]
    RemoteCapabilityRequirement(CapabilityId),
    #[error("local required projection is not supported remotely: {0}")]
    LocalProjectionRequirement(ProjectionId),
    #[error("remote required projection is not supported locally: {0}")]
    RemoteProjectionRequirement(ProjectionId),
}

/// A sealed, point-in-time result of capability negotiation.
///
/// Safe external code can clone a valid token but cannot construct or deserialize one. The
/// complete checkpoint authority used during negotiation remains private for later locked
/// revalidation by synchronization code.
#[derive(Clone, PartialEq, Eq)]
pub struct NegotiatedHandshake {
    checkpoint: AdmissionCheckpoint,
    capabilities: Vec<CapabilityId>,
    projections: Vec<ProjectionId>,
}

impl fmt::Debug for NegotiatedHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NegotiatedHandshake")
            .field("logical_store_id", self.checkpoint.logical_store_id())
            .field("capabilities", &self.capabilities)
            .field("projections", &self.projections)
            .finish_non_exhaustive()
    }
}

impl NegotiatedHandshake {
    #[must_use]
    pub const fn logical_store_id(&self) -> &LogicalStoreId {
        self.checkpoint.logical_store_id()
    }

    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }

    #[must_use]
    pub fn projections(&self) -> &[ProjectionId] {
        &self.projections
    }

    #[must_use]
    pub fn supports_capability(&self, capability: &CapabilityId) -> bool {
        self.capabilities.binary_search(capability).is_ok()
    }

    #[must_use]
    pub fn supports_projection(&self, projection: &ProjectionId) -> bool {
        self.projections.binary_search(projection).is_ok()
    }

    pub(crate) const fn bound_checkpoint(&self) -> &AdmissionCheckpoint {
        &self.checkpoint
    }

    pub(crate) fn supports_git_union_cas(&self) -> bool {
        self.capabilities
            .binary_search_by(|capability| capability.as_str().cmp(GIT_UNION_CAS_CAPABILITY))
            .is_ok()
    }
}

/// Negotiates exact bidirectional capability and projection subsets against current durable
/// checkpoint identity and trust authority.
///
/// The checkpoint is read by this function before any transfer-capable object is accepted or
/// constructed. Unknown optional remote support remains inert because only its intersection with
/// the explicitly supplied, known local support is returned.
///
/// # Errors
/// Fails closed for missing/malformed checkpoint authority, identity/trust disagreement, unknown
/// remote requirements, or any failed subset direction.
pub fn negotiate_handshake(
    store: &Store,
    expected_store: &LogicalStoreId,
    expected_trust: LocalTrustBinding,
    local: &HandshakeRequirements,
    remote: &CapabilityOffer,
) -> Result<NegotiatedHandshake, NegotiationError> {
    let checkpoint = store
        .admission_checkpoint()
        .map_err(NegotiationError::CheckpointAuthority)?
        .ok_or(NegotiationError::MissingCheckpoint)?;

    if checkpoint.logical_store_id() != expected_store {
        return Err(NegotiationError::ExpectedStoreMismatch);
    }
    if remote.logical_store_id() != expected_store {
        return Err(NegotiationError::RemoteStoreMismatch);
    }
    if *checkpoint.local_trust_binding() != expected_trust {
        return Err(NegotiationError::TrustMismatch);
    }

    for capability in remote.required_capabilities() {
        if !known_capability(capability) {
            return Err(NegotiationError::UnknownRequiredCapability(
                capability.clone(),
            ));
        }
    }
    for projection in remote.required_projections() {
        if !known_projection(projection) {
            return Err(NegotiationError::UnknownRequiredProjection(
                projection.clone(),
            ));
        }
    }

    require_subset(
        local.required_capabilities(),
        remote.supported_capabilities(),
        |identifier| NegotiationError::LocalCapabilityRequirement(identifier.clone()),
    )?;
    require_subset(
        remote.required_capabilities(),
        local.supported_capabilities(),
        |identifier| NegotiationError::RemoteCapabilityRequirement(identifier.clone()),
    )?;
    require_subset(
        local.required_projections(),
        remote.supported_projections(),
        |identifier| NegotiationError::LocalProjectionRequirement(identifier.clone()),
    )?;
    require_subset(
        remote.required_projections(),
        local.supported_projections(),
        |identifier| NegotiationError::RemoteProjectionRequirement(identifier.clone()),
    )?;

    Ok(NegotiatedHandshake {
        checkpoint,
        capabilities: intersection(
            local.supported_capabilities(),
            remote.supported_capabilities(),
        ),
        projections: intersection(
            local.supported_projections(),
            remote.supported_projections(),
        ),
    })
}

fn require_subset<T: Ord>(
    required: &[T],
    supported: &[T],
    error: impl Fn(&T) -> NegotiationError,
) -> Result<(), NegotiationError> {
    for identifier in required {
        if supported.binary_search(identifier).is_err() {
            return Err(error(identifier));
        }
    }
    Ok(())
}

fn intersection<T: Ord + Clone>(left: &[T], right: &[T]) -> Vec<T> {
    let mut result = Vec::with_capacity(left.len().min(right.len()));
    let (mut left_index, mut right_index) = (0, 0);
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => {
                result.push(left[left_index].clone());
                left_index += 1;
                right_index += 1;
            }
        }
    }
    result
}

fn known_capability(capability: &CapabilityId) -> bool {
    S5_CAPABILITIES.contains(&capability.as_str())
}

fn known_projection(projection: &ProjectionId) -> bool {
    S5_PROJECTIONS.binary_search(&projection.as_str()).is_ok()
}
