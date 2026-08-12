use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ActorId, BatchId, Digest, DigestError, DomainRegistry, Record, RecordCodecError, RecordId,
    RecordSchemaId,
    hash::{framed_hash, hash_bytes},
    json::{StrictJsonError, decode_strict, encode_pretty},
    record::{decode_record, encode_record},
};

pub const BATCH_SCHEMA_V1: &str = "wayjournal.batch/v1";
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
const CONTENT_DIGEST_DOMAIN: &[u8] = b"wayjournal-content-v1\0";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"wayjournal-batch-request-v1\0";
const IDEMPOTENCY_DIGEST_DOMAIN: &[u8] = b"wayjournal-idempotency-key-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRef {
    path: String,
    record_id: RecordId,
    record_schema: RecordSchemaId,
    content_digest: Digest,
}

impl RecordRef {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub const fn record_id(&self) -> RecordId {
        self.record_id
    }
    #[must_use]
    pub const fn content_digest(&self) -> Digest {
        self.content_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchManifest {
    batch_id: BatchId,
    actor: ActorId,
    members: Vec<RecordRef>,
    idempotency_key_digest: Digest,
    request_digest: Digest,
}

impl BatchManifest {
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        BATCH_SCHEMA_V1
    }
    #[must_use]
    pub const fn batch_id(&self) -> BatchId {
        self.batch_id
    }
    #[must_use]
    pub const fn actor(&self) -> &ActorId {
        &self.actor
    }
    #[must_use]
    pub fn members(&self) -> &[RecordRef] {
        &self.members
    }
    #[must_use]
    pub const fn request_digest(&self) -> Digest {
        self.request_digest
    }
    #[must_use]
    pub const fn idempotency_key_digest(&self) -> Digest {
        self.idempotency_key_digest
    }
    #[must_use]
    pub fn canonical_path(&self) -> String {
        format!("journal/batches/{}.json", self.batch_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRecord {
    record: Record,
    path: String,
    bytes: Vec<u8>,
}

impl PreparedRecord {
    #[must_use]
    pub const fn record(&self) -> &Record {
        &self.record
    }
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBatch {
    manifest: BatchManifest,
    manifest_path: String,
    manifest_bytes: Vec<u8>,
    records: Vec<PreparedRecord>,
}

#[cfg(test)]
impl BatchManifest {
    pub(crate) fn replace_only_member_for_test(
        &mut self,
        record: &Record,
        registry: &DomainRegistry,
        keep_manifest_path: bool,
    ) -> PreparedRecord {
        assert_eq!(self.members.len(), 1);
        let bytes = encode_record(record, registry).expect("test record");
        let path = record.canonical_path();
        let reference_path = if keep_manifest_path {
            self.members[0].path.clone()
        } else {
            path.clone()
        };
        self.members[0].record_id = record.record_id;
        self.members[0].record_schema = record.record_schema.clone();
        self.members[0].content_digest = content_digest(&bytes);
        self.request_digest = framed_hash(
            REQUEST_DIGEST_DOMAIN,
            [(reference_path.as_bytes(), bytes.as_slice())],
        );
        PreparedRecord {
            record: record.clone(),
            path: reference_path,
            bytes,
        }
    }
}

impl PreparedBatch {
    #[must_use]
    pub const fn manifest(&self) -> &BatchManifest {
        &self.manifest
    }
    #[must_use]
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }
    #[must_use]
    pub fn records(&self) -> &[PreparedRecord] {
        &self.records
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredMember<'a> {
    path: &'a [u8],
    bytes: &'a [u8],
}

impl<'a> StoredMember<'a> {
    #[must_use]
    pub const fn new(path: &'a [u8], bytes: &'a [u8]) -> Self {
        Self { path, bytes }
    }
    #[must_use]
    pub const fn path(self) -> &'a [u8] {
        self.path
    }
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyDecision<'a> {
    New,
    Replay(&'a BatchManifest),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BatchError {
    #[error("batch must contain at least one record")]
    EmptyBatch,
    #[error("record {record_id} has batch id {actual}, expected {expected}")]
    MixedBatchId {
        record_id: RecordId,
        expected: BatchId,
        actual: BatchId,
    },
    #[error("record {record_id} has actor {actual}, expected {expected}")]
    MixedActor {
        record_id: RecordId,
        expected: String,
        actual: String,
    },
    #[error("record id is duplicated in batch: {record_id}")]
    DuplicateRecordId { record_id: RecordId },
    #[error("invalid record {record_id}: {source}")]
    InvalidRecord {
        record_id: RecordId,
        source: RecordCodecError,
    },
    #[error("batch manifest exceeds the {MAX_BATCH_BYTES}-byte limit")]
    ManifestTooLarge,
    #[error("invalid batch JSON: {0}")]
    InvalidJson(String),
    #[error("batch manifest must be a JSON object")]
    ManifestNotObject,
    #[error("invalid batch manifest: {0}")]
    InvalidManifest(String),
    #[error("unsupported batch schema: {0}")]
    UnsupportedSchema(String),
    #[error("batch members must be sorted and duplicate-free")]
    UnsortedMembers,
    #[error("duplicate stored member path: {path:?}")]
    DuplicateStoredPath { path: Vec<u8> },
    #[error("batch member is missing: {path}")]
    MissingMember { path: String },
    #[error("batch has an extra member: {path:?}")]
    ExtraMember { path: Vec<u8> },
    #[error("stored record at {path:?} is invalid: {source}")]
    InvalidStoredRecord {
        path: Vec<u8>,
        source: RecordCodecError,
    },
    #[error("stored record identity does not match manifest path {path}")]
    MemberIdentityMismatch { path: String },
    #[error("stored record at {path} has the wrong batch id")]
    MemberBatchMismatch { path: String },
    #[error("stored record at {path} has the wrong actor")]
    MemberActorMismatch { path: String },
    #[error("stored record digest mismatch at {path}")]
    MemberDigestMismatch { path: String },
    #[error("batch request digest mismatch")]
    RequestDigestMismatch,
    #[error("generic record has no manifest owner: {path:?}")]
    UnownedRecord { path: Vec<u8> },
    #[error("generic record has multiple manifest owners: {path:?}")]
    MultiplyOwnedRecord { path: Vec<u8> },
    #[error("manifest references a record absent from the complete store: {path}")]
    OwnershipMissingMember { path: String },
    #[error("idempotency replay request differs for batch {batch_id}")]
    IdempotencyRequestMismatch { batch_id: BatchId },
    #[error("idempotency ownership is duplicated across batches: {batch_ids:?}")]
    DuplicateIdempotencyOwnership { batch_ids: Vec<BatchId> },
    #[error("batch manifest is not canonical JSON")]
    NonCanonical,
    #[error(transparent)]
    InvalidDigest(#[from] DigestError),
}

impl From<StrictJsonError> for BatchError {
    fn from(error: StrictJsonError) -> Self {
        Self::InvalidJson(error.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecordRef {
    content_digest: String,
    path: String,
    record_id: String,
    record_schema: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    actor: String,
    batch_id: String,
    idempotency_key_digest: String,
    members: Vec<RawRecordRef>,
    request_digest: String,
    schema: String,
}

fn content_digest(bytes: &[u8]) -> Digest {
    hash_bytes(CONTENT_DIGEST_DOMAIN, bytes)
}

fn idempotency_digest(actor: &ActorId, key: &str) -> Digest {
    framed_hash(
        IDEMPOTENCY_DIGEST_DOMAIN,
        [(actor.as_str().as_bytes(), key.as_bytes())],
    )
}

/// Prepares canonical generic record members and one immutable manifest.
///
/// # Errors
/// Returns [`BatchError`] for empty, mixed, duplicated, or invalid batches.
pub fn prepare_batch(
    records: &[Record],
    idempotency_key: &str,
    registry: &DomainRegistry,
) -> Result<PreparedBatch, BatchError> {
    let Some(first) = records.first() else {
        return Err(BatchError::EmptyBatch);
    };
    let expected_batch = first.batch_id;
    let expected_actor = first.actor.clone();
    let mut ids = BTreeSet::new();
    let mut sorted = BTreeMap::new();
    for record in records {
        if record.batch_id != expected_batch {
            return Err(BatchError::MixedBatchId {
                record_id: record.record_id,
                expected: expected_batch,
                actual: record.batch_id,
            });
        }
        if record.actor != expected_actor {
            return Err(BatchError::MixedActor {
                record_id: record.record_id,
                expected: expected_actor.to_string(),
                actual: record.actor.to_string(),
            });
        }
        if !ids.insert(record.record_id) {
            return Err(BatchError::DuplicateRecordId {
                record_id: record.record_id,
            });
        }
        let bytes =
            encode_record(record, registry).map_err(|source| BatchError::InvalidRecord {
                record_id: record.record_id,
                source,
            })?;
        let path = record.canonical_path();
        sorted.insert(
            path.clone(),
            PreparedRecord {
                record: record.clone(),
                path,
                bytes,
            },
        );
    }
    let records = sorted.into_values().collect::<Vec<_>>();
    let request_digest = framed_hash(
        REQUEST_DIGEST_DOMAIN,
        records
            .iter()
            .map(|record| (record.path.as_bytes(), record.bytes.as_slice())),
    );
    let manifest = BatchManifest {
        batch_id: expected_batch,
        actor: expected_actor.clone(),
        members: records
            .iter()
            .map(|record| RecordRef {
                path: record.path.clone(),
                record_id: record.record.record_id,
                record_schema: record.record.record_schema.clone(),
                content_digest: content_digest(&record.bytes),
            })
            .collect(),
        idempotency_key_digest: idempotency_digest(&expected_actor, idempotency_key),
        request_digest,
    };
    let manifest_bytes = encode_manifest(&manifest)?;
    Ok(PreparedBatch {
        manifest_path: manifest.canonical_path(),
        manifest_bytes,
        manifest,
        records,
    })
}

fn encode_manifest(manifest: &BatchManifest) -> Result<Vec<u8>, BatchError> {
    let raw = RawManifest {
        actor: manifest.actor.to_string(),
        batch_id: manifest.batch_id.to_string(),
        idempotency_key_digest: manifest.idempotency_key_digest.to_string(),
        members: manifest
            .members
            .iter()
            .map(|member| RawRecordRef {
                content_digest: member.content_digest.to_string(),
                path: member.path.clone(),
                record_id: member.record_id.to_string(),
                record_schema: member.record_schema.to_string(),
            })
            .collect(),
        request_digest: manifest.request_digest.to_string(),
        schema: BATCH_SCHEMA_V1.to_owned(),
    };
    let value = serde_json::to_value(raw)
        .map_err(|error| BatchError::InvalidManifest(error.to_string()))?;
    let bytes = encode_pretty(&value)?;
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(BatchError::ManifestTooLarge);
    }
    Ok(bytes)
}

/// Decodes a closed, canonical `wayjournal.batch/v1` manifest.
///
/// # Errors
/// Returns [`BatchError`] for malformed, open, unbounded, or noncanonical bytes.
pub fn decode_batch_manifest(bytes: &[u8]) -> Result<BatchManifest, BatchError> {
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(BatchError::ManifestTooLarge);
    }
    let value = decode_strict(bytes)?;
    let object = value.as_object().ok_or(BatchError::ManifestNotObject)?;
    let schema = object
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BatchError::InvalidManifest("schema must be a string".to_owned()))?;
    if schema != BATCH_SCHEMA_V1 {
        return Err(BatchError::UnsupportedSchema(schema.to_owned()));
    }
    let raw: RawManifest = serde_json::from_value(value)
        .map_err(|error| BatchError::InvalidManifest(error.to_string()))?;
    if raw.members.is_empty() {
        return Err(BatchError::EmptyBatch);
    }
    let members = raw
        .members
        .into_iter()
        .map(|member| {
            let record_id = member
                .record_id
                .parse()
                .map_err(|error| BatchError::InvalidManifest(format!("record_id: {error}")))?;
            let record_schema: RecordSchemaId = member
                .record_schema
                .parse()
                .map_err(|error| BatchError::InvalidManifest(format!("record_schema: {error}")))?;
            let path_domain = member.path.split('/').nth(2);
            let schema_domain = record_schema
                .as_str()
                .split_once('/')
                .map(|(domain, _)| domain);
            if !crate::layout::validate_journal_record_path(&member.path)
                || !member.path.ends_with(&format!("/{record_id}.json"))
                || path_domain != schema_domain
            {
                return Err(BatchError::InvalidManifest(format!(
                    "member path does not match record identity: {}",
                    member.path
                )));
            }
            Ok(RecordRef {
                path: member.path,
                record_id,
                record_schema,
                content_digest: Digest::parse(&member.content_digest)?,
            })
        })
        .collect::<Result<Vec<_>, BatchError>>()?;
    if !members.windows(2).all(|pair| pair[0].path < pair[1].path)
        || members
            .iter()
            .map(|member| member.record_id)
            .collect::<BTreeSet<_>>()
            .len()
            != members.len()
    {
        return Err(BatchError::UnsortedMembers);
    }
    let manifest = BatchManifest {
        batch_id: raw
            .batch_id
            .parse()
            .map_err(|error| BatchError::InvalidManifest(format!("batch_id: {error}")))?,
        actor: ActorId::parse(&raw.actor)
            .map_err(|error| BatchError::InvalidManifest(format!("actor: {error}")))?,
        members,
        idempotency_key_digest: Digest::parse(&raw.idempotency_key_digest)?,
        request_digest: Digest::parse(&raw.request_digest)?,
    };
    if encode_manifest(&manifest)? != bytes {
        return Err(BatchError::NonCanonical);
    }
    Ok(manifest)
}

/// Validates exact manifest membership, envelope ownership, content digests, and request digest.
///
/// # Errors
/// Returns [`BatchError`] for missing, extra, duplicate, malformed, or mismatched members.
pub fn validate_batch_members(
    manifest: &BatchManifest,
    members: &[StoredMember<'_>],
    registry: &DomainRegistry,
) -> Result<Vec<Record>, BatchError> {
    let mut by_path = BTreeMap::new();
    for member in members {
        if by_path.insert(member.path.to_vec(), member.bytes).is_some() {
            return Err(BatchError::DuplicateStoredPath {
                path: member.path.to_vec(),
            });
        }
    }
    let mut decoded = Vec::with_capacity(manifest.members.len());
    let mut hashed = Vec::with_capacity(manifest.members.len());
    for reference in &manifest.members {
        let Some(bytes) = by_path.remove(reference.path.as_bytes()) else {
            return Err(BatchError::MissingMember {
                path: reference.path.clone(),
            });
        };
        if content_digest(bytes) != reference.content_digest {
            return Err(BatchError::MemberDigestMismatch {
                path: reference.path.clone(),
            });
        }
        let record =
            decode_record(bytes, registry).map_err(|source| BatchError::InvalidStoredRecord {
                path: reference.path.as_bytes().to_vec(),
                source,
            })?;
        if record.canonical_path() != reference.path
            || record.record_id != reference.record_id
            || record.record_schema != reference.record_schema
        {
            return Err(BatchError::MemberIdentityMismatch {
                path: reference.path.clone(),
            });
        }
        if record.batch_id != manifest.batch_id {
            return Err(BatchError::MemberBatchMismatch {
                path: reference.path.clone(),
            });
        }
        if record.actor != manifest.actor {
            return Err(BatchError::MemberActorMismatch {
                path: reference.path.clone(),
            });
        }
        hashed.push((reference.path.as_str(), bytes));
        decoded.push(record);
    }
    if let Some((path, _)) = by_path.pop_first() {
        return Err(BatchError::ExtraMember { path });
    }
    let actual = framed_hash(
        REQUEST_DIGEST_DOMAIN,
        hashed.iter().map(|(path, bytes)| (path.as_bytes(), *bytes)),
    );
    if actual != manifest.request_digest {
        return Err(BatchError::RequestDigestMismatch);
    }
    Ok(decoded)
}

/// Validates exactly-one manifest ownership for every complete generic record set.
///
/// # Errors
/// Returns [`BatchError`] when a record is unowned, multiply owned, absent, or invalid.
pub fn validate_batch_ownership(
    records: &[StoredMember<'_>],
    manifests: &[&BatchManifest],
    registry: &DomainRegistry,
) -> Result<(), BatchError> {
    let mut record_paths = BTreeSet::new();
    for record in records {
        if !record_paths.insert(record.path.to_vec()) {
            return Err(BatchError::DuplicateStoredPath {
                path: record.path.to_vec(),
            });
        }
        decode_record(record.bytes, registry).map_err(|source| {
            BatchError::InvalidStoredRecord {
                path: record.path.to_vec(),
                source,
            }
        })?;
    }
    let by_path = records
        .iter()
        .map(|record| (record.path, record.bytes))
        .collect::<BTreeMap<_, _>>();
    let mut ownership = BTreeMap::<Vec<u8>, usize>::new();
    for manifest in manifests {
        let members = manifest
            .members
            .iter()
            .map(|member| {
                by_path
                    .get(member.path.as_bytes())
                    .map(|bytes| StoredMember::new(member.path.as_bytes(), bytes))
                    .ok_or_else(|| BatchError::OwnershipMissingMember {
                        path: member.path.clone(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_batch_members(manifest, &members, registry)?;
        for member in &manifest.members {
            *ownership
                .entry(member.path.as_bytes().to_vec())
                .or_default() += 1;
        }
    }
    for path in &record_paths {
        match ownership.get(path).copied().unwrap_or(0) {
            0 => return Err(BatchError::UnownedRecord { path: path.clone() }),
            1 => {}
            _ => return Err(BatchError::MultiplyOwnedRecord { path: path.clone() }),
        }
    }
    if let Some(path) = ownership.keys().find(|path| !record_paths.contains(*path)) {
        return Err(BatchError::OwnershipMissingMember {
            path: String::from_utf8_lossy(path).into_owned(),
        });
    }
    Ok(())
}

/// Classifies actor-scoped retry ownership against visible manifests.
///
/// # Errors
/// Returns [`BatchError`] for a changed replay request or multiple owners.
pub fn classify_idempotency<'a>(
    manifests: impl IntoIterator<Item = &'a BatchManifest>,
    actor: &ActorId,
    key: &str,
    request_digest: Digest,
) -> Result<IdempotencyDecision<'a>, BatchError> {
    let digest = idempotency_digest(actor, key);
    let mut matches = manifests
        .into_iter()
        .filter(|manifest| manifest.actor == *actor && manifest.idempotency_key_digest == digest)
        .collect::<Vec<_>>();
    matches.sort_by_key(|manifest| manifest.batch_id);
    match matches.as_slice() {
        [] => Ok(IdempotencyDecision::New),
        [manifest] if manifest.request_digest == request_digest => {
            Ok(IdempotencyDecision::Replay(manifest))
        }
        [manifest] => Err(BatchError::IdempotencyRequestMismatch {
            batch_id: manifest.batch_id,
        }),
        _ => Err(BatchError::DuplicateIdempotencyOwnership {
            batch_ids: matches.iter().map(|manifest| manifest.batch_id).collect(),
        }),
    }
}
