#![cfg_attr(not(test), allow(dead_code))]

use std::{
    ffi::{OsStr, OsString},
    io::{Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
    },
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Digest, LogicalStoreId, Store, StoreRevisionRef,
    json::{decode_strict, encode_pretty},
    store::{Directory, MAX_CANONICAL_ENTRIES, MAX_TOTAL_CANONICAL_BYTES},
};

use super::{
    ApprovedRemote, GitObjectFormat, GitOid, GitSyncOperationId, GitSyncPendingPhase,
    LocalTrustBinding,
};

pub(super) const MAX_PENDING_ROOT_BYTES: usize = 64 * 1024;
pub(super) const MAX_BULK_ADDITIONS: usize = MAX_CANONICAL_ENTRIES;
pub(super) const MAX_BULK_ADDITION_BYTES: u64 = MAX_TOTAL_CANONICAL_BYTES;
pub(super) const ADDITIONS_PER_CHUNK: usize = 4_096;
pub(super) const MAX_ADDITION_CHUNKS: usize = 245;
pub(super) const MAX_CANONICAL_PATH_BYTES: usize = 223;
pub(super) const MAX_ENCODED_ADDITION_BYTES: usize = 265;
pub(super) const MAX_ADDITION_INDEX_BYTES: usize = 16 * 1024;
const PENDING_SCHEMA: &str = "wayjournal.sync-pending/v1";

#[derive(Debug, Error)]
pub(super) enum PendingError {
    #[error("pending store I/O failed: {0}")]
    Store(#[from] crate::StoreError),
    #[error("pending synchronization state is invalid: {0}")]
    Invalid(String),
    #[error("pending synchronization root exceeds 64 KiB")]
    Oversized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingDocument {
    schema: String,
    pub operation_id: GitSyncOperationId,
    pub phase: GitSyncPendingPhase,
    pub logical_store_id: LogicalStoreId,
    pub local_trust_binding: LocalTrustBinding,
    pub approved_remote: ApprovedRemote,
    pub object_format: GitObjectFormat,
    pub original_base_commit: GitOid,
    pub original_base_revision: StoreRevisionRef,
    pub advance_from_commit: GitOid,
    pub advance_from_revision: StoreRevisionRef,
    pub observed_local_tip: GitOid,
    pub expected_remote_tip: GitOid,
    pub candidate_commit: GitOid,
    pub candidate_revision: StoreRevisionRef,
    pub candidate_parents: Vec<GitOid>,
    pub additions_count: u64,
    pub additions_total_bytes: u64,
    pub additions_index_digest: Digest,
    pub predecessor_operation_id: Option<GitSyncOperationId>,
    pub stale_remote_oid: Option<GitOid>,
}

impl PendingDocument {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        operation_id: GitSyncOperationId,
        phase: GitSyncPendingPhase,
        logical_store_id: LogicalStoreId,
        local_trust_binding: LocalTrustBinding,
        approved_remote: ApprovedRemote,
        object_format: GitObjectFormat,
        original_base_commit: GitOid,
        original_base_revision: StoreRevisionRef,
        advance_from_commit: GitOid,
        advance_from_revision: StoreRevisionRef,
        observed_local_tip: GitOid,
        expected_remote_tip: GitOid,
        candidate_commit: GitOid,
        candidate_revision: StoreRevisionRef,
        mut candidate_parents: Vec<GitOid>,
        predecessor_operation_id: Option<GitSyncOperationId>,
    ) -> Self {
        candidate_parents.sort();
        candidate_parents.dedup();
        Self {
            schema: PENDING_SCHEMA.to_owned(),
            operation_id,
            phase,
            logical_store_id,
            local_trust_binding,
            approved_remote,
            object_format,
            original_base_commit,
            original_base_revision,
            advance_from_commit,
            advance_from_revision,
            observed_local_tip,
            expected_remote_tip,
            candidate_commit,
            candidate_revision,
            candidate_parents,
            additions_count: 0,
            additions_total_bytes: 0,
            additions_index_digest: Digest::from_hash(blake3::hash(b"")),
            predecessor_operation_id,
            stale_remote_oid: None,
        }
    }

    pub(super) fn validate(&self) -> Result<(), PendingError> {
        if self.schema != PENDING_SCHEMA {
            return Err(PendingError::Invalid("unsupported schema".to_owned()));
        }
        validate_addition_totals(
            usize::try_from(self.additions_count)
                .map_err(|_| PendingError::Invalid("addition count exceeds usize".to_owned()))?,
            self.additions_total_bytes,
        )?;
        let format = self.object_format;
        for oid in [
            &self.original_base_commit,
            &self.advance_from_commit,
            &self.observed_local_tip,
            &self.expected_remote_tip,
            &self.candidate_commit,
        ]
        .into_iter()
        .chain(self.candidate_parents.iter())
        .chain(self.stale_remote_oid.iter())
        {
            if oid.format() != format {
                return Err(PendingError::Invalid(
                    "object formats do not agree".to_owned(),
                ));
            }
        }
        if self.candidate_parents.is_empty()
            || self
                .candidate_parents
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(PendingError::Invalid(
                "candidate parents are not sorted and unique".to_owned(),
            ));
        }
        match self.phase {
            GitSyncPendingPhase::RemoteCasStale if self.stale_remote_oid.is_none() => {
                return Err(PendingError::Invalid(
                    "stale phase has no observed remote".to_owned(),
                ));
            }
            GitSyncPendingPhase::RemoteCasConfirmed if self.stale_remote_oid.is_some() => {
                return Err(PendingError::Invalid(
                    "confirmed phase has stale remote evidence".to_owned(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

pub(super) fn validate_addition_totals(count: usize, bytes: u64) -> Result<(), PendingError> {
    if count > MAX_BULK_ADDITIONS {
        return Err(PendingError::Invalid(
            "addition count exceeds store capacity".to_owned(),
        ));
    }
    if bytes > MAX_BULK_ADDITION_BYTES {
        return Err(PendingError::Invalid(
            "addition bytes exceed store capacity".to_owned(),
        ));
    }
    chunk_count(count)?;
    Ok(())
}

pub(super) fn chunk_count(count: usize) -> Result<usize, PendingError> {
    let chunks = count.div_ceil(ADDITIONS_PER_CHUNK);
    if chunks > MAX_ADDITION_CHUNKS {
        return Err(PendingError::Invalid(
            "addition chunk count exceeds capacity".to_owned(),
        ));
    }
    Ok(chunks)
}

pub(super) const fn max_metadata_bytes() -> usize {
    MAX_BULK_ADDITIONS * MAX_ENCODED_ADDITION_BYTES
        + MAX_ADDITION_CHUNKS * 64
        + MAX_ADDITION_INDEX_BYTES
        + MAX_PENDING_ROOT_BYTES
}

const ADDITION_MAGIC: &[u8] = b"wayjournal.sync-additions/v1\0";
const ADDITION_HEADER_BYTES: usize = 64;
const MAX_CHUNK_BYTES: usize =
    ADDITION_HEADER_BYTES + ADDITIONS_PER_CHUNK * MAX_ENCODED_ADDITION_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdditionEntry {
    pub path: Vec<u8>,
    pub byte_length: u64,
    pub content_digest: Digest,
}

pub(super) fn encode_chunk(
    chunk_number: u32,
    entries: &[AdditionEntry],
) -> Result<Vec<u8>, PendingError> {
    if chunk_number as usize >= MAX_ADDITION_CHUNKS
        || entries.is_empty()
        || entries.len() > ADDITIONS_PER_CHUNK
    {
        return Err(PendingError::Invalid(
            "addition chunk number or count is outside bounds".to_owned(),
        ));
    }
    let mut bytes =
        Vec::with_capacity(ADDITION_HEADER_BYTES + entries.len() * MAX_ENCODED_ADDITION_BYTES);
    bytes.extend_from_slice(ADDITION_MAGIC);
    bytes.extend_from_slice(&chunk_number.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| PendingError::Invalid("chunk count exceeds u32".to_owned()))?
            .to_be_bytes(),
    );
    bytes.resize(ADDITION_HEADER_BYTES, 0);
    let mut previous: Option<&[u8]> = None;
    for entry in entries {
        if entry.path.is_empty()
            || entry.path.len() > MAX_CANONICAL_PATH_BYTES
            || !entry.path.is_ascii()
            || !matches!(
                crate::classify_path(&entry.path),
                crate::PathClass::LegacyEvent
                    | crate::PathClass::LegacyBatch
                    | crate::PathClass::JournalRecord
                    | crate::PathClass::JournalBatch
            )
            || previous.is_some_and(|path| path >= entry.path.as_slice())
        {
            return Err(PendingError::Invalid(
                "addition path is not sorted canonical ASCII".to_owned(),
            ));
        }
        let path_length = u16::try_from(entry.path.len())
            .map_err(|_| PendingError::Invalid("addition path exceeds u16".to_owned()))?;
        bytes.extend_from_slice(&path_length.to_be_bytes());
        bytes.extend_from_slice(&entry.path);
        bytes.extend_from_slice(&entry.byte_length.to_be_bytes());
        bytes.extend_from_slice(entry.content_digest.as_bytes());
        previous = Some(&entry.path);
    }
    if bytes.len() > MAX_CHUNK_BYTES {
        return Err(PendingError::Invalid(
            "encoded addition chunk exceeds bound".to_owned(),
        ));
    }
    Ok(bytes)
}

pub(super) fn decode_chunk(bytes: &[u8]) -> Result<(u32, Vec<AdditionEntry>), PendingError> {
    if bytes.len() < ADDITION_HEADER_BYTES || bytes.len() > MAX_CHUNK_BYTES {
        return Err(PendingError::Invalid(
            "addition chunk byte length is outside bounds".to_owned(),
        ));
    }
    if &bytes[..ADDITION_MAGIC.len()] != ADDITION_MAGIC
        || bytes[ADDITION_MAGIC.len() + 8..ADDITION_HEADER_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(PendingError::Invalid(
            "addition chunk header is invalid".to_owned(),
        ));
    }
    let chunk_offset = ADDITION_MAGIC.len();
    let chunk_number = u32::from_be_bytes(
        bytes[chunk_offset..chunk_offset + 4]
            .try_into()
            .expect("four-byte chunk number"),
    );
    let count = u32::from_be_bytes(
        bytes[chunk_offset + 4..chunk_offset + 8]
            .try_into()
            .expect("four-byte chunk count"),
    ) as usize;
    if chunk_number as usize >= MAX_ADDITION_CHUNKS || count == 0 || count > ADDITIONS_PER_CHUNK {
        return Err(PendingError::Invalid(
            "addition chunk number or count is outside bounds".to_owned(),
        ));
    }
    let mut cursor = ADDITION_HEADER_BYTES;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let path_length = take_u16(bytes, &mut cursor)? as usize;
        if path_length == 0 || path_length > MAX_CANONICAL_PATH_BYTES {
            return Err(PendingError::Invalid(
                "addition path length is outside bounds".to_owned(),
            ));
        }
        let path = take(bytes, &mut cursor, path_length)?.to_vec();
        let byte_length = u64::from_be_bytes(
            take(bytes, &mut cursor, 8)?
                .try_into()
                .expect("eight-byte length"),
        );
        let digest = Digest::from_hash(blake3::Hash::from_bytes(
            take(bytes, &mut cursor, 32)?
                .try_into()
                .expect("32-byte digest"),
        ));
        entries.push(AdditionEntry {
            path,
            byte_length,
            content_digest: digest,
        });
    }
    if cursor != bytes.len() {
        return Err(PendingError::Invalid(
            "addition chunk has trailing bytes".to_owned(),
        ));
    }
    let canonical = encode_chunk(chunk_number, &entries)?;
    if canonical != bytes {
        return Err(PendingError::Invalid(
            "addition chunk is noncanonical".to_owned(),
        ));
    }
    Ok((chunk_number, entries))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], PendingError> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| PendingError::Invalid("addition chunk offset overflow".to_owned()))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| PendingError::Invalid("addition chunk is truncated".to_owned()))?;
    *cursor = end;
    Ok(value)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, PendingError> {
    Ok(u16::from_be_bytes(
        take(bytes, cursor, 2)?
            .try_into()
            .expect("two-byte path length"),
    ))
}

pub(super) fn encode_document(document: &PendingDocument) -> Result<Vec<u8>, PendingError> {
    document.validate()?;
    let value =
        serde_json::to_value(document).map_err(|error| PendingError::Invalid(error.to_string()))?;
    let bytes = encode_pretty(&value).map_err(|error| PendingError::Invalid(error.to_string()))?;
    if bytes.len() > MAX_PENDING_ROOT_BYTES {
        return Err(PendingError::Oversized);
    }
    Ok(bytes)
}

pub(super) fn decode_document(bytes: &[u8]) -> Result<PendingDocument, PendingError> {
    if bytes.len() > MAX_PENDING_ROOT_BYTES {
        return Err(PendingError::Oversized);
    }
    let value = decode_strict(bytes).map_err(|error| PendingError::Invalid(error.to_string()))?;
    let document: PendingDocument = serde_json::from_value(value.clone())
        .map_err(|error| PendingError::Invalid(error.to_string()))?;
    document.validate()?;
    let canonical =
        encode_pretty(&value).map_err(|error| PendingError::Invalid(error.to_string()))?;
    if canonical != bytes {
        return Err(PendingError::Invalid(
            "pending root is not canonical JSON".to_owned(),
        ));
    }
    Ok(document)
}

const INDEX_MAGIC: &[u8] = b"wayjournal.sync-additions-index/v1\0";
const INDEX_HEADER_BYTES: usize = 64;
const INDEX_ENTRY_BYTES: usize = 48;

#[derive(Debug)]
struct IndexEntry {
    number: u32,
    count: u32,
    encoded_length: u64,
    digest: Digest,
}

fn encode_index(
    count: u64,
    total_bytes: u64,
    chunks: &[IndexEntry],
) -> Result<Vec<u8>, PendingError> {
    if chunks.len() > MAX_ADDITION_CHUNKS {
        return Err(PendingError::Invalid(
            "index chunk count exceeds bound".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(INDEX_HEADER_BYTES + chunks.len() * INDEX_ENTRY_BYTES);
    bytes.extend_from_slice(INDEX_MAGIC);
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&total_bytes.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(chunks.len())
            .map_err(|_| PendingError::Invalid("index chunk count exceeds u32".to_owned()))?
            .to_be_bytes(),
    );
    bytes.resize(INDEX_HEADER_BYTES, 0);
    for chunk in chunks {
        bytes.extend_from_slice(&chunk.number.to_be_bytes());
        bytes.extend_from_slice(&chunk.count.to_be_bytes());
        bytes.extend_from_slice(&chunk.encoded_length.to_be_bytes());
        bytes.extend_from_slice(chunk.digest.as_bytes());
    }
    if bytes.len() > MAX_ADDITION_INDEX_BYTES {
        return Err(PendingError::Invalid(
            "addition index exceeds 16 KiB".to_owned(),
        ));
    }
    Ok(bytes)
}

fn decode_index(bytes: &[u8]) -> Result<(u64, u64, Vec<IndexEntry>), PendingError> {
    if bytes.len() < INDEX_HEADER_BYTES || bytes.len() > MAX_ADDITION_INDEX_BYTES {
        return Err(PendingError::Invalid(
            "addition index size is outside bounds".to_owned(),
        ));
    }
    if &bytes[..INDEX_MAGIC.len()] != INDEX_MAGIC {
        return Err(PendingError::Invalid(
            "addition index magic is invalid".to_owned(),
        ));
    }
    let mut cursor = INDEX_MAGIC.len();
    let count = u64::from_be_bytes(take(bytes, &mut cursor, 8)?.try_into().expect("u64"));
    let total_bytes = u64::from_be_bytes(take(bytes, &mut cursor, 8)?.try_into().expect("u64"));
    let chunks = u32::from_be_bytes(take(bytes, &mut cursor, 4)?.try_into().expect("u32")) as usize;
    if bytes[cursor..INDEX_HEADER_BYTES]
        .iter()
        .any(|byte| *byte != 0)
        || chunks > MAX_ADDITION_CHUNKS
        || bytes.len() != INDEX_HEADER_BYTES + chunks * INDEX_ENTRY_BYTES
    {
        return Err(PendingError::Invalid(
            "addition index header is invalid".to_owned(),
        ));
    }
    cursor = INDEX_HEADER_BYTES;
    let mut entries = Vec::with_capacity(chunks);
    for expected in 0..chunks {
        let number = u32::from_be_bytes(take(bytes, &mut cursor, 4)?.try_into().expect("u32"));
        let chunk_count = u32::from_be_bytes(take(bytes, &mut cursor, 4)?.try_into().expect("u32"));
        let encoded_length =
            u64::from_be_bytes(take(bytes, &mut cursor, 8)?.try_into().expect("u64"));
        let digest = Digest::from_hash(blake3::Hash::from_bytes(
            take(bytes, &mut cursor, 32)?.try_into().expect("digest"),
        ));
        if number as usize != expected
            || chunk_count == 0
            || chunk_count as usize > ADDITIONS_PER_CHUNK
        {
            return Err(PendingError::Invalid(
                "addition index entry is invalid".to_owned(),
            ));
        }
        entries.push(IndexEntry {
            number,
            count: chunk_count,
            encoded_length,
            digest,
        });
    }
    let canonical = encode_index(count, total_bytes, &entries)?;
    if canonical != bytes {
        return Err(PendingError::Invalid(
            "addition index is noncanonical".to_owned(),
        ));
    }
    Ok((count, total_bytes, entries))
}

pub(super) fn create_operation(
    store: &Store,
    operation_id: &GitSyncOperationId,
) -> Result<Directory, PendingError> {
    let name = OsString::from(operation_id.to_string());
    let (operation, created) = store.sync_pending_dir.ensure_dir(&name)?;
    if !created {
        return Err(PendingError::Invalid("operation id collided".to_owned()));
    }
    operation.sync()?;
    store.sync_pending_dir.sync()?;
    Ok(operation)
}

#[cfg(test)]
pub(super) fn stage_additions(
    operation: &Directory,
    document: &mut PendingDocument,
    current: &std::collections::BTreeSet<Vec<u8>>,
    candidate: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(), PendingError> {
    let mut addition_count = 0_usize;
    let mut total_bytes = 0_u64;
    for (_, bytes) in candidate
        .iter()
        .filter(|(path, _)| !current.contains(*path))
    {
        addition_count = addition_count
            .checked_add(1)
            .ok_or_else(|| PendingError::Invalid("addition count overflow".to_owned()))?;
        total_bytes =
            total_bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                    PendingError::Invalid("addition byte count exceeds u64".to_owned())
                })?)
                .ok_or_else(|| PendingError::Invalid("addition byte count overflow".to_owned()))?;
    }
    stage_known_additions(
        operation,
        document,
        addition_count,
        total_bytes,
        candidate
            .iter()
            .filter(|(path, _)| !current.contains(*path))
            .map(|(path, bytes)| (path.clone(), bytes.clone())),
    )
}

/// Stages a preflight-counted sorted addition stream while retaining only one canonical payload
/// and one metadata chunk. Callers must derive the totals without retaining the payload set.
pub(super) fn stage_known_additions(
    operation: &Directory,
    document: &mut PendingDocument,
    addition_count: usize,
    total_bytes: u64,
    additions: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> Result<(), PendingError> {
    validate_addition_totals(addition_count, total_bytes)?;
    let (additions_dir, created) = operation.ensure_dir(OsStr::new("additions"))?;
    if !created {
        return Err(PendingError::Invalid(
            "additions directory already exists".to_owned(),
        ));
    }
    let (chunks_dir, _) = additions_dir.ensure_dir(OsStr::new("chunks"))?;
    let (blobs_dir, _) = additions_dir.ensure_dir(OsStr::new("blobs"))?;
    let mut index_entries = Vec::new();
    let mut additions = additions.into_iter();
    let mut observed_count = 0_usize;
    let mut observed_bytes = 0_u64;
    let mut previous_path: Option<Vec<u8>> = None;
    for chunk_number in 0..chunk_count(addition_count)? {
        let chunk_name = format!("{chunk_number:06}");
        let (blob_chunk, created) = blobs_dir.ensure_dir(OsStr::new(&chunk_name))?;
        if !created {
            return Err(PendingError::Invalid(
                "blob chunk already exists".to_owned(),
            ));
        }
        let remaining = addition_count.saturating_sub(observed_count);
        let group_count = remaining.min(ADDITIONS_PER_CHUNK);
        let mut metadata = Vec::with_capacity(group_count);
        for position in 0..group_count {
            let (path, bytes) = additions.next().ok_or_else(|| {
                PendingError::Invalid("addition stream ended before its declared count".to_owned())
            })?;
            if previous_path
                .as_deref()
                .is_some_and(|previous| previous >= path.as_slice())
            {
                return Err(PendingError::Invalid(
                    "addition stream is not globally ordered".to_owned(),
                ));
            }
            let byte_length = u64::try_from(bytes.len())
                .map_err(|_| PendingError::Invalid("blob length exceeds u64".to_owned()))?;
            observed_bytes = observed_bytes
                .checked_add(byte_length)
                .ok_or_else(|| PendingError::Invalid("addition byte count overflow".to_owned()))?;
            let ordinal = chunk_number * ADDITIONS_PER_CHUNK + position;
            let name = format!("{ordinal:08}.blob");
            write_new(&blob_chunk, OsStr::new(&name), &bytes)?;
            let content_digest = Digest::from_hash(blake3::hash(&bytes));
            previous_path = Some(path.clone());
            metadata.push(AdditionEntry {
                path,
                byte_length,
                content_digest,
            });
            observed_count += 1;
        }
        blob_chunk.sync()?;
        let encoded = encode_chunk(
            u32::try_from(chunk_number).expect("bounded chunk"),
            &metadata,
        )?;
        let name = format!("{chunk_number:06}.bin");
        write_new(&chunks_dir, OsStr::new(&name), &encoded)?;
        index_entries.push(IndexEntry {
            number: u32::try_from(chunk_number).expect("bounded chunk"),
            count: u32::try_from(metadata.len()).expect("bounded chunk count"),
            encoded_length: u64::try_from(encoded.len()).expect("encoded chunk length"),
            digest: Digest::from_hash(blake3::hash(&encoded)),
        });
    }
    if additions.next().is_some()
        || observed_count != addition_count
        || observed_bytes != total_bytes
    {
        return Err(PendingError::Invalid(
            "addition stream does not match its declared totals".to_owned(),
        ));
    }
    chunks_dir.sync()?;
    blobs_dir.sync()?;
    let index = encode_index(
        u64::try_from(addition_count)
            .map_err(|_| PendingError::Invalid("addition count exceeds u64".to_owned()))?,
        total_bytes,
        &index_entries,
    )?;
    write_new(&additions_dir, OsStr::new("index.bin"), &index)?;
    additions_dir.sync()?;
    operation.sync()?;
    document.additions_count = u64::try_from(addition_count)
        .map_err(|_| PendingError::Invalid("addition count exceeds u64".to_owned()))?;
    document.additions_total_bytes = total_bytes;
    document.additions_index_digest = Digest::from_hash(blake3::hash(&index));
    Ok(())
}

pub(crate) struct StagedAddition {
    pub path: Vec<u8>,
    pub bytes: Vec<u8>,
    pub file: std::fs::File,
}

/// Validates the closed staged-addition layout and visits one blob at a time.
///
/// Keeping the callback inside the chunk/blob walk ensures recovery memory is bounded by one
/// metadata chunk and one canonical file, even at the one-million-entry/one-GiB limits.
#[allow(clippy::too_many_lines)]
pub(super) fn for_each_addition(
    pending: &DurablePending,
    mut visit: impl FnMut(StagedAddition) -> Result<(), PendingError>,
) -> Result<(), PendingError> {
    let additions = pending.directory.open_dir(OsStr::new("additions"))?;
    let index_file = additions.open_file(OsStr::new("index.bin"))?;
    let index = crate::store::read_file_bounded(
        index_file,
        MAX_ADDITION_INDEX_BYTES,
        &additions.path.join("index.bin"),
    )?;
    if Digest::from_hash(blake3::hash(&index)) != pending.document.additions_index_digest {
        return Err(PendingError::Invalid(
            "addition index digest mismatch".to_owned(),
        ));
    }
    let (count, total_bytes, entries) = decode_index(&index)?;
    if count != pending.document.additions_count
        || total_bytes != pending.document.additions_total_bytes
    {
        return Err(PendingError::Invalid("addition totals mismatch".to_owned()));
    }
    let chunks = additions.open_dir(OsStr::new("chunks"))?;
    let blobs = additions.open_dir(OsStr::new("blobs"))?;
    require_exact_names(&additions, &[b"blobs", b"chunks", b"index.bin"])?;
    let expected_chunk_names = entries
        .iter()
        .map(|entry| format!("{:06}.bin", entry.number).into_bytes())
        .collect::<Vec<_>>();
    let expected_blob_chunk_names = entries
        .iter()
        .map(|entry| format!("{:06}", entry.number).into_bytes())
        .collect::<Vec<_>>();
    require_exact_owned_names(&chunks, &expected_chunk_names)?;
    require_exact_owned_names(&blobs, &expected_blob_chunk_names)?;
    let mut observed_count = 0_u64;
    let mut observed_bytes = 0_u64;
    let mut previous_path: Option<Vec<u8>> = None;
    for entry in entries {
        let chunk_name = format!("{:06}.bin", entry.number);
        let chunk_file = chunks.open_file(OsStr::new(&chunk_name))?;
        let encoded = crate::store::read_file_bounded(
            chunk_file,
            MAX_CHUNK_BYTES,
            &chunks.path.join(&chunk_name),
        )?;
        if encoded.len() as u64 != entry.encoded_length
            || Digest::from_hash(blake3::hash(&encoded)) != entry.digest
        {
            return Err(PendingError::Invalid(
                "addition chunk binding mismatch".to_owned(),
            ));
        }
        let (_, metadata) = decode_chunk(&encoded)?;
        if metadata.len() != entry.count as usize {
            return Err(PendingError::Invalid(
                "addition chunk count mismatch".to_owned(),
            ));
        }
        let blob_chunk_name = format!("{:06}", entry.number);
        let blob_chunk = blobs.open_dir(OsStr::new(&blob_chunk_name))?;
        let expected_blob_names = (0..metadata.len())
            .map(|position| {
                let ordinal = entry.number as usize * ADDITIONS_PER_CHUNK + position;
                format!("{ordinal:08}.blob").into_bytes()
            })
            .collect::<Vec<_>>();
        require_exact_owned_names(&blob_chunk, &expected_blob_names)?;
        for (position, metadata) in metadata.into_iter().enumerate() {
            let ordinal = entry.number as usize * ADDITIONS_PER_CHUNK + position;
            let name = format!("{ordinal:08}.blob");
            let file = blob_chunk.open_file(OsStr::new(&name))?;
            let limit = usize::try_from(metadata.byte_length)
                .map_err(|_| PendingError::Invalid("blob length exceeds usize".to_owned()))?;
            let bytes = crate::store::read_file_bounded(
                file.try_clone()
                    .map_err(|error| PendingError::Invalid(error.to_string()))?,
                limit,
                &blob_chunk.path.join(&name),
            )?;
            if bytes.len() as u64 != metadata.byte_length
                || Digest::from_hash(blake3::hash(&bytes)) != metadata.content_digest
            {
                return Err(PendingError::Invalid(
                    "staged blob binding mismatch".to_owned(),
                ));
            }
            observed_count = observed_count
                .checked_add(1)
                .ok_or_else(|| PendingError::Invalid("staged count overflow".to_owned()))?;
            observed_bytes = observed_bytes
                .checked_add(metadata.byte_length)
                .ok_or_else(|| PendingError::Invalid("staged byte count overflow".to_owned()))?;
            if previous_path
                .as_deref()
                .is_some_and(|previous| previous >= metadata.path.as_slice())
            {
                return Err(PendingError::Invalid(
                    "staged additions are not globally ordered".to_owned(),
                ));
            }
            previous_path = Some(metadata.path.clone());
            visit(StagedAddition {
                path: metadata.path,
                bytes,
                file,
            })?;
        }
    }
    if observed_count != count || observed_bytes != total_bytes {
        return Err(PendingError::Invalid(
            "staged additions do not match index totals".to_owned(),
        ));
    }
    Ok(())
}

fn require_exact_names(directory: &Directory, expected: &[&[u8]]) -> Result<(), PendingError> {
    let expected = expected
        .iter()
        .map(|name| name.to_vec())
        .collect::<Vec<_>>();
    require_exact_owned_names(directory, &expected)
}

fn require_exact_owned_names(
    directory: &Directory,
    expected: &[Vec<u8>],
) -> Result<(), PendingError> {
    let mut expected = expected.to_vec();
    expected.sort();
    if directory.bounded_names(expected.len().saturating_add(1))? != expected {
        return Err(PendingError::Invalid(format!(
            "unexpected entry in closed pending layout at {}",
            directory.path.display()
        )));
    }
    Ok(())
}

fn write_new(directory: &Directory, name: &OsStr, bytes: &[u8]) -> Result<(), PendingError> {
    let mut file = directory.create_file(name)?;
    file.write_all(bytes)
        .map_err(|error| PendingError::Invalid(error.to_string()))?;
    file.sync_all()
        .map_err(|error| PendingError::Invalid(error.to_string()))?;
    Ok(())
}

pub(super) fn publish_document(
    operation: &Directory,
    document: &PendingDocument,
) -> Result<(), PendingError> {
    let bytes = encode_document(document)?;
    write_new(operation, OsStr::new("pending.json"), &bytes)?;
    super::fault::hit("pending-root-file-durable");
    operation.sync()?;
    Ok(())
}

pub(super) fn replace_document(
    pending: &mut DurablePending,
    document: PendingDocument,
) -> Result<(), PendingError> {
    let bytes = encode_document(&document)?;
    let temporary = format!(".pending.tmp-{}", uuid::Uuid::now_v7());
    write_new(&pending.directory, OsStr::new(&temporary), &bytes)?;
    super::fault::hit("phase-temporary-durable");
    pending
        .directory
        .rename_file(OsStr::new(&temporary), OsStr::new("pending.json"))?;
    super::fault::hit("phase-renamed");
    pending.directory.sync()?;
    super::fault::hit("phase-parent-durable");
    let current = pending.directory.open_file(OsStr::new("pending.json"))?;
    let current = crate::store::read_file_bounded(
        current,
        MAX_PENDING_ROOT_BYTES,
        &pending.directory.path.join("pending.json"),
    )?;
    if current != bytes {
        return Err(PendingError::Invalid(
            "pending phase replacement mismatch".to_owned(),
        ));
    }
    pending.document = document;
    Ok(())
}

pub(super) fn retire_operation(
    store: &Store,
    pending: &DurablePending,
) -> Result<(), PendingError> {
    let mut budget = maximum_cleanup_entries();
    remove_contents(&pending.directory, 0, &mut budget)?;
    let name = OsString::from(pending.name.to_string());
    if !store.sync_pending_dir.entry_is(&name, &pending.directory)? {
        return Err(PendingError::Invalid(
            "pending operation binding was replaced".to_owned(),
        ));
    }
    store.sync_pending_dir.unlink_dir(&name)?;
    super::fault::hit("pending-directory-unlinked");
    store.sync_pending_dir.sync()?;
    Ok(())
}

pub(super) struct DurablePending {
    pub name: GitSyncOperationId,
    #[allow(dead_code)]
    pub directory: Directory,
    pub document: PendingDocument,
}

pub(super) struct PendingDiscovery {
    pub active: Option<DurablePending>,
    pub disposable: Vec<(GitSyncOperationId, Directory)>,
    pub predecessor: Option<DurablePending>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateAction {
    Allow,
    CleanDisposable,
}

fn map_pending_error(error: PendingError) -> crate::StoreError {
    match error {
        PendingError::Store(error) => error,
        other => crate::StoreError::InvalidGitSyncState {
            message: other.to_string(),
        },
    }
}

pub(crate) fn gate_without_git(store: &Store) -> Result<GateAction, crate::StoreError> {
    let discovery = discover(store).map_err(map_pending_error)?;
    if let Some(active) = discovery.active {
        if store.has_transaction_residue_locked()? {
            return Err(crate::StoreError::ConflictingRecoveryState);
        }
        return Err(crate::StoreError::GitSyncPending {
            operation_id: active.name,
            phase: active.document.phase,
        });
    }
    if discovery.predecessor.is_some() {
        return Err(crate::StoreError::InvalidGitSyncState {
            message: "pending predecessor exists without an active successor".to_owned(),
        });
    }
    Ok(if discovery.disposable.is_empty() {
        GateAction::Allow
    } else {
        GateAction::CleanDisposable
    })
}

pub(super) fn retire_named_disposable(
    store: &Store,
    disposable: Vec<(GitSyncOperationId, Directory)>,
    expected: Option<&GitSyncOperationId>,
) -> Result<(), PendingError> {
    for (name, directory) in disposable {
        // With an active predecessor (no predecessor link of its own), an unrooted second slot is
        // an interrupted successor attempt and is safely disposable. Once the active document is
        // itself a successor, only residue bearing its named predecessor identity is disposable.
        if expected.is_some() && Some(&name) != expected {
            return Err(PendingError::Invalid(
                "disposable pending slot is not the active successor's predecessor".to_owned(),
            ));
        }
        let mut budget = maximum_cleanup_entries();
        remove_contents(&directory, 0, &mut budget)?;
        let os_name = OsString::from(name.to_string());
        if !store.sync_pending_dir.entry_is(&os_name, &directory)? {
            return Err(PendingError::Invalid(
                "disposable predecessor binding changed".to_owned(),
            ));
        }
        store.sync_pending_dir.unlink_dir(&os_name)?;
        store.sync_pending_dir.sync()?;
    }
    Ok(())
}

pub(crate) fn clean_disposable_locked(store: &Store) -> Result<(), crate::StoreError> {
    let discovery = discover(store).map_err(map_pending_error)?;
    if let Some(active) = discovery.active {
        return Err(crate::StoreError::GitSyncPending {
            operation_id: active.name,
            phase: active.document.phase,
        });
    }
    for (name, directory) in discovery.disposable {
        let mut budget = maximum_cleanup_entries();
        remove_contents(&directory, 0, &mut budget)?;
        let os_name = OsString::from_vec(name.to_string().into_bytes());
        if !store.sync_pending_dir.entry_is(&os_name, &directory)? {
            return Err(crate::StoreError::InvalidGitSyncState {
                message: "disposable pending binding was replaced".to_owned(),
            });
        }
        store.sync_pending_dir.unlink_dir(&os_name)?;
        store.sync_pending_dir.sync()?;
    }
    Ok(())
}

const CLEANUP_BATCH: usize = 4_096;

fn maximum_cleanup_entries() -> usize {
    // One maximum fetched repository, one blob per addition, chunk metadata and all fixed
    // ancestry. This is deliberately a count bound, while deletion itself stays batched.
    super::git::MAX_PENDING_REPO_FS_ENTRIES
        .saturating_add(MAX_BULK_ADDITIONS)
        .saturating_add(MAX_ADDITION_CHUNKS.saturating_mul(3))
        .saturating_add(64)
}

fn remove_contents(
    directory: &Directory,
    depth: usize,
    budget: &mut usize,
) -> Result<(), crate::StoreError> {
    if depth > 64 {
        return Err(crate::StoreError::InvalidGitSyncState {
            message: "disposable pending residue exceeds cleanup depth".to_owned(),
        });
    }
    loop {
        let batch_limit = (*budget).min(CLEANUP_BATCH);
        if batch_limit == 0 {
            return Err(crate::StoreError::InvalidGitSyncState {
                message: "disposable pending residue exceeds cleanup count".to_owned(),
            });
        }
        let names = directory.name_batch(batch_limit)?;
        if names.is_empty() {
            return directory.sync();
        }
        for name in names {
            *budget =
                budget
                    .checked_sub(1)
                    .ok_or_else(|| crate::StoreError::InvalidGitSyncState {
                        message: "disposable pending residue exceeds cleanup count".to_owned(),
                    })?;
            let os_name = OsStr::from_bytes(&name);
            if directory.kind(os_name)? == rustix::fs::FileType::Directory {
                let child = directory.open_dir(os_name)?;
                remove_contents(&child, depth + 1, budget)?;
                if !directory.entry_is(os_name, &child)? {
                    return Err(crate::StoreError::InvalidGitSyncState {
                        message: "disposable pending child binding was replaced".to_owned(),
                    });
                }
                directory.unlink_dir(os_name)?;
            } else {
                directory.unlink_file(os_name)?;
            }
        }
        directory.sync()?;
    }
}

pub(super) fn validate_closed_layout(pending: &DurablePending) -> Result<(), PendingError> {
    let names = pending.directory.bounded_names(4)?;
    for name in &names {
        if matches!(
            name.as_slice(),
            b"additions" | b"pending.json" | b"repo.git"
        ) {
            continue;
        }
        let text = std::str::from_utf8(name)
            .map_err(|_| PendingError::Invalid("non-UTF-8 pending residue".to_owned()))?;
        let Some(suffix) = text.strip_prefix(".pending.tmp-") else {
            return Err(PendingError::Invalid(
                "unexpected pending operation entry".to_owned(),
            ));
        };
        let id = uuid::Uuid::parse_str(suffix)
            .map_err(|_| PendingError::Invalid("invalid pending temporary".to_owned()))?;
        if id.get_version_num() != 7
            || id.get_variant() != uuid::Variant::RFC4122
            || pending.directory.kind(OsStr::from_bytes(name))? != rustix::fs::FileType::RegularFile
        {
            return Err(PendingError::Invalid(
                "invalid pending temporary".to_owned(),
            ));
        }
        pending.directory.unlink_file(OsStr::from_bytes(name))?;
        pending.directory.sync()?;
    }
    require_exact_names(
        &pending.directory,
        &[b"additions", b"pending.json", b"repo.git"],
    )?;
    for required_directory in ["additions", "repo.git"] {
        if pending.directory.kind(OsStr::new(required_directory))?
            != rustix::fs::FileType::Directory
        {
            return Err(PendingError::Invalid(format!(
                "{required_directory} is not a directory"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn discover(store: &Store) -> Result<PendingDiscovery, PendingError> {
    let names = store.sync_pending_dir.bounded_names(2)?;
    let mut durable = Vec::new();
    let mut disposable = Vec::new();
    for raw_name in names {
        let name_text = std::str::from_utf8(&raw_name)
            .map_err(|_| PendingError::Invalid("operation name is not UTF-8".to_owned()))?;
        let name: GitSyncOperationId = name_text.parse().map_err(PendingError::Invalid)?;
        let os_name = OsStr::new(name_text);
        if store.sync_pending_dir.kind(os_name)? != rustix::fs::FileType::Directory {
            return Err(PendingError::Invalid(
                "operation entry is not a directory".to_owned(),
            ));
        }
        let directory = store.sync_pending_dir.open_dir(os_name)?;
        let file = match directory.open_file(OsStr::new("pending.json")) {
            Ok(file) => file,
            Err(crate::StoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                disposable.push((name, directory));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let size = directory.require_regular(&file, OsStr::new("pending.json"))?;
        if size > MAX_PENDING_ROOT_BYTES as u64 {
            return Err(PendingError::Oversized);
        }
        let metadata = file
            .metadata()
            .map_err(|error| PendingError::Invalid(error.to_string()))?;
        if metadata.mode() & 0o777 != 0o600 {
            return Err(PendingError::Invalid(
                "pending root mode is not 0600".to_owned(),
            ));
        }
        let mut bytes =
            Vec::with_capacity(usize::try_from(size).map_err(|_| {
                PendingError::Invalid("pending root size exceeds usize".to_owned())
            })?);
        file.take(MAX_PENDING_ROOT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| PendingError::Invalid(error.to_string()))?;
        let document = decode_document(&bytes)?;
        if document.operation_id != name {
            return Err(PendingError::Invalid(
                "operation directory and document differ".to_owned(),
            ));
        }
        durable.push(DurablePending {
            name,
            directory,
            document,
        });
    }
    if durable.len() > 2 || durable.len() + disposable.len() > 2 {
        return Err(PendingError::Invalid(
            "more than two pending operation slots".to_owned(),
        ));
    }
    let (active, predecessor) = match durable.len() {
        0 => (None, None),
        1 => (durable.pop(), None),
        2 => {
            let right = durable.pop().expect("two entries");
            let left = durable.pop().expect("two entries");
            let (successor, predecessor) =
                if left.document.predecessor_operation_id.as_ref() == Some(&right.name) {
                    (left, right)
                } else if right.document.predecessor_operation_id.as_ref() == Some(&left.name) {
                    (right, left)
                } else {
                    return Err(PendingError::Invalid(
                        "two pending slots have no unique predecessor linkage".to_owned(),
                    ));
                };
            if predecessor.document.phase != GitSyncPendingPhase::RemoteCasStale
                || successor.document.original_base_commit
                    != predecessor.document.original_base_commit
                || successor.document.original_base_revision
                    != predecessor.document.original_base_revision
                || successor.document.logical_store_id != predecessor.document.logical_store_id
                || successor.document.local_trust_binding
                    != predecessor.document.local_trust_binding
                || successor.document.approved_remote != predecessor.document.approved_remote
                || successor.document.object_format != predecessor.document.object_format
                || successor.document.advance_from_commit != predecessor.document.candidate_commit
                || successor.document.advance_from_revision
                    != predecessor.document.candidate_revision
                || successor.document.observed_local_tip != predecessor.document.candidate_commit
                || successor.document.expected_remote_tip
                    != predecessor
                        .document
                        .stale_remote_oid
                        .clone()
                        .expect("stale validated")
            {
                return Err(PendingError::Invalid(
                    "two pending slots are not a fully bound stale succession".to_owned(),
                ));
            }
            (Some(successor), Some(predecessor))
        }
        _ => unreachable!(),
    };
    Ok(PendingDiscovery {
        active,
        disposable,
        predecessor,
    })
}

#[cfg(test)]
fn test_document() -> PendingDocument {
    let object_format = GitObjectFormat::Sha1;
    let oid = |byte: char| GitOid::parse(object_format, &byte.to_string().repeat(40)).expect("OID");
    PendingDocument {
        schema: PENDING_SCHEMA.to_owned(),
        operation_id: "01913f1d-8e2a-7c30-8f4a-426614174090"
            .parse()
            .expect("operation"),
        phase: GitSyncPendingPhase::Prepared,
        logical_store_id: LogicalStoreId::new(
            "01913f1d-8e2a-7c30-8f4a-426614174010"
                .parse()
                .expect("store UUID"),
            "7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447"
                .parse()
                .expect("fingerprint"),
        ),
        local_trust_binding: LocalTrustBinding::parse(
            "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        )
        .expect("trust"),
        approved_remote: ApprovedRemote::new(
            super::ApprovedRemoteLocator::parse("file:///srv/git/store.git").expect("locator"),
            super::ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
        object_format,
        original_base_commit: oid('1'),
        original_base_revision: StoreRevisionRef::parse(
            "wayjournal.store/blake3-framed-v1",
            "1c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        )
        .expect("revision"),
        advance_from_commit: oid('1'),
        advance_from_revision: StoreRevisionRef::parse(
            "wayjournal.store/blake3-framed-v1",
            "1c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        )
        .expect("revision"),
        observed_local_tip: oid('2'),
        expected_remote_tip: oid('3'),
        candidate_commit: oid('4'),
        candidate_revision: StoreRevisionRef::parse(
            "wayjournal.store/blake3-framed-v1",
            "4c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        )
        .expect("revision"),
        candidate_parents: vec![oid('2'), oid('3')],
        additions_count: 1,
        additions_total_bytes: 10,
        additions_index_digest: "5c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
            .parse()
            .expect("digest"),
        predecessor_operation_id: None,
        stale_remote_oid: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_root_codec_is_closed_canonical_and_bounded() {
        let document = test_document();
        let encoded = encode_document(&document).expect("encode");
        assert!(encoded.len() <= MAX_PENDING_ROOT_BYTES);
        assert_eq!(decode_document(&encoded).expect("decode"), document);

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).expect("JSON");
        value["unknown"] = serde_json::json!(true);
        let mut unknown = serde_json::to_vec_pretty(&value).expect("encode hostile");
        unknown.push(b'\n');
        assert!(decode_document(&unknown).is_err());
        assert!(decode_document(&vec![b' '; MAX_PENDING_ROOT_BYTES + 1]).is_err());
    }

    #[test]
    fn addition_chunk_round_trips_maximal_path_and_short_final_chunk() {
        let domain = format!("{}.{}.c", "a".repeat(63), "b".repeat(62));
        let path = format!(
            "journal/records/{domain}/01913f1d-8e2a-7c30-8f4a-426614174010/01913f1d-8e2a-7c30-8f4a-426614174011.json"
        )
        .into_bytes();
        assert_eq!(path.len(), MAX_CANONICAL_PATH_BYTES);
        let entry = AdditionEntry {
            path,
            byte_length: MAX_BULK_ADDITION_BYTES,
            content_digest: "5c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
                .parse()
                .expect("digest"),
        };
        let encoded = encode_chunk(244, std::slice::from_ref(&entry)).expect("chunk");
        assert_eq!(decode_chunk(&encoded).expect("decode"), (244, vec![entry]));
    }

    #[test]
    fn closed_operation_layout_rejects_unbound_entries() {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-pending-closed-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).expect("root");
        for directory in ["additions", "repo.git"] {
            std::fs::create_dir(root.join(directory)).expect("required directory");
        }
        std::fs::write(root.join("pending.json"), b"bound by discovery").expect("root file");
        let pending = DurablePending {
            name: test_document().operation_id.clone(),
            directory: Directory::open_ambient(&root).expect("open"),
            document: test_document(),
        };
        validate_closed_layout(&pending).expect("closed layout");
        std::fs::write(root.join("unbound"), b"hostile").expect("extra");
        assert!(validate_closed_layout(&pending).is_err());
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn cleanup_is_batched_beyond_the_old_disposable_limit() {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-pending-cleanup-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).expect("root");
        for index in 0..4_097 {
            std::fs::write(root.join(format!("{index:08}")), b"").expect("entry");
        }
        let directory = Directory::open_ambient(&root).expect("open");
        let mut budget = maximum_cleanup_entries();
        remove_contents(&directory, 0, &mut budget).expect("batched cleanup");
        assert_eq!(std::fs::read_dir(&root).expect("read").count(), 0);
        drop(directory);
        std::fs::remove_dir(root).expect("cleanup root");
    }

    fn capacity_entry(ordinal: usize) -> AdditionEntry {
        let id = format!("00000000-0000-7000-8000-{ordinal:012x}");
        AdditionEntry {
            path: format!("journal/records/wayjournal.profile/{id}/{id}.json").into_bytes(),
            byte_length: 1,
            content_digest: Digest::from_hash(blake3::hash(&ordinal.to_be_bytes())),
        }
    }

    #[test]
    #[ignore = "explicit full-capacity gate: encodes and decodes one million real entries"]
    fn full_capacity_metadata_streams_every_boundary() {
        for count in [100_000, 100_001, 1_000_000] {
            let mut observed = 0_usize;
            for chunk in 0..chunk_count(count).expect("supported count") {
                let start = chunk * ADDITIONS_PER_CHUNK;
                let end = count.min(start + ADDITIONS_PER_CHUNK);
                let entries = (start..end).map(capacity_entry).collect::<Vec<_>>();
                let encoded = encode_chunk(u32::try_from(chunk).unwrap(), &entries).unwrap();
                let (_, decoded) = decode_chunk(&encoded).unwrap();
                assert_eq!(decoded, entries);
                observed += decoded.len();
            }
            assert_eq!(observed, count);
        }
        assert!(validate_addition_totals(1_000_001, 0).is_err());
        assert!(validate_addition_totals(1, 1024 * 1024 * 1024).is_ok());
        assert!(validate_addition_totals(1, 1024 * 1024 * 1024 + 1).is_err());
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    #[ignore = "explicit full-capacity gate: creates, streams, publishes, and retires 100001 real additions"]
    fn boundary_publication_recovery_and_retirement_is_real() {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-pending-boundary-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).expect("root");
        let registry = crate::wayjournal_domain_registry().expect("registry");
        #[derive(Debug)]
        struct NoLegacy;
        impl crate::LegacyStoreAdapter for NoLegacy {
            fn validate(&self, _: &[crate::LegacyEntry<'_>]) -> Result<(), String> {
                Ok(())
            }
        }
        let store = Store::open(&root, registry, std::sync::Arc::new(NoLegacy)).expect("store");
        let operation_id: GitSyncOperationId =
            "01913f1d-8e2a-7c30-8f4a-426614174090".parse().unwrap();
        let operation = create_operation(&store, &operation_id).unwrap();
        let mut document = test_document();
        let current = std::collections::BTreeSet::new();
        let mut candidate = std::collections::BTreeMap::new();
        for ordinal in 0..100_001_usize {
            let id = format!("00000000-0000-7000-8000-{ordinal:012x}");
            candidate.insert(
                format!("journal/records/wayjournal.profile/{id}/{id}.json").into_bytes(),
                b"{}\n".to_vec(),
            );
        }
        stage_additions(&operation, &mut document, &current, &candidate).unwrap();
        publish_document(&operation, &document).unwrap();
        let pending = DurablePending {
            name: operation_id,
            directory: operation,
            document,
        };
        let mut count = 0_usize;
        for_each_addition(&pending, |addition| {
            assert_eq!(addition.bytes, b"{}\n");
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 100_001);
        retire_operation(&store, &pending).unwrap();
        assert_eq!(
            std::fs::read_dir(root.join(".wayjournal-local/sync-pending"))
                .unwrap()
                .count(),
            0
        );
        drop(store);
        std::fs::remove_dir_all(root).expect("cleanup root");
    }

    #[test]
    #[allow(clippy::items_after_statements, clippy::too_many_lines)]
    #[ignore = "explicit full-capacity gate: stages, recovers, publishes, and retires exactly 1 GiB"]
    fn exact_one_gib_publication_recovery_and_retirement_is_real() {
        const FILES: usize = 1024;
        const BYTES_PER_FILE: usize = crate::MAX_LEGACY_FILE_BYTES;
        const EXACT_BYTES: u64 = 1024 * 1024 * 1024;

        fn addition(ordinal: usize) -> (Vec<u8>, Vec<u8>) {
            let entity = format!("00000000-0000-7000-8000-{ordinal:012x}");
            let record = format!("00000000-0000-7000-9000-{ordinal:012x}");
            let mut bytes = vec![b'x'; BYTES_PER_FILE];
            bytes[..8].copy_from_slice(&ordinal.to_be_bytes());
            (format!("events/{entity}/{record}.json").into_bytes(), bytes)
        }

        let root = std::env::temp_dir().join(format!(
            "wayjournal-pending-exact-gib-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).expect("root");
        let registry = crate::wayjournal_domain_registry().expect("registry");
        #[derive(Debug)]
        struct AcceptLegacy;
        impl crate::LegacyStoreAdapter for AcceptLegacy {
            fn validate(&self, _: &[crate::LegacyEntry<'_>]) -> Result<(), String> {
                Ok(())
            }
        }
        let store = Store::open(&root, registry, std::sync::Arc::new(AcceptLegacy)).expect("store");

        // +1 is rejected by production preflight before any payload is requested or written.
        let rejected_id: GitSyncOperationId =
            "01913f1d-8e2a-7c30-8f4a-42661417408f".parse().unwrap();
        let rejected = create_operation(&store, &rejected_id).unwrap();
        let mut rejected_document = test_document();
        assert!(
            stage_known_additions(
                &rejected,
                &mut rejected_document,
                FILES + 1,
                EXACT_BYTES + 1,
                std::iter::empty(),
            )
            .is_err()
        );
        assert!(!rejected.path.join("additions").exists());
        let rejected_pending = DurablePending {
            name: rejected_id,
            directory: rejected,
            document: rejected_document,
        };
        retire_operation(&store, &rejected_pending).unwrap();

        fn high_water_bytes() -> u64 {
            let status = std::fs::read_to_string("/proc/self/status").expect("procfs status");
            let line = status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))
                .expect("VmHWM");
            line.split_ascii_whitespace()
                .nth(1)
                .expect("VmHWM value")
                .parse::<u64>()
                .expect("VmHWM integer")
                * 1024
        }
        let before_high_water = high_water_bytes();
        let operation_id: GitSyncOperationId =
            "01913f1d-8e2a-7c30-8f4a-426614174090".parse().unwrap();
        let operation = create_operation(&store, &operation_id).unwrap();
        let mut document = test_document();
        stage_known_additions(
            &operation,
            &mut document,
            FILES,
            EXACT_BYTES,
            (0..FILES).map(addition),
        )
        .unwrap();
        assert_eq!(document.additions_total_bytes, EXACT_BYTES);
        publish_document(&operation, &document).unwrap();
        store.sync_pending_dir.sync().unwrap();
        let pending = DurablePending {
            name: operation_id,
            directory: operation,
            document,
        };
        let mut recovered_count = 0_usize;
        let mut recovered_bytes = 0_u64;
        for_each_addition(&pending, |addition| {
            crate::store::bulk::publish_addition(&store, &addition)?;
            recovered_count += 1;
            recovered_bytes += addition.bytes.len() as u64;
            Ok(())
        })
        .unwrap();
        assert_eq!(recovered_count, FILES);
        assert_eq!(recovered_bytes, EXACT_BYTES);
        assert_eq!(
            std::fs::read_dir(root.join("events")).unwrap().count(),
            FILES
        );
        retire_operation(&store, &pending).unwrap();
        let high_water_growth = high_water_bytes().saturating_sub(before_high_water);
        assert!(
            high_water_growth < 128 * 1024 * 1024,
            "exact-1-GiB staging/recovery/publication retained {high_water_growth} bytes"
        );
        assert_eq!(
            std::fs::read_dir(root.join(".wayjournal-local/sync-pending"))
                .unwrap()
                .count(),
            0
        );
        drop(store);
        std::fs::remove_dir_all(root).expect("cleanup root");
    }

    #[test]
    #[ignore = "explicit full-capacity gate: creates and retires one million filesystem entries"]
    fn full_capacity_retirement_removes_one_million_entries() {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-pending-million-cleanup-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).expect("root");
        let directory = Directory::open_ambient(&root).expect("open");
        for index in 0..1_000_000 {
            let file = directory
                .create_file(OsStr::new(&format!("{index:08}")))
                .expect("entry");
            file.sync_all().expect("entry durable");
        }
        directory.sync().expect("million-entry directory durable");
        let mut budget = maximum_cleanup_entries();
        remove_contents(&directory, 0, &mut budget).expect("full retirement");
        assert_eq!(std::fs::read_dir(&root).expect("read").count(), 0);
        drop(directory);
        std::fs::remove_dir(root).expect("cleanup root");
    }

    #[test]
    fn addition_index_supports_store_capacity_boundaries() {
        assert!(validate_addition_totals(100_000, MAX_TOTAL_CANONICAL_BYTES).is_ok());
        assert!(validate_addition_totals(100_001, MAX_TOTAL_CANONICAL_BYTES).is_ok());
        assert!(validate_addition_totals(MAX_BULK_ADDITIONS, MAX_TOTAL_CANONICAL_BYTES).is_ok());
        assert!(validate_addition_totals(MAX_BULK_ADDITIONS + 1, 0).is_err());
        assert!(validate_addition_totals(1, MAX_BULK_ADDITION_BYTES).is_ok());
        assert!(validate_addition_totals(1, MAX_BULK_ADDITION_BYTES + 1).is_err());
        assert_eq!(chunk_count(MAX_BULK_ADDITIONS).expect("chunks"), 245);
        assert_eq!(max_metadata_bytes(), 265_097_600);
        assert_eq!(MAX_CANONICAL_PATH_BYTES, 223);
        assert_eq!(MAX_ENCODED_ADDITION_BYTES, 265);
    }
}
