#![cfg_attr(not(test), allow(dead_code))]

use std::{
    ffi::OsStr,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Digest, LogicalStoreId, Store, StoreRevisionRef,
    json::{decode_strict, encode_pretty},
};

use super::{
    ApprovedRemote, GitOid, GitQuarantineReason, GitSyncOperationId, GitSyncRequest,
    LocalTrustBinding, QuarantineIncidentId,
};

const QUARANTINE_SCHEMA: &str = "wayjournal.git-quarantine/v1";
const MAX_INCIDENT_BYTES: usize = 16 * 1024;
const MAX_INCIDENTS: usize = 1_024;

#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("quarantine I/O failed: {0}")]
    Store(#[from] crate::StoreError),
    #[error("quarantine incident exceeds 16 KiB")]
    Oversized,
    #[error("invalid quarantine incident: {0}")]
    Invalid(String),
    #[error("quarantine incident capacity is exhausted")]
    CapacityExhausted,
    #[error("quarantine incident authority differs from the synchronization request")]
    AuthorityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuarantineIncident {
    schema: String,
    pub(super) incident_id: QuarantineIncidentId,
    pub(super) reason: GitQuarantineReason,
    logical_store_id: LogicalStoreId,
    local_trust_binding: LocalTrustBinding,
    approved_remote: ApprovedRemote,
    checkpoint_commit: GitOid,
    checkpoint_revision: StoreRevisionRef,
    observed_commit: Option<GitOid>,
    evidence_digest: Digest,
}

impl QuarantineIncident {
    fn validate(&self) -> Result<(), QuarantineError> {
        if self.schema != QUARANTINE_SCHEMA {
            return Err(QuarantineError::Invalid("unsupported schema".to_owned()));
        }
        if self
            .observed_commit
            .as_ref()
            .is_some_and(|observed| observed.format() != self.checkpoint_commit.format())
        {
            return Err(QuarantineError::Invalid(
                "observed and checkpoint object formats differ".to_owned(),
            ));
        }
        Ok(())
    }
}

#[allow(dead_code)]
fn encode(incident: &QuarantineIncident) -> Result<Vec<u8>, QuarantineError> {
    incident.validate()?;
    let value = serde_json::to_value(incident)
        .map_err(|error| QuarantineError::Invalid(error.to_string()))?;
    let bytes =
        encode_pretty(&value).map_err(|error| QuarantineError::Invalid(error.to_string()))?;
    if bytes.len() > MAX_INCIDENT_BYTES {
        return Err(QuarantineError::Oversized);
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<QuarantineIncident, QuarantineError> {
    if bytes.len() > MAX_INCIDENT_BYTES {
        return Err(QuarantineError::Oversized);
    }
    let value =
        decode_strict(bytes).map_err(|error| QuarantineError::Invalid(error.to_string()))?;
    let incident: QuarantineIncident = serde_json::from_value(value.clone())
        .map_err(|error| QuarantineError::Invalid(error.to_string()))?;
    incident.validate()?;
    let canonical =
        encode_pretty(&value).map_err(|error| QuarantineError::Invalid(error.to_string()))?;
    if canonical != bytes {
        return Err(QuarantineError::Invalid(
            "incident is not canonical JSON".to_owned(),
        ));
    }
    Ok(incident)
}

pub(super) fn ensure_capacity(store: &Store) -> Result<(), QuarantineError> {
    if store.quarantine_dir.bounded_names(MAX_INCIDENTS)?.len() >= MAX_INCIDENTS {
        return Err(QuarantineError::CapacityExhausted);
    }
    Ok(())
}

pub(super) fn active(
    store: &Store,
    request: &GitSyncRequest,
) -> Result<Option<QuarantineIncident>, QuarantineError> {
    let names = store.quarantine_dir.bounded_names(MAX_INCIDENTS)?;
    let Some(name) = names.first() else {
        return Ok(None);
    };
    if store.quarantine_dir.kind(OsStr::from_bytes(name))? != rustix::fs::FileType::RegularFile {
        return Err(QuarantineError::Invalid(
            "incident entry is not a regular file".to_owned(),
        ));
    }
    let text = std::str::from_utf8(name)
        .map_err(|_| QuarantineError::Invalid("incident filename is not UTF-8".to_owned()))?;
    let stem = text
        .strip_suffix(".json")
        .ok_or_else(|| QuarantineError::Invalid("incident filename is not canonical".to_owned()))?;
    let incident_id: QuarantineIncidentId = stem.parse().map_err(QuarantineError::Invalid)?;
    let file = store.quarantine_dir.open_file(OsStr::from_bytes(name))?;
    let size = store
        .quarantine_dir
        .require_regular(&file, OsStr::from_bytes(name))?;
    if size > MAX_INCIDENT_BYTES as u64 {
        return Err(QuarantineError::Oversized);
    }
    if file
        .metadata()
        .map_err(|error| QuarantineError::Invalid(error.to_string()))?
        .mode()
        & 0o777
        != 0o600
    {
        return Err(QuarantineError::Invalid(
            "incident mode is not 0600".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(size)
            .map_err(|_| QuarantineError::Invalid("incident size exceeds usize".to_owned()))?,
    );
    file.take(MAX_INCIDENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| QuarantineError::Invalid(error.to_string()))?;
    let incident = decode(&bytes)?;
    if incident.incident_id != incident_id {
        return Err(QuarantineError::Invalid(
            "incident filename and document differ".to_owned(),
        ));
    }
    if incident.local_trust_binding != request.local_trust()
        || incident.approved_remote != *request.approved_remote()
    {
        return Err(QuarantineError::AuthorityMismatch);
    }
    Ok(Some(incident))
}

#[allow(clippy::too_many_arguments, dead_code)]
pub(super) fn persist(
    store: &Store,
    logical_store_id: LogicalStoreId,
    request: &GitSyncRequest,
    checkpoint_commit: GitOid,
    checkpoint_revision: StoreRevisionRef,
    reason: GitQuarantineReason,
    observed_commit: Option<GitOid>,
    operation_id: Option<&GitSyncOperationId>,
) -> Result<QuarantineIncident, QuarantineError> {
    if let Some(existing) = active(store, request)? {
        return Ok(existing);
    }
    ensure_capacity(store)?;
    let incident_id = QuarantineIncidentId::now_v7();
    let evidence_digest = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"wayjournal-quarantine-evidence-v1\0");
        hasher.update(reason_string(reason).as_bytes());
        hasher.update(checkpoint_commit.as_hex().as_bytes());
        if let Some(observed) = &observed_commit {
            hasher.update(observed.as_hex().as_bytes());
        }
        if let Some(operation) = operation_id {
            hasher.update(operation.to_string().as_bytes());
        }
        Digest::from_hash(hasher.finalize())
    };
    let incident = QuarantineIncident {
        schema: QUARANTINE_SCHEMA.to_owned(),
        incident_id: incident_id.clone(),
        reason,
        logical_store_id,
        local_trust_binding: request.local_trust(),
        approved_remote: request.approved_remote().clone(),
        checkpoint_commit,
        checkpoint_revision,
        observed_commit,
        evidence_digest,
    };
    let bytes = encode(&incident)?;
    let name = format!("{incident_id}.json");
    let mut file = store.quarantine_dir.create_file(OsStr::new(&name))?;
    file.write_all(&bytes)
        .map_err(|error| QuarantineError::Invalid(error.to_string()))?;
    file.sync_all()
        .map_err(|error| QuarantineError::Invalid(error.to_string()))?;
    store.quarantine_dir.sync()?;
    Ok(incident)
}

#[allow(dead_code)]
fn reason_string(reason: GitQuarantineReason) -> &'static str {
    match reason {
        GitQuarantineReason::Deletion => "deletion",
        GitQuarantineReason::Modification => "modification",
        GitQuarantineReason::RollbackNonAncestry => "rollback_non_ancestry",
        GitQuarantineReason::MissingApprovedRef => "missing_approved_ref",
        GitQuarantineReason::InvalidCommitSnapshot => "invalid_commit_snapshot",
        GitQuarantineReason::MalformedHistory => "malformed_history",
        GitQuarantineReason::PathCollision => "path_collision",
        GitQuarantineReason::UuidCollision => "uuid_collision",
        GitQuarantineReason::LogicalIdentityMismatch => "logical_identity_mismatch",
        GitQuarantineReason::TrustMismatch => "trust_mismatch",
        GitQuarantineReason::UnapprovedRemoteRef => "unapproved_remote_ref",
        GitQuarantineReason::UnsafeRepositoryState => "unsafe_repository_state",
        GitQuarantineReason::HostilePublicationState => "hostile_publication_state",
    }
}

use std::os::unix::ffi::OsStrExt;
