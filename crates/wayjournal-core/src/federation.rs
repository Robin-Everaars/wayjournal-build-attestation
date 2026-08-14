use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::{Seek, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use url::Url;

use crate::{Digest, DigestError, LogicalStoreId, StoreRevisionRef, store::Directory};

mod checkpoint;
mod fault;
mod git;
mod history;
pub(crate) mod pending;
mod quarantine;
pub use checkpoint::CheckpointError;
pub use git::GitCommandError;
pub use quarantine::QuarantineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}
impl GitObjectFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
    const fn hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}
impl FromStr for GitObjectFormat {
    type Err = GitOidError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            _ => Err(GitOidError::UnsupportedFormat(input.to_owned())),
        }
    }
}
impl Serialize for GitObjectFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for GitObjectFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GitOidError {
    #[error("unsupported Git object format: {0}")]
    UnsupportedFormat(String),
    #[error("noncanonical {format} object id: {value}")]
    NonCanonical { format: &'static str, value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitOid {
    format: GitObjectFormat,
    hex: String,
}
impl GitOid {
    /// Parses one lowercase object ID with the exact length for `format`.
    /// # Errors
    /// Returns [`GitOidError`] for an unsupported length or noncanonical hex.
    pub fn parse(format: GitObjectFormat, hex: &str) -> Result<Self, GitOidError> {
        if hex.len() != format.hex_len()
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(GitOidError::NonCanonical {
                format: format.as_str(),
                value: hex.to_owned(),
            });
        }
        Ok(Self {
            format,
            hex: hex.to_owned(),
        })
    }
    #[must_use]
    pub const fn format(&self) -> GitObjectFormat {
        self.format
    }
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.hex
    }
}
impl<'de> Deserialize<'de> for GitOid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawGitOid {
            format: GitObjectFormat,
            hex: String,
        }
        let raw = RawGitOid::deserialize(deserializer)?;
        Self::parse(raw.format, &raw.hex).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LocalTrustBinding(Digest);
impl LocalTrustBinding {
    /// Parses one caller-held canonical 32-byte trust binding.
    /// # Errors
    /// Returns [`DigestError`] for noncanonical lowercase hex.
    pub fn parse(hex: &str) -> Result<Self, DigestError> {
        Digest::parse(hex).map(Self)
    }
    #[must_use]
    pub const fn as_digest(self) -> Digest {
        self.0
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("remote locator is invalid")]
    InvalidLocator,
    #[error("remote locator contains credentials")]
    CredentialBearingLocator,
    #[error("remote transport is unsupported")]
    UnsupportedTransport,
    #[error("approved ref must be one canonical refs/heads ref")]
    InvalidRef,
    #[error("Git executable must be an absolute ordinary executable file")]
    InvalidGitExecutable,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ApprovedRemoteLocator(String);
impl ApprovedRemoteLocator {
    /// Parses a credential-free canonical `file://` or `https://` locator.
    /// # Errors
    /// Rejects credentials, unsupported transports, query, fragment, port, and relative paths.
    pub fn parse(value: &str) -> Result<Self, ApprovalError> {
        if value.as_bytes().contains(&b'%') {
            return Err(ApprovalError::InvalidLocator);
        }
        let parsed = Url::parse(value).map_err(|_| ApprovalError::InvalidLocator)?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ApprovalError::CredentialBearingLocator);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ApprovalError::InvalidLocator);
        }
        match parsed.scheme() {
            "https" => {
                if parsed.host_str().is_none() || parsed.port().is_some() {
                    return Err(ApprovalError::InvalidLocator);
                }
            }
            "file" => {
                if parsed
                    .host_str()
                    .is_some_and(|host| !host.is_empty() && host != "localhost")
                    || !Path::new(parsed.path()).is_absolute()
                {
                    return Err(ApprovalError::InvalidLocator);
                }
            }
            _ => return Err(ApprovalError::UnsupportedTransport),
        }
        if parsed.as_str() != value {
            return Err(ApprovalError::InvalidLocator);
        }
        Ok(Self(value.to_owned()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for ApprovedRemoteLocator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ApprovedRef(String);
impl ApprovedRef {
    /// Parses one canonical fully qualified branch ref.
    /// # Errors
    /// Returns [`ApprovalError::InvalidRef`] for all non-`refs/heads/...` forms.
    pub fn parse(value: &str) -> Result<Self, ApprovalError> {
        let Some(name) = value.strip_prefix("refs/heads/") else {
            return Err(ApprovalError::InvalidRef);
        };
        let invalid = name.is_empty()
            || name.starts_with('/')
            || name.ends_with('/')
            || name.ends_with('.')
            || name.contains("..")
            || name.contains("@{")
            || name.bytes().any(|b| {
                b <= b' '
                    || b == 0x7f
                    || matches!(b, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
            })
            || name.split('/').any(|part| {
                part.is_empty()
                    || part.starts_with('.')
                    || part
                        .get(part.len().saturating_sub(5)..)
                        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".lock"))
            });
        if invalid {
            return Err(ApprovalError::InvalidRef);
        }
        Ok(Self(value.to_owned()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for ApprovedRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRemote {
    locator: ApprovedRemoteLocator,
    reference: ApprovedRef,
}
impl ApprovedRemote {
    #[must_use]
    pub const fn new(locator: ApprovedRemoteLocator, reference: ApprovedRef) -> Self {
        Self { locator, reference }
    }
    #[must_use]
    pub const fn locator(&self) -> &ApprovedRemoteLocator {
        &self.locator
    }
    #[must_use]
    pub const fn reference(&self) -> &ApprovedRef {
        &self.reference
    }
}

#[derive(Debug, Clone)]
pub struct GitSyncRequest {
    git_executable: PathBuf,
    executable: Arc<File>,
    local_trust: LocalTrustBinding,
    approved_remote: ApprovedRemote,
}
impl GitSyncRequest {
    /// Creates one closed admission request from explicit trusted inputs.
    /// # Errors
    /// Rejects a Git executable that is relative or not an ordinary file.
    pub fn new(
        git_executable: PathBuf,
        local_trust: LocalTrustBinding,
        approved_remote: ApprovedRemote,
    ) -> Result<Self, ApprovalError> {
        if !git_executable.is_absolute() {
            return Err(ApprovalError::InvalidGitExecutable);
        }
        let descriptor = rustix::fs::open(
            &git_executable,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| ApprovalError::InvalidGitExecutable)?;
        let executable = File::from(descriptor);
        let metadata = executable
            .metadata()
            .map_err(|_| ApprovalError::InvalidGitExecutable)?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return Err(ApprovalError::InvalidGitExecutable);
        }
        Ok(Self {
            git_executable,
            executable: Arc::new(executable),
            local_trust,
            approved_remote,
        })
    }
    #[must_use]
    pub fn git_executable(&self) -> &Path {
        &self.git_executable
    }
    pub(super) fn executable_proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.executable.as_raw_fd()))
    }
    #[must_use]
    pub const fn local_trust(&self) -> LocalTrustBinding {
        self.local_trust
    }
    #[must_use]
    pub const fn approved_remote(&self) -> &ApprovedRemote {
        &self.approved_remote
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCheckpoint {
    logical_store_id: LogicalStoreId,
    local_trust_binding: LocalTrustBinding,
    approved_remote: ApprovedRemote,
    accepted_commit: GitOid,
    accepted_revision: StoreRevisionRef,
}
impl AdmissionCheckpoint {
    #[must_use]
    pub const fn logical_store_id(&self) -> &LogicalStoreId {
        &self.logical_store_id
    }
    #[must_use]
    pub const fn local_trust_binding(&self) -> &LocalTrustBinding {
        &self.local_trust_binding
    }
    #[must_use]
    pub const fn approved_remote(&self) -> &ApprovedRemote {
        &self.approved_remote
    }
    #[must_use]
    pub const fn accepted_commit(&self) -> &GitOid {
        &self.accepted_commit
    }
    #[must_use]
    pub const fn accepted_revision(&self) -> StoreRevisionRef {
        self.accepted_revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitAdmissionOutcome {
    GenesisValidated {
        commit: GitOid,
        revision: StoreRevisionRef,
    },
    UpToDate {
        commit: GitOid,
        revision: StoreRevisionRef,
    },
    AdvanceRequired {
        accepted: Option<GitOid>,
        local: GitOid,
        remote: Option<GitOid>,
    },
}

/// Identifier of one durable advancing synchronization operation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GitSyncOperationId(String);
impl GitSyncOperationId {
    #[must_use]
    pub fn now_v7() -> Self {
        Self(uuid::Uuid::now_v7().hyphenated().to_string())
    }
}
impl fmt::Display for GitSyncOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl FromStr for GitSyncOperationId {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let id =
            uuid::Uuid::parse_str(value).map_err(|_| "operation id is not UUIDv7".to_owned())?;
        if id.get_version_num() != 7
            || id.get_variant() != uuid::Variant::RFC4122
            || id.hyphenated().to_string() != value
        {
            return Err("operation id is not canonical UUIDv7".to_owned());
        }
        Ok(Self(value.to_owned()))
    }
}
impl<'de> Deserialize<'de> for GitSyncOperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

/// Durable phase hint. Recovery always verifies the bound filesystem and Git truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitSyncPendingPhase {
    Prepared,
    FilesPublished,
    LocalRefPublished,
    CheckpointPublished,
    RemoteCasStale,
    RemoteCasConfirmed,
}

/// Identifier of one immutable local quarantine incident.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct QuarantineIncidentId(String);
impl QuarantineIncidentId {
    #[must_use]
    pub fn now_v7() -> Self {
        Self(uuid::Uuid::now_v7().hyphenated().to_string())
    }
}
impl fmt::Display for QuarantineIncidentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl FromStr for QuarantineIncidentId {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let id =
            uuid::Uuid::parse_str(value).map_err(|_| "incident id is not UUIDv7".to_owned())?;
        if id.get_version_num() != 7
            || id.get_variant() != uuid::Variant::RFC4122
            || id.hyphenated().to_string() != value
        {
            return Err("incident id is not canonical UUIDv7".to_owned());
        }
        Ok(Self(value.to_owned()))
    }
}
impl<'de> Deserialize<'de> for QuarantineIncidentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

/// Closed, redaction-safe reasons for rejecting automatic Git advancement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitQuarantineReason {
    Deletion,
    Modification,
    RollbackNonAncestry,
    MissingApprovedRef,
    InvalidCommitSnapshot,
    MalformedHistory,
    PathCollision,
    UuidCollision,
    LogicalIdentityMismatch,
    TrustMismatch,
    UnapprovedRemoteRef,
    UnsafeRepositoryState,
    HostilePublicationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitSyncOutcome {
    UpToDate {
        commit: GitOid,
        revision: StoreRevisionRef,
    },
    Advanced {
        commit: GitOid,
        revision: StoreRevisionRef,
    },
    StaleRemoteCas {
        candidate: GitOid,
        observed_remote: GitOid,
    },
    Quarantined {
        incident_id: QuarantineIncidentId,
        reason: GitQuarantineReason,
    },
}

#[derive(Debug, Error)]
pub enum GitSyncError {
    #[error("Git admission must be bootstrapped before advancing sync")]
    BootstrapRequired,
    #[error("advancing Git synchronization is required")]
    AdvanceRequired,
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    #[error(transparent)]
    Git(#[from] GitCommandError),
    #[error(transparent)]
    Store(#[from] crate::StoreError),
    #[error(transparent)]
    Quarantine(#[from] QuarantineError),
    #[error(transparent)]
    LegacyStreaming(#[from] crate::LegacyStreamingError),
    #[error("pending synchronization failed: {message}")]
    PendingState { message: String },
    #[error(transparent)]
    Admission(#[from] GitAdmissionError),
}

impl From<pending::PendingError> for GitSyncError {
    fn from(error: pending::PendingError) -> Self {
        Self::PendingState {
            message: error.to_string(),
        }
    }
}

#[derive(Debug, Error)]
pub enum GitAdmissionError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    #[error(transparent)]
    Git(#[from] GitCommandError),
    #[error(transparent)]
    Store(#[from] crate::StoreError),
    #[error("{operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("local trust binding does not match the checkpoint")]
    LocalTrustMismatch,
    #[error("approved remote does not match the checkpoint")]
    UnapprovedRemote,
    #[error("approved ref does not match the checkpoint")]
    UnapprovedRef,
    #[error("strict initialized identity is required")]
    MissingIdentity,
    #[error("Git tree logical identity does not match the local store")]
    IdentityMismatch,
    #[error("Git tree revision does not match the local filesystem")]
    CandidateRevisionMismatch,
    #[error("checkpoint logical identity does not match its accepted tree or local store")]
    CheckpointIdentityMismatch,
    #[error("checkpoint revision does not match its accepted Git tree")]
    CheckpointRevisionMismatch,
    #[error("checkpoint Git object format does not match the local repository")]
    CheckpointObjectFormatMismatch,
    #[error("checkpoint accepted commit is unavailable or invalid")]
    CheckpointCommitUnavailable,
    #[error("Git tree contains a noncanonical tracked path")]
    NonCanonicalTrackedPath,
    #[error("Git tree entry is not a non-executable regular blob")]
    InvalidTreeEntry,
}

impl crate::Store {
    /// Explicitly advances the approved Git replica after a checkpoint has been bootstrapped.
    /// # Errors
    /// Fails closed when bootstrap or advancing synchronization is required.
    #[allow(clippy::too_many_lines)]
    pub fn sync_git_union(&self, request: &GitSyncRequest) -> Result<GitSyncOutcome, GitSyncError> {
        self.require_legacy_streaming(crate::LegacyStreamRequirement::FullDomainBounded)?;
        let guard = self.lock_exclusive_unsnapshotted()?;
        if let Some(incident) = quarantine::active(self, request)? {
            return Ok(GitSyncOutcome::Quarantined {
                incident_id: incident.incident_id,
                reason: incident.reason,
            });
        }
        quarantine::ensure_capacity(self)?;
        let checkpoint = checkpoint::read(self)?.ok_or(GitSyncError::BootstrapRequired)?;
        require_checkpoint_authority(&checkpoint, request)?;
        let discovery = pending::discover(self)?;
        if discovery.active.is_some() && self.has_transaction_residue_locked()? {
            return Err(crate::StoreError::ConflictingRecoveryState.into());
        }
        if let Some(active) = discovery.active {
            pending::retire_named_disposable(
                self,
                discovery.disposable,
                active.document.predecessor_operation_id.as_ref(),
            )?;
            return recover_sync_operation(
                self,
                request,
                &guard,
                checkpoint,
                active,
                discovery.predecessor,
            );
        }
        pending::clean_disposable_locked(self)?;
        guard.recover_transactions()?;
        let current = guard.scan_visible_streaming_locked()?;
        match start_sync_operation(
            self,
            request,
            &checkpoint,
            &checkpoint,
            &current,
            None,
            None,
        )? {
            StartOperation::Pending(active) => {
                recover_sync_operation(self, request, &guard, checkpoint, *active, None)
            }
            StartOperation::Quarantined(outcome) => Ok(outcome),
        }
    }

    /// Reads the durable local admission anchor. Malformed state is never treated as absent.
    /// # Errors
    /// Returns a checkpoint or descriptor-safe I/O error for malformed local state.
    pub fn admission_checkpoint(&self) -> Result<Option<AdmissionCheckpoint>, GitAdmissionError> {
        let _exclusive = self.exclusive_snapshot()?;
        checkpoint::read(self).map_err(Into::into)
    }

    /// Establishes or verifies the read-only Git admission anchor.
    ///
    /// This S4a operation never advances Git, the canonical filesystem, or an existing
    /// checkpoint. Differing tips return [`GitAdmissionOutcome::AdvanceRequired`].
    /// # Errors
    /// Fails closed on approval, Git, identity, tree, checkpoint, or store validation errors.
    #[allow(clippy::too_many_lines)]
    pub fn bootstrap_git_admission(
        &self,
        request: &GitSyncRequest,
    ) -> Result<GitAdmissionOutcome, GitAdmissionError> {
        let guard = self.lock_exclusive_unsnapshotted()?;
        let discovery =
            pending::discover(self).map_err(|error| crate::StoreError::InvalidGitSyncState {
                message: error.to_string(),
            })?;
        if discovery.active.is_some() && self.has_transaction_residue_locked()? {
            return Err(crate::StoreError::ConflictingRecoveryState.into());
        }
        let checkpoint_before = checkpoint::read(self)?;
        let runner = git::GitRunner::new(request);
        let current = if let Some(active) = discovery.active {
            if active.document.local_trust_binding != request.local_trust {
                return Err(GitAdmissionError::LocalTrustMismatch);
            }
            if active.document.approved_remote.locator != request.approved_remote.locator {
                return Err(GitAdmissionError::UnapprovedRemote);
            }
            if active.document.approved_remote.reference != request.approved_remote.reference {
                return Err(GitAdmissionError::UnapprovedRef);
            }
            let Some(checkpoint) = &checkpoint_before else {
                return Err(crate::StoreError::GitSyncPending {
                    operation_id: active.name,
                    phase: active.document.phase,
                }
                .into());
            };
            if checkpoint.accepted_commit != active.document.candidate_commit
                || checkpoint.accepted_revision != active.document.candidate_revision
                || checkpoint.logical_store_id != active.document.logical_store_id
            {
                return Err(crate::StoreError::GitSyncPending {
                    operation_id: active.name,
                    phase: active.document.phase,
                }
                .into());
            }
            let local = git::inspect_local(self, &runner, request)?;
            if local.tip != active.document.candidate_commit {
                return Err(crate::StoreError::GitSyncPending {
                    operation_id: active.name,
                    phase: active.document.phase,
                }
                .into());
            }
            git::require_local_commit(&runner, &local, &local.tip)?;
            let local_snapshot = git::local_tree_snapshot(self, &runner, &local, &local.tip)?;
            let visible = guard.scan_visible_locked()?;
            require_same_store(&local_snapshot, &visible)?;
            if local_snapshot.revision() != visible.revision()
                || visible.revision() != checkpoint.accepted_revision
            {
                return Err(GitAdmissionError::CandidateRevisionMismatch);
            }
            visible
        } else {
            pending::clean_disposable_locked(self)?;
            guard.recover_transactions()?;
            guard.scan_visible_locked()?
        };
        let current_identity = current
            .identity()
            .ok_or(GitAdmissionError::MissingIdentity)?;
        if let Some(checkpoint) = &checkpoint_before {
            if checkpoint.local_trust_binding != request.local_trust {
                return Err(GitAdmissionError::LocalTrustMismatch);
            }
            if checkpoint.approved_remote.locator != request.approved_remote.locator {
                return Err(GitAdmissionError::UnapprovedRemote);
            }
            if checkpoint.approved_remote.reference != request.approved_remote.reference {
                return Err(GitAdmissionError::UnapprovedRef);
            }
            if checkpoint.logical_store_id != *current_identity.logical_id() {
                return Err(GitAdmissionError::CheckpointIdentityMismatch);
            }
        }
        let local = git::inspect_local(self, &runner, request)?;
        git::require_local_commit(&runner, &local, &local.tip)?;
        let local_snapshot = git::local_tree_snapshot(self, &runner, &local, &local.tip)?;
        require_same_store(&local_snapshot, &current)?;
        if local_snapshot.revision() != current.revision() {
            return Err(GitAdmissionError::CandidateRevisionMismatch);
        }

        if let Some(checkpoint) = &checkpoint_before {
            if checkpoint.accepted_commit.format() != local.format {
                return Err(GitAdmissionError::CheckpointObjectFormatMismatch);
            }
            git::require_local_commit(&runner, &local, &checkpoint.accepted_commit)
                .map_err(|_| GitAdmissionError::CheckpointCommitUnavailable)?;
            let accepted =
                git::local_tree_snapshot(self, &runner, &local, &checkpoint.accepted_commit)
                    .map_err(|_| GitAdmissionError::CheckpointCommitUnavailable)?;
            let accepted_identity = accepted
                .identity()
                .ok_or(GitAdmissionError::CheckpointIdentityMismatch)?;
            if accepted_identity.logical_id() != &checkpoint.logical_store_id {
                return Err(GitAdmissionError::CheckpointIdentityMismatch);
            }
            if accepted.revision() != checkpoint.accepted_revision {
                return Err(GitAdmissionError::CheckpointRevisionMismatch);
            }
            if local.tip != checkpoint.accepted_commit
                || current.revision() != checkpoint.accepted_revision
            {
                return Ok(GitAdmissionOutcome::AdvanceRequired {
                    accepted: Some(checkpoint.accepted_commit.clone()),
                    local: local.tip,
                    remote: None,
                });
            }
        }

        recover_attempts(self)?;
        let (attempt_name, attempt) = create_attempt(self)?;
        let result = (|| {
            let fetched = git::fetch_remote(&runner, request, &attempt, local.format)?;
            git::require_fetched_commit(&runner, &fetched, &fetched.remote_tip)?;
            if local.tip != fetched.remote_tip {
                return Ok(GitAdmissionOutcome::AdvanceRequired {
                    accepted: checkpoint_before
                        .as_ref()
                        .map(|checkpoint| checkpoint.accepted_commit.clone()),
                    local: local.tip,
                    remote: Some(fetched.remote_tip),
                });
            }
            let remote = git::fetched_tree_snapshot(self, &runner, &fetched, &fetched.remote_tip)?;
            require_same_store(&remote, &current)?;
            if current.revision() != remote.revision() {
                return Err(GitAdmissionError::CandidateRevisionMismatch);
            }
            match checkpoint_before {
                None => {
                    let checkpoint = AdmissionCheckpoint {
                        logical_store_id: current_identity.logical_id().clone(),
                        local_trust_binding: request.local_trust,
                        approved_remote: request.approved_remote.clone(),
                        accepted_commit: fetched.remote_tip.clone(),
                        accepted_revision: remote.revision(),
                    };
                    checkpoint::write(self, &checkpoint)?;
                    Ok(GitAdmissionOutcome::GenesisValidated {
                        commit: fetched.remote_tip,
                        revision: remote.revision(),
                    })
                }
                Some(checkpoint) => Ok(GitAdmissionOutcome::UpToDate {
                    commit: checkpoint.accepted_commit,
                    revision: checkpoint.accepted_revision,
                }),
            }
        })();
        let cleanup = cleanup_attempt(self, &attempt_name, &attempt);
        match (result, cleanup) {
            (_, Err(error)) | (Err(error), Ok(())) => Err(error),
            (Ok(outcome), Ok(())) => Ok(outcome),
        }
    }
}

enum StartOperation {
    Pending(Box<pending::DurablePending>),
    Quarantined(GitSyncOutcome),
}

fn require_checkpoint_authority(
    checkpoint: &AdmissionCheckpoint,
    request: &GitSyncRequest,
) -> Result<(), GitSyncError> {
    if checkpoint.local_trust_binding != request.local_trust {
        return Err(GitAdmissionError::LocalTrustMismatch.into());
    }
    if checkpoint.approved_remote.locator != request.approved_remote.locator {
        return Err(GitAdmissionError::UnapprovedRemote.into());
    }
    if checkpoint.approved_remote.reference != request.approved_remote.reference {
        return Err(GitAdmissionError::UnapprovedRef.into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn start_sync_operation(
    store: &crate::Store,
    request: &GitSyncRequest,
    original_base: &AdmissionCheckpoint,
    advance_from: &AdmissionCheckpoint,
    current: &crate::StoreSnapshot,
    predecessor: Option<GitSyncOperationId>,
    predecessor_pending: Option<&pending::DurablePending>,
) -> Result<StartOperation, GitSyncError> {
    let current_identity = current
        .identity()
        .ok_or(GitAdmissionError::MissingIdentity)?;
    if current_identity.logical_id() != &advance_from.logical_store_id {
        return Err(GitAdmissionError::CheckpointIdentityMismatch.into());
    }
    let runner = git::GitRunner::new(request);
    let local = match git::inspect_local(store, &runner, request) {
        Ok(local) => local,
        Err(error) if error.is_hostile_repository_state() => {
            let incident = quarantine::persist(
                store,
                original_base.logical_store_id.clone(),
                request,
                original_base.accepted_commit.clone(),
                original_base.accepted_revision,
                GitQuarantineReason::UnsafeRepositoryState,
                None,
                None,
            )?;
            return Ok(StartOperation::Quarantined(GitSyncOutcome::Quarantined {
                incident_id: incident.incident_id,
                reason: incident.reason,
            }));
        }
        Err(error) => return Err(error.into()),
    };
    git::require_local_commit(&runner, &local, &local.tip)?;
    let local_snapshot = git::local_tree_snapshot_streaming(store, &runner, &local, &local.tip)?;
    require_same_store(&local_snapshot, current)?;
    if local_snapshot.revision() != current.revision() {
        return Err(GitAdmissionError::CandidateRevisionMismatch.into());
    }

    let operation_id = GitSyncOperationId::now_v7();
    let operation = pending::create_operation(store, &operation_id)?;
    fault::hit("operation-directory-durable");
    let (repository, local_tip, remote_tip) =
        match git::create_sync_repository(&runner, request, &operation, &local) {
            Ok(repository) => repository,
            Err(error) if error.is_hostile_repository_state() => {
                let incident = quarantine::persist(
                    store,
                    original_base.logical_store_id.clone(),
                    request,
                    original_base.accepted_commit.clone(),
                    original_base.accepted_revision,
                    GitQuarantineReason::UnsafeRepositoryState,
                    None,
                    Some(&operation_id),
                )?;
                return Ok(StartOperation::Quarantined(GitSyncOutcome::Quarantined {
                    incident_id: incident.incident_id,
                    reason: incident.reason,
                }));
            }
            Err(error) => return Err(error.into()),
        };
    if let Err(error) = history::validate_histories(
        store,
        &runner,
        &repository,
        &original_base.accepted_commit,
        &local_tip,
        &remote_tip,
    ) {
        let incident = quarantine::persist(
            store,
            original_base.logical_store_id.clone(),
            request,
            original_base.accepted_commit.clone(),
            original_base.accepted_revision,
            error.reason,
            Some(remote_tip),
            Some(&operation_id),
        )?;
        return Ok(StartOperation::Quarantined(GitSyncOutcome::Quarantined {
            incident_id: incident.incident_id,
            reason: incident.reason,
        }));
    }
    let candidate = match git::select_candidate(&runner, &repository, &local_tip, &remote_tip) {
        Ok(candidate) => candidate,
        Err(error) if error.operation() == "create union tree" => {
            let incident = quarantine::persist(
                store,
                original_base.logical_store_id.clone(),
                request,
                original_base.accepted_commit.clone(),
                original_base.accepted_revision,
                GitQuarantineReason::PathCollision,
                Some(remote_tip),
                Some(&operation_id),
            )?;
            return Ok(StartOperation::Quarantined(GitSyncOutcome::Quarantined {
                incident_id: incident.incident_id,
                reason: incident.reason,
            }));
        }
        Err(error) => return Err(error.into()),
    };
    let candidate_snapshot = repository.tree_snapshot(store, &runner, &candidate)?;
    require_same_store(&candidate_snapshot, current)?;
    let candidate_parents = repository.commit_parents(&runner, &candidate)?;
    let mut document = pending::PendingDocument::new(
        operation_id.clone(),
        GitSyncPendingPhase::Prepared,
        advance_from.logical_store_id.clone(),
        request.local_trust,
        request.approved_remote.clone(),
        local.format,
        original_base.accepted_commit.clone(),
        original_base.accepted_revision,
        advance_from.accepted_commit.clone(),
        advance_from.accepted_revision,
        local_tip.clone(),
        remote_tip,
        candidate,
        candidate_snapshot.revision(),
        candidate_parents,
        predecessor,
    );
    drop(candidate_snapshot);
    drop(local_snapshot);
    let mut diff_file = operation.temporary_file()?;
    let diff_output = diff_file
        .try_clone()
        .map_err(|source| GitAdmissionError::Io {
            operation: "retain candidate addition diff",
            source,
        })?;
    repository.spool_tree_additions(
        &runner,
        &local_tip,
        &document.candidate_commit,
        diff_output,
    )?;
    diff_file
        .seek(SeekFrom::Start(0))
        .map_err(|source| GitAdmissionError::Io {
            operation: "rewind candidate addition diff",
            source,
        })?;
    let count_source = diff_file
        .try_clone()
        .map_err(|source| GitAdmissionError::Io {
            operation: "retain candidate addition diff",
            source,
        })?;
    let (addition_count, addition_bytes) = repository
        .tree_addition_source(&runner, count_source)?
        .totals()?;
    diff_file
        .seek(SeekFrom::Start(0))
        .map_err(|source| GitAdmissionError::Io {
            operation: "rewind candidate addition diff",
            source,
        })?;
    let staging_source = diff_file
        .try_clone()
        .map_err(|source| GitAdmissionError::Io {
            operation: "retain candidate addition diff",
            source,
        })?;
    let mut additions = repository.tree_addition_source(&runner, staging_source)?;
    let mut source_error = None;
    let stage_result = {
        let stream = std::iter::from_fn(|| match additions.next_file() {
            Ok(Some(file)) => Some((file.path, file.bytes)),
            Ok(None) => None,
            Err(error) => {
                source_error = Some(error);
                None
            }
        });
        pending::stage_known_additions(
            &operation,
            &mut document,
            addition_count,
            addition_bytes,
            stream,
        )
    };
    let finish_result = additions.finish();
    if let Some(error) = source_error {
        return Err(error.into());
    }
    finish_result?;
    stage_result?;
    git::sync_repository_durable(&runner, &repository)?;
    operation.sync()?;
    fault::hit("repository-and-additions-durable");
    pending::publish_document(&operation, &document)?;
    store.sync_pending_dir.sync()?;
    fault::hit("pending-root-durable");
    if let Some(predecessor) = predecessor_pending {
        // The successor is now independently durable; predecessor retirement is safe.
        fault::hit("successor-before-predecessor-retirement");
        pending::retire_operation(store, predecessor)?;
        fault::hit("predecessor-retired-durable");
    }
    Ok(StartOperation::Pending(Box::new(pending::DurablePending {
        name: operation_id,
        directory: operation,
        document,
    })))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]
fn recover_sync_operation(
    store: &crate::Store,
    request: &GitSyncRequest,
    guard: &crate::store::UnsnapshottedExclusive<'_>,
    mut checkpoint_value: AdmissionCheckpoint,
    mut active: pending::DurablePending,
    predecessor: Option<pending::DurablePending>,
) -> Result<GitSyncOutcome, GitSyncError> {
    if active.document.local_trust_binding != request.local_trust
        || active.document.approved_remote != *request.approved_remote()
        || active.document.logical_store_id != checkpoint_value.logical_store_id
    {
        return Err(GitAdmissionError::LocalTrustMismatch.into());
    }
    pending::validate_closed_layout(&active)?;
    let runner = git::GitRunner::new(request);
    let repository =
        match git::open_sync_repository(&active.directory, active.document.object_format) {
            Ok(repository) => repository,
            Err(error) if error.is_hostile_repository_state() => {
                return quarantine_publication(
                    store,
                    request,
                    &checkpoint_value,
                    &active,
                    GitQuarantineReason::UnsafeRepositoryState,
                );
            }
            Err(error) => return Err(error.into()),
        };
    git::require_sync_commit(&runner, &repository, &active.document.candidate_commit)?;
    let candidate_snapshot =
        repository.tree_snapshot(store, &runner, &active.document.candidate_commit)?;
    let actual_parents = repository.commit_parents(&runner, &active.document.candidate_commit)?;
    let ancestry_valid = repository.is_ancestor(
        &runner,
        &active.document.original_base_commit,
        &active.document.observed_local_tip,
    )? && repository.is_ancestor(
        &runner,
        &active.document.original_base_commit,
        &active.document.expected_remote_tip,
    )? && repository.is_ancestor(
        &runner,
        &active.document.observed_local_tip,
        &active.document.candidate_commit,
    )? && repository.is_ancestor(
        &runner,
        &active.document.expected_remote_tip,
        &active.document.candidate_commit,
    )?;
    if candidate_snapshot.revision() != active.document.candidate_revision
        || candidate_snapshot
            .identity()
            .is_none_or(|identity| identity.logical_id() != &active.document.logical_store_id)
        || actual_parents != active.document.candidate_parents
        || !ancestry_valid
    {
        return quarantine_publication(
            store,
            request,
            &checkpoint_value,
            &active,
            GitQuarantineReason::HostilePublicationState,
        );
    }
    let original_snapshot =
        repository.tree_snapshot(store, &runner, &active.document.original_base_commit)?;
    let advance_snapshot =
        repository.tree_snapshot(store, &runner, &active.document.advance_from_commit)?;
    if original_snapshot.revision() != active.document.original_base_revision
        || advance_snapshot.revision() != active.document.advance_from_revision
        || original_snapshot
            .identity()
            .is_none_or(|identity| identity.logical_id() != &active.document.logical_store_id)
        || advance_snapshot
            .identity()
            .is_none_or(|identity| identity.logical_id() != &active.document.logical_store_id)
    {
        return quarantine_publication(
            store,
            request,
            &checkpoint_value,
            &active,
            GitQuarantineReason::HostilePublicationState,
        );
    }
    let base_snapshot =
        repository.tree_snapshot(store, &runner, &active.document.observed_local_tip)?;
    if base_snapshot
        .identity()
        .is_none_or(|identity| identity.logical_id() != &active.document.logical_store_id)
    {
        return quarantine_publication(
            store,
            request,
            &checkpoint_value,
            &active,
            GitQuarantineReason::HostilePublicationState,
        );
    }
    let mut observed_additions = 0_u64;
    let staged_valid = pending::for_each_addition(&active, |file| {
        observed_additions = observed_additions.saturating_add(1);
        let existed = repository
            .path_exists(&runner, &active.document.observed_local_tip, &file.path)
            .map_err(|error| pending::PendingError::Invalid(error.to_string()))?;
        let candidate = repository
            .path_bytes(
                &runner,
                &active.document.candidate_commit,
                &file.path,
                file.bytes.len(),
            )
            .map_err(|error| pending::PendingError::Invalid(error.to_string()))?;
        if existed || candidate != file.bytes {
            return Err(pending::PendingError::Invalid(
                "staged blob does not equal candidate-only path".to_owned(),
            ));
        }
        Ok(())
    });
    if staged_valid.is_err() || observed_additions != active.document.additions_count {
        return quarantine_publication(
            store,
            request,
            &checkpoint_value,
            &active,
            GitQuarantineReason::HostilePublicationState,
        );
    }

    loop {
        // The phase is never authority. Re-derive every prerequisite from durable filesystem,
        // approved-ref and checkpoint truth, accepting only old or candidate at each surface.
        let visible_before = guard.scan_visible_streaming_locked()?;
        if visible_before.revision() == base_snapshot.revision() {
            let mut publication_failed = false;
            for rank in 0..=1 {
                if pending::for_each_addition(&active, |file| {
                    if crate::store::bulk::publication_rank(&file.path) == rank {
                        crate::store::bulk::publish_addition(store, &file)
                            .map_err(pending::PendingError::from)?;
                    }
                    Ok(())
                })
                .is_err()
                {
                    publication_failed = true;
                    break;
                }
            }
            if publication_failed
                || guard.scan_visible_streaming_locked()?.revision()
                    != active.document.candidate_revision
            {
                return quarantine_publication(
                    store,
                    request,
                    &checkpoint_value,
                    &active,
                    GitQuarantineReason::HostilePublicationState,
                );
            }
        } else if visible_before.revision() != active.document.candidate_revision {
            return quarantine_publication(
                store,
                request,
                &checkpoint_value,
                &active,
                GitQuarantineReason::HostilePublicationState,
            );
        }

        let local = git::inspect_local(store, &runner, request)?;
        if local.tip == active.document.observed_local_tip {
            git::advance_local_ref(
                &runner,
                request,
                &local,
                &repository,
                &active.document.observed_local_tip,
                &active.document.candidate_commit,
            )?;
        } else if local.tip != active.document.candidate_commit {
            return quarantine_publication(
                store,
                request,
                &checkpoint_value,
                &active,
                GitQuarantineReason::HostilePublicationState,
            );
        } else {
            git::advance_local_ref(
                &runner,
                request,
                &local,
                &repository,
                &active.document.observed_local_tip,
                &active.document.candidate_commit,
            )?;
        }

        let expected_checkpoint = AdmissionCheckpoint {
            logical_store_id: active.document.logical_store_id.clone(),
            local_trust_binding: active.document.local_trust_binding,
            approved_remote: active.document.approved_remote.clone(),
            accepted_commit: active.document.advance_from_commit.clone(),
            accepted_revision: active.document.advance_from_revision,
        };
        let candidate_checkpoint = AdmissionCheckpoint {
            logical_store_id: active.document.logical_store_id.clone(),
            local_trust_binding: active.document.local_trust_binding,
            approved_remote: active.document.approved_remote.clone(),
            accepted_commit: active.document.candidate_commit.clone(),
            accepted_revision: active.document.candidate_revision,
        };
        let durable_checkpoint = checkpoint::read(store)?.ok_or(GitSyncError::BootstrapRequired)?;
        if durable_checkpoint == expected_checkpoint {
            checkpoint::replace_expected(store, &expected_checkpoint, &candidate_checkpoint)?;
            checkpoint_value = candidate_checkpoint;
        } else if durable_checkpoint == candidate_checkpoint {
            checkpoint_value = durable_checkpoint;
        } else {
            return quarantine_publication(
                store,
                request,
                &checkpoint_value,
                &active,
                GitQuarantineReason::HostilePublicationState,
            );
        }

        match active.document.phase {
            GitSyncPendingPhase::Prepared => {
                let mut publication_failed = false;
                // Records/events precede batch markers while each pass holds only one staged
                // blob. Revalidation on each pass also detects closed-layout changes.
                for rank in 0..=1 {
                    if pending::for_each_addition(&active, |file| {
                        if crate::store::bulk::publication_rank(&file.path) == rank {
                            crate::store::bulk::publish_addition(store, &file)
                                .map_err(pending::PendingError::from)?;
                        }
                        Ok(())
                    })
                    .is_err()
                    {
                        publication_failed = true;
                        break;
                    }
                }
                if publication_failed {
                    return quarantine_publication(
                        store,
                        request,
                        &checkpoint_value,
                        &active,
                        GitQuarantineReason::HostilePublicationState,
                    );
                }
                let visible = guard.scan_visible_streaming_locked()?;
                if visible.revision() != active.document.candidate_revision {
                    return quarantine_publication(
                        store,
                        request,
                        &checkpoint_value,
                        &active,
                        GitQuarantineReason::HostilePublicationState,
                    );
                }
                fault::hit("canonical-files-durable");
                let mut next = active.document.clone();
                next.phase = GitSyncPendingPhase::FilesPublished;
                pending::replace_document(&mut active, next)?;
                fault::hit("files-phase-durable");
            }
            GitSyncPendingPhase::FilesPublished => {
                let local = git::inspect_local(store, &runner, request)?;
                git::advance_local_ref(
                    &runner,
                    request,
                    &local,
                    &repository,
                    &active.document.observed_local_tip,
                    &active.document.candidate_commit,
                )?;
                fault::hit("local-ref-durable");
                let mut next = active.document.clone();
                next.phase = GitSyncPendingPhase::LocalRefPublished;
                pending::replace_document(&mut active, next)?;
                fault::hit("local-ref-phase-durable");
            }
            GitSyncPendingPhase::LocalRefPublished => {
                let expected = AdmissionCheckpoint {
                    logical_store_id: active.document.logical_store_id.clone(),
                    local_trust_binding: active.document.local_trust_binding,
                    approved_remote: active.document.approved_remote.clone(),
                    accepted_commit: active.document.advance_from_commit.clone(),
                    accepted_revision: active.document.advance_from_revision,
                };
                let candidate = AdmissionCheckpoint {
                    logical_store_id: active.document.logical_store_id.clone(),
                    local_trust_binding: active.document.local_trust_binding,
                    approved_remote: active.document.approved_remote.clone(),
                    accepted_commit: active.document.candidate_commit.clone(),
                    accepted_revision: active.document.candidate_revision,
                };
                checkpoint::replace_expected(store, &expected, &candidate)?;
                fault::hit("checkpoint-durable");
                checkpoint_value = candidate;
                let mut next = active.document.clone();
                next.phase = GitSyncPendingPhase::CheckpointPublished;
                pending::replace_document(&mut active, next)?;
                fault::hit("checkpoint-phase-durable");
            }
            GitSyncPendingPhase::CheckpointPublished => {
                let pushed = git::push_candidate_exact_lease(
                    &runner,
                    request,
                    &repository,
                    &active.document.expected_remote_tip,
                )?;
                fault::hit("push-response-lost");
                let observed = git::observe_remote_ref(
                    &runner,
                    request,
                    active.document.object_format,
                    &repository.bare,
                )?;
                match observed {
                    Some(observed) if observed == active.document.candidate_commit => {
                        let mut next = active.document.clone();
                        next.phase = GitSyncPendingPhase::RemoteCasConfirmed;
                        pending::replace_document(&mut active, next)?;
                        fault::hit("remote-confirmed-phase-durable");
                    }
                    Some(observed) if observed == active.document.expected_remote_tip => {
                        if pushed {
                            return Err(GitCommandError {
                                operation: "confirm synchronization push",
                                message: "successful push was not remotely observable".to_owned(),
                            }
                            .into());
                        }
                        return Err(GitCommandError {
                            operation: "push synchronization candidate",
                            message: "exact lease was rejected without remote movement".to_owned(),
                        }
                        .into());
                    }
                    Some(observed) => {
                        let mut next = active.document.clone();
                        next.phase = GitSyncPendingPhase::RemoteCasStale;
                        next.stale_remote_oid = Some(observed.clone());
                        pending::replace_document(&mut active, next)?;
                        fault::hit("remote-stale-phase-durable");
                        return Ok(GitSyncOutcome::StaleRemoteCas {
                            candidate: active.document.candidate_commit.clone(),
                            observed_remote: observed,
                        });
                    }
                    None => {
                        return quarantine_publication(
                            store,
                            request,
                            &checkpoint_value,
                            &active,
                            GitQuarantineReason::MissingApprovedRef,
                        );
                    }
                }
            }
            GitSyncPendingPhase::RemoteCasStale => {
                let current = guard.scan_visible_streaming_locked()?;
                let original = AdmissionCheckpoint {
                    logical_store_id: active.document.logical_store_id.clone(),
                    local_trust_binding: active.document.local_trust_binding,
                    approved_remote: active.document.approved_remote.clone(),
                    accepted_commit: active.document.original_base_commit.clone(),
                    accepted_revision: active.document.original_base_revision,
                };
                match start_sync_operation(
                    store,
                    request,
                    &original,
                    &checkpoint_value,
                    &current,
                    Some(active.name.clone()),
                    Some(&active),
                )? {
                    StartOperation::Pending(successor) => {
                        return recover_sync_operation(
                            store,
                            request,
                            guard,
                            checkpoint_value,
                            *successor,
                            None,
                        );
                    }
                    StartOperation::Quarantined(outcome) => return Ok(outcome),
                }
            }
            GitSyncPendingPhase::RemoteCasConfirmed => {
                let visible = guard.scan_visible_streaming_locked()?;
                let local = git::inspect_local(store, &runner, request)?;
                let durable = checkpoint::read(store)?.ok_or(GitSyncError::BootstrapRequired)?;
                let remote = git::observe_remote_ref(
                    &runner,
                    request,
                    active.document.object_format,
                    &repository.bare,
                )?;
                if visible.revision() != active.document.candidate_revision
                    || local.tip != active.document.candidate_commit
                    || durable.accepted_commit != active.document.candidate_commit
                    || durable.accepted_revision != active.document.candidate_revision
                    || remote.as_ref() != Some(&active.document.candidate_commit)
                {
                    return quarantine_publication(
                        store,
                        request,
                        &checkpoint_value,
                        &active,
                        GitQuarantineReason::HostilePublicationState,
                    );
                }
                git::remove_internal_local_candidate(&runner, &local)?;
                fault::hit("internal-candidate-removed");
                if let Some(predecessor) = predecessor.as_ref() {
                    fault::hit("confirmed-before-predecessor-retirement");
                    pending::retire_operation(store, predecessor)?;
                    fault::hit("confirmed-predecessor-retired-durable");
                }
                let up_to_date = active.document.candidate_commit
                    == active.document.advance_from_commit
                    && active.document.expected_remote_tip == active.document.candidate_commit;
                let commit = active.document.candidate_commit.clone();
                let revision = active.document.candidate_revision;
                pending::retire_operation(store, &active)?;
                fault::hit("pending-retired-durable");
                return Ok(if up_to_date {
                    GitSyncOutcome::UpToDate { commit, revision }
                } else {
                    GitSyncOutcome::Advanced { commit, revision }
                });
            }
        }
    }
}

fn quarantine_publication(
    store: &crate::Store,
    request: &GitSyncRequest,
    checkpoint: &AdmissionCheckpoint,
    active: &pending::DurablePending,
    reason: GitQuarantineReason,
) -> Result<GitSyncOutcome, GitSyncError> {
    let incident = quarantine::persist(
        store,
        checkpoint.logical_store_id.clone(),
        request,
        checkpoint.accepted_commit.clone(),
        checkpoint.accepted_revision,
        reason,
        Some(active.document.candidate_commit.clone()),
        Some(&active.name),
    )?;
    Ok(GitSyncOutcome::Quarantined {
        incident_id: incident.incident_id,
        reason: incident.reason,
    })
}

fn require_same_store(
    candidate: &crate::StoreSnapshot,
    current: &crate::StoreSnapshot,
) -> Result<(), GitAdmissionError> {
    let candidate = candidate
        .identity()
        .ok_or(GitAdmissionError::MissingIdentity)?;
    let current = current
        .identity()
        .ok_or(GitAdmissionError::MissingIdentity)?;
    if candidate.logical_id() != current.logical_id() {
        return Err(GitAdmissionError::IdentityMismatch);
    }
    Ok(())
}

const MAX_ATTEMPTS: usize = 32;
const MAX_ATTEMPT_ENTRIES: usize = 100_000;
const MAX_ATTEMPT_DEPTH: usize = 64;

fn recover_attempts(store: &crate::Store) -> Result<(), GitAdmissionError> {
    for name in store.admission_attempts_dir.bounded_names(MAX_ATTEMPTS)? {
        let text = std::str::from_utf8(&name).map_err(|_| {
            crate::store::invalid_layout(
                &store.admission_attempts_dir.path,
                "invalid admission attempt name",
            )
        })?;
        let uuid = uuid::Uuid::parse_str(text).map_err(|_| {
            crate::store::invalid_layout(
                &store.admission_attempts_dir.path,
                "invalid admission attempt name",
            )
        })?;
        if uuid.get_version_num() != 7 || uuid.get_variant() != uuid::Variant::RFC4122 {
            return Err(crate::store::invalid_layout(
                &store.admission_attempts_dir.path,
                "invalid admission attempt name",
            )
            .into());
        }
        let os_name = OsStr::from_bytes(&name);
        let attempt = store.admission_attempts_dir.open_dir(os_name)?;
        cleanup_attempt(store, os_name, &attempt)?;
    }
    Ok(())
}

fn create_attempt(store: &crate::Store) -> Result<(OsString, Directory), GitAdmissionError> {
    let name = OsString::from(uuid::Uuid::now_v7().hyphenated().to_string());
    let (attempt, created) = store.admission_attempts_dir.ensure_dir(&name)?;
    if !created {
        return Err(crate::store::invalid_layout(
            &store.admission_attempts_dir.path.join(&name),
            "admission attempt collided",
        )
        .into());
    }
    attempt.sync()?;
    store.admission_attempts_dir.sync()?;
    Ok((name, attempt))
}

fn cleanup_attempt(
    store: &crate::Store,
    name: &OsStr,
    attempt: &Directory,
) -> Result<(), GitAdmissionError> {
    if !store.admission_attempts_dir.entry_is(name, attempt)? {
        return Err(crate::store::invalid_layout(
            &store.admission_attempts_dir.path.join(name),
            "admission attempt binding was replaced",
        )
        .into());
    }
    let mut budget = MAX_ATTEMPT_ENTRIES;
    remove_attempt_contents(attempt, 0, &mut budget)?;
    if !store.admission_attempts_dir.entry_is(name, attempt)? {
        return Err(crate::store::invalid_layout(
            &store.admission_attempts_dir.path.join(name),
            "admission attempt binding changed during cleanup",
        )
        .into());
    }
    store.admission_attempts_dir.unlink_dir(name)?;
    store.admission_attempts_dir.sync()?;
    Ok(())
}

fn remove_attempt_contents(
    directory: &Directory,
    depth: usize,
    budget: &mut usize,
) -> Result<(), GitAdmissionError> {
    if depth > MAX_ATTEMPT_DEPTH {
        return Err(crate::store::invalid_layout(
            &directory.path,
            "admission attempt exceeds depth limit",
        )
        .into());
    }
    let names = directory.bounded_names((*budget).saturating_add(1))?;
    for name in names {
        *budget = budget.checked_sub(1).ok_or_else(|| {
            crate::store::invalid_layout(
                &directory.path,
                "admission attempt exceeds entry-count limit",
            )
        })?;
        let os_name = OsStr::from_bytes(&name);
        if directory.kind(os_name)? == rustix::fs::FileType::Directory {
            let child = directory.open_dir(os_name)?;
            remove_attempt_contents(&child, depth + 1, budget)?;
            if !directory.entry_is(os_name, &child)? {
                return Err(crate::store::invalid_layout(
                    &directory.path.join(os_name),
                    "admission attempt child was replaced",
                )
                .into());
            }
            directory.unlink_dir(os_name)?;
        } else {
            directory.unlink_file(os_name)?;
        }
    }
    directory.sync()?;
    Ok(())
}

impl fmt::Display for GitObjectFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    use crate::{LegacyEntry, LegacyStoreAdapter, Store, wayjournal_domain_registry};
    use std::{
        fs,
        os::unix::fs::symlink,
        path::{Path, PathBuf},
        process::Command,
    };

    #[derive(Debug)]
    struct NoLegacy;
    impl LegacyStoreAdapter for NoLegacy {
        fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
            Ok(())
        }
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wayjournal-federation-{label}-{}",
                uuid::Uuid::now_v7()
            ));
            fs::create_dir(&path).expect("test directory");
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn git() -> PathBuf {
        PathBuf::from(std::env::var_os("WAYJOURNAL_TEST_GIT").expect("WAYJOURNAL_TEST_GIT"))
    }

    fn run(cwd: &Path, args: &[&str]) {
        let output = Command::new(git())
            .current_dir(cwd)
            .args(args)
            .output()
            .expect("Git command");
        assert!(
            output.status.success(),
            "Git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn request() -> GitSyncRequest {
        GitSyncRequest::new(
            git(),
            LocalTrustBinding::parse(
                "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
            )
            .expect("trust"),
            ApprovedRemote::new(
                ApprovedRemoteLocator::parse("file:///tmp/approved.git").expect("locator"),
                ApprovedRef::parse("refs/heads/main").expect("ref"),
            ),
        )
        .expect("request")
    }

    #[test]
    fn retained_attempt_descriptor_never_cleans_or_writes_through_a_replacement() {
        let root = TestDir::new("attempt-anchor");
        let store = Store::open(
            &root.0,
            wayjournal_domain_registry().expect("registry"),
            Arc::new(NoLegacy),
        )
        .expect("store");
        let (name, attempt) = create_attempt(&store).expect("attempt");
        let original = store.admission_attempts_dir.path.join(&name);
        let retained = root.0.join("retained-attempt");
        let outside = root.0.join("outside-attempt");
        fs::rename(&original, &retained).expect("move attempt");
        fs::create_dir(&outside).expect("outside");
        symlink(&outside, &original).expect("replacement");
        attempt
            .ensure_dir(OsStr::new("retained-only"))
            .expect("retained write");
        assert!(retained.join("retained-only").is_dir());
        assert!(fs::read_dir(&outside).expect("outside").next().is_none());
        assert!(cleanup_attempt(&store, &name, &attempt).is_err());
        assert!(fs::read_dir(&outside).expect("outside").next().is_none());
    }

    #[test]
    fn retained_git_directory_is_used_after_ambient_gitdir_replacement() {
        let root = TestDir::new("git-anchor");
        let store = Store::open(
            &root.0,
            wayjournal_domain_registry().expect("registry"),
            Arc::new(NoLegacy),
        )
        .expect("store");
        run(&root.0, &["init", "-b", "main"]);
        run(&root.0, &["config", "user.name", "Wayjournal Test"]);
        run(
            &root.0,
            &["config", "user.email", "wayjournal@example.invalid"],
        );
        run(&root.0, &["commit", "--allow-empty", "-m", "retained"]);
        let expected = Command::new(git())
            .current_dir(&root.0)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("tip");
        assert!(expected.status.success());
        let expected = GitOid::parse(
            GitObjectFormat::Sha1,
            std::str::from_utf8(&expected.stdout).expect("UTF-8").trim(),
        )
        .expect("OID");
        let git_dir = store
            .root_dir
            .open_dir(OsStr::new(".git"))
            .expect("Git dir");
        let retained = root.0.join("retained-gitdir");
        fs::rename(root.0.join(".git"), &retained).expect("move Git dir");
        run(&root.0, &["init", "-b", "hostile"]);
        run(&root.0, &["config", "user.name", "Hostile"]);
        run(
            &root.0,
            &["config", "user.email", "hostile@example.invalid"],
        );
        run(&root.0, &["commit", "--allow-empty", "-m", "replacement"]);
        let (attempt_name, attempt) = create_attempt(&store).expect("attempt");
        let request = request();
        let runner = git::GitRunner::new(&request);
        let local =
            git::inspect_local_anchored(&runner, &request, git_dir).expect("retained local Git");
        assert_eq!(local.tip, expected);
        cleanup_attempt(&store, &attempt_name, &attempt).expect("cleanup");
    }
}
