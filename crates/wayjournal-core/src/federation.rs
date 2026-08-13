use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
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
mod git;
pub use checkpoint::CheckpointError;
pub use git::GitCommandError;

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
        let exclusive = self.exclusive_snapshot()?;
        let current = exclusive.snapshot();
        let current_identity = current
            .identity()
            .ok_or(GitAdmissionError::MissingIdentity)?;
        let checkpoint_before = checkpoint::read(self)?;
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
        let runner = git::GitRunner::new(request);
        let local = git::inspect_local(self, &runner, request)?;
        git::require_local_commit(&runner, &local, &local.tip)?;
        let local_snapshot = git::local_tree_snapshot(self, &runner, &local, &local.tip)?;
        require_same_store(&local_snapshot, current)?;
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
            require_same_store(&remote, current)?;
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
