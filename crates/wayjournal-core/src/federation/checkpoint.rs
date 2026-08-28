use std::{
    ffi::OsStr,
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    LogicalStoreId, Store, StoreRevisionRef, StoreUuid,
    json::{decode_strict, encode_pretty},
};

use super::{
    AdmissionCheckpoint, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, GitObjectFormat,
    GitOid, LocalTrustBinding,
};

/// Canonical filename for the local admission-checkpoint wire document.
pub const ADMISSION_CHECKPOINT_FILENAME: &str = "admission-v1.json";
/// Maximum accepted size of an admission-checkpoint wire document.
pub const MAX_ADMISSION_CHECKPOINT_BYTES: usize = 8 * 1024;
const CHECKPOINT_SCHEMA: &str = "wayjournal.admission-checkpoint/v1";

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("checkpoint I/O failed: {0}")]
    Store(#[from] crate::StoreError),
    #[error("checkpoint exceeds 8 KiB")]
    Oversized,
    #[error("checkpoint is not strict canonical v1 JSON: {0}")]
    Invalid(String),
    #[error("checkpoint does not equal the expected old value")]
    ExpectedOldMismatch,
    #[error("checkpoint replacement was not durable at the expected candidate")]
    ReplacementMismatch,
    #[cfg(test)]
    #[error("injected checkpoint crash at barrier {0}")]
    InjectedCrash(usize),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCheckpoint {
    accepted_commit: String,
    accepted_git_object_format: GitObjectFormat,
    accepted_revision_algorithm: String,
    accepted_revision_digest: String,
    genesis_fingerprint: String,
    local_trust_binding: String,
    remote_locator: String,
    remote_ref: String,
    schema: String,
    store_uuid: String,
}

pub(super) fn read(store: &Store) -> Result<Option<AdmissionCheckpoint>, CheckpointError> {
    recover_residue(store)?;
    let name = OsStr::new(ADMISSION_CHECKPOINT_FILENAME);
    let file = match store.checkpoints_dir.open_file(name) {
        Ok(file) => file,
        Err(crate::StoreError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let size = store.checkpoints_dir.require_regular(&file, name)?;
    require_private_mode(&file)?;
    if size > MAX_ADMISSION_CHECKPOINT_BYTES as u64 {
        return Err(CheckpointError::Oversized);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(size).map_err(|_| CheckpointError::Oversized)?);
    file.take(MAX_ADMISSION_CHECKPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            crate::store::io_error(
                "read admission checkpoint",
                &store.checkpoints_dir.path.join(name),
                source,
            )
        })?;
    if bytes.len() > MAX_ADMISSION_CHECKPOINT_BYTES {
        return Err(CheckpointError::Oversized);
    }
    decode_admission_checkpoint(&bytes).map(Some)
}

fn recover_residue(store: &Store) -> Result<(), CheckpointError> {
    let names = store.checkpoints_dir.bounded_names(4)?;
    let prefix = format!(".{ADMISSION_CHECKPOINT_FILENAME}.tmp-");
    let mut temporary = None;
    for name in names {
        if name == ADMISSION_CHECKPOINT_FILENAME.as_bytes() {
            if store.checkpoints_dir.kind(OsStr::from_bytes(&name))?
                != rustix::fs::FileType::RegularFile
            {
                return Err(CheckpointError::Invalid(
                    "checkpoint target is not a regular file".to_owned(),
                ));
            }
            continue;
        }
        let Ok(text) = std::str::from_utf8(&name) else {
            return Err(CheckpointError::Invalid(
                "unknown checkpoint-directory entry".to_owned(),
            ));
        };
        let Some(suffix) = text.strip_prefix(&prefix) else {
            return Err(CheckpointError::Invalid(
                "unknown checkpoint-directory entry".to_owned(),
            ));
        };
        let uuid = uuid::Uuid::parse_str(suffix).map_err(|_| {
            CheckpointError::Invalid("invalid checkpoint temporary name".to_owned())
        })?;
        if uuid.get_version_num() != 7
            || uuid.get_variant() != uuid::Variant::RFC4122
            || temporary.is_some()
        {
            return Err(CheckpointError::Invalid(
                "invalid or multiple checkpoint temporary files".to_owned(),
            ));
        }
        let os_name = OsStr::from_bytes(&name);
        if store.checkpoints_dir.kind(os_name)? != rustix::fs::FileType::RegularFile {
            return Err(CheckpointError::Invalid(
                "checkpoint temporary is not a regular file".to_owned(),
            ));
        }
        let file = store.checkpoints_dir.open_file(os_name)?;
        require_private_mode(&file)?;
        if store.checkpoints_dir.require_regular(&file, os_name)?
            > MAX_ADMISSION_CHECKPOINT_BYTES as u64
        {
            return Err(CheckpointError::Oversized);
        }
        temporary = Some(name);
    }
    if let Some(name) = temporary {
        store
            .checkpoints_dir
            .unlink_file(OsStr::from_bytes(&name))?;
        store.checkpoints_dir.sync()?;
    }
    Ok(())
}

fn require_private_mode(file: &std::fs::File) -> Result<(), CheckpointError> {
    let metadata = file
        .metadata()
        .map_err(|error| CheckpointError::Invalid(error.to_string()))?;
    if metadata.mode() & 0o777 != 0o600 {
        return Err(CheckpointError::Invalid(
            "checkpoint file mode is not 0600".to_owned(),
        ));
    }
    Ok(())
}

fn encode_exact(checkpoint: &AdmissionCheckpoint) -> Result<Vec<u8>, CheckpointError> {
    let raw = RawCheckpoint {
        accepted_commit: checkpoint.accepted_commit.as_hex().to_owned(),
        accepted_git_object_format: checkpoint.accepted_commit.format(),
        accepted_revision_algorithm: checkpoint.accepted_revision.algorithm().to_string(),
        accepted_revision_digest: checkpoint.accepted_revision.digest().to_string(),
        genesis_fingerprint: checkpoint
            .logical_store_id
            .genesis_fingerprint()
            .to_string(),
        local_trust_binding: checkpoint.local_trust_binding.as_digest().to_string(),
        remote_locator: checkpoint.approved_remote.locator().as_str().to_owned(),
        remote_ref: checkpoint.approved_remote.reference().as_str().to_owned(),
        schema: CHECKPOINT_SCHEMA.to_owned(),
        store_uuid: checkpoint.logical_store_id.store_uuid().to_string(),
    };
    let value =
        serde_json::to_value(raw).map_err(|error| CheckpointError::Invalid(error.to_string()))?;
    encode_pretty(&value).map_err(|error| CheckpointError::Invalid(error.to_string()))
}

/// Encodes checkpoint data as the closed canonical admission-checkpoint wire format.
///
/// The returned bytes are data only. Callers must separately authenticate the file, retained
/// lock and current store state before treating them as fresh or trusted.
///
/// # Errors
/// Returns [`CheckpointError`] if encoding fails or exceeds the wire-size bound.
pub fn encode_admission_checkpoint(
    checkpoint: &AdmissionCheckpoint,
) -> Result<Vec<u8>, CheckpointError> {
    let bytes = encode_exact(checkpoint)?;
    if bytes.len() > MAX_ADMISSION_CHECKPOINT_BYTES {
        return Err(CheckpointError::Oversized);
    }
    Ok(bytes)
}

pub(super) fn write(
    store: &Store,
    checkpoint: &AdmissionCheckpoint,
) -> Result<(), CheckpointError> {
    write_impl(store, checkpoint, |_| Ok(()))
}

#[allow(dead_code)]
pub(super) fn replace_expected(
    store: &Store,
    expected: &AdmissionCheckpoint,
    candidate: &AdmissionCheckpoint,
) -> Result<(), CheckpointError> {
    let expected_bytes = encode_admission_checkpoint(expected)?;
    let candidate_bytes = encode_admission_checkpoint(candidate)?;
    let current = read_current_bytes(store)?;
    if current == candidate_bytes {
        decode_admission_checkpoint(&current)?;
        return Ok(());
    }
    if current != expected_bytes {
        return Err(CheckpointError::ExpectedOldMismatch);
    }
    let temporary = format!(
        ".{ADMISSION_CHECKPOINT_FILENAME}.tmp-{}",
        uuid::Uuid::now_v7()
    );
    let temporary_name = OsStr::new(&temporary);
    let mut file = store.checkpoints_dir.create_file(temporary_name)?;
    file.write_all(&candidate_bytes).map_err(|source| {
        crate::store::io_error(
            "write expected-old checkpoint",
            &store.checkpoints_dir.path.join(temporary_name),
            source,
        )
    })?;
    file.sync_all().map_err(|source| {
        crate::store::io_error(
            "sync expected-old checkpoint",
            &store.checkpoints_dir.path.join(temporary_name),
            source,
        )
    })?;
    super::fault::hit("checkpoint-temporary-durable");
    drop(file);
    if read_current_bytes(store)? != expected_bytes {
        store.checkpoints_dir.unlink_file(temporary_name)?;
        store.checkpoints_dir.sync()?;
        return Err(CheckpointError::ExpectedOldMismatch);
    }
    store
        .checkpoints_dir
        .rename_file(temporary_name, OsStr::new(ADMISSION_CHECKPOINT_FILENAME))?;
    super::fault::hit("checkpoint-renamed");
    store.checkpoints_dir.sync()?;
    super::fault::hit("checkpoint-parent-durable");
    let published = read_current_bytes(store)?;
    if published != candidate_bytes || decode_admission_checkpoint(&published)? != *candidate {
        return Err(CheckpointError::ReplacementMismatch);
    }
    Ok(())
}

fn read_current_bytes(store: &Store) -> Result<Vec<u8>, CheckpointError> {
    let name = OsStr::new(ADMISSION_CHECKPOINT_FILENAME);
    let file = store.checkpoints_dir.open_file(name)?;
    let size = store.checkpoints_dir.require_regular(&file, name)?;
    require_private_mode(&file)?;
    if size > MAX_ADMISSION_CHECKPOINT_BYTES as u64 {
        return Err(CheckpointError::Oversized);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(size).map_err(|_| CheckpointError::Oversized)?);
    file.take(MAX_ADMISSION_CHECKPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            crate::store::io_error(
                "read expected-old checkpoint",
                &store.checkpoints_dir.path.join(name),
                source,
            )
        })?;
    if bytes.len() > MAX_ADMISSION_CHECKPOINT_BYTES {
        return Err(CheckpointError::Oversized);
    }
    Ok(bytes)
}

fn write_impl(
    store: &Store,
    checkpoint: &AdmissionCheckpoint,
    mut barrier: impl FnMut(usize) -> Result<(), CheckpointError>,
) -> Result<(), CheckpointError> {
    let bytes = encode_admission_checkpoint(checkpoint)?;
    let temporary = format!(
        ".{ADMISSION_CHECKPOINT_FILENAME}.tmp-{}",
        uuid::Uuid::now_v7()
    );
    let temporary_name = OsStr::new(&temporary);
    let mut file = store.checkpoints_dir.create_file(temporary_name)?;
    rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).map_err(
        |error| {
            crate::store::io_error(
                "set admission checkpoint mode",
                &store.checkpoints_dir.path.join(temporary_name),
                error.into(),
            )
        },
    )?;
    file.write_all(&bytes).map_err(|source| {
        crate::store::io_error(
            "write admission checkpoint",
            &store.checkpoints_dir.path.join(temporary_name),
            source,
        )
    })?;
    barrier(0)?;
    file.sync_all().map_err(|source| {
        crate::store::io_error(
            "sync admission checkpoint",
            &store.checkpoints_dir.path.join(temporary_name),
            source,
        )
    })?;
    barrier(1)?;
    drop(file);
    store
        .checkpoints_dir
        .rename_file(temporary_name, OsStr::new(ADMISSION_CHECKPOINT_FILENAME))?;
    barrier(2)?;
    store.checkpoints_dir.sync()?;
    barrier(3)?;
    Ok(())
}

#[cfg(test)]
fn write_with_barrier_for_test(
    store: &Store,
    checkpoint: &AdmissionCheckpoint,
    target: usize,
) -> Result<(), CheckpointError> {
    write_impl(store, checkpoint, |barrier| {
        if barrier == target {
            Err(CheckpointError::InjectedCrash(barrier))
        } else {
            Ok(())
        }
    })
}

fn decode_exact(bytes: &[u8]) -> Result<AdmissionCheckpoint, CheckpointError> {
    let value =
        decode_strict(bytes).map_err(|error| CheckpointError::Invalid(error.to_string()))?;
    let raw: RawCheckpoint = serde_json::from_value(value.clone())
        .map_err(|error| CheckpointError::Invalid(error.to_string()))?;
    if raw.schema != CHECKPOINT_SCHEMA {
        return Err(CheckpointError::Invalid("unsupported schema".to_owned()));
    }
    let canonical =
        encode_pretty(&value).map_err(|error| CheckpointError::Invalid(error.to_string()))?;
    if canonical != bytes {
        return Err(CheckpointError::Invalid(
            "noncanonical JSON bytes".to_owned(),
        ));
    }
    let logical_store_id = LogicalStoreId::new(
        raw.store_uuid
            .parse::<StoreUuid>()
            .map_err(|error| CheckpointError::Invalid(error.to_string()))?,
        raw.genesis_fingerprint
            .parse()
            .map_err(|error: crate::DigestError| CheckpointError::Invalid(error.to_string()))?,
    );
    let accepted_commit = GitOid::parse(raw.accepted_git_object_format, &raw.accepted_commit)
        .map_err(|error| CheckpointError::Invalid(error.to_string()))?;
    let accepted_revision = StoreRevisionRef::parse(
        &raw.accepted_revision_algorithm,
        &raw.accepted_revision_digest,
    )
    .map_err(|error| CheckpointError::Invalid(error.to_string()))?;
    let local_trust_binding = LocalTrustBinding::parse(&raw.local_trust_binding)
        .map_err(|error| CheckpointError::Invalid(error.to_string()))?;
    let approved_remote = ApprovedRemote::new(
        ApprovedRemoteLocator::parse(&raw.remote_locator)
            .map_err(|error| CheckpointError::Invalid(error.to_string()))?,
        ApprovedRef::parse(&raw.remote_ref)
            .map_err(|error| CheckpointError::Invalid(error.to_string()))?,
    );
    Ok(AdmissionCheckpoint {
        logical_store_id,
        local_trust_binding,
        approved_remote,
        accepted_commit,
        accepted_revision,
    })
}

/// Decodes closed canonical admission-checkpoint wire bytes into data.
///
/// Successful decoding validates only the bounded wire representation and checked field values.
/// It does not establish file authenticity, lock ownership, freshness, trust or correspondence
/// with current store state. Callers must perform those checks separately.
///
/// # Errors
/// Returns [`CheckpointError`] for oversized, malformed, noncanonical or unsupported input.
pub fn decode_admission_checkpoint(bytes: &[u8]) -> Result<AdmissionCheckpoint, CheckpointError> {
    if bytes.len() > MAX_ADMISSION_CHECKPOINT_BYTES {
        return Err(CheckpointError::Oversized);
    }
    decode_exact(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LegacyEntry, LegacyStoreAdapter, Store, wayjournal_domain_registry};
    use std::{fs, path::PathBuf, sync::Arc};

    #[derive(Debug)]
    struct NoLegacy;
    impl LegacyStoreAdapter for NoLegacy {
        fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
            Ok(())
        }
    }
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wayjournal-checkpoint-barrier-{}",
                uuid::Uuid::now_v7()
            ));
            fs::create_dir(&path).expect("dir");
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn checkpoint(commit: &str) -> AdmissionCheckpoint {
        AdmissionCheckpoint {
            logical_store_id: LogicalStoreId::new(
                "01913f1d-8e2a-7c30-8f4a-426614174010"
                    .parse()
                    .expect("uuid"),
                "7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447"
                    .parse()
                    .expect("digest"),
            ),
            local_trust_binding: LocalTrustBinding::parse(
                "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
            )
            .expect("trust"),
            approved_remote: ApprovedRemote::new(
                ApprovedRemoteLocator::parse("file:///srv/git/store.git").expect("url"),
                ApprovedRef::parse("refs/heads/main").expect("ref"),
            ),
            accepted_commit: GitOid::parse(GitObjectFormat::Sha1, commit).expect("commit"),
            accepted_revision: StoreRevisionRef::parse(
                "wayjournal.store/blake3-framed-v1",
                "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
            )
            .expect("revision"),
        }
    }
    #[test]
    fn checkpoint_replace_requires_expected_old() {
        let directory = TestDir::new();
        let store = Store::open(
            &directory.0,
            wayjournal_domain_registry().expect("registry"),
            Arc::new(NoLegacy),
        )
        .expect("store");
        let expected = checkpoint("1111111111111111111111111111111111111111");
        let unrelated = checkpoint("2222222222222222222222222222222222222222");
        let candidate = checkpoint("3333333333333333333333333333333333333333");
        write(&store, &unrelated).expect("unrelated");
        assert!(replace_expected(&store, &expected, &candidate).is_err());
        assert_eq!(
            read(&store)
                .expect("read")
                .expect("present")
                .accepted_commit(),
            unrelated.accepted_commit()
        );
        replace_expected(&store, &unrelated, &candidate).expect("expected replacement");
        assert_eq!(
            read(&store)
                .expect("read")
                .expect("present")
                .accepted_commit(),
            candidate.accepted_commit()
        );
    }

    #[test]
    fn every_atomic_replace_barrier_reopens_as_exactly_old_or_new() {
        for barrier in 0..4 {
            let directory = TestDir::new();
            let store = Store::open(
                &directory.0,
                wayjournal_domain_registry().expect("registry"),
                Arc::new(NoLegacy),
            )
            .expect("store");
            let old = checkpoint("1111111111111111111111111111111111111111");
            let new = checkpoint("2222222222222222222222222222222222222222");
            write(&store, &old).expect("old");
            assert!(write_with_barrier_for_test(&store, &new, barrier).is_err());
            let reopened = read(&store).expect("recover").expect("checkpoint");
            let expected = if barrier < 2 {
                old.accepted_commit()
            } else {
                new.accepted_commit()
            };
            assert_eq!(reopened.accepted_commit(), expected, "barrier {barrier}");
        }
    }
}
