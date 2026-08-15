use thiserror::Error;

use crate::{
    GitSyncError, GitSyncOutcome, GitSyncRequest, LogicalStoreId, NegotiatedHandshake, ProofCache,
    ProofCacheDisposition, Store, StoreRevisionRef,
};

use super::{AdmissionCheckpoint, CheckpointError, GitAdmissionError};

/// Maximum number of stores accepted by one preflighted synchronization call.
pub const MAX_MULTI_SYNC_TARGETS: usize = 256;

/// One explicitly authorized store synchronization target.
pub struct StoreSyncTarget<'a> {
    pub expected_store: LogicalStoreId,
    pub store: &'a Store,
    pub request: &'a GitSyncRequest,
    pub handshake: &'a NegotiatedHandshake,
}

/// Failure to observe the durable checkpoint after a synchronization attempt.
#[derive(Debug, Error)]
pub enum CheckpointObservationError {
    #[error("failed to retain the store lock for checkpoint observation: {0}")]
    Store(#[from] crate::StoreError),
    #[error("failed to read the durable checkpoint after synchronization: {0}")]
    Checkpoint(#[from] CheckpointError),
    #[error("the durable admission checkpoint is absent after synchronization")]
    MissingCheckpoint,
}

/// Failure from one authorized S5 store synchronization attempt.
#[derive(Debug, Error)]
pub enum AuthorizedGitSyncError {
    #[error("the negotiated handshake identity does not match the locked checkpoint")]
    HandshakeIdentityMismatch,
    #[error("the negotiated handshake is stale relative to the complete locked checkpoint")]
    StaleHandshake,
    #[error("the negotiated handshake lacks wayjournal.sync/git-union-cas-v1")]
    MissingNegotiatedSyncCapability,
    #[error(transparent)]
    Sync(#[from] GitSyncError),
}

/// Independent result for one store after the all-target preflight succeeds.
#[derive(Debug)]
pub struct PerStoreSyncResult {
    pub store: LogicalStoreId,
    pub before: StoreRevisionRef,
    pub after: Result<StoreRevisionRef, CheckpointObservationError>,
    pub cache_disposition: ProofCacheDisposition,
    pub sync_result: Result<GitSyncOutcome, AuthorizedGitSyncError>,
}

/// Structural or initial-authority failure that aborts before any transfer-capable operation.
#[derive(Debug, Error)]
pub enum MultiStoreSyncError {
    #[error("multi-store synchronization requires at least one target")]
    Empty,
    #[error("multi-store synchronization exceeds the {MAX_MULTI_SYNC_TARGETS}-target limit")]
    TooManyTargets,
    #[error("multi-store targets must be strictly ordered by logical store identity")]
    UnsortedTargets,
    #[error("multi-store targets contain a duplicate logical store identity")]
    DuplicateTarget,
    #[error(
        "initial checkpoint authority for {store:?} could not be read without transfer: {source}"
    )]
    CheckpointAuthority {
        store: LogicalStoreId,
        #[source]
        source: Box<GitSyncError>,
    },
    #[error("target {store:?} has no durable admission checkpoint")]
    MissingCheckpoint { store: LogicalStoreId },
    #[error("target, current store, and checkpoint identities disagree for {store:?}")]
    TargetStoreIdentityMismatch { store: LogicalStoreId },
    #[error(
        "the negotiated handshake is not bound to the complete current checkpoint for {store:?}"
    )]
    HandshakeCheckpointMismatch { store: LogicalStoreId },
    #[error(
        "the synchronization request does not equal current checkpoint authority for {store:?}"
    )]
    RequestAuthorityMismatch { store: LogicalStoreId },
    #[error("the negotiated handshake for {store:?} lacks wayjournal.sync/git-union-cas-v1")]
    MissingSyncCapability { store: LogicalStoreId },
}

struct PreflightTarget<'a> {
    target: &'a StoreSyncTarget<'a>,
    checkpoint: AdmissionCheckpoint,
}

/// Synchronizes an ordered set of stores after a complete zero-transfer authority preflight.
///
/// Every target is structurally checked and compared with its current complete durable checkpoint
/// before any target enters synchronization. Each target then revalidates that same sealed
/// checkpoint while continuously retaining the exact S4 transfer lock. Runtime outcomes remain
/// independent and in input order; one failure never rolls back or suppresses later targets.
///
/// # Errors
/// Returns a call-level error for empty, oversized, unordered, duplicate, identity-confused, stale,
/// request-confused, or sync-capability-deficient initial input. Every such error occurs before any
/// Git runner, remote probe, credential path, hook, or network operation is constructed or invoked.
pub fn sync_stores(
    targets: &[StoreSyncTarget<'_>],
    cache: Option<&ProofCache>,
) -> Result<Vec<PerStoreSyncResult>, MultiStoreSyncError> {
    validate_target_shape(targets)?;

    let mut preflight = Vec::with_capacity(targets.len());
    for target in targets {
        let (checkpoint, current_store) = preflight_authority(target)?;
        if current_store != target.expected_store
            || checkpoint.logical_store_id() != &target.expected_store
        {
            return Err(MultiStoreSyncError::TargetStoreIdentityMismatch {
                store: target.expected_store.clone(),
            });
        }
        if target.handshake.logical_store_id() != &target.expected_store
            || target.handshake.bound_checkpoint() != &checkpoint
        {
            return Err(MultiStoreSyncError::HandshakeCheckpointMismatch {
                store: target.expected_store.clone(),
            });
        }
        if *checkpoint.local_trust_binding() != target.request.local_trust()
            || checkpoint.approved_remote() != target.request.approved_remote()
        {
            return Err(MultiStoreSyncError::RequestAuthorityMismatch {
                store: target.expected_store.clone(),
            });
        }
        if !target.handshake.supports_git_union_cas() {
            return Err(MultiStoreSyncError::MissingSyncCapability {
                store: target.expected_store.clone(),
            });
        }
        preflight.push(PreflightTarget { target, checkpoint });
    }

    // Internal deterministic seam: checkpoint changes after this point are caught only by the
    // mandatory comparison under the target's exact transfer lock.
    super::fault::multi_preflight_barrier();

    let mut results = Vec::with_capacity(preflight.len());
    for authorized in preflight {
        let before = authorized.checkpoint.accepted_revision();
        let sync_result = authorized
            .target
            .store
            .sync_git_union_authorized(authorized.target.request, authorized.target.handshake);
        let after = observe_checkpoint(authorized.target.store)
            .map(|checkpoint| checkpoint.accepted_revision());
        let cache_disposition = match &after {
            Ok(revision) if *revision == before => ProofCacheDisposition::Unchanged,
            Ok(revision) => cache.map_or(ProofCacheDisposition::Unavailable, |cache| {
                cache.invalidate_store(&authorized.target.expected_store, before, *revision)
            }),
            Err(_) => ProofCacheDisposition::Unavailable,
        };
        results.push(PerStoreSyncResult {
            store: authorized.target.expected_store.clone(),
            before,
            after,
            cache_disposition,
            sync_result,
        });
    }
    Ok(results)
}

fn validate_target_shape(targets: &[StoreSyncTarget<'_>]) -> Result<(), MultiStoreSyncError> {
    if targets.is_empty() {
        return Err(MultiStoreSyncError::Empty);
    }
    if targets.len() > MAX_MULTI_SYNC_TARGETS {
        return Err(MultiStoreSyncError::TooManyTargets);
    }
    for pair in targets.windows(2) {
        match pair[0].expected_store.cmp(&pair[1].expected_store) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => return Err(MultiStoreSyncError::DuplicateTarget),
            std::cmp::Ordering::Greater => return Err(MultiStoreSyncError::UnsortedTargets),
        }
    }
    Ok(())
}

fn preflight_authority(
    target: &StoreSyncTarget<'_>,
) -> Result<(AdmissionCheckpoint, LogicalStoreId), MultiStoreSyncError> {
    target
        .store
        .require_legacy_streaming(crate::LegacyStreamRequirement::FullDomainBounded)
        .map_err(|source| MultiStoreSyncError::CheckpointAuthority {
            store: target.expected_store.clone(),
            source: Box::new(GitSyncError::LegacyStreaming(source)),
        })?;
    let guard = target
        .store
        .lock_exclusive_unsnapshotted()
        .map_err(|source| MultiStoreSyncError::CheckpointAuthority {
            store: target.expected_store.clone(),
            source: Box::new(GitSyncError::Store(source)),
        })?;
    let checkpoint = super::admission_checkpoint_locked(&guard)
        .map_err(|source| MultiStoreSyncError::CheckpointAuthority {
            store: target.expected_store.clone(),
            source: Box::new(GitSyncError::Checkpoint(source)),
        })?
        .ok_or_else(|| MultiStoreSyncError::MissingCheckpoint {
            store: target.expected_store.clone(),
        })?;
    let current = guard.validate_visible_s4b_locked().map_err(|source| {
        MultiStoreSyncError::CheckpointAuthority {
            store: target.expected_store.clone(),
            source: Box::new(GitSyncError::Store(source)),
        }
    })?;
    let identity = current
        .identity()
        .ok_or_else(|| MultiStoreSyncError::CheckpointAuthority {
            store: target.expected_store.clone(),
            source: Box::new(GitSyncError::Admission(GitAdmissionError::MissingIdentity)),
        })?
        .logical_id()
        .clone();
    Ok((checkpoint, identity))
}

fn observe_checkpoint(store: &Store) -> Result<AdmissionCheckpoint, CheckpointObservationError> {
    let guard = store.lock_exclusive_unsnapshotted()?;
    super::admission_checkpoint_locked(&guard)?.ok_or(CheckpointObservationError::MissingCheckpoint)
}
