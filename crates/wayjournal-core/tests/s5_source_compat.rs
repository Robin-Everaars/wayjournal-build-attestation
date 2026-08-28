use wayjournal_core::{GitSyncError, StoreError};

// This external exhaustive match is the finalized S4 source surface. Adding a variant to the
// legacy error breaks this integration target at compile time; S5 errors belong to additive types.
#[allow(dead_code)]
fn match_finalized_s4_git_sync_error(error: &GitSyncError) {
    match error {
        GitSyncError::BootstrapRequired
        | GitSyncError::AdvanceRequired
        | GitSyncError::Approval(_)
        | GitSyncError::Checkpoint(_)
        | GitSyncError::Git(_)
        | GitSyncError::Store(_)
        | GitSyncError::Quarantine(_)
        | GitSyncError::LegacyStreaming(_)
        | GitSyncError::PendingState { .. }
        | GitSyncError::Admission(_) => {}
    }
}

#[test]
fn finalized_s4_git_sync_error_remains_exhaustively_matchable() {
    match_finalized_s4_git_sync_error(&GitSyncError::BootstrapRequired);
}

// StoreError predates the additive operation API and remains exhaustively matchable. Operation
// lifecycle failures belong to ExclusiveOperationError rather than widening this enum.
#[allow(dead_code)]
fn match_finalized_store_error(error: &StoreError) {
    match error {
        StoreError::Io { .. }
        | StoreError::LockPoisoned
        | StoreError::InvalidLayout { .. }
        | StoreError::CrossDeviceLayout { .. }
        | StoreError::RevisionMismatch { .. }
        | StoreError::RecoveryBaseChanged { .. }
        | StoreError::InvalidJournal { .. }
        | StoreError::PublicationConflict { .. }
        | StoreError::GitSyncPending { .. }
        | StoreError::InvalidGitSyncState { .. }
        | StoreError::ConflictingRecoveryState
        | StoreError::InjectedCrash { .. }
        | StoreError::Batch(_)
        | StoreError::Corrupt { .. } => {}
    }
}

#[test]
fn finalized_store_error_remains_exhaustively_matchable() {
    match_finalized_store_error(&StoreError::LockPoisoned);
}
