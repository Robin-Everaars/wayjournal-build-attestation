use wayjournal_core::GitSyncError;

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
