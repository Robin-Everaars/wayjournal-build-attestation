#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use thiserror::Error;

use crate::Store;
#[cfg(test)]
use crate::store::RawFile;

use super::{
    GitAdmissionError, GitObjectFormat, GitOid, GitQuarantineReason,
    git::{GitRunner, SyncRepository},
};

const MAX_NEW_COMMITS: usize = 10_000;
const MAX_PARENTS_PER_COMMIT: usize = 64;
const MAX_COMMIT_BYTES: usize = 1024 * 1024;
const MAX_GRAPH_OUTPUT: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
#[error("history admission failed: {message}")]
pub(super) struct HistoryError {
    pub reason: GitQuarantineReason,
    message: String,
}

impl HistoryError {
    fn new(reason: GitQuarantineReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub(super) enum HistoryValidationError {
    #[error(transparent)]
    Hostile(#[from] HistoryError),
    #[error(transparent)]
    Operational(#[from] GitAdmissionError),
}

fn classify_admission_error(error: GitAdmissionError) -> HistoryValidationError {
    if let Some(reason) = super::admission_quarantine_reason(&error) {
        HistoryError::new(reason, error.to_string()).into()
    } else {
        HistoryValidationError::Operational(error)
    }
}

fn classify_git_error(error: super::GitCommandError) -> HistoryValidationError {
    if error.is_hostile_history_bound() {
        HistoryError::new(GitQuarantineReason::MalformedHistory, error.to_string()).into()
    } else {
        HistoryValidationError::Operational(error.into())
    }
}

#[derive(Debug)]
struct CommitLine {
    oid: GitOid,
    parents: Vec<GitOid>,
}

pub(super) fn validate_histories(
    store: &Store,
    runner: &GitRunner<'_>,
    repository: &SyncRepository,
    boundary: &GitOid,
    local_tip: &GitOid,
    remote_tip: &GitOid,
) -> Result<(), HistoryValidationError> {
    for tip in [local_tip, remote_tip] {
        if !repository
            .is_ancestor(runner, boundary, tip)
            .map_err(classify_git_error)?
        {
            return Err(HistoryError::new(
                GitQuarantineReason::RollbackNonAncestry,
                "checkpoint is not an ancestor of an advancing tip",
            )
            .into());
        }
    }

    let graph = repository
        .new_history(runner, boundary, local_tip, remote_tip, MAX_GRAPH_OUTPUT)
        .map_err(classify_git_error)?;
    let lines = parse_graph(repository.format(), &graph).map_err(HistoryValidationError::from)?;
    validate_tree(store, runner, repository, boundary)?;
    let mut validated = BTreeSet::new();
    validated.insert(boundary.clone());
    let new_ids = lines
        .iter()
        .map(|line| line.oid.clone())
        .collect::<BTreeSet<_>>();
    for line in &lines {
        repository
            .require_commit_bounded(runner, &line.oid, MAX_COMMIT_BYTES)
            .map_err(classify_git_error)?;
        for parent in &line.parents {
            if validated.contains(parent) {
                continue;
            }
            if new_ids.contains(parent) {
                return Err(HistoryError::new(
                    GitQuarantineReason::MalformedHistory,
                    "history is not parent-before-child",
                )
                .into());
            }
            if !repository
                .is_ancestor(runner, parent, boundary)
                .map_err(classify_git_error)?
            {
                return Err(HistoryError::new(
                    GitQuarantineReason::RollbackNonAncestry,
                    "new history escapes the trusted checkpoint ancestry",
                )
                .into());
            }
            repository
                .require_commit_bounded(runner, parent, MAX_COMMIT_BYTES)
                .map_err(classify_git_error)?;
            validate_tree(store, runner, repository, parent)?;
            validated.insert(parent.clone());
        }
        for parent in &line.parents {
            if let Some(reason) = repository
                .immutable_edge_violation(runner, parent, &line.oid)
                .map_err(classify_git_error)?
            {
                return Err(HistoryError::new(
                    reason,
                    "immutable history edge changed existing bytes",
                )
                .into());
            }
        }
        validate_tree(store, runner, repository, &line.oid)?;
        validated.insert(line.oid.clone());
    }
    if !validated.contains(local_tip) || !validated.contains(remote_tip) {
        return Err(HistoryError::new(
            GitQuarantineReason::MalformedHistory,
            "history enumeration omitted an advancing tip",
        )
        .into());
    }
    // Tip validation above is complete. Do not retain either tip: candidate construction uses
    // Git's disk-backed merge machinery and recovery reopens individual paths as needed.
    Ok(())
}

fn parse_graph(format: GitObjectFormat, bytes: &[u8]) -> Result<Vec<CommitLine>, HistoryError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        HistoryError::new(
            GitQuarantineReason::MalformedHistory,
            "history output is not UTF-8",
        )
    })?;
    let mut lines = Vec::new();
    for line in text.lines() {
        if lines.len() >= MAX_NEW_COMMITS {
            return Err(HistoryError::new(
                GitQuarantineReason::MalformedHistory,
                "new history exceeds commit-count bound",
            ));
        }
        let mut words = line.split_ascii_whitespace();
        let oid = GitOid::parse(
            format,
            words.next().ok_or_else(|| {
                HistoryError::new(GitQuarantineReason::MalformedHistory, "empty history line")
            })?,
        )
        .map_err(|error| {
            HistoryError::new(GitQuarantineReason::MalformedHistory, error.to_string())
        })?;
        let parents = words
            .map(|word| {
                GitOid::parse(format, word).map_err(|error| {
                    HistoryError::new(GitQuarantineReason::MalformedHistory, error.to_string())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if parents.is_empty() || parents.len() > MAX_PARENTS_PER_COMMIT {
            return Err(HistoryError::new(
                GitQuarantineReason::MalformedHistory,
                "new commit parent count is outside bounds",
            ));
        }
        lines.push(CommitLine { oid, parents });
    }
    Ok(lines)
}

fn validate_tree(
    store: &Store,
    runner: &GitRunner<'_>,
    repository: &SyncRepository,
    oid: &GitOid,
) -> Result<(), HistoryValidationError> {
    repository
        .tree_snapshot(store, runner, oid)
        .map_err(classify_admission_error)?;
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
fn validate_loaded_tree(
    store: &Store,
    files: BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(), HistoryError> {
    let raw = files
        .into_iter()
        .map(|(path, bytes)| RawFile { path, bytes })
        .collect::<Vec<_>>();
    crate::store::scan_collected(store, &raw, Vec::new())
        .map_err(GitAdmissionError::from)
        .map_err(|error| {
            let reason = super::admission_quarantine_reason(&error)
                .unwrap_or(GitQuarantineReason::InvalidCommitSnapshot);
            HistoryError::new(reason, error.to_string())
        })?;
    Ok(())
}

#[cfg(test)]
pub(super) fn require_immutable_edge(
    parent: &BTreeMap<Vec<u8>, Vec<u8>>,
    child: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(), HistoryError> {
    for (path, bytes) in parent {
        match child.get(path) {
            None => {
                return Err(HistoryError::new(
                    GitQuarantineReason::Deletion,
                    "canonical path was deleted",
                ));
            }
            Some(candidate) if candidate != bytes => {
                return Err(HistoryError::new(
                    GitQuarantineReason::Modification,
                    "canonical path bytes were modified",
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn exact_union(
    mut local: BTreeMap<Vec<u8>, Vec<u8>>,
    remote: BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, HistoryError> {
    for (path, bytes) in remote {
        if let Some(existing) = local.get(&path) {
            if existing != &bytes {
                return Err(HistoryError::new(
                    GitQuarantineReason::PathCollision,
                    "canonical path collision has unequal bytes",
                ));
            }
        } else {
            local.insert(path, bytes);
        }
    }
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(values: &[(&[u8], &[u8])]) -> BTreeMap<Vec<u8>, Vec<u8>> {
        values
            .iter()
            .map(|(path, bytes)| (path.to_vec(), bytes.to_vec()))
            .collect()
    }

    #[test]
    fn history_rejects_delete_modify_and_restore() {
        let parent = map(&[(b"events/a", b"one")]);
        assert_eq!(
            require_immutable_edge(&parent, &BTreeMap::new())
                .expect_err("deletion")
                .reason,
            GitQuarantineReason::Deletion
        );
        assert_eq!(
            require_immutable_edge(&parent, &map(&[(b"events/a", b"two")]))
                .expect_err("modification")
                .reason,
            GitQuarantineReason::Modification
        );
    }

    #[test]
    fn exact_union_rejects_unequal_shared_paths() {
        let local = map(&[(b"events/a", b"one")]);
        let remote = map(&[(b"events/a", b"two")]);
        assert_eq!(
            exact_union(local, remote).expect_err("collision").reason,
            GitQuarantineReason::PathCollision
        );
    }
}
