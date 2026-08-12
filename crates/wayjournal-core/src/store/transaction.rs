use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
};

use rustix::fs::{self as rfs, AtFlags, FileType};
use serde::{Deserialize, Serialize};

use crate::{
    BatchId, BatchManifest, MAX_BATCH_BYTES, MAX_RECORD_BYTES, PreparedBatch, StoreRevisionRef,
    decode_batch_manifest,
};

use super::{
    CommitOutcome, Directory, ExclusiveSnapshot, RawFile, Store, StoreError, StoreSnapshot,
    enforce_limits, io_error, read_file_bounded, scan_collected, scan_visible, visible_inventory,
};
#[cfg(test)]
use super::{RacePoint, race};

const JOURNAL_SCHEMA_V1: &str = "wayjournal.transaction/v1";
const MAX_JOURNAL_BYTES: usize = 4096;
const MAX_JOURNAL_MEMBERS: usize = 16_384;
const MAX_LOCAL_ENTRIES: usize = MAX_JOURNAL_MEMBERS + 8;
const MAX_LOCAL_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CrashPoint {
    StageDirectory,
    StageRecordsDirectory,
    RecordFile,
    StageRecords,
    ManifestFile,
    StageManifest,
    JournalFile,
    StageJournal,
    JournalPublished,
    RecordPublished,
    ManifestPublished,
    JournalRemoved,
    StageRemoved,
}
impl CrashPoint {
    const fn name(self) -> &'static str {
        match self {
            Self::StageDirectory => "stage_directory",
            Self::StageRecordsDirectory => "stage_records_directory",
            Self::RecordFile => "record_file",
            Self::StageRecords => "stage_records",
            Self::ManifestFile => "manifest_file",
            Self::StageManifest => "stage_manifest",
            Self::JournalFile => "journal_file",
            Self::StageJournal => "stage_journal",
            Self::JournalPublished => "journal_published",
            Self::RecordPublished => "record_published",
            Self::ManifestPublished => "manifest_published",
            Self::JournalRemoved => "journal_removed",
            Self::StageRemoved => "stage_removed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJournal {
    base_algorithm: String,
    base_digest: String,
    batch_id: String,
    manifest_hash: String,
    member_count: u64,
    schema: String,
}
struct Journal {
    base: StoreRevisionRef,
    batch_id: BatchId,
    manifest_hash: String,
    member_count: usize,
}
struct StagedRecord {
    file: File,
    target: String,
    bytes: Vec<u8>,
}
struct StagedManifest {
    file: File,
    manifest: BatchManifest,
    bytes: Vec<u8>,
}

type Barrier<'a> = &'a mut dyn FnMut(CrashPoint) -> io::Result<()>;

pub(super) fn exclusive_snapshot(store: &Store) -> Result<ExclusiveSnapshot<'_>, StoreError> {
    let local_guard = store
        .local_lock
        .write()
        .map_err(|_| StoreError::LockPoisoned)?;
    let file_guard = store.root_dir.lock_file()?;
    file_guard
        .lock()
        .map_err(|source| io_error("acquire exclusive root lock", &store.root, source))?;
    recover_locked(store, &mut |_| Ok(()))?;
    let snapshot = scan_visible(store)?;
    Ok(ExclusiveSnapshot {
        snapshot,
        _file_guard: file_guard,
        _local_guard: local_guard,
    })
}

pub(super) fn append(
    store: &Store,
    prepared: &PreparedBatch,
    expected: StoreRevisionRef,
) -> Result<CommitOutcome, StoreError> {
    append_inner(store, prepared, expected, &mut |_| Ok(()))
}
fn append_inner(
    store: &Store,
    prepared: &PreparedBatch,
    expected: StoreRevisionRef,
    barrier: Barrier<'_>,
) -> Result<CommitOutcome, StoreError> {
    let _local = store
        .local_lock
        .write()
        .map_err(|_| StoreError::LockPoisoned)?;
    let lock = store.root_dir.lock_file()?;
    lock.lock()
        .map_err(|source| io_error("acquire exclusive root lock", &store.root, source))?;
    recover_locked(store, barrier)?;
    let snapshot = scan_visible(store)?;
    if snapshot.revision() != expected {
        return Err(StoreError::RevisionMismatch {
            expected,
            actual: snapshot.revision(),
        });
    }
    if let Some(batch_id) = classify_prepared(snapshot.manifests(), prepared)? {
        return Ok(CommitOutcome::Replay {
            batch_id,
            revision: snapshot.revision(),
        });
    }
    validate_candidate(store, prepared)?;
    stage_batch(store, prepared, snapshot.revision(), barrier)?;
    recover_one(store, prepared.manifest().batch_id(), barrier)?;
    let committed = scan_visible(store)?;
    Ok(CommitOutcome::Published {
        batch_id: prepared.manifest().batch_id(),
        revision: committed.revision(),
    })
}

fn classify_prepared(
    manifests: &[BatchManifest],
    prepared: &PreparedBatch,
) -> Result<Option<BatchId>, StoreError> {
    let target = prepared.manifest();
    let mut matches = manifests
        .iter()
        .filter(|manifest| {
            manifest.actor() == target.actor()
                && manifest.idempotency_key_digest() == target.idempotency_key_digest()
        })
        .collect::<Vec<_>>();
    matches.sort_by_key(|manifest| manifest.batch_id());
    match matches.as_slice() {
        [] => Ok(None),
        [manifest] if manifest.request_digest() == target.request_digest() => {
            Ok(Some(manifest.batch_id()))
        }
        [manifest] => Err(crate::BatchError::IdempotencyRequestMismatch {
            batch_id: manifest.batch_id(),
        }
        .into()),
        _ => Err(crate::BatchError::DuplicateIdempotencyOwnership {
            batch_ids: matches.iter().map(|manifest| manifest.batch_id()).collect(),
        }
        .into()),
    }
}
fn validate_candidate(
    store: &Store,
    prepared: &PreparedBatch,
) -> Result<StoreSnapshot, StoreError> {
    let (mut files, nonregular, inventory) = visible_inventory(store)?;
    enforce_limits(
        files
            .iter()
            .map(|file| (file.path.as_slice(), file.bytes.len()))
            .chain(
                prepared
                    .records()
                    .iter()
                    .map(|record| (record.path().as_bytes(), record.bytes().len())),
            )
            .chain(std::iter::once((
                prepared.manifest_path().as_bytes(),
                prepared.manifest_bytes().len(),
            ))),
        nonregular.iter().map(Vec::as_slice),
        inventory.iter(),
    )?;
    for record in prepared.records() {
        if files
            .iter()
            .any(|file| file.path == record.path().as_bytes())
        {
            return Err(StoreError::PublicationConflict {
                path: store.root.join(record.path()),
            });
        }
        files.push(RawFile {
            path: record.path().as_bytes().to_vec(),
            bytes: record.bytes().to_vec(),
        });
    }
    if files
        .iter()
        .any(|file| file.path == prepared.manifest_path().as_bytes())
    {
        return Err(StoreError::PublicationConflict {
            path: store.root.join(prepared.manifest_path()),
        });
    }
    files.push(RawFile {
        path: prepared.manifest_path().as_bytes().to_vec(),
        bytes: prepared.manifest_bytes().to_vec(),
    });
    files.sort_by(|a, b| a.path.cmp(&b.path));
    scan_collected(store, &files, nonregular)
}

fn stage_batch(
    store: &Store,
    prepared: &PreparedBatch,
    base: StoreRevisionRef,
    barrier: Barrier<'_>,
) -> Result<(), StoreError> {
    let stage_name = prepared.manifest().batch_id().to_string();
    let (stage, created) = store.stages_dir.ensure_dir(OsStr::new(&stage_name))?;
    if !created {
        return Err(invalid_journal(&stage.path, "stage already exists"));
    }
    store.stages_dir.sync()?;
    hit(barrier, CrashPoint::StageDirectory)?;
    #[cfg(test)]
    race(RacePoint::DynamicStage);
    let (records, created) = stage.ensure_dir(OsStr::new("records"))?;
    if !created {
        return Err(invalid_journal(
            &records.path,
            "staged records already exists",
        ));
    }
    stage.sync()?;
    hit(barrier, CrashPoint::StageRecordsDirectory)?;
    for (index, record) in prepared.records().iter().enumerate() {
        let name = format!("{index:08}.json");
        write_new_synced(&records, OsStr::new(&name), record.bytes())?;
        hit(barrier, CrashPoint::RecordFile)?;
    }
    records.sync()?;
    hit(barrier, CrashPoint::StageRecords)?;
    write_new_synced(
        &stage,
        OsStr::new("manifest.json"),
        prepared.manifest_bytes(),
    )?;
    hit(barrier, CrashPoint::ManifestFile)?;
    stage.sync()?;
    hit(barrier, CrashPoint::StageManifest)?;
    let raw = RawJournal {
        base_algorithm: base.algorithm().to_string(),
        base_digest: base.digest().to_string(),
        batch_id: prepared.manifest().batch_id().to_string(),
        manifest_hash: manifest_hash(prepared.manifest_bytes()),
        member_count: u64::try_from(prepared.records().len())
            .map_err(|_| invalid_journal(&stage.path, "member count exceeds u64"))?,
        schema: JOURNAL_SCHEMA_V1.to_owned(),
    };
    let bytes = encode_journal(&raw, &stage.path)?;
    let temporary = write_new_synced(&stage, OsStr::new("journal.tmp"), &bytes)?;
    hit(barrier, CrashPoint::JournalFile)?;
    stage.sync()?;
    hit(barrier, CrashPoint::StageJournal)?;
    let journal_name = format!("{}.json", prepared.manifest().batch_id());
    link_fd_no_clobber(
        &temporary,
        &store.recovery_dir,
        OsStr::new(&journal_name),
        &bytes,
    )?;
    store.recovery_dir.sync()?;
    hit(barrier, CrashPoint::JournalPublished)
}

pub(super) fn recover(store: &Store) -> Result<(), StoreError> {
    let _local = store
        .local_lock
        .write()
        .map_err(|_| StoreError::LockPoisoned)?;
    let lock = store.root_dir.lock_file()?;
    lock.lock()
        .map_err(|source| io_error("acquire exclusive root lock", &store.root, source))?;
    recover_locked(store, &mut |_| Ok(()))
}
fn recover_locked(store: &Store, barrier: Barrier<'_>) -> Result<(), StoreError> {
    #[cfg(test)]
    race(RacePoint::RecoveryRoot);
    for batch_id in listed_journals(store)? {
        recover_one(store, batch_id, barrier)?;
    }
    clean_unprepared_stages(store)
}
#[allow(clippy::too_many_lines)]
fn recover_one(store: &Store, batch_id: BatchId, barrier: Barrier<'_>) -> Result<(), StoreError> {
    let journal_name = format!("{batch_id}.json");
    let journal_path = store.recovery_dir.path.join(&journal_name);
    let journal_file = store.recovery_dir.open_file(OsStr::new(&journal_name))?;
    let journal_bytes = bounded_regular(
        &store.recovery_dir,
        OsStr::new(&journal_name),
        journal_file,
        MAX_JOURNAL_BYTES,
    )?;
    let journal = decode_journal(&journal_path, &journal_bytes)?;
    if journal.batch_id != batch_id {
        return Err(invalid_journal(
            &journal_path,
            "journal filename and batch id differ",
        ));
    }

    let stage_name = batch_id.to_string();
    #[cfg(test)]
    race(RacePoint::RecoveryStage);
    let stage = store.stages_dir.open_dir(OsStr::new(&stage_name))?;
    validate_stage_root(&stage)?;
    let staged_journal = stage.open_file(OsStr::new("journal.tmp"))?;
    if bounded_regular(
        &stage,
        OsStr::new("journal.tmp"),
        staged_journal,
        MAX_JOURNAL_BYTES,
    )? != journal_bytes
    {
        return Err(invalid_journal(
            &journal_path,
            "published and staged journals differ",
        ));
    }
    let manifest_file = stage.open_file(OsStr::new("manifest.json"))?;
    let manifest_bytes = bounded_regular(
        &stage,
        OsStr::new("manifest.json"),
        manifest_file
            .try_clone()
            .map_err(|source| io_error("clone staged manifest", &stage.path, source))?,
        MAX_BATCH_BYTES,
    )?;
    if manifest_hash(&manifest_bytes) != journal.manifest_hash {
        return Err(invalid_journal(
            &journal_path,
            "staged manifest hash mismatch",
        ));
    }
    let manifest = decode_batch_manifest(&manifest_bytes)
        .map_err(|error| invalid_journal(&journal_path, &error.to_string()))?;
    if manifest.batch_id() != batch_id || manifest.members().len() != journal.member_count {
        return Err(invalid_journal(
            &journal_path,
            "journal ownership or count mismatch",
        ));
    }
    let records_dir = stage.open_dir(OsStr::new("records"))?;
    validate_ordinals(&records_dir, journal.member_count)?;
    let mut staged = Vec::new();
    for index in 0..journal.member_count {
        let name = format!("{index:08}.json");
        let file = records_dir.open_file(OsStr::new(&name))?;
        let bytes = bounded_regular(
            &records_dir,
            OsStr::new(&name),
            file.try_clone()
                .map_err(|source| io_error("clone staged record", &records_dir.path, source))?,
            MAX_RECORD_BYTES,
        )?;
        let record = crate::decode_record(&bytes, &store.registry)
            .map_err(|error| invalid_journal(&journal_path, &error.to_string()))?;
        staged.push(StagedRecord {
            file,
            target: record.canonical_path(),
            bytes,
        });
    }
    staged.sort_by(|a, b| a.target.cmp(&b.target));
    if staged
        .windows(2)
        .any(|pair| pair[0].target == pair[1].target)
    {
        return Err(invalid_journal(
            &journal_path,
            "duplicate staged record path",
        ));
    }
    let members = staged
        .iter()
        .map(|record| crate::StoredMember::new(record.target.as_bytes(), &record.bytes))
        .collect::<Vec<_>>();
    crate::validate_batch_members(&manifest, &members, &store.registry)
        .map_err(|error| invalid_journal(&journal_path, &error.to_string()))?;
    let staged_manifest = StagedManifest {
        file: manifest_file,
        manifest,
        bytes: manifest_bytes,
    };
    if let Err(error) = validate_recovery_base(store, &journal, &staged_manifest, &staged) {
        if matches!(
            error,
            StoreError::Corrupt {
                issue: crate::StoreCorruption::InvalidDomainFold { .. }
            }
        ) {
            store.recovery_dir.unlink_file(OsStr::new(&journal_name))?;
            store.recovery_dir.sync()?;
            let mut cleanup_entries = 1;
            remove_tree(
                &store.stages_dir,
                OsStr::new(&stage_name),
                &mut cleanup_entries,
            )?;
            store.stages_dir.sync()?;
        }
        return Err(error);
    }

    for record in &staged {
        let (parent, name) = record_target_parent(store, &record.target, true)?;
        link_fd_no_clobber(&record.file, &parent, &name, &record.bytes)?;
        parent.sync()?;
        hit(barrier, CrashPoint::RecordPublished)?;
    }
    let manifest_name = format!("{}.json", staged_manifest.manifest.batch_id());
    link_fd_no_clobber(
        &staged_manifest.file,
        &store.journal_batches_dir,
        OsStr::new(&manifest_name),
        &staged_manifest.bytes,
    )?;
    store.journal_batches_dir.sync()?;
    hit(barrier, CrashPoint::ManifestPublished)?;
    store.recovery_dir.unlink_file(OsStr::new(&journal_name))?;
    store.recovery_dir.sync()?;
    hit(barrier, CrashPoint::JournalRemoved)?;
    let mut cleanup_entries = 1;
    remove_tree(
        &store.stages_dir,
        OsStr::new(&stage_name),
        &mut cleanup_entries,
    )?;
    store.stages_dir.sync()?;
    hit(barrier, CrashPoint::StageRemoved)
}

fn validate_recovery_base(
    store: &Store,
    journal: &Journal,
    manifest: &StagedManifest,
    staged: &[StagedRecord],
) -> Result<(), StoreError> {
    let mut targets = staged
        .iter()
        .map(|record| (record.target.as_bytes().to_vec(), record.bytes.as_slice()))
        .collect::<BTreeMap<_, _>>();
    targets.insert(
        manifest.manifest.canonical_path().into_bytes(),
        manifest.bytes.as_slice(),
    );
    let (files, nonregular, inventory) = visible_inventory(store)?;
    let mut base = Vec::new();
    let mut present = BTreeSet::new();
    for file in files {
        if let Some(expected) = targets.get(&file.path) {
            if file.bytes != *expected {
                return Err(StoreError::PublicationConflict {
                    path: store.root.join(OsString::from_vec(file.path)),
                });
            }
            present.insert(file.path);
        } else {
            base.push(file);
        }
    }
    if present.len() == targets.len() {
        scan_visible(store)?;
        return Ok(());
    }
    enforce_limits(
        base.iter()
            .map(|file| (file.path.as_slice(), file.bytes.len()))
            .chain(
                staged
                    .iter()
                    .map(|record| (record.target.as_bytes(), record.bytes.len())),
            )
            .chain(std::iter::once((
                manifest.manifest.canonical_path().as_bytes(),
                manifest.bytes.len(),
            ))),
        nonregular.iter().map(Vec::as_slice),
        inventory.iter(),
    )?;
    let snapshot = scan_collected(store, &base, nonregular)?;
    if snapshot.revision() != journal.base {
        return Err(StoreError::RecoveryBaseChanged {
            expected: journal.base,
            actual: snapshot.revision(),
        });
    }
    let mut candidate = base;
    for record in staged {
        candidate.push(RawFile {
            path: record.target.as_bytes().to_vec(),
            bytes: record.bytes.clone(),
        });
    }
    candidate.push(RawFile {
        path: manifest.manifest.canonical_path().into_bytes(),
        bytes: manifest.bytes.clone(),
    });
    candidate.sort_by(|a, b| a.path.cmp(&b.path));
    scan_collected(store, &candidate, Vec::new())?;
    Ok(())
}

fn listed_journals(store: &Store) -> Result<Vec<BatchId>, StoreError> {
    let names = store.recovery_dir.bounded_names(MAX_LOCAL_ENTRIES)?;
    let mut ids = Vec::new();
    for bytes in names {
        let name = std::str::from_utf8(&bytes).map_err(|_| {
            invalid_journal(&store.recovery_dir.path, "journal filename is not UTF-8")
        })?;
        if store.recovery_dir.kind(OsStr::from_bytes(&bytes))? != FileType::RegularFile {
            return Err(invalid_journal(
                &store.recovery_dir.path.join(OsStr::from_bytes(&bytes)),
                "journal is not a regular file",
            ));
        }
        let stem = name.strip_suffix(".json").ok_or_else(|| {
            invalid_journal(
                &store.recovery_dir.path,
                "journal filename is not canonical",
            )
        })?;
        ids.push(stem.parse().map_err(|_| {
            invalid_journal(&store.recovery_dir.path, "journal filename is not UUIDv7")
        })?);
    }
    ids.sort();
    Ok(ids)
}
fn clean_unprepared_stages(store: &Store) -> Result<(), StoreError> {
    let names = store.stages_dir.bounded_names(MAX_LOCAL_ENTRIES)?;
    let mut consumed = names.len();
    for name in names {
        remove_tree(&store.stages_dir, OsStr::from_bytes(&name), &mut consumed)?;
    }
    store.stages_dir.sync()
}
struct CleanupFrame {
    directory: Directory,
    names: Vec<Vec<u8>>,
    next: usize,
    name: OsString,
}
fn remove_tree(parent: &Directory, name: &OsStr, consumed: &mut usize) -> Result<(), StoreError> {
    if parent.kind(name)? != FileType::Directory {
        return parent.unlink_file(name);
    }
    let directory = parent.open_dir(name)?;
    let remaining = MAX_LOCAL_ENTRIES.saturating_sub(*consumed);
    let names = directory.bounded_names(remaining)?;
    *consumed = consumed
        .checked_add(names.len())
        .ok_or_else(|| invalid_journal(&directory.path, "cleanup entry count overflow"))?;
    let mut stack = vec![CleanupFrame {
        directory,
        names,
        next: 0,
        name: name.to_os_string(),
    }];
    while !stack.is_empty() {
        let depth = stack.len();
        let Some(frame) = stack.last_mut() else {
            break;
        };
        if let Some(nested) = frame.names.get(frame.next).cloned() {
            frame.next += 1;
            let nested_name = OsStr::from_bytes(&nested);
            if frame.directory.kind(nested_name)? == FileType::Directory {
                if depth >= MAX_LOCAL_DEPTH {
                    return Err(invalid_journal(
                        &frame.directory.path,
                        "cleanup depth limit exceeded",
                    ));
                }
                let child = frame.directory.open_dir(nested_name)?;
                let remaining = MAX_LOCAL_ENTRIES.saturating_sub(*consumed);
                let names = child.bounded_names(remaining)?;
                *consumed = consumed
                    .checked_add(names.len())
                    .ok_or_else(|| invalid_journal(&child.path, "cleanup entry count overflow"))?;
                stack.push(CleanupFrame {
                    directory: child,
                    names,
                    next: 0,
                    name: OsString::from_vec(nested),
                });
            } else {
                frame.directory.unlink_file(nested_name)?;
            }
        } else {
            let Some(finished) = stack.pop() else {
                return Err(invalid_journal(&parent.path, "cleanup stack underflow"));
            };
            finished.directory.sync()?;
            if let Some(ancestor) = stack.last() {
                ancestor.directory.unlink_dir(&finished.name)?;
            } else {
                parent.unlink_dir(&finished.name)?;
            }
        }
    }
    Ok(())
}
fn validate_stage_root(stage: &Directory) -> Result<(), StoreError> {
    let expected = BTreeSet::from([
        b"journal.tmp".to_vec(),
        b"manifest.json".to_vec(),
        b"records".to_vec(),
    ]);
    if stage
        .bounded_names(MAX_LOCAL_ENTRIES)?
        .into_iter()
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(invalid_journal(
            &stage.path,
            "stage entries are incomplete or unexpected",
        ));
    }
    if stage.kind(OsStr::new("records"))? != FileType::Directory {
        return Err(invalid_journal(
            &stage.path,
            "staged records is not a directory",
        ));
    }
    Ok(())
}
fn validate_ordinals(directory: &Directory, count: usize) -> Result<(), StoreError> {
    let expected = (0..count)
        .map(|index| format!("{index:08}.json").into_bytes())
        .collect::<BTreeSet<_>>();
    if directory
        .bounded_names(MAX_LOCAL_ENTRIES)?
        .into_iter()
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(invalid_journal(
            &directory.path,
            "staged record ordinals are incomplete or unexpected",
        ));
    }
    Ok(())
}
fn record_target_parent(
    store: &Store,
    target: &str,
    create: bool,
) -> Result<(Directory, OsString), StoreError> {
    let parts = target.split('/').collect::<Vec<_>>();
    let ["journal", "records", domain, entity, file] = parts.as_slice() else {
        return Err(invalid_journal(
            &store.root.join(target),
            "record target is not canonical",
        ));
    };
    let domain = if create {
        ensure_synced(&store.records_dir, OsStr::new(domain))?
    } else {
        store.records_dir.open_dir(OsStr::new(domain))?
    };
    let entity = if create {
        ensure_synced(&domain, OsStr::new(entity))?
    } else {
        domain.open_dir(OsStr::new(entity))?
    };
    Ok((entity, OsString::from(file)))
}
fn ensure_synced(parent: &Directory, name: &OsStr) -> Result<Directory, StoreError> {
    let (directory, created) = parent.ensure_dir(name)?;
    if created {
        directory.sync()?;
        parent.sync()?;
    }
    Ok(directory)
}
fn encode_journal(journal: &RawJournal, path: &Path) -> Result<Vec<u8>, StoreError> {
    let bytes =
        serde_json::to_vec(journal).map_err(|error| invalid_journal(path, &error.to_string()))?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(invalid_journal(path, "journal exceeds byte limit"));
    }
    Ok(bytes)
}
fn decode_journal(path: &Path, bytes: &[u8]) -> Result<Journal, StoreError> {
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(invalid_journal(path, "journal exceeds byte limit"));
    }
    let raw: RawJournal =
        serde_json::from_slice(bytes).map_err(|error| invalid_journal(path, &error.to_string()))?;
    if raw.schema != JOURNAL_SCHEMA_V1 || encode_journal(&raw, path)? != bytes {
        return Err(invalid_journal(path, "unsupported or noncanonical journal"));
    }
    let member_count = usize::try_from(raw.member_count)
        .map_err(|_| invalid_journal(path, "member count exceeds usize"))?;
    if member_count == 0 || member_count > MAX_JOURNAL_MEMBERS {
        return Err(invalid_journal(path, "member count outside bounds"));
    }
    Ok(Journal {
        base: StoreRevisionRef::parse(&raw.base_algorithm, &raw.base_digest)
            .map_err(|error| invalid_journal(path, &error.to_string()))?,
        batch_id: raw
            .batch_id
            .parse()
            .map_err(|_| invalid_journal(path, "batch id is not UUIDv7"))?,
        manifest_hash: raw.manifest_hash,
        member_count,
    })
}
fn manifest_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn write_new_synced(directory: &Directory, name: &OsStr, bytes: &[u8]) -> Result<File, StoreError> {
    let mut file = directory.create_file(name)?;
    file.write_all(bytes).map_err(|source| {
        io_error(
            "write staged descriptor",
            &directory.path.join(name),
            source,
        )
    })?;
    file.sync_all()
        .map_err(|source| io_error("sync staged descriptor", &directory.path.join(name), source))?;
    Ok(file)
}
fn bounded_regular(
    directory: &Directory,
    name: &OsStr,
    file: File,
    limit: usize,
) -> Result<Vec<u8>, StoreError> {
    let length = directory.require_regular(&file, name)?;
    if length > limit as u64 {
        return Err(invalid_journal(
            &directory.path.join(name),
            "staged or recovery file exceeds byte limit",
        ));
    }
    read_file_bounded(file, limit, &directory.path.join(name)).map_err(|error| match error {
        StoreError::InvalidLayout { path, .. } => {
            invalid_journal(&path, "staged or recovery file exceeds byte limit")
        }
        other => other,
    })
}
fn link_fd_no_clobber(
    source: &File,
    target_dir: &Directory,
    target_name: &OsStr,
    expected: &[u8],
) -> Result<(), StoreError> {
    #[cfg(test)]
    race(RacePoint::PublicationTarget);
    // `AT_SYMLINK_FOLLOW` on procfs' descriptor link names the already-open inode. This avoids
    // resolving a mutable stage name again while retaining no-clobber `linkat` publication.
    let proc_source = PathBuf::from(format!("/proc/self/fd/{}", source.as_raw_fd()));
    match rfs::linkat(
        rfs::CWD,
        &proc_source,
        target_dir.file(),
        target_name,
        AtFlags::SYMLINK_FOLLOW,
    ) {
        Ok(()) => {
            let target = target_dir.open_file(target_name)?;
            let source_stat = rfs::fstat(source).map_err(|error| {
                io_error(
                    "inspect retained publication source",
                    &proc_source,
                    error.into(),
                )
            })?;
            let target_stat = rfs::fstat(&target).map_err(|error| {
                io_error(
                    "inspect published target",
                    &target_dir.path.join(target_name),
                    error.into(),
                )
            })?;
            if source_stat.st_dev == target_stat.st_dev && source_stat.st_ino == target_stat.st_ino
            {
                Ok(())
            } else {
                Err(StoreError::PublicationConflict {
                    path: target_dir.path.join(target_name),
                })
            }
        }
        Err(rustix::io::Errno::EXIST) => {
            let path = target_dir.path.join(target_name);
            let Ok(target) = target_dir.open_file(target_name) else {
                return Err(StoreError::PublicationConflict { path });
            };
            match read_file_bounded(target, expected.len(), &path) {
                Ok(actual) if actual == expected => Ok(()),
                Ok(_) | Err(StoreError::InvalidLayout { .. }) => {
                    Err(StoreError::PublicationConflict { path })
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(io_error(
            "publish immutable descriptor",
            &target_dir.path.join(target_name),
            error.into(),
        )),
    }
}
fn hit(barrier: Barrier<'_>, point: CrashPoint) -> Result<(), StoreError> {
    barrier(point).map_err(|_| StoreError::InjectedCrash {
        point: point.name(),
    })
}
fn invalid_journal(path: &Path, message: &str) -> StoreError {
    StoreError::InvalidJournal {
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CrashPoint, MAX_JOURNAL_BYTES, MAX_LOCAL_DEPTH, MAX_LOCAL_ENTRIES, append_inner,
        link_fd_no_clobber, recover_one, stage_batch,
    };
    use crate::{
        ActorId, DomainRegistration, DomainRegistry, KindId, LegacyEntry, LegacyStoreAdapter,
        MAX_BATCH_BYTES, MAX_RECORD_BYTES, Record, RecordTimestamp, Store, StoreError,
        prepare_batch,
    };
    use serde_json::{Value, json};
    use std::{
        cell::Cell,
        collections::BTreeMap,
        ffi::OsStr,
        fs, io,
        io::Write,
        os::unix::{fs::symlink, net::UnixListener},
        rc::Rc,
        sync::Arc,
    };
    #[derive(Debug)]
    struct NoLegacy;
    impl LegacyStoreAdapter for NoLegacy {
        fn validate(&self, entries: &[LegacyEntry<'_>]) -> Result<(), String> {
            if entries.is_empty() {
                Ok(())
            } else {
                Err("unexpected legacy".into())
            }
        }
    }
    fn validator(_: &KindId, payload: &Value) -> Result<(), String> {
        if payload == &json!({"ok":true}) {
            Ok(())
        } else {
            Err("bad".into())
        }
    }
    static KINDS: &[&str] = &["record.made"];
    static DOMAINS: &[DomainRegistration] = &[DomainRegistration::new(
        "test.domain",
        "test.domain/v1",
        KINDS,
        validator,
    )];
    fn record(id: &str, entity: &str) -> Record {
        Record {
            record_schema: "test.domain/v1".parse().unwrap(),
            domain: "test.domain".parse().unwrap(),
            kind: "record.made".parse().unwrap(),
            record_id: id.parse().unwrap(),
            entity_id: entity.parse().unwrap(),
            batch_id: "01913f1d-8e2a-7c30-8f4a-426614174099".parse().unwrap(),
            actor: ActorId::parse("test:crash").unwrap(),
            occurred_at: "2026-08-12T13:00:00Z".parse::<RecordTimestamp>().unwrap(),
            recorded_at: "2026-08-12T13:00:01Z".parse::<RecordTimestamp>().unwrap(),
            parents: Vec::new(),
            payload: json!({"ok":true}),
        }
    }
    fn records() -> [Record; 2] {
        [
            record(
                "01913f1d-8e2a-7c30-8f4a-426614174001",
                "123e4567-e89b-42d3-a456-426614174000",
            ),
            record(
                "01913f1d-8e2a-7c30-8f4a-426614174002",
                "123e4567-e89b-42d3-a456-426614174001",
            ),
        ]
    }
    fn fixture_store(label: &str) -> (std::path::PathBuf, DomainRegistry, Store) {
        let root =
            std::env::temp_dir().join(format!("wayjournal-{label}-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        let registry = DomainRegistry::new(DOMAINS).unwrap();
        let store = Store::open_legacy_s1_s2(&root, registry, Arc::new(NoLegacy)).unwrap();
        (root, registry, store)
    }
    fn interrupted(
        label: &str,
    ) -> (
        std::path::PathBuf,
        DomainRegistry,
        Store,
        crate::PreparedBatch,
    ) {
        let (root, registry, store) = fixture_store(label);
        let empty = store.read().unwrap().revision();
        let batch = prepare_batch(&records(), label, &registry).unwrap();
        let mut count = 0;
        assert!(
            append_inner(&store, &batch, empty, &mut |_| {
                count += 1;
                if count == 10 {
                    Err(io::Error::other("stop after journal publication"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        (root, registry, store, batch)
    }
    fn s3_record(domain: &str, kind: &str, id: &str, parents: &[&str], payload: Value) -> Record {
        Record {
            record_schema: format!("{domain}/v1").parse().unwrap(),
            domain: domain.parse().unwrap(),
            kind: kind.parse().unwrap(),
            record_id: id.parse().unwrap(),
            entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010".parse().unwrap(),
            batch_id: "01913f1d-8e2a-7c30-8f4a-426614174099".parse().unwrap(),
            actor: ActorId::parse("test:recovery").unwrap(),
            occurred_at: "2026-08-12T13:00:00Z".parse().unwrap(),
            recorded_at: "2026-08-12T13:00:01Z".parse().unwrap(),
            parents: parents.iter().map(|id| id.parse().unwrap()).collect(),
            payload,
        }
    }
    fn strict_fixture(label: &str) -> (std::path::PathBuf, DomainRegistry, Store) {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-strict-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root).unwrap();
        let registry = crate::wayjournal_domain_registry().unwrap();
        let store = Store::open(&root, registry, Arc::new(NoLegacy)).unwrap();
        let genesis = Record {
            record_schema: "wayjournal.identity/v1".parse().unwrap(),
            domain: "wayjournal.identity".parse().unwrap(),
            kind: "store.genesis".parse().unwrap(),
            record_id: "01913f1d-8e2a-7c30-8f4a-426614174011".parse().unwrap(),
            entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010".parse().unwrap(),
            batch_id: "01913f1d-8e2a-7c30-8f4a-426614174012".parse().unwrap(),
            actor: ActorId::parse("test:recovery").unwrap(),
            occurred_at: "2026-08-12T13:00:00Z".parse().unwrap(),
            recorded_at: "2026-08-12T13:00:01Z".parse().unwrap(),
            parents: vec![],
            payload: json!({"store_kind":"wayjournal.personal","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"}),
        };
        let batch = prepare_batch(&[genesis], &format!("{label}-genesis"), &registry).unwrap();
        store
            .append(&batch, store.read().unwrap().revision())
            .unwrap();
        (root, registry, store)
    }
    #[allow(clippy::too_many_lines)]
    fn recovery_hostiles() -> Vec<(&'static str, Vec<Record>)> {
        let a = "01913f1d-8e2a-7c30-8f4a-426614174041";
        let b = "01913f1d-8e2a-7c30-8f4a-426614174042";
        let c = "01913f1d-8e2a-7c30-8f4a-426614174043";
        let target = json!({"genesis_fingerprint":"3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"});
        let other = json!({"genesis_fingerprint":"3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174020"});
        vec![
            (
                "dangling",
                vec![s3_record(
                    "wayjournal.profile",
                    "profile.display_name.set",
                    a,
                    &[b],
                    json!({"value":"x"}),
                )],
            ),
            (
                "cycle",
                vec![
                    s3_record(
                        "wayjournal.profile",
                        "profile.display_name.set",
                        a,
                        &[b],
                        json!({"value":"a"}),
                    ),
                    s3_record(
                        "wayjournal.profile",
                        "profile.display_name.set",
                        b,
                        &[a],
                        json!({"value":"b"}),
                    ),
                ],
            ),
            (
                "wrong-domain",
                vec![
                    s3_record(
                        "wayjournal.catalog",
                        "catalog.name.set",
                        a,
                        &[],
                        json!({"target":target,"value":"a"}),
                    ),
                    s3_record(
                        "wayjournal.profile",
                        "profile.display_name.set",
                        b,
                        &[a],
                        json!({"value":"b"}),
                    ),
                ],
            ),
            (
                "fake-resolution",
                vec![
                    s3_record(
                        "wayjournal.profile",
                        "profile.display_name.set",
                        a,
                        &[],
                        json!({"value":"a"}),
                    ),
                    s3_record(
                        "wayjournal.profile",
                        "profile.display_name.resolve",
                        b,
                        &[a],
                        json!({"candidates":[a,c],"value":"a"}),
                    ),
                ],
            ),
            (
                "partial-resolution",
                vec![
                    s3_record(
                        "wayjournal.profile",
                        "profile.display_name.set",
                        a,
                        &[],
                        json!({"value":"a"}),
                    ),
                    s3_record(
                        "wayjournal.profile",
                        "profile.display_name.set",
                        b,
                        &[],
                        json!({"value":"b"}),
                    ),
                    s3_record(
                        "wayjournal.profile",
                        "profile.display_name.resolve",
                        c,
                        &[a, b],
                        json!({"candidates":[a],"value":"a"}),
                    ),
                ],
            ),
            (
                "fake-remove",
                vec![
                    s3_record(
                        "wayjournal.profile",
                        "profile.alias.add",
                        a,
                        &[],
                        json!({"key":"me","value":"test:a"}),
                    ),
                    s3_record(
                        "wayjournal.profile",
                        "profile.alias.remove",
                        b,
                        &[a],
                        json!({"adds":[a,c],"key":"me"}),
                    ),
                ],
            ),
            (
                "mixed-target",
                vec![
                    s3_record(
                        "wayjournal.catalog",
                        "catalog.name.set",
                        a,
                        &[],
                        json!({"target":target,"value":"a"}),
                    ),
                    s3_record(
                        "wayjournal.catalog",
                        "catalog.enabled.set",
                        b,
                        &[],
                        json!({"target":other,"value":true}),
                    ),
                ],
            ),
        ]
    }
    #[test]
    fn post_journal_published_recovery_rejects_all_semantic_hostiles_and_cleans_residue() {
        for (label, records) in recovery_hostiles() {
            let (root, registry, store) = strict_fixture(label);
            let prepared = prepare_batch(&records, label, &registry).unwrap();
            stage_batch(
                &store,
                &prepared,
                store.read().unwrap().revision(),
                &mut |_| Ok(()),
            )
            .unwrap();
            assert!(
                matches!(
                    recover_one(&store, prepared.manifest().batch_id(), &mut |_| Ok(())),
                    Err(StoreError::Corrupt {
                        issue: crate::StoreCorruption::InvalidDomainFold { .. }
                    })
                ),
                "{label}"
            );
            assert!(
                fs::read_dir(root.join("journal/batches")).unwrap().count() == 1,
                "{label}"
            );
            assert!(
                fs::read_dir(root.join(".wayjournal-local/recovery"))
                    .unwrap()
                    .next()
                    .is_none(),
                "{label}"
            );
            assert!(
                fs::read_dir(root.join(".wayjournal-local/stages"))
                    .unwrap()
                    .next()
                    .is_none(),
                "{label}"
            );
            assert_eq!(store.read().unwrap().records().len(), 1, "{label}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn collision_reader_is_descriptor_relative_and_expected_plus_one_bounded() {
        let (root, _, store) = fixture_store("collision-bound");
        let source_dir = store.stages_dir.ensure_dir(OsStr::new("source")).unwrap().0;
        let mut source = source_dir.create_file(OsStr::new("value")).unwrap();
        source.write_all(b"expected").unwrap();
        source.sync_all().unwrap();
        let name = OsStr::new("collision.json");
        let mut target = store.recovery_dir.create_file(name).unwrap();
        target.write_all(&vec![b'x'; 1024 * 1024]).unwrap();
        target.sync_all().unwrap();
        assert!(matches!(
            link_fd_no_clobber(&source, &store.recovery_dir, name, b"expected"),
            Err(crate::StoreError::PublicationConflict { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dynamic_stage_recovery_and_target_substitutions_fail_closed_or_stay_anchored() {
        let (root, registry, store) = fixture_store("dynamic-stage-race");
        let empty = store.read().unwrap().revision();
        let batch = prepare_batch(&records(), "dynamic-stage-race", &registry).unwrap();
        let stage = root
            .join(".wayjournal-local/stages")
            .join(batch.manifest().batch_id().to_string());
        let moved = root.join("moved-stage");
        let outside = root.join("outside-stage");
        fs::create_dir(&outside).unwrap();
        let once = Rc::new(Cell::new(false));
        let flag = Rc::clone(&once);
        let guard = crate::store::race_hooks::install(move |point| {
            if point == crate::store::race_hooks::Point::DynamicStage && !flag.replace(true) {
                fs::rename(&stage, &moved).unwrap();
                symlink(&outside, &stage).unwrap();
            }
        });
        assert!(store.append(&batch, empty).is_err());
        assert!(
            fs::read_dir(root.join("outside-stage"))
                .unwrap()
                .next()
                .is_none()
        );
        drop(guard);
        fs::remove_dir_all(root).unwrap();

        let (root, _, store, _) = interrupted("recovery-root-race");
        let recovery = root.join(".wayjournal-local/recovery");
        let moved = root.join("retained-recovery");
        let outside = root.join("outside-recovery");
        fs::create_dir(&outside).unwrap();
        let once = Rc::new(Cell::new(false));
        let flag = Rc::clone(&once);
        let guard = crate::store::race_hooks::install(move |point| {
            if point == crate::store::race_hooks::Point::RecoveryRoot && !flag.replace(true) {
                fs::rename(&recovery, &moved).unwrap();
                symlink(&outside, &recovery).unwrap();
            }
        });
        assert_eq!(store.read().unwrap().records().len(), 2);
        assert!(
            fs::read_dir(root.join("outside-recovery"))
                .unwrap()
                .next()
                .is_none()
        );
        drop(guard);
        fs::remove_dir_all(root).unwrap();

        let (root, _, store, batch) = interrupted("recovery-stage-race");
        let stage = root
            .join(".wayjournal-local/stages")
            .join(batch.manifest().batch_id().to_string());
        let moved = root.join("retained-stage");
        let outside = root.join("outside-recovery-stage");
        fs::create_dir(&outside).unwrap();
        let once = Rc::new(Cell::new(false));
        let flag = Rc::clone(&once);
        let guard = crate::store::race_hooks::install(move |point| {
            if point == crate::store::race_hooks::Point::RecoveryStage && !flag.replace(true) {
                fs::rename(&stage, &moved).unwrap();
                symlink(&outside, &stage).unwrap();
            }
        });
        assert!(store.read().is_err());
        assert!(
            fs::read_dir(root.join("outside-recovery-stage"))
                .unwrap()
                .next()
                .is_none()
        );
        drop(guard);
        fs::remove_dir_all(root).unwrap();

        let (root, _, store, batch) = interrupted("publication-target-race");
        let target = root.join(batch.records()[0].path());
        let target_hook = target.clone();
        let once = Rc::new(Cell::new(false));
        let flag = Rc::clone(&once);
        let guard = crate::store::race_hooks::install(move |point| {
            if point == crate::store::race_hooks::Point::PublicationTarget && !flag.replace(true) {
                fs::create_dir_all(target_hook.parent().unwrap()).unwrap();
                fs::write(&target_hook, b"hostile collision").unwrap();
            }
        });
        assert!(matches!(
            store.read(),
            Err(crate::StoreError::PublicationConflict { .. })
        ));
        assert_eq!(fs::read(target).unwrap(), b"hostile collision");
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_staged_manifest_record_and_recovery_journal_fail_before_allocation() {
        for (label, relative, size) in [
            (
                "large-stage-record",
                "records/00000000.json",
                MAX_RECORD_BYTES + 1,
            ),
            ("large-stage-manifest", "manifest.json", MAX_BATCH_BYTES + 1),
        ] {
            let (root, _, store, batch) = interrupted(label);
            let stage = root
                .join(".wayjournal-local/stages")
                .join(batch.manifest().batch_id().to_string());
            fs::write(stage.join(relative), vec![b'x'; size]).unwrap();
            assert!(matches!(
                store.read(),
                Err(crate::StoreError::InvalidJournal { .. })
            ));
            fs::remove_dir_all(root).unwrap();
        }
        let (root, _, store, batch) = interrupted("large-recovery-journal");
        fs::write(
            root.join(".wayjournal-local/recovery")
                .join(format!("{}.json", batch.manifest().batch_id())),
            vec![b'x'; MAX_JOURNAL_BYTES + 1],
        )
        .unwrap();
        assert!(matches!(
            store.read(),
            Err(crate::StoreError::InvalidJournal { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reduced_limit_append_and_partial_recovery_refuse_before_unreadable_publication() {
        fn limits(entries: usize) -> impl Drop {
            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) {
                    crate::store::TEST_SCAN_LIMITS.set(None);
                }
            }
            crate::store::TEST_SCAN_LIMITS.set(Some(crate::store::ScanLimits {
                entries,
                bytes: 1024 * 1024 * 1024,
            }));
            Reset
        }
        let (root, registry, store) = fixture_store("candidate-limit-append");
        let empty = store.read().unwrap().revision();
        let batch = prepare_batch(&records(), "candidate-limit-append", &registry).unwrap();
        let guard = limits(7);
        assert!(matches!(
            store.append(&batch, empty),
            Err(crate::StoreError::InvalidLayout { .. })
        ));
        assert!(
            fs::read_dir(root.join(".wayjournal-local/stages"))
                .unwrap()
                .next()
                .is_none()
        );
        drop(guard);
        let guard = limits(8);
        store.append(&batch, empty).unwrap();
        assert_eq!(store.read().unwrap().records().len(), 2);
        drop(guard);
        fs::remove_dir_all(root).unwrap();

        let (root, registry, store) = fixture_store("candidate-limit-recovery");
        let empty = store.read().unwrap().revision();
        let batch = prepare_batch(&records(), "candidate-limit-recovery", &registry).unwrap();
        let mut count = 0;
        assert!(
            append_inner(&store, &batch, empty, &mut |_| {
                count += 1;
                if count == 11 {
                    Err(io::Error::other("partial record publication"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        let second = root.join(batch.records()[1].path());
        let guard = limits(7);
        assert!(matches!(
            store.read(),
            Err(crate::StoreError::InvalidLayout { .. })
        ));
        assert!(!second.exists());
        drop(guard);
        let guard = limits(8);
        assert_eq!(store.read().unwrap().records().len(), 2);
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hostile_cleanup_rejects_deep_and_broad_trees_and_unlinks_symlink_and_nonregular() {
        let (root, _, store) = fixture_store("cleanup-deep");
        let mut deep = root.join(".wayjournal-local/stages/deep");
        for _ in 0..=MAX_LOCAL_DEPTH {
            deep.push("d");
        }
        fs::create_dir_all(&deep).unwrap();
        assert!(matches!(
            store.read(),
            Err(crate::StoreError::InvalidJournal { .. })
        ));
        fs::remove_dir_all(root).unwrap();

        let (root, _, store) = fixture_store("cleanup-broad");
        let broad = root.join(".wayjournal-local/stages/broad");
        fs::create_dir(&broad).unwrap();
        for index in 0..=MAX_LOCAL_ENTRIES {
            fs::write(broad.join(format!("{index:05}")), b"").unwrap();
        }
        assert!(matches!(
            store.read(),
            Err(crate::StoreError::InvalidLayout { .. })
        ));
        fs::remove_dir_all(root).unwrap();

        let (root, _, store) = fixture_store("cleanup-nonregular");
        let stage = root.join(".wayjournal-local/stages/nonregular");
        fs::create_dir(&stage).unwrap();
        let outside = root.join("outside");
        fs::write(&outside, b"retained").unwrap();
        symlink(&outside, stage.join("link")).unwrap();
        let short_socket = std::env::temp_dir().join(format!("wjs-{}", uuid::Uuid::now_v7()));
        let socket = UnixListener::bind(&short_socket).unwrap();
        fs::rename(&short_socket, stage.join("socket")).unwrap();
        store.read().unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"retained");
        assert!(!stage.exists());
        drop(socket);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_repeated_durability_barrier_recovers_old_or_complete() {
        let expected = BTreeMap::from([
            (CrashPoint::StageDirectory, 1),
            (CrashPoint::StageRecordsDirectory, 1),
            (CrashPoint::RecordFile, 2),
            (CrashPoint::StageRecords, 1),
            (CrashPoint::ManifestFile, 1),
            (CrashPoint::StageManifest, 1),
            (CrashPoint::JournalFile, 1),
            (CrashPoint::StageJournal, 1),
            (CrashPoint::JournalPublished, 1),
            (CrashPoint::RecordPublished, 2),
            (CrashPoint::ManifestPublished, 1),
            (CrashPoint::JournalRemoved, 1),
            (CrashPoint::StageRemoved, 1),
        ]);
        for stop in 1..=15 {
            let (root, registry, store) = fixture_store(&format!("crash-{stop}"));
            let empty = store.read().unwrap().revision();
            let batch = prepare_batch(&records(), "crash", &registry).unwrap();
            let mut count = 0;
            let mut seen = BTreeMap::new();
            let result = append_inner(&store, &batch, empty, &mut |point| {
                *seen.entry(point).or_insert(0) += 1;
                count += 1;
                if count == stop {
                    Err(io::Error::other("crash"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err());
            let recovered = store.read().unwrap();
            if stop < 10 {
                assert!(recovered.records().is_empty(), "{stop}");
            } else {
                assert_eq!(recovered.records().len(), 2, "{stop}");
                assert_eq!(recovered.manifests().len(), 1, "{stop}");
            }
            if stop == 15 {
                assert_eq!(seen, expected);
            }
            assert!(
                fs::read_dir(root.join(".wayjournal-local/recovery"))
                    .unwrap()
                    .next()
                    .is_none()
            );
            assert!(
                fs::read_dir(root.join(".wayjournal-local/stages"))
                    .unwrap()
                    .next()
                    .is_none()
            );
            fs::remove_dir_all(root).unwrap();
        }
    }
}
