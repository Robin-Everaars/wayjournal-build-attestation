use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read},
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
    sync::{Arc, RwLock, RwLockWriteGuard},
};

use rustix::fs::{self as rfs, AtFlags, Dir, FileType, Mode, OFlags};
use thiserror::Error;

pub(crate) mod bulk;
pub(super) mod streaming;
mod transaction;

#[cfg(test)]
mod race_hooks {
    use std::cell::RefCell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Point {
        RootAnchor,
        ReservedAnchors,
        ScanRoot,
        DynamicStage,
        RecoveryRoot,
        RecoveryStage,
        PublicationTarget,
    }
    type Hook = Box<dyn FnMut(Point)>;
    thread_local! { static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) }; }
    pub struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            HOOK.with(|hook| *hook.borrow_mut() = None);
        }
    }
    pub fn install(hook: impl FnMut(Point) + 'static) -> Guard {
        HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        Guard
    }
    pub fn hit(point: Point) {
        HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(point);
            }
        });
    }
}
#[cfg(test)]
use race_hooks::{Point as RacePoint, hit as race};

use crate::{
    ActorId, BatchError, BatchId, BatchManifest, DomainRegistry, GenesisError, PathClass, Record,
    RecordId, RevisionEntry, StoreIdentity, StoreRevisionRef, StoredMember, classify_path,
    compute_store_revision, decode_batch_manifest, decode_record, validate_batch_ownership,
    validate_store_identity,
};

const LOCAL_DIR: &str = ".wayjournal-local";
const STAGES_DIR: &str = "stages";
const RECOVERY_DIR: &str = "recovery";
const CHECKPOINTS_DIR: &str = "checkpoints";
const ADMISSION_ATTEMPTS_DIR: &str = "admission-attempts";
const SYNC_PENDING_DIR: &str = "sync-pending";
const QUARANTINE_DIR: &str = "quarantine";
/// Maximum bytes supplied for one frozen legacy file.
pub const MAX_LEGACY_FILE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_CANONICAL_ENTRIES: usize = 1_000_000;
pub(crate) const MAX_TOTAL_CANONICAL_BYTES: u64 = 1024 * 1024 * 1024;

/// Counts the canonical file-plus-parent entry set from a sorted file stream.
///
/// Canonical root directories (`events`, `batches`, and `journal`) are store anchors rather than
/// entries. Every other directory prefix is counted once, without retaining the full path set.
pub(crate) struct CanonicalEntryBudget {
    entries: usize,
    previous_file: Option<Vec<u8>>,
}
impl CanonicalEntryBudget {
    pub(crate) const fn new() -> Self {
        Self {
            entries: 0,
            previous_file: None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_entries(entries: usize) -> Self {
        Self {
            entries,
            previous_file: None,
        }
    }

    pub(crate) fn push_sorted_file(&mut self, path: &[u8], limit: usize) -> Result<(), ()> {
        if self
            .previous_file
            .as_deref()
            .is_some_and(|previous| previous >= path)
        {
            return Err(());
        }
        let previous = self.previous_file.as_deref();
        let mut added = 1_usize;
        for (end, _) in path.iter().enumerate().filter(|(_, byte)| **byte == b'/') {
            let parent = &path[..end];
            if matches!(parent, b"events" | b"batches" | b"journal") {
                continue;
            }
            let already_counted = previous.is_some_and(|previous| {
                previous.starts_with(parent) && previous.get(parent.len()) == Some(&b'/')
            });
            if !already_counted {
                added = added.checked_add(1).ok_or(())?;
            }
        }
        self.entries = self.entries.checked_add(added).ok_or(())?;
        if self.entries > limit {
            return Err(());
        }
        self.previous_file = Some(path.to_vec());
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LegacyEntry<'a> {
    path: &'a [u8],
    bytes: &'a [u8],
    class: PathClass,
}
impl<'a> LegacyEntry<'a> {
    pub(crate) const fn new(path: &'a [u8], bytes: &'a [u8], class: PathClass) -> Self {
        Self { path, bytes, class }
    }

    #[must_use]
    pub const fn path(self) -> &'a [u8] {
        self.path
    }
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    #[must_use]
    pub const fn class(self) -> PathClass {
        self.class
    }
}

/// Memory contract requested from a frozen-legacy validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyStreamRequirement {
    /// Compatibility mode may collect entries before calling the frozen validator.
    CompatibleCollecting,
    /// Full S4b capacity must be validated with bounded working memory.
    FullDomainBounded,
}

/// Typed failure returned by the additive legacy streaming contract.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LegacyStreamingError {
    #[error("the legacy adapter does not support bounded full-domain streaming")]
    UnsupportedFullDomain,
    #[error("the legacy entry source failed: {0}")]
    Source(String),
    #[error("legacy validation failed: {0}")]
    Invalid(String),
}

/// Pull source used by object-safe legacy streaming validators.
pub trait LegacyEntrySource {
    /// Returns the next entry. The borrowed entry remains valid until the next call.
    /// # Errors
    /// Returns a stable non-sensitive source error.
    fn next_entry(&mut self) -> Result<Option<LegacyEntry<'_>>, String>;
}

/// Structural validator for the frozen legacy Waytask files.
pub trait LegacyStoreAdapter: std::fmt::Debug + Send + Sync {
    /// Validates the complete frozen legacy set without applying consumer folds.
    /// # Errors
    /// Returns a stable non-sensitive description when invalid.
    fn validate(&self, entries: &[LegacyEntry<'_>]) -> Result<(), String>;

    /// Proves that the requested streaming memory contract is implemented.
    ///
    /// Existing adapters retain source compatibility. They support collecting compatibility
    /// validation but must opt in explicitly before S4b can process the full store domain.
    /// # Errors
    /// Returns [`LegacyStreamingError::UnsupportedFullDomain`] for the default bounded request.
    fn require_streaming(
        &self,
        requirement: LegacyStreamRequirement,
    ) -> Result<(), LegacyStreamingError> {
        match requirement {
            LegacyStreamRequirement::CompatibleCollecting => Ok(()),
            LegacyStreamRequirement::FullDomainBounded => {
                Err(LegacyStreamingError::UnsupportedFullDomain)
            }
        }
    }

    /// Validates frozen legacy entries from an object-safe pull source.
    ///
    /// The compatibility default preserves the exact existing `validate` semantics by collecting
    /// and borrowing the entries. Full-domain validation fails closed even if only the capability
    /// method is overridden; bounded adapters must override this method too.
    /// # Errors
    /// Returns a typed capability, source, or validation failure.
    fn validate_stream(
        &self,
        requirement: LegacyStreamRequirement,
        source: &mut dyn LegacyEntrySource,
    ) -> Result<(), LegacyStreamingError> {
        if requirement == LegacyStreamRequirement::FullDomainBounded {
            return Err(LegacyStreamingError::UnsupportedFullDomain);
        }
        self.require_streaming(requirement)?;
        let mut owned = Vec::<OwnedLegacyEntry>::new();
        while let Some(entry) = source.next_entry().map_err(LegacyStreamingError::Source)? {
            owned.push(OwnedLegacyEntry {
                path: entry.path.to_vec(),
                bytes: entry.bytes.to_vec(),
                class: entry.class,
            });
        }
        let borrowed = owned
            .iter()
            .map(|entry| LegacyEntry {
                path: &entry.path,
                bytes: &entry.bytes,
                class: entry.class,
            })
            .collect::<Vec<_>>();
        self.validate(&borrowed)
            .map_err(LegacyStreamingError::Invalid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreCorruption {
    NonRegularPath {
        path: Vec<u8>,
    },
    InvalidCanonicalPath {
        path: Vec<u8>,
    },
    InvalidManifest {
        path: Vec<u8>,
        message: String,
    },
    InvalidRecord {
        path: Vec<u8>,
        message: String,
    },
    DuplicateGlobalRecordId {
        record_id: RecordId,
        paths: Vec<Vec<u8>>,
    },
    GenericOwnership(BatchError),
    InvalidGenesis(GenesisError),
    InvalidDomainFold {
        domain: String,
        entity: String,
        message: String,
    },
    InvalidLegacy {
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("store lock was poisoned")]
    LockPoisoned,
    #[error("invalid store layout at {path}: {message}")]
    InvalidLayout { path: PathBuf, message: String },
    #[error("store path is on a different filesystem: {path}")]
    CrossDeviceLayout { path: PathBuf },
    #[error("expected store revision {expected:?}, found {actual:?}")]
    RevisionMismatch {
        expected: StoreRevisionRef,
        actual: StoreRevisionRef,
    },
    #[error("recovery base changed from {expected:?} to {actual:?}")]
    RecoveryBaseChanged {
        expected: StoreRevisionRef,
        actual: StoreRevisionRef,
    },
    #[error("invalid recovery journal {path}: {message}")]
    InvalidJournal { path: PathBuf, message: String },
    #[error("immutable publication target conflicts at {path}")]
    PublicationConflict { path: PathBuf },
    #[error("Git synchronization {operation_id} is pending in phase {phase:?}")]
    GitSyncPending {
        operation_id: crate::GitSyncOperationId,
        phase: crate::GitSyncPendingPhase,
    },
    #[error("invalid Git synchronization state: {message}")]
    InvalidGitSyncState { message: String },
    #[error("Git synchronization pending state conflicts with ordinary transaction recovery")]
    ConflictingRecoveryState,
    #[error("injected crash at {point}")]
    InjectedCrash { point: &'static str },
    #[error("batch operation failed: {0}")]
    Batch(#[from] BatchError),
    #[error("store corruption: {issue:?}")]
    Corrupt { issue: StoreCorruption },
}

#[derive(Debug, Error)]
pub enum ExclusiveOperationError {
    #[error("exclusive store operation requires successful recovery")]
    RecoveryRequired,
    #[error("exclusive store operation state was invalidated; recover it before continuing")]
    StateInvalidated,
    #[error("Git synchronization residue appeared during the exclusive store operation")]
    PendingCleanupRequired,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendPreview {
    Publish {
        revision: StoreRevisionRef,
    },
    Replay {
        batch_id: BatchId,
        revision: StoreRevisionRef,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    Published {
        batch_id: BatchId,
        revision: StoreRevisionRef,
    },
    Replay {
        batch_id: BatchId,
        revision: StoreRevisionRef,
    },
}

#[derive(Debug, Clone)]
pub struct StoreSnapshot {
    revision: StoreRevisionRef,
    manifests: Vec<BatchManifest>,
    records: Vec<Record>,
    identity: Option<StoreIdentity>,
    legacy: Vec<OwnedLegacyEntry>,
}
#[derive(Debug, Clone)]
struct OwnedLegacyEntry {
    path: Vec<u8>,
    bytes: Vec<u8>,
    class: PathClass,
}
struct CollectedLegacySource<'a> {
    entries: &'a [OwnedLegacyEntry],
    next: usize,
}
impl LegacyEntrySource for CollectedLegacySource<'_> {
    fn next_entry(&mut self) -> Result<Option<LegacyEntry<'_>>, String> {
        let index = self.next;
        self.next = self.next.saturating_add(1);
        Ok(self.entries.get(index).map(|entry| LegacyEntry {
            path: &entry.path,
            bytes: &entry.bytes,
            class: entry.class,
        }))
    }
}
impl StoreSnapshot {
    #[must_use]
    pub const fn revision(&self) -> StoreRevisionRef {
        self.revision
    }
    #[must_use]
    pub fn manifests(&self) -> &[BatchManifest] {
        &self.manifests
    }
    #[must_use]
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    #[must_use]
    pub const fn identity(&self) -> Option<&StoreIdentity> {
        self.identity.as_ref()
    }
    #[must_use]
    pub fn legacy_entries(&self) -> Vec<LegacyEntry<'_>> {
        self.legacy
            .iter()
            .map(|entry| LegacyEntry {
                path: &entry.path,
                bytes: &entry.bytes,
                class: entry.class,
            })
            .collect()
    }
}

/// Descriptor-only proof of the store root retained by a live exclusive operation.
///
/// The duplicate returned here is derived from the retained inode and does not carry the
/// operation's independently opened flock, so callers cannot unlock the operation through it.
pub struct RetainedStoreRoot<'operation> {
    directory: &'operation Directory,
}
impl RetainedStoreRoot<'_> {
    /// Duplicates the retained root descriptor without ambient path discovery.
    /// # Errors
    /// Returns a store I/O error when the descriptor cannot be duplicated.
    pub fn duplicate_descriptor(&self) -> Result<File, StoreError> {
        self.directory.file.try_clone().map_err(|source| {
            io_error(
                "duplicate retained store root",
                &self.directory.path,
                source,
            )
        })
    }

    /// Reports whether `descriptor` identifies this exact retained root inode.
    /// # Errors
    /// Returns a store I/O error when either descriptor cannot be inspected.
    pub fn is_same_root(&self, descriptor: &File) -> Result<bool, StoreError> {
        Directory::file_is_same(&self.directory.file, descriptor)
    }
}

/// One operation continuously retaining process-local write exclusion and the root-inode flock.
///
/// Acquisition is deliberately not reentrant: beginning a nested operation on the same store
/// blocks according to the underlying write-lock semantics. Call locked methods on this value
/// instead of reacquiring through [`Store`].
pub struct ExclusiveStoreOperation<'store> {
    pub(super) guard: UnsnapshottedExclusive<'store>,
    pub(super) snapshot: Option<StoreSnapshot>,
    pub(super) recovered: bool,
    pub(super) invalidated: bool,
}

/// Bounded recovery residue observed under a live exclusive retained-root lock.
///
/// The private lifetime binding prevents this observation from outliving the operation whose
/// retained descriptors and lock authority produced it.
#[derive(Debug)]
#[non_exhaustive]
pub struct ExclusiveRecoveryObservation<'operation> {
    pub(super) batch_ids: Vec<BatchId>,
    pub(super) git_cleanup_required: bool,
    pub(super) _operation: std::marker::PhantomData<&'operation ()>,
}
impl ExclusiveRecoveryObservation<'_> {
    /// Returns the sorted, unique ordinary transaction batch IDs.
    #[must_use]
    pub fn batch_ids(&self) -> &[BatchId] {
        &self.batch_ids
    }

    /// Reports whether disposable Git synchronization residue requires cleanup by recovery.
    #[must_use]
    pub const fn git_cleanup_required(&self) -> bool {
        self.git_cleanup_required
    }
}

/// A validated snapshot held under the retained root-directory inode lock.
pub struct ExclusiveSnapshot<'store> {
    operation: ExclusiveStoreOperation<'store>,
}
impl ExclusiveSnapshot<'_> {
    /// # Panics
    /// Panics only if the private constructor violates its recovered-operation invariant.
    #[must_use]
    pub const fn snapshot(&self) -> &StoreSnapshot {
        match self.operation.snapshot.as_ref() {
            Some(snapshot) => snapshot,
            None => panic!("exclusive snapshot invariant violated"),
        }
    }
}

/// Exclusive retained-root lock acquired before any canonical filesystem scan.
pub(super) struct UnsnapshottedExclusive<'a> {
    store: &'a Store,
    _file_guard: File,
    _local_guard: RwLockWriteGuard<'a, ()>,
}
impl UnsnapshottedExclusive<'_> {
    pub(crate) const fn store(&self) -> &Store {
        self.store
    }

    pub(super) fn recover_transactions(&self) -> Result<(), StoreError> {
        transaction::recover_locked_default(self.store)
    }

    pub(super) fn scan_visible_locked(&self) -> Result<StoreSnapshot, StoreError> {
        scan_visible(self.store)
    }

    pub(super) fn validate_visible_s4b_locked(
        &self,
    ) -> Result<streaming::ValidatedStoreState, StoreError> {
        validate_visible_s4b(self.store)
    }

    pub(super) fn validate_visible_s4b_for_record_locked(
        &self,
        record_id: RecordId,
    ) -> Result<
        (
            streaming::ValidatedStoreState,
            Option<streaming::ValidatedRecordSubject>,
        ),
        StoreError,
    > {
        validate_visible_s4b_for_record(self.store, record_id)
    }
}

/// Retained directory descriptor. All descendants are opened one component at a time with
/// `openat(O_NOFOLLOW)` and checked with `fstat`, so renames cannot redirect an operation.
#[derive(Debug)]
pub(super) struct Directory {
    file: File,
    pub path: PathBuf,
    device: u64,
}

pub(super) enum OpenedEntry {
    Directory(Directory),
    Regular(File),
}

impl Directory {
    fn from_file(
        path: PathBuf,
        file: File,
        expected_device: Option<u64>,
    ) -> Result<Self, StoreError> {
        let stat = rfs::fstat(&file)
            .map_err(|error| io_error("inspect directory descriptor", &path, error.into()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(invalid_layout(
                &path,
                "descriptor is not an ordinary directory",
            ));
        }
        let device = device_id(stat.st_dev, &path)?;
        if expected_device.is_some_and(|expected| expected != device) {
            return Err(StoreError::CrossDeviceLayout { path });
        }
        Ok(Self { file, path, device })
    }
    pub(crate) fn open_ambient(path: &Path) -> Result<Self, StoreError> {
        let fd = rfs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| io_error("open store root", path, error.into()))?;
        Self::from_file(path.to_owned(), File::from(fd), None)
    }
    pub fn open_dir(&self, name: &OsStr) -> Result<Self, StoreError> {
        self.open_dir_with_device(name, Some(self.device))
    }
    pub(super) fn open_dir_any_device(&self, name: &OsStr) -> Result<Self, StoreError> {
        self.open_dir_with_device(name, None)
    }
    fn open_dir_with_device(
        &self,
        name: &OsStr,
        expected_device: Option<u64>,
    ) -> Result<Self, StoreError> {
        validate_component(name, &self.path)?;
        let fd = rfs::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            io_error(
                "open directory component",
                &self.path.join(name),
                error.into(),
            )
        })?;
        Self::from_file(self.path.join(name), File::from(fd), expected_device)
    }
    pub(super) fn open_entry(&self, name: &OsStr) -> Result<OpenedEntry, StoreError> {
        validate_component(name, &self.path)?;
        let fd = rfs::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| io_error("open directory entry", &self.path.join(name), error.into()))?;
        let file = File::from(fd);
        let stat = rfs::fstat(&file).map_err(|error| {
            io_error(
                "inspect directory entry descriptor",
                &self.path.join(name),
                error.into(),
            )
        })?;
        if device_id(stat.st_dev, &self.path.join(name))? != self.device {
            return Err(StoreError::CrossDeviceLayout {
                path: self.path.join(name),
            });
        }
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => Self::from_file(self.path.join(name), file, Some(self.device))
                .map(OpenedEntry::Directory),
            FileType::RegularFile => Ok(OpenedEntry::Regular(file)),
            _ => Err(invalid_layout(
                &self.path.join(name),
                "path is not an ordinary file or directory",
            )),
        }
    }
    pub fn ensure_dir(&self, name: &OsStr) -> Result<(Self, bool), StoreError> {
        validate_component(name, &self.path)?;
        let mut created = false;
        match rfs::mkdirat(&self.file, name, Mode::RWXU) {
            Ok(()) => {
                created = true;
                rfs::chmodat(&self.file, name, Mode::RWXU, AtFlags::empty()).map_err(|error| {
                    io_error(
                        "set directory component mode",
                        &self.path.join(name),
                        error.into(),
                    )
                })?;
            }
            Err(rustix::io::Errno::EXIST) => {
                if self.kind(name)? != FileType::Directory {
                    return Err(invalid_layout(
                        &self.path.join(name),
                        "reserved path is not an ordinary directory",
                    ));
                }
            }
            Err(error) => {
                return Err(io_error(
                    "create directory component",
                    &self.path.join(name),
                    error.into(),
                ));
            }
        }
        Ok((self.open_dir(name)?, created))
    }
    pub fn open_file(&self, name: &OsStr) -> Result<File, StoreError> {
        validate_component(name, &self.path)?;
        let fd = rfs::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            io_error(
                "open regular file component",
                &self.path.join(name),
                error.into(),
            )
        })?;
        let file = File::from(fd);
        self.require_regular(&file, name)?;
        Ok(file)
    }
    pub fn create_file(&self, name: &OsStr) -> Result<File, StoreError> {
        validate_component(name, &self.path)?;
        let fd = rfs::openat(
            &self.file,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| {
            io_error(
                "create regular file component",
                &self.path.join(name),
                error.into(),
            )
        })?;
        let file = File::from(fd);
        rfs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|error| {
            io_error(
                "set regular file component mode",
                &self.path.join(name),
                error.into(),
            )
        })?;
        Ok(file)
    }
    #[cfg(target_os = "linux")]
    pub fn temporary_file(&self) -> Result<File, StoreError> {
        let display = self.path.join("<temporary>");
        let fd = rfs::openat(
            &self.file,
            OsStr::new("."),
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| io_error("create unnamed temporary file", &display, error.into()))?;
        let file = File::from(fd);
        rfs::fchmod(&file, Mode::RUSR | Mode::WUSR)
            .map_err(|error| io_error("set unnamed temporary file mode", &display, error.into()))?;
        Ok(file)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn temporary_file(&self) -> Result<File, StoreError> {
        Err(io_error(
            "create unnamed temporary file",
            &self.path.join("<temporary>"),
            io::Error::new(
                io::ErrorKind::Unsupported,
                "secure unnamed temporary staging requires Linux O_TMPFILE",
            ),
        ))
    }

    pub fn require_regular(&self, file: &File, name: &OsStr) -> Result<u64, StoreError> {
        let stat = rfs::fstat(file).map_err(|error| {
            io_error(
                "inspect regular file descriptor",
                &self.path.join(name),
                error.into(),
            )
        })?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(invalid_layout(
                &self.path.join(name),
                "path is not an ordinary regular file",
            ));
        }
        if device_id(stat.st_dev, &self.path.join(name))? != self.device {
            return Err(StoreError::CrossDeviceLayout {
                path: self.path.join(name),
            });
        }
        Ok(stat.st_size.max(0).cast_unsigned())
    }
    pub fn for_each_name(
        &self,
        limit: usize,
        mut visit: impl FnMut(&[u8]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let mut dir = Dir::read_from(&self.file)
            .map_err(|error| io_error("read directory descriptor", &self.path, error.into()))?;
        let mut count = 0_usize;
        while let Some(entry) = dir.read() {
            let entry = entry
                .map_err(|error| io_error("read directory entry", &self.path, error.into()))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid_layout(&self.path, "directory entry count overflow"))?;
            if count > limit {
                return Err(invalid_layout(
                    &self.path,
                    "directory exceeds entry-count limit",
                ));
            }
            visit(name)?;
        }
        Ok(())
    }
    pub fn bounded_names(&self, limit: usize) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut names = Vec::new();
        self.for_each_name(limit, |name| {
            names.push(name.to_vec());
            Ok(())
        })?;
        names.sort();
        Ok(names)
    }
    /// Returns at most `limit` names without allocating for the rest of a large directory.
    pub fn name_batch(&self, limit: usize) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut dir = Dir::read_from(&self.file)
            .map_err(|error| io_error("read directory descriptor", &self.path, error.into()))?;
        let mut names = Vec::with_capacity(limit.min(4_096));
        while names.len() < limit {
            let Some(entry) = dir.read() else { break };
            let entry = entry
                .map_err(|error| io_error("read directory entry", &self.path, error.into()))?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
        names.sort();
        Ok(names)
    }
    pub fn kind(&self, name: &OsStr) -> Result<FileType, StoreError> {
        validate_component(name, &self.path)?;
        let stat = rfs::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
            io_error(
                "inspect directory entry",
                &self.path.join(name),
                error.into(),
            )
        })?;
        if device_id(stat.st_dev, &self.path.join(name))? != self.device {
            return Err(StoreError::CrossDeviceLayout {
                path: self.path.join(name),
            });
        }
        Ok(FileType::from_raw_mode(stat.st_mode))
    }
    pub fn sync(&self) -> Result<(), StoreError> {
        rfs::fsync(&self.file)
            .map_err(|error| io_error("sync directory descriptor", &self.path, error.into()))
    }
    pub fn unlink_file(&self, name: &OsStr) -> Result<(), StoreError> {
        rfs::unlinkat(&self.file, name, AtFlags::empty())
            .map_err(|error| io_error("unlink file", &self.path.join(name), error.into()))
    }
    pub fn unlink_dir(&self, name: &OsStr) -> Result<(), StoreError> {
        rfs::unlinkat(&self.file, name, AtFlags::REMOVEDIR)
            .map_err(|error| io_error("unlink directory", &self.path.join(name), error.into()))
    }
    pub fn rename_file(&self, old: &OsStr, new: &OsStr) -> Result<(), StoreError> {
        validate_component(old, &self.path)?;
        validate_component(new, &self.path)?;
        rfs::renameat(&self.file, old, &self.file, new)
            .map_err(|error| io_error("replace local file", &self.path.join(new), error.into()))
    }
    pub fn file(&self) -> &File {
        &self.file
    }
    pub(crate) fn try_clone(&self) -> Result<Self, StoreError> {
        let file = self
            .file
            .try_clone()
            .map_err(|source| io_error("clone retained directory", &self.path, source))?;
        Self::from_file(self.path.clone(), file, Some(self.device))
    }
    pub fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }
    pub fn child_proc_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.file.as_raw_fd()
        ))
    }
    pub(super) fn identity_key(&self) -> Result<(u64, u64), StoreError> {
        let stat = rfs::fstat(&self.file)
            .map_err(|error| io_error("inspect retained directory", &self.path, error.into()))?;
        Ok((device_id(stat.st_dev, &self.path)?, stat.st_ino as u64))
    }
    pub(super) fn same_identity(&self, other: &Self) -> Result<bool, StoreError> {
        let left = rfs::fstat(&self.file)
            .map_err(|error| io_error("inspect retained directory", &self.path, error.into()))?;
        let right = rfs::fstat(&other.file)
            .map_err(|error| io_error("inspect retained directory", &other.path, error.into()))?;
        Ok(left.st_dev == right.st_dev && left.st_ino == right.st_ino)
    }
    pub(super) fn same_authority(&self, other: &Self) -> Result<bool, StoreError> {
        let left = rfs::fstat(&self.file)
            .map_err(|error| io_error("inspect retained directory", &self.path, error.into()))?;
        let right = rfs::fstat(&other.file)
            .map_err(|error| io_error("inspect retained directory", &other.path, error.into()))?;
        Ok(left.st_dev == right.st_dev && left.st_uid == right.st_uid)
    }
    pub(super) fn file_same_authority(&self, file: &File) -> Result<bool, StoreError> {
        let directory = rfs::fstat(&self.file)
            .map_err(|error| io_error("inspect retained directory", &self.path, error.into()))?;
        let candidate = rfs::fstat(file)
            .map_err(|error| io_error("inspect retained file", &self.path, error.into()))?;
        Ok(directory.st_dev == candidate.st_dev && directory.st_uid == candidate.st_uid)
    }
    pub(super) fn file_identity_key(file: &File) -> Result<(u64, u64), StoreError> {
        let stat = rfs::fstat(file)
            .map_err(|error| io_error("inspect retained file", Path::new("."), error.into()))?;
        Ok((device_id(stat.st_dev, Path::new("."))?, stat.st_ino as u64))
    }
    pub(super) fn file_is_same(left: &File, right: &File) -> Result<bool, StoreError> {
        Ok(Self::file_identity_key(left)? == Self::file_identity_key(right)?)
    }
    pub fn entry_is(&self, name: &OsStr, child: &Self) -> Result<bool, StoreError> {
        validate_component(name, &self.path)?;
        let entry = rfs::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
            io_error(
                "inspect retained directory entry",
                &self.path.join(name),
                error.into(),
            )
        })?;
        let retained = rfs::fstat(&child.file).map_err(|error| {
            io_error(
                "inspect retained directory descriptor",
                &child.path,
                error.into(),
            )
        })?;
        Ok(entry.st_dev == retained.st_dev
            && entry.st_ino == retained.st_ino
            && FileType::from_raw_mode(entry.st_mode) == FileType::Directory)
    }
    pub(crate) fn file_entry_is(&self, name: &OsStr, file: &File) -> Result<bool, StoreError> {
        validate_component(name, &self.path)?;
        let entry = rfs::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
            io_error(
                "inspect retained file entry",
                &self.path.join(name),
                error.into(),
            )
        })?;
        let retained = rfs::fstat(file).map_err(|error| {
            io_error(
                "inspect retained file descriptor",
                &self.path.join(name),
                error.into(),
            )
        })?;
        Ok(entry.st_dev == retained.st_dev
            && entry.st_ino == retained.st_ino
            && FileType::from_raw_mode(entry.st_mode) == FileType::RegularFile)
    }
    pub fn lock_file(&self) -> Result<File, StoreError> {
        let fd = rfs::openat(
            &self.file,
            OsStr::new("."),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            io_error(
                "open independent root lock descriptor",
                &self.path,
                error.into(),
            )
        })?;
        Ok(File::from(fd))
    }
}

fn validate_component(name: &OsStr, path: &Path) -> Result<(), StoreError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(invalid_layout(
            path,
            "invalid descriptor-relative path component",
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub struct Store {
    pub(super) root: PathBuf,
    registry: DomainRegistry,
    legacy: Arc<dyn LegacyStoreAdapter>,
    local_lock: Arc<RwLock<()>>,
    pub(super) root_dir: Arc<Directory>,
    pub(super) events_dir: Arc<Directory>,
    pub(super) batches_dir: Arc<Directory>,
    pub(super) journal_dir: Arc<Directory>,
    pub(super) records_dir: Arc<Directory>,
    pub(super) journal_batches_dir: Arc<Directory>,
    pub(super) stages_dir: Arc<Directory>,
    pub(super) recovery_dir: Arc<Directory>,
    pub(super) checkpoints_dir: Arc<Directory>,
    pub(super) admission_attempts_dir: Arc<Directory>,
    pub(super) sync_pending_dir: Arc<Directory>,
    pub(super) quarantine_dir: Arc<Directory>,
    strict_domains: bool,
}
impl Store {
    pub(super) fn require_legacy_streaming(
        &self,
        requirement: LegacyStreamRequirement,
    ) -> Result<(), LegacyStreamingError> {
        self.legacy.require_streaming(requirement)
    }

    pub(super) fn validate_legacy_stream(
        &self,
        requirement: LegacyStreamRequirement,
        source: &mut dyn LegacyEntrySource,
    ) -> Result<(), StoreError> {
        self.legacy
            .validate_stream(requirement, source)
            .map_err(|error| StoreError::Corrupt {
                issue: StoreCorruption::InvalidLegacy {
                    message: error.to_string(),
                },
            })
    }

    /// Opens or initializes a store. Cooperative processes lock the retained store-root inode.
    /// Names below that inode may be renamed by an attacker without redirecting in-flight work.
    /// The caller is responsible for binding the ambient root pathname to the intended store;
    /// replacing that binding creates a distinct store and is outside cooperative serialization.
    /// # Errors
    /// Fails closed for symlinks, non-directories, cross-device descendants, or malformed state.
    pub fn open(
        root: impl Into<PathBuf>,
        registry: DomainRegistry,
        legacy: Arc<dyn LegacyStoreAdapter>,
    ) -> Result<Self, StoreError> {
        Self::open_strict(root, registry, legacy)
    }

    /// Opens an S1/S2 compatibility store. It refuses any S3 built-in domain data.
    /// # Errors
    /// Fails for invalid layout or if S3 data is visible.
    pub fn open_legacy_s1_s2(
        root: impl Into<PathBuf>,
        registry: DomainRegistry,
        legacy: Arc<dyn LegacyStoreAdapter>,
    ) -> Result<Self, StoreError> {
        let store = Self::open_mode(&root.into(), registry, legacy, false)?;
        store.read()?;
        Ok(store)
    }

    /// Opens an S3 strict store with mandatory sealed identity/profile/catalog invariants.
    /// # Errors
    /// Fails when built-ins are absent or for the same reasons as [`Store::open`].
    pub fn open_strict(
        root: impl Into<PathBuf>,
        registry: DomainRegistry,
        legacy: Arc<dyn LegacyStoreAdapter>,
    ) -> Result<Self, StoreError> {
        Self::require_strict_builtins(&registry)?;
        Self::open_mode(&root.into(), registry, legacy, true)
    }

    /// Opens an S3 strict store from an already retained directory descriptor.
    /// The descriptor is `fstat`-validated and becomes the root-lock authority;
    /// every reserved child derives descriptor-relatively. `diagnostic_path` is
    /// never an authority: it is never created or canonicalized, store access
    /// never reopens it, and renaming the real root cannot redirect the store.
    /// One caveat for callers: when the root is a linked Git worktree, Git
    /// federation resolves these bytes ambiently and then requires the result
    /// to still name the retained root inode, failing closed when it does not.
    /// # Errors
    /// Fails when the descriptor is not an ordinary directory, cannot be
    /// synchronized, or cannot yield an independent read-only root-lock
    /// descriptor; when built-ins are absent; or for the same layout reasons as
    /// [`Store::open_strict`].
    pub fn open_strict_retained_root(
        root: File,
        diagnostic_path: PathBuf,
        registry: DomainRegistry,
        legacy: Arc<dyn LegacyStoreAdapter>,
    ) -> Result<Self, StoreError> {
        Self::require_strict_builtins(&registry)?;
        let root_dir = Arc::new(Directory::from_file(diagnostic_path.clone(), root, None)?);
        // `fstat` alone accepts descriptors the store can never operate through:
        // an `O_PATH` handle is a legal `mkdirat` target but cannot be synced,
        // and a root without read permission cannot yield the root-lock
        // descriptor every read takes. Refuse both here, while the reserved
        // layout still does not exist, rather than after creating it.
        root_dir.sync()?;
        drop(root_dir.lock_file()?);
        Self::open_from_root(diagnostic_path, root_dir, registry, legacy, true)
    }

    fn require_strict_builtins(registry: &DomainRegistry) -> Result<(), StoreError> {
        if !registry.has_sealed_builtins()
            || !registry.supports("wayjournal.identity", crate::IDENTITY_SCHEMA_V1)
            || !registry.supports("wayjournal.profile", crate::PROFILE_SCHEMA_V1)
            || !registry.supports("wayjournal.catalog", crate::CATALOG_SCHEMA_V1)
        {
            return Err(invalid_layout(
                Path::new("."),
                "strict store requires sealed identity/profile/catalog v1 built-ins",
            ));
        }
        Ok(())
    }

    fn open_mode(
        requested: &Path,
        registry: DomainRegistry,
        legacy: Arc<dyn LegacyStoreAdapter>,
        strict_domains: bool,
    ) -> Result<Self, StoreError> {
        create_root_durable(requested)?;
        let root = fs::canonicalize(requested)
            .map_err(|source| io_error("canonicalize store root", requested, source))?;
        let root_dir = Arc::new(Directory::open_ambient(&root)?);
        Self::open_from_root(root, root_dir, registry, legacy, strict_domains)
    }

    fn open_from_root(
        root: PathBuf,
        root_dir: Arc<Directory>,
        registry: DomainRegistry,
        legacy: Arc<dyn LegacyStoreAdapter>,
        strict_domains: bool,
    ) -> Result<Self, StoreError> {
        #[cfg(test)]
        race(RacePoint::RootAnchor);
        let (events, _) = root_dir.ensure_dir(OsStr::new("events"))?;
        let (batches, _) = root_dir.ensure_dir(OsStr::new("batches"))?;
        let (journal, _) = root_dir.ensure_dir(OsStr::new("journal"))?;
        let (records, _) = journal.ensure_dir(OsStr::new("records"))?;
        let (journal_batches, _) = journal.ensure_dir(OsStr::new("batches"))?;
        let (local, _) = root_dir.ensure_dir(OsStr::new(LOCAL_DIR))?;
        let (stages, _) = local.ensure_dir(OsStr::new(STAGES_DIR))?;
        let (recovery, _) = local.ensure_dir(OsStr::new(RECOVERY_DIR))?;
        let (checkpoints, _) = local.ensure_dir(OsStr::new(CHECKPOINTS_DIR))?;
        let (admission_attempts, _) = local.ensure_dir(OsStr::new(ADMISSION_ATTEMPTS_DIR))?;
        let (sync_pending, _) = local.ensure_dir(OsStr::new(SYNC_PENDING_DIR))?;
        let (quarantine, _) = local.ensure_dir(OsStr::new(QUARANTINE_DIR))?;
        #[cfg(test)]
        race(RacePoint::ReservedAnchors);
        for directory in [
            &records,
            &journal_batches,
            &stages,
            &recovery,
            &checkpoints,
            &admission_attempts,
            &sync_pending,
            &quarantine,
        ] {
            directory.sync()?;
        }
        journal.sync()?;
        local.sync()?;
        root_dir.sync()?;
        Ok(Self {
            root,
            registry,
            legacy,
            local_lock: Arc::new(RwLock::new(())),
            root_dir,
            events_dir: Arc::new(events),
            batches_dir: Arc::new(batches),
            journal_dir: Arc::new(journal),
            records_dir: Arc::new(records),
            journal_batches_dir: Arc::new(journal_batches),
            stages_dir: Arc::new(stages),
            recovery_dir: Arc::new(recovery),
            checkpoints_dir: Arc::new(checkpoints),
            admission_attempts_dir: Arc::new(admission_attempts),
            sync_pending_dir: Arc::new(sync_pending),
            quarantine_dir: Arc::new(quarantine),
            strict_domains,
        })
    }
    /// Recovers local residue and returns a validated snapshot.
    /// # Errors
    /// Returns layout, I/O, recovery, codec, or ownership failures.
    pub fn read(&self) -> Result<StoreSnapshot, StoreError> {
        loop {
            let needs_exclusive = {
                let _local = self
                    .local_lock
                    .read()
                    .map_err(|_| StoreError::LockPoisoned)?;
                let lock = self.root_dir.lock_file()?;
                lock.lock_shared()
                    .map_err(|source| io_error("acquire shared root lock", &self.root, source))?;
                match crate::federation::pending::gate_without_git(self)? {
                    crate::federation::pending::GateAction::Allow => {
                        if !self.has_residue()? {
                            return scan_visible(self);
                        }
                        true
                    }
                    crate::federation::pending::GateAction::CleanDisposable => true,
                }
            };
            if needs_exclusive {
                let mut operation = self.begin_exclusive_operation()?;
                transaction::recover_operation(&mut operation)?;
            }
        }
    }
    pub(super) fn lock_exclusive_unsnapshotted(
        &self,
    ) -> Result<UnsnapshottedExclusive<'_>, StoreError> {
        let local_guard = self
            .local_lock
            .write()
            .map_err(|_| StoreError::LockPoisoned)?;
        let file_guard = self.root_dir.lock_file()?;
        file_guard
            .lock()
            .map_err(|source| io_error("acquire exclusive root lock", &self.root, source))?;
        Ok(UnsnapshottedExclusive {
            store: self,
            _file_guard: file_guard,
            _local_guard: local_guard,
        })
    }

    /// Begins an exclusive operation before recovery or canonical scanning.
    ///
    /// The operation continuously holds the process-local write guard and an independently
    /// opened flock on the retained root inode. It is intentionally non-reentrant; use its
    /// locked methods rather than calling another store entry point while it is live.
    /// # Errors
    /// Returns locking or retained-descriptor failures.
    pub fn begin_exclusive_operation(&self) -> Result<ExclusiveStoreOperation<'_>, StoreError> {
        Ok(ExclusiveStoreOperation {
            guard: self.lock_exclusive_unsnapshotted()?,
            snapshot: None,
            recovered: false,
            invalidated: false,
        })
    }

    /// Returns a validated snapshot while holding the exclusive retained-root lock.
    /// # Errors
    /// Returns locking, recovery, or scan failures.
    pub fn exclusive_snapshot(&self) -> Result<ExclusiveSnapshot<'_>, StoreError> {
        transaction::exclusive_snapshot(self)
    }

    /// Creates a local presence proof from the current durable checkpoint and canonical snapshot.
    ///
    /// The checkpoint is read while the retained-root exclusive lock is held. Its identity and
    /// revision must equal the validated snapshot and requested subject, and the requested record
    /// must be present at that subject. The caller supplies only provenance time, never trust,
    /// remote/ref approval, checkpoint identity, or revision authority.
    ///
    /// # Errors
    /// Fails closed for pending/recovery state, missing or malformed checkpoint authority,
    /// identity/revision disagreement, an absent record, or a record/subject mismatch.
    pub fn verified_proof(
        &self,
        subject: &crate::QualifiedEntityRef,
        record_id: RecordId,
        observed_at: crate::RecordTimestamp,
    ) -> Result<crate::VerifiedProof, crate::ProofError> {
        let guard = self.lock_exclusive_unsnapshotted()?;
        crate::federation::pending::clean_disposable_locked(self)?;
        if crate::federation::pending::gate_without_git(self)?
            != crate::federation::pending::GateAction::Allow
        {
            return Err(StoreError::InvalidGitSyncState {
                message: "disposable pending cleanup did not converge".to_owned(),
            }
            .into());
        }
        guard.recover_transactions()?;
        let checkpoint = crate::federation::admission_checkpoint_locked(&guard)?
            .ok_or(crate::ProofError::MissingCheckpoint)?;
        let (snapshot, record_subject) = guard.validate_visible_s4b_for_record_locked(record_id)?;
        let identity = snapshot
            .identity()
            .ok_or(crate::ProofError::MissingIdentity)?;
        if checkpoint.logical_store_id() != identity.logical_id()
            || checkpoint.logical_store_id() != &subject.store
        {
            return Err(crate::ProofError::IdentityMismatch);
        }
        if checkpoint.accepted_revision() != snapshot.revision() {
            return Err(crate::ProofError::RevisionMismatch);
        }
        let record_subject = record_subject.ok_or(crate::ProofError::RecordNotFound)?;
        if record_subject.domain != subject.domain || record_subject.entity_id != subject.entity_id
        {
            return Err(crate::ProofError::SubjectMismatch);
        }
        Ok(crate::VerifiedProof::from_checkpoint(
            subject.clone(),
            record_id,
            checkpoint.accepted_revision(),
            *checkpoint.local_trust_binding(),
            observed_at,
        ))
    }

    /// Publishes one prepared generic batch at exactly `expected`.
    /// # Errors
    /// Returns stale revision, collision, recovery, validation, or I/O failures.
    pub fn append(
        &self,
        prepared: &crate::PreparedBatch,
        expected: StoreRevisionRef,
    ) -> Result<CommitOutcome, StoreError> {
        transaction::append(self, prepared, expected)
    }
    fn has_residue(&self) -> Result<bool, StoreError> {
        self.has_transaction_residue_locked()
    }

    pub(crate) fn has_transaction_residue_locked(&self) -> Result<bool, StoreError> {
        fn nonempty(directory: &Directory) -> Result<bool, StoreError> {
            let mut found = false;
            directory.for_each_name(MAX_CANONICAL_ENTRIES, |_| {
                found = true;
                Ok(())
            })?;
            Ok(found)
        }
        Ok(nonempty(&self.recovery_dir)? || nonempty(&self.stages_dir)?)
    }
}
fn create_root_durable(path: &Path) -> Result<(), StoreError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|source| io_error("resolve current directory", path, source))?
            .join(path)
    };
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    while fs::symlink_metadata(existing).is_err() {
        let name = existing
            .file_name()
            .ok_or_else(|| invalid_layout(path, "store root has no existing ancestor"))?;
        missing.push(name.to_os_string());
        existing = existing
            .parent()
            .ok_or_else(|| invalid_layout(path, "store root escaped filesystem root"))?;
    }
    let mut parent = Directory::open_ambient(existing)?;
    for name in missing.iter().rev() {
        let (child, created) = parent.ensure_dir(name)?;
        if !created {
            return Err(invalid_layout(
                &child.path,
                "store root component raced with creation",
            ));
        }
        child.sync()?;
        parent.sync()?;
        parent = child;
    }
    if missing.is_empty() {
        parent.sync()?;
    }
    Ok(())
}
pub(super) fn invalid_layout(path: &Path, message: &str) -> StoreError {
    StoreError::InvalidLayout {
        path: path.to_owned(),
        message: message.to_owned(),
    }
}
fn device_id(device: impl TryInto<u64>, path: &Path) -> Result<u64, StoreError> {
    device
        .try_into()
        .map_err(|_| invalid_layout(path, "negative filesystem device identifier"))
}
pub(super) fn io_error(operation: &'static str, path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

#[derive(Clone)]
pub(super) struct RawFile {
    pub path: Vec<u8>,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Copy)]
struct ScanLimits {
    entries: usize,
    bytes: u64,
}
const DEFAULT_SCAN_LIMITS: ScanLimits = ScanLimits {
    entries: MAX_CANONICAL_ENTRIES,
    bytes: MAX_TOTAL_CANONICAL_BYTES,
};
#[cfg(test)]
thread_local! { static TEST_SCAN_LIMITS: std::cell::Cell<Option<ScanLimits>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
fn active_scan_limits() -> ScanLimits {
    TEST_SCAN_LIMITS
        .with(std::cell::Cell::get)
        .unwrap_or(DEFAULT_SCAN_LIMITS)
}
#[cfg(not(test))]
const fn active_scan_limits() -> ScanLimits {
    DEFAULT_SCAN_LIMITS
}
struct ScanBudget {
    limits: ScanLimits,
    entries: usize,
    bytes: u64,
}
impl ScanBudget {
    fn entry(&mut self, path: &Path) -> Result<(), StoreError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| invalid_layout(path, "canonical entry count overflow"))?;
        if self.entries > self.limits.entries {
            return Err(invalid_layout(
                path,
                "canonical store exceeds entry-count limit",
            ));
        }
        Ok(())
    }
    fn reserve_bytes(&mut self, length: u64, path: &Path) -> Result<(), StoreError> {
        let remaining = self.limits.bytes.saturating_sub(self.bytes);
        if length > remaining {
            return Err(invalid_layout(
                path,
                "canonical store exceeds aggregate-byte limit",
            ));
        }
        self.bytes += length;
        Ok(())
    }
}
pub(super) fn collect_visible(store: &Store) -> Result<(Vec<RawFile>, Vec<Vec<u8>>), StoreError> {
    let (files, nonregular, _) = collect_visible_inventory(store, active_scan_limits())?;
    Ok((files, nonregular))
}
type VisibleInventory = (
    Vec<RawFile>,
    Vec<Vec<u8>>,
    std::collections::BTreeSet<Vec<u8>>,
);
pub(super) fn visible_inventory(store: &Store) -> Result<VisibleInventory, StoreError> {
    collect_visible_inventory(store, active_scan_limits())
}
#[cfg(test)]
fn collect_visible_with_limits(
    store: &Store,
    limits: ScanLimits,
) -> Result<(Vec<RawFile>, Vec<Vec<u8>>), StoreError> {
    let (files, nonregular, _) = collect_visible_inventory(store, limits)?;
    Ok((files, nonregular))
}
fn collect_visible_inventory(
    store: &Store,
    limits: ScanLimits,
) -> Result<VisibleInventory, StoreError> {
    #[cfg(test)]
    race(RacePoint::ScanRoot);
    let mut files = Vec::new();
    let mut nonregular = Vec::new();
    let mut inventory = std::collections::BTreeSet::new();
    let mut budget = ScanBudget {
        limits,
        entries: 0,
        bytes: 0,
    };
    for (directory, prefix) in [
        (&*store.batches_dir, b"batches".as_slice()),
        (&*store.events_dir, b"events".as_slice()),
        (&*store.journal_dir, b"journal".as_slice()),
    ] {
        collect_directory(
            directory,
            prefix,
            &mut files,
            &mut nonregular,
            &mut inventory,
            &mut budget,
        )?;
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    nonregular.sort();
    Ok((files, nonregular, inventory))
}
pub(super) fn enforce_limits<'a>(
    files: impl IntoIterator<Item = (&'a [u8], usize)>,
    nonregular: impl IntoIterator<Item = &'a [u8]>,
    existing: impl IntoIterator<Item = &'a Vec<u8>>,
) -> Result<(), StoreError> {
    let files = files.into_iter().collect::<Vec<_>>();
    let mut entries = existing
        .into_iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for (path, _) in &files {
        add_entry_and_canonical_parents(&mut entries, path);
    }
    for path in nonregular {
        add_entry_and_canonical_parents(&mut entries, path);
    }
    let limits = active_scan_limits();
    if entries.len() > limits.entries {
        return Err(invalid_layout(
            Path::new("."),
            "canonical store exceeds entry-count limit",
        ));
    }
    let total = files.iter().try_fold(0_u64, |total, (_, length)| {
        total.checked_add(u64::try_from(*length).ok()?)
    });
    if total.is_none_or(|total| total > limits.bytes) {
        return Err(invalid_layout(
            Path::new("."),
            "canonical store exceeds aggregate-byte limit",
        ));
    }
    Ok(())
}
fn add_entry_and_canonical_parents(entries: &mut std::collections::BTreeSet<Vec<u8>>, path: &[u8]) {
    entries.insert(path.to_vec());
    let mut end = path.len();
    while let Some(slash) = path[..end].iter().rposition(|byte| *byte == b'/') {
        let parent = &path[..slash];
        if parent == b"events" || parent == b"batches" || parent == b"journal" {
            break;
        }
        entries.insert(parent.to_vec());
        end = slash;
    }
}
fn collect_directory(
    directory: &Directory,
    prefix: &[u8],
    files: &mut Vec<RawFile>,
    nonregular: &mut Vec<Vec<u8>>,
    inventory: &mut std::collections::BTreeSet<Vec<u8>>,
    budget: &mut ScanBudget,
) -> Result<(), StoreError> {
    directory.for_each_name(
        budget.limits.entries.saturating_sub(budget.entries),
        |name| {
            budget.entry(&directory.path)?;
            let component = OsStr::from_bytes(name);
            let mut relative = prefix.to_vec();
            relative.push(b'/');
            relative.extend(name);
            inventory.insert(relative.clone());
            match directory.kind(component)? {
                FileType::Directory if valid_canonical_directory(&relative) => {
                    let child = directory.open_dir(component)?;
                    collect_directory(&child, &relative, files, nonregular, inventory, budget)?;
                }
                FileType::Directory => files.push(RawFile {
                    path: relative,
                    bytes: Vec::new(),
                }),
                FileType::RegularFile => {
                    let limit = match classify_path(&relative) {
                        PathClass::JournalRecord => crate::MAX_RECORD_BYTES,
                        PathClass::JournalBatch => crate::MAX_BATCH_BYTES,
                        PathClass::LegacyEvent | PathClass::LegacyBatch => MAX_LEGACY_FILE_BYTES,
                        PathClass::InvalidReserved | PathClass::NonCanonical => 0,
                    };
                    let file = directory.open_file(component)?;
                    let length = directory.require_regular(&file, component)?;
                    if length > limit as u64 {
                        return Err(invalid_layout(
                            &directory.path.join(component),
                            "canonical file exceeds its byte limit",
                        ));
                    }
                    budget.reserve_bytes(length, &directory.path.join(component))?;
                    let bytes = read_file_bounded(
                        file.try_clone().map_err(|source| {
                            io_error(
                                "clone visible file descriptor",
                                &directory.path.join(component),
                                source,
                            )
                        })?,
                        limit,
                        &directory.path.join(component),
                    )?;
                    let stable_length = directory.require_regular(&file, component)?;
                    if stable_length != length || stable_length != bytes.len() as u64 {
                        return Err(invalid_layout(
                            &directory.path.join(component),
                            "canonical file changed while being scanned",
                        ));
                    }
                    files.push(RawFile {
                        path: relative,
                        bytes,
                    });
                }
                _ => nonregular.push(relative),
            }
            Ok(())
        },
    )
}
fn valid_canonical_directory(path: &[u8]) -> bool {
    let Ok(path) = std::str::from_utf8(path) else {
        return false;
    };
    let parts = path.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["events", entity] => uuid::Uuid::parse_str(entity).is_ok_and(|id| {
            entity == &id.hyphenated().to_string()
                && !id.is_nil()
                && id.get_variant() == uuid::Variant::RFC4122
                && [4, 5, 7].contains(&id.get_version_num())
        }),
        ["journal", "records" | "batches"] => true,
        ["journal", "records", domain] => domain.parse::<crate::DomainId>().is_ok(),
        ["journal", "records", domain, entity] => {
            domain.parse::<crate::DomainId>().is_ok() && entity.parse::<crate::EntityId>().is_ok()
        }
        _ => false,
    }
}
pub(super) fn read_file_bounded(
    mut file: File,
    limit: usize,
    path: &Path,
) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    (&mut file)
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read descriptor", path, source))?;
    if bytes.len() > limit {
        return Err(invalid_layout(path, "file exceeds byte limit"));
    }
    Ok(bytes)
}
fn canonical_file_limit(class: PathClass) -> Option<usize> {
    match class {
        PathClass::LegacyEvent | PathClass::LegacyBatch => Some(MAX_LEGACY_FILE_BYTES),
        PathClass::JournalRecord => Some(crate::MAX_RECORD_BYTES),
        PathClass::JournalBatch => Some(crate::MAX_BATCH_BYTES),
        PathClass::InvalidReserved | PathClass::NonCanonical => None,
    }
}

fn reserve_streamed_visible_bytes(total: &mut u64, length: usize) -> Result<(), StoreError> {
    *total = total
        .checked_add(
            u64::try_from(length)
                .map_err(|_| invalid_layout(Path::new("."), "canonical byte count exceeds u64"))?,
        )
        .ok_or_else(|| invalid_layout(Path::new("."), "canonical byte count overflow"))?;
    if *total > MAX_TOTAL_CANONICAL_BYTES {
        return Err(invalid_layout(
            Path::new("."),
            "canonical store exceeds aggregate-byte limit",
        ));
    }
    Ok(())
}

fn validate_visible_s4b(store: &Store) -> Result<streaming::ValidatedStoreState, StoreError> {
    let replay = visible_s4b_replay(store)?;
    streaming::validate_bounded_replay(store, &replay)
}

fn validate_visible_s4b_for_record(
    store: &Store,
    record_id: RecordId,
) -> Result<
    (
        streaming::ValidatedStoreState,
        Option<streaming::ValidatedRecordSubject>,
    ),
    StoreError,
> {
    let replay = visible_s4b_replay(store)?;
    streaming::validate_bounded_replay_for_record(store, &replay, record_id)
}

fn visible_s4b_replay(store: &Store) -> Result<streaming::CanonicalReplay, StoreError> {
    #[cfg(test)]
    race(RacePoint::ScanRoot);
    let mut builder = streaming::replay_builder(store)?;
    let mut budget = ScanBudget {
        limits: active_scan_limits(),
        entries: 0,
        bytes: 0,
    };
    for (directory, prefix) in [
        (&*store.batches_dir, b"batches".as_slice()),
        (&*store.events_dir, b"events".as_slice()),
        (&*store.journal_dir, b"journal".as_slice()),
    ] {
        spool_visible_replay_directory(directory, prefix, &mut builder, &mut budget)?;
    }
    builder.finish()
}

fn spool_visible_replay_directory(
    directory: &Directory,
    prefix: &[u8],
    builder: &mut streaming::CanonicalReplayBuilder<'_>,
    budget: &mut ScanBudget,
) -> Result<(), StoreError> {
    directory.for_each_name(
        budget.limits.entries.saturating_sub(budget.entries),
        |name| {
            budget.entry(&directory.path)?;
            let component = OsStr::from_bytes(name);
            let mut relative = prefix.to_vec();
            relative.push(b'/');
            relative.extend(name);
            match directory.kind(component)? {
                FileType::Directory if valid_canonical_directory(&relative) => {
                    let child = directory.open_dir(component)?;
                    spool_visible_replay_directory(&child, &relative, builder, budget)?;
                }
                FileType::RegularFile => {
                    let Some(limit) = canonical_file_limit(classify_path(&relative)) else {
                        return Err(StoreError::Corrupt {
                            issue: StoreCorruption::InvalidCanonicalPath { path: relative },
                        });
                    };
                    let file = directory.open_file(component)?;
                    let length = directory.require_regular(&file, component)?;
                    if length > limit as u64 {
                        return Err(invalid_layout(
                            &directory.path.join(component),
                            "canonical file exceeds its byte limit",
                        ));
                    }
                    budget.reserve_bytes(length, &directory.path.join(component))?;
                    let bytes = read_file_bounded(
                        file.try_clone().map_err(|source| {
                            io_error(
                                "clone visible replay descriptor",
                                &directory.path.join(component),
                                source,
                            )
                        })?,
                        limit,
                        &directory.path.join(component),
                    )?;
                    let stable_length = directory.require_regular(&file, component)?;
                    if stable_length != length || stable_length != bytes.len() as u64 {
                        return Err(invalid_layout(
                            &directory.path.join(component),
                            "canonical file changed while being replayed",
                        ));
                    }
                    builder.push(RawFile {
                        path: relative,
                        bytes,
                    })?;
                }
                FileType::Directory => {
                    return Err(StoreError::Corrupt {
                        issue: StoreCorruption::InvalidCanonicalPath { path: relative },
                    });
                }
                _ => {
                    return Err(StoreError::Corrupt {
                        issue: StoreCorruption::NonRegularPath { path: relative },
                    });
                }
            }
            Ok(())
        },
    )
}

pub(super) fn scan_visible(store: &Store) -> Result<StoreSnapshot, StoreError> {
    let (files, nonregular) = collect_visible(store)?;
    scan_collected(store, &files, nonregular)
}
enum DecodedFile {
    Manifest(BatchManifest),
    Record(Record),
    Legacy(OwnedLegacyEntry),
}

fn decode_visible_file(
    file: &RawFile,
    registry: &DomainRegistry,
) -> Result<DecodedFile, StoreError> {
    match classify_path(&file.path) {
        PathClass::JournalBatch => {
            let manifest =
                decode_batch_manifest(&file.bytes).map_err(|error| StoreError::Corrupt {
                    issue: StoreCorruption::InvalidManifest {
                        path: file.path.clone(),
                        message: error.to_string(),
                    },
                })?;
            if manifest.canonical_path().as_bytes() != file.path {
                return Err(invalid_canonical_file(file));
            }
            Ok(DecodedFile::Manifest(manifest))
        }
        PathClass::JournalRecord => {
            let record =
                decode_record(&file.bytes, registry).map_err(|error| StoreError::Corrupt {
                    issue: StoreCorruption::InvalidRecord {
                        path: file.path.clone(),
                        message: error.to_string(),
                    },
                })?;
            if record.canonical_path().as_bytes() != file.path {
                return Err(invalid_canonical_file(file));
            }
            Ok(DecodedFile::Record(record))
        }
        class @ (PathClass::LegacyBatch | PathClass::LegacyEvent) => {
            Ok(DecodedFile::Legacy(OwnedLegacyEntry {
                path: file.path.clone(),
                bytes: file.bytes.clone(),
                class,
            }))
        }
        PathClass::InvalidReserved | PathClass::NonCanonical => Err(invalid_canonical_file(file)),
    }
}

fn invalid_canonical_file(file: &RawFile) -> StoreError {
    StoreError::Corrupt {
        issue: StoreCorruption::InvalidCanonicalPath {
            path: file.path.clone(),
        },
    }
}

fn validate_builtin_folds<'a>(
    records: impl IntoIterator<Item = &'a Record>,
) -> Result<(), StoreError> {
    let mut grouped = BTreeMap::<(String, String), Vec<crate::DomainOperation>>::new();
    for record in records {
        if !matches!(
            record.domain.as_str(),
            "wayjournal.profile" | "wayjournal.catalog"
        ) {
            continue;
        }
        let operation = crate::DomainOperation::try_from(record.clone()).map_err(|error| {
            StoreError::Corrupt {
                issue: StoreCorruption::InvalidDomainFold {
                    domain: record.domain.to_string(),
                    entity: record.entity_id.to_string(),
                    message: error.to_string(),
                },
            }
        })?;
        grouped
            .entry((record.domain.to_string(), record.entity_id.to_string()))
            .or_default()
            .push(operation);
    }
    for ((domain, entity), operations) in grouped {
        let result = if domain == "wayjournal.profile" {
            crate::fold_profile(&operations).map(|_| ())
        } else {
            crate::fold_catalogs(&operations).map(|_| ())
        };
        result.map_err(|error| StoreError::Corrupt {
            issue: StoreCorruption::InvalidDomainFold {
                domain,
                entity,
                message: error.to_string(),
            },
        })?;
    }
    Ok(())
}

fn validate_global_idempotency(manifests: &[BatchManifest]) -> Result<(), StoreError> {
    let mut owners = BTreeMap::<(ActorId, String), Vec<BatchId>>::new();
    for manifest in manifests {
        owners
            .entry((
                manifest.actor().clone(),
                manifest.idempotency_key_digest().to_string(),
            ))
            .or_default()
            .push(manifest.batch_id());
    }
    if let Some((_, batch_ids)) = owners
        .into_iter()
        .find(|(_, batch_ids)| batch_ids.len() > 1)
    {
        return Err(StoreError::Corrupt {
            issue: StoreCorruption::GenericOwnership(BatchError::DuplicateIdempotencyOwnership {
                batch_ids,
            }),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn scan_collected(
    store: &Store,
    files: &[RawFile],
    nonregular: Vec<Vec<u8>>,
) -> Result<StoreSnapshot, StoreError> {
    scan_collected_with_legacy_mode(
        store,
        files,
        nonregular,
        LegacyScanMode::Validate(LegacyStreamRequirement::CompatibleCollecting),
    )
}

#[derive(Clone, Copy)]
enum LegacyScanMode {
    Validate(LegacyStreamRequirement),
}

fn scan_collected_with_legacy_mode(
    store: &Store,
    files: &[RawFile],
    nonregular: Vec<Vec<u8>>,
    legacy_mode: LegacyScanMode,
) -> Result<StoreSnapshot, StoreError> {
    if let Some(path) = nonregular.into_iter().next() {
        return Err(StoreError::Corrupt {
            issue: StoreCorruption::NonRegularPath { path },
        });
    }
    let mut manifests = Vec::new();
    let mut records_by_path = BTreeMap::<Vec<u8>, (Record, Vec<u8>)>::new();
    let mut ids = BTreeMap::<RecordId, Vec<Vec<u8>>>::new();
    let mut legacy = Vec::new();
    for file in files {
        match decode_visible_file(file, &store.registry)? {
            DecodedFile::Manifest(manifest) => manifests.push(manifest),
            DecodedFile::Record(record) => {
                ids.entry(record.record_id)
                    .or_default()
                    .push(file.path.clone());
                records_by_path.insert(file.path.clone(), (record, file.bytes.clone()));
            }
            DecodedFile::Legacy(entry) => legacy.push(entry),
        }
    }
    if let Some((record_id, mut paths)) = ids.into_iter().find(|(_, paths)| paths.len() > 1) {
        paths.sort();
        return Err(StoreError::Corrupt {
            issue: StoreCorruption::DuplicateGlobalRecordId { record_id, paths },
        });
    }
    // Canonical manifest-path order defines publication order; UUIDv7 provides the
    // immutable sortable batch identity used by the first-batch genesis invariant.
    manifests.sort_by_key(BatchManifest::batch_id);
    validate_global_idempotency(&manifests)?;
    let stored = records_by_path
        .iter()
        .map(|(path, (_, bytes))| StoredMember::new(path, bytes))
        .collect::<Vec<_>>();
    let refs = manifests.iter().collect::<Vec<_>>();
    validate_batch_ownership(&stored, &refs, &store.registry).map_err(|error| {
        StoreError::Corrupt {
            issue: StoreCorruption::GenericOwnership(error),
        }
    })?;
    if !store.strict_domains
        && records_by_path.values().any(|(record, _)| {
            matches!(
                record.domain.as_str(),
                "wayjournal.identity" | "wayjournal.profile" | "wayjournal.catalog"
            )
        })
    {
        return Err(StoreError::Corrupt {
            issue: StoreCorruption::InvalidDomainFold {
                domain: "wayjournal.reserved".to_owned(),
                entity: "legacy-s1-s2".to_owned(),
                message: "S3 built-in data cannot be opened in legacy mode".to_owned(),
            },
        });
    }
    let identity = if store.strict_domains {
        let identity =
            validate_store_identity(&manifests, &stored, &store.registry).map_err(|error| {
                StoreError::Corrupt {
                    issue: StoreCorruption::InvalidGenesis(error),
                }
            })?;
        validate_builtin_folds(records_by_path.values().map(|(record, _)| record))?;
        identity
    } else {
        None
    };
    let revision = resolve_scanned_revision(store, files, &legacy, legacy_mode)?;
    Ok(StoreSnapshot {
        revision,
        manifests,
        records: records_by_path
            .into_values()
            .map(|(record, _)| record)
            .collect(),
        identity,
        legacy,
    })
}

fn resolve_scanned_revision(
    store: &Store,
    files: &[RawFile],
    legacy: &[OwnedLegacyEntry],
    mode: LegacyScanMode,
) -> Result<StoreRevisionRef, StoreError> {
    match mode {
        LegacyScanMode::Validate(requirement) => {
            validate_collected_legacy(store, legacy, requirement)?;
            compute_store_revision(
                files
                    .iter()
                    .map(|file| RevisionEntry::regular(file.path.clone(), file.bytes.clone())),
            )
            .map_err(|error| StoreError::Corrupt {
                issue: StoreCorruption::InvalidCanonicalPath {
                    path: error.to_string().into_bytes(),
                },
            })
        }
    }
}

fn validate_collected_legacy(
    store: &Store,
    legacy: &[OwnedLegacyEntry],
    requirement: LegacyStreamRequirement,
) -> Result<(), StoreError> {
    match requirement {
        LegacyStreamRequirement::CompatibleCollecting => {
            let borrowed = legacy
                .iter()
                .map(|entry| LegacyEntry {
                    path: &entry.path,
                    bytes: &entry.bytes,
                    class: entry.class,
                })
                .collect::<Vec<_>>();
            store
                .legacy
                .validate(&borrowed)
                .map_err(|message| StoreError::Corrupt {
                    issue: StoreCorruption::InvalidLegacy { message },
                })
        }
        LegacyStreamRequirement::FullDomainBounded => {
            let mut source = CollectedLegacySource {
                entries: legacy,
                next: 0,
            };
            store
                .legacy
                .validate_stream(requirement, &mut source)
                .map_err(|error| StoreError::Corrupt {
                    issue: StoreCorruption::InvalidLegacy {
                        message: error.to_string(),
                    },
                })
        }
    }
}

#[cfg(test)]
mod s4b_lock_tests {
    use super::*;
    use crate::{LegacyEntry, LegacyStoreAdapter, wayjournal_domain_registry};
    use std::{fs, sync::Arc};

    #[derive(Debug)]
    struct NoLegacy;
    impl LegacyStoreAdapter for NoLegacy {
        fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn legacy_streaming_default_preserves_validate_and_rejects_full_domain() {
        #[derive(Debug)]
        struct RejectOne;
        impl LegacyStoreAdapter for RejectOne {
            fn validate(&self, entries: &[LegacyEntry<'_>]) -> Result<(), String> {
                if entries.len() == 1 {
                    Err("one entry rejected".to_owned())
                } else {
                    Ok(())
                }
            }
        }

        struct OneEntrySource {
            emitted: bool,
            path: Vec<u8>,
            bytes: Vec<u8>,
        }
        impl crate::LegacyEntrySource for OneEntrySource {
            fn next_entry(&mut self) -> Result<Option<LegacyEntry<'_>>, String> {
                if self.emitted {
                    return Ok(None);
                }
                self.emitted = true;
                Ok(Some(LegacyEntry {
                    path: &self.path,
                    bytes: &self.bytes,
                    class: PathClass::LegacyBatch,
                }))
            }
        }

        let adapter = RejectOne;
        let mut source = OneEntrySource {
            emitted: false,
            path: b"batches/01913f1d-8e2a-7c30-8f4a-426614174012.json".to_vec(),
            bytes: b"legacy".to_vec(),
        };
        assert_eq!(
            adapter.validate_stream(
                crate::LegacyStreamRequirement::CompatibleCollecting,
                &mut source,
            ),
            Err(crate::LegacyStreamingError::Invalid(
                "one entry rejected".to_owned()
            ))
        );
        assert_eq!(
            adapter.require_streaming(crate::LegacyStreamRequirement::FullDomainBounded),
            Err(crate::LegacyStreamingError::UnsupportedFullDomain)
        );
    }

    #[test]
    fn full_domain_default_cannot_be_enabled_by_capability_only() {
        #[derive(Debug)]
        struct CapabilityOnly;
        impl LegacyStoreAdapter for CapabilityOnly {
            fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
                Ok(())
            }

            fn require_streaming(
                &self,
                _: crate::LegacyStreamRequirement,
            ) -> Result<(), crate::LegacyStreamingError> {
                Ok(())
            }
        }

        struct EmptySource;
        impl crate::LegacyEntrySource for EmptySource {
            fn next_entry(&mut self) -> Result<Option<LegacyEntry<'_>>, String> {
                Ok(None)
            }
        }

        assert_eq!(
            CapabilityOnly.validate_stream(
                crate::LegacyStreamRequirement::FullDomainBounded,
                &mut EmptySource,
            ),
            Err(crate::LegacyStreamingError::UnsupportedFullDomain)
        );
    }

    #[test]
    fn unsnapshotted_lock_does_not_scan_partial_store() {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-s4b-unsnapshotted-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root).expect("root");
        let store = Store::open(
            &root,
            wayjournal_domain_registry().expect("registry"),
            Arc::new(NoLegacy),
        )
        .expect("store");
        fs::write(root.join("journal/batches/not-canonical.json"), b"partial")
            .expect("partial prefix");
        let guard = store
            .lock_exclusive_unsnapshotted()
            .expect("lock without scan");
        assert!(guard.scan_visible_locked().is_err());
        drop(guard);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn store_retains_s4b_local_directories() {
        let root =
            std::env::temp_dir().join(format!("wayjournal-s4b-retained-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).expect("root");
        let store = Store::open(
            &root,
            wayjournal_domain_registry().expect("registry"),
            Arc::new(NoLegacy),
        )
        .expect("store");
        assert!(store.sync_pending_dir.path.ends_with("sync-pending"));
        assert!(store.quarantine_dir.path.ends_with("quarantine"));
        store.sync_pending_dir.sync().expect("pending sync");
        store.quarantine_dir.sync().expect("quarantine sync");
        fs::remove_dir_all(root).expect("cleanup");
    }
}

#[cfg(test)]
mod hostile_tests {
    use super::{
        LegacyEntry, LegacyEntrySource, LegacyStoreAdapter, LegacyStreamRequirement,
        LegacyStreamingError, ScanLimits, Store, StoreError, collect_visible_with_limits,
        race_hooks, validate_visible_s4b,
    };
    use crate::{DomainRegistry, RevisionEntry, compute_store_revision};
    use std::{
        fs,
        os::unix::fs::symlink,
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    #[derive(Debug)]
    struct AcceptLegacy;
    impl LegacyStoreAdapter for AcceptLegacy {
        fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
            Ok(())
        }
    }
    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "wayjournal-hostile-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&path).unwrap();
        path
    }
    fn open(path: &Path) -> Store {
        Store::open_legacy_s1_s2(
            path,
            DomainRegistry::new(&[]).unwrap(),
            Arc::new(AcceptLegacy),
        )
        .unwrap()
    }

    #[test]
    fn streamed_scan_reads_the_enumerated_inode_after_namespace_replacement() {
        const ENTITY: &str = "123e4567-e89b-42d3-a456-426614174000";
        const RECORD: &str = "01913f1d-8e2a-7c30-8f4a-426614174099.json";

        #[derive(Debug)]
        struct ReplacingLegacy {
            root: PathBuf,
            replaced: AtomicBool,
        }
        impl LegacyStoreAdapter for ReplacingLegacy {
            fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
                Ok(())
            }

            fn require_streaming(
                &self,
                _: LegacyStreamRequirement,
            ) -> Result<(), LegacyStreamingError> {
                Ok(())
            }

            fn validate_stream(
                &self,
                _: LegacyStreamRequirement,
                source: &mut dyn LegacyEntrySource,
            ) -> Result<(), LegacyStreamingError> {
                if !self.replaced.swap(true, Ordering::SeqCst) {
                    fs::rename(
                        self.root.join(format!("events/{ENTITY}")),
                        self.root.join("enumerated-entity"),
                    )
                    .map_err(|error| LegacyStreamingError::Invalid(error.to_string()))?;
                    let replacement = self.root.join(format!("events/{ENTITY}"));
                    fs::create_dir(&replacement)
                        .map_err(|error| LegacyStreamingError::Invalid(error.to_string()))?;
                    fs::write(replacement.join(RECORD), b"replacement")
                        .map_err(|error| LegacyStreamingError::Invalid(error.to_string()))?;
                }
                while source
                    .next_entry()
                    .map_err(LegacyStreamingError::Source)?
                    .is_some()
                {}
                Ok(())
            }
        }

        let root = root("streamed-binding");
        let adapter = Arc::new(ReplacingLegacy {
            root: root.clone(),
            replaced: AtomicBool::new(false),
        });
        let store =
            Store::open_legacy_s1_s2(&root, DomainRegistry::new(&[]).unwrap(), adapter).unwrap();
        let entity = root.join(format!("events/{ENTITY}"));
        fs::create_dir(&entity).unwrap();
        fs::write(entity.join(RECORD), b"original").unwrap();
        let path = format!("events/{ENTITY}/{RECORD}").into_bytes();
        let expected = compute_store_revision([RevisionEntry::regular(path, b"original")])
            .expect("original revision");

        let snapshot = validate_visible_s4b(&store).expect("streamed snapshot");

        assert_eq!(snapshot.revision(), expected);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn traversal_budgets_count_nonregular_before_collection_and_bytes_before_allocation() {
        let count_root = root("count-budget");
        let store = open(&count_root);
        let outside = count_root.join("outside");
        fs::write(&outside, b"x").unwrap();
        symlink(&outside, count_root.join("events/one")).unwrap();
        symlink(&outside, count_root.join("events/two")).unwrap();
        assert!(matches!(
            collect_visible_with_limits(
                &store,
                ScanLimits {
                    entries: 1,
                    bytes: 100
                }
            ),
            Err(StoreError::InvalidLayout { .. })
        ));
        fs::remove_dir_all(count_root).unwrap();

        let byte_root = root("byte-budget");
        let store = open(&byte_root);
        fs::write(
            byte_root.join("batches/01913f1d-8e2a-7c30-8f4a-426614174099.json"),
            b"four",
        )
        .unwrap();
        assert!(matches!(
            collect_visible_with_limits(
                &store,
                ScanLimits {
                    entries: 10,
                    bytes: 3
                }
            ),
            Err(StoreError::InvalidLayout { .. })
        ));
        fs::remove_dir_all(byte_root).unwrap();
    }

    #[test]
    fn root_and_reserved_substitution_hooks_cannot_redirect_descriptors() {
        let root_path = root("root-race");
        let moved = root_path.with_extension("retained");
        let hook_root = root_path.clone();
        let hook_moved = moved.clone();
        let guard = race_hooks::install(move |point| {
            if point == race_hooks::Point::RootAnchor {
                fs::rename(&hook_root, &hook_moved).unwrap();
                fs::create_dir(&hook_root).unwrap();
                fs::write(hook_root.join("hostile"), b"outside").unwrap();
            }
        });
        let store = open(&root_path);
        store.read().unwrap();
        assert!(moved.join("journal/records").is_dir());
        drop(guard);
        drop(store);
        fs::remove_dir_all(&root_path).unwrap();
        fs::remove_dir_all(&moved).unwrap();

        let root_path = root("reserved-race");
        let hook_root = root_path.clone();
        let guard = race_hooks::install(move |point| {
            if point == race_hooks::Point::ReservedAnchors {
                let journal = hook_root.join("journal");
                let retained = hook_root.join("retained-journal");
                fs::rename(&journal, &retained).unwrap();
                fs::create_dir(&journal).unwrap();
                fs::write(journal.join("hostile"), b"outside").unwrap();
            }
        });
        let store = open(&root_path);
        store.read().unwrap();
        assert!(root_path.join("retained-journal/records").is_dir());
        drop(guard);
        drop(store);
        fs::remove_dir_all(root_path).unwrap();

        let root_path = root("scan-race");
        let store = open(&root_path);
        let journal = root_path.join("journal");
        let retained = root_path.join("retained-scan-journal");
        let outside = root_path.join("outside-scan");
        fs::create_dir(&outside).unwrap();
        let guard = race_hooks::install(move |point| {
            if point == race_hooks::Point::ScanRoot && journal.exists() {
                fs::rename(&journal, &retained).unwrap();
                symlink(&outside, &journal).unwrap();
            }
        });
        store.read().unwrap();
        assert!(
            root_path
                .join("outside-scan")
                .read_dir()
                .unwrap()
                .next()
                .is_none()
        );
        drop(guard);
        drop(store);
        fs::remove_dir_all(root_path).unwrap();
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod non_linux_tests {
    use super::{Directory, StoreError};
    use std::{fs, io};

    #[test]
    fn secure_unnamed_temporary_staging_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-non-linux-temporary-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root).expect("create test directory");
        let directory = Directory::open_ambient(&root).expect("open test directory");

        let error = directory
            .temporary_file()
            .expect_err("non-Linux must not substitute a named temporary file");
        match error {
            StoreError::Io {
                operation,
                path,
                source,
            } => {
                assert_eq!(operation, "create unnamed temporary file");
                assert_eq!(path, root.join("<temporary>"));
                assert_eq!(source.kind(), io::ErrorKind::Unsupported);
                assert_eq!(
                    source.to_string(),
                    "secure unnamed temporary staging requires Linux O_TMPFILE"
                );
            }
            other => panic!("unexpected error: {other}"),
        }

        drop(directory);
        fs::remove_dir_all(&root).expect("remove test directory");
    }
}
