use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use rustix::fs::{self as rfs, FileType, Mode};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    LogicalStoreId, ProofId, RevisionVector, RevisionVectorEntry, Store, StoreRevisionRef,
    VerifiedProof, decode_revision_vector, decode_verified_proof, encode_revision_vector,
    encode_verified_proof,
    json::{decode_strict, encode_pretty},
    store::{Directory, StoreError, UnsnapshottedExclusive},
};

/// Closed schema identifier for one disposable projection-cache entry.
pub const PROJECTION_CACHE_ENTRY_SCHEMA_V1: &str = "wayjournal.projection-cache-entry/v1";
/// Maximum encoded bytes in one cache entry.
pub const MAX_PROOF_CACHE_ENTRY_BYTES: usize = 64 * 1024;
/// Maximum number of final entries in one cache root.
pub const MAX_PROOF_CACHE_ENTRIES: usize = 16_384;
/// Maximum aggregate encoded bytes in one cache root.
pub const MAX_PROOF_CACHE_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

const FINAL_SUFFIX: &str = ".json";
const TEMP_PREFIX: &str = ".wayjournal-cache-tmp-";

/// One durable local dependency authority.
///
/// The handle selects a store. It never supplies or relabels a current revision.
#[derive(Clone)]
pub struct DependencyStore<'a> {
    pub expected_store: LogicalStoreId,
    pub store: &'a Store,
}

/// Result of exact-id cache lookup.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofCacheLookup {
    Hit(VerifiedProof),
    Miss,
    Stale,
    Reset,
    Unavailable,
}

/// Result of publishing an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofCacheInsert {
    Inserted,
    AlreadyPresent,
}

/// Best-effort cache invalidation disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofCacheDisposition {
    Unchanged,
    Invalidated,
    Reset,
    Unavailable,
}

/// Typed cache construction, input, authority, and publication failures.
#[derive(Debug, Error)]
pub enum ProofCacheError {
    #[error("invalid cache path: {0}")]
    InvalidPath(String),
    #[error("cache filesystem operation failed: {0}")]
    Io(String),
    #[error(
        "cache root must be an effective-user-owned mode-0700 directory on its parent's device"
    )]
    InvalidRoot,
    #[error("cache root ambient binding was reset")]
    Reset,
    #[error("dependency authorities exceed the 256-store limit")]
    TooManyAuthorities,
    #[error("dependency authorities must be strictly ordered and unique by expected store")]
    InvalidAuthorityOrder,
    #[error("dependency authorities contain physically aliased retained store roots")]
    AliasedAuthorityRoots,
    #[error("a dependency authority aliases the retained cache root")]
    CacheAuthorityAlias,
    #[error("durable dependency checkpoint authority is unavailable: {0}")]
    AuthorityUnavailable(String),
    #[error("proof source dependency is absent, duplicated, or disagrees with its source revision")]
    InvalidSourceDependency,
    #[error("the proof source revision is not current under locked durable checkpoint authority")]
    StaleProof,
    #[error("cache entry exceeds the 64-KiB limit")]
    EntryTooLarge,
    #[error("cache layout is unavailable: {0}")]
    InvalidLayout(String),
}

/// A hostile-safe, disposable exact-id projection cache.
///
/// The parent and root directory descriptors and root identity are retained for the lifetime of
/// this value. Every public operation reopens the ambient basename before and after descriptor-
/// relative work. Cache data has no journal, checkpoint, trust, or durability authority.
#[derive(Debug)]
pub struct ProofCache {
    parent: Directory,
    basename: OsString,
    root: Directory,
    root_identity: (u64, u64),
    reset: AtomicBool,
    local_lock: Mutex<()>,
}

impl ProofCache {
    /// Opens an existing secure cache root or creates one securely.
    ///
    /// # Errors
    /// Rejects a missing basename, symlink/non-directory root, cross-device root, wrong owner or
    /// mode, or descriptor-safe filesystem failure.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ProofCacheError> {
        let path = path.as_ref();
        let basename = path
            .file_name()
            .filter(|name| !name.as_bytes().is_empty())
            .ok_or_else(|| ProofCacheError::InvalidPath(path.display().to_string()))?
            .to_os_string();
        let parent_path = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = Directory::open_ambient(parent_path).map_err(cache_store_error)?;
        let root = open_or_create_root(&parent, &basename)?;
        require_secure_root(&parent, &root)?;
        let root_identity = root.identity_key().map_err(cache_store_error)?;
        Ok(Self {
            parent,
            basename,
            root,
            root_identity,
            reset: AtomicBool::new(false),
            local_lock: Mutex::new(()),
        })
    }

    /// Looks up exactly one proof id using only current locked durable checkpoint revisions.
    ///
    /// A serialized revision vector never supplies freshness. All dependency locks remain held
    /// through decoding, comparison, root post-validation, and the decision to return a hit.
    ///
    /// # Errors
    /// Returns structural authority-input errors. Missing or unusable live authority produces
    /// [`ProofCacheLookup::Unavailable`] and never a proof.
    pub fn lookup(
        &self,
        proof_id: &ProofId,
        authorities: &[DependencyStore<'_>],
    ) -> Result<ProofCacheLookup, ProofCacheError> {
        if !self.binding_matches() {
            return Ok(ProofCacheLookup::Reset);
        }
        if let Err(error) = validate_authority_inputs(self, authorities) {
            let _ = self.binding_matches();
            return Err(error);
        }
        let locked = match lock_authorities(authorities) {
            Ok(locked) => locked,
            Err(ProofCacheError::AuthorityUnavailable(_)) => {
                return Ok(if self.binding_matches() {
                    ProofCacheLookup::Unavailable
                } else {
                    ProofCacheLookup::Reset
                });
            }
            Err(error) => {
                let _ = self.binding_matches();
                return Err(error);
            }
        };
        let fresh = locked.vector();

        let operation = match self.begin_operation() {
            Ok(operation) => operation,
            Err(OperationStart::Reset) => return Ok(ProofCacheLookup::Reset),
            Err(OperationStart::Unavailable) => return Ok(ProofCacheLookup::Unavailable),
        };
        let mut requested = None;
        if visit_entries(&self.root, |id, bytes, entry| {
            if id == *proof_id {
                requested = Some((bytes.to_vec(), entry));
            }
            Ok(())
        })
        .is_err()
        {
            return Ok(self.finish_failed_lookup(operation));
        }

        let provisional = match requested {
            None => ProofCacheLookup::Miss,
            Some((_, entry)) if !same_dependency_stores(&entry.dependencies, fresh) => {
                ProofCacheLookup::Unavailable
            }
            Some((_, entry)) if entry.dependencies != *fresh => ProofCacheLookup::Stale,
            Some((_, entry)) => ProofCacheLookup::Hit(entry.proof),
        };
        if !self.binding_matches() {
            return Ok(ProofCacheLookup::Reset);
        }
        drop(operation);
        drop(locked);
        Ok(provisional)
    }

    /// Publishes one proof with a dependency vector derived exclusively from locked checkpoints.
    ///
    /// # Errors
    /// Fails without a successful publication when authority is unavailable, the proof source is
    /// stale, the secure root binding changed, or any entry/layout/limit invariant is violated.
    pub fn insert(
        &self,
        proof: &VerifiedProof,
        authorities: &[DependencyStore<'_>],
    ) -> Result<ProofCacheInsert, ProofCacheError> {
        let (locked, encoded) = self.prepare_insert(proof, authorities)?;
        let operation = self.begin_operation().map_err(|state| match state {
            OperationStart::Reset => ProofCacheError::Reset,
            OperationStart::Unavailable => {
                ProofCacheError::InvalidLayout("cache root is unavailable".to_owned())
            }
        })?;
        let mut existing = None;
        let layout = visit_entries(&self.root, |id, bytes, _| {
            if id == proof.proof_id() {
                existing = Some(bytes.to_vec());
            }
            Ok(())
        })?;
        if existing.as_deref() == Some(encoded.as_slice()) {
            if !self.binding_matches() {
                return Err(ProofCacheError::Reset);
            }
            drop(operation);
            drop(locked);
            return Ok(ProofCacheInsert::AlreadyPresent);
        }
        if existing.is_none() && layout.entries == MAX_PROOF_CACHE_ENTRIES {
            return Err(ProofCacheError::InvalidLayout(
                "cache entry-count limit would be exceeded".to_owned(),
            ));
        }
        let old_size = existing.as_ref().map_or(0_u64, |bytes| bytes.len() as u64);
        let retained_total = layout.total_bytes.checked_sub(old_size).ok_or_else(|| {
            ProofCacheError::InvalidLayout("cache byte count underflow".to_owned())
        })?;
        checked_total_bytes(retained_total, encoded.len() as u64)?;

        let final_name = final_name(proof.proof_id());
        let temp_name = OsString::from(format!("{TEMP_PREFIX}{}", uuid::Uuid::now_v7()));
        let publication = (|| {
            let mut file = self
                .root
                .create_file(&temp_name)
                .map_err(cache_store_error)?;
            file.write_all(&encoded)
                .map_err(|error| cache_io("write cache temporary", &self.root.path, error))?;
            file.flush()
                .map_err(|error| cache_io("flush cache temporary", &self.root.path, error))?;
            drop(file);
            let retained = self.root.open_file(&temp_name).map_err(cache_store_error)?;
            require_secure_entry(&self.root, &retained, &temp_name)?;
            let mut observed = Vec::new();
            (&retained)
                .take((MAX_PROOF_CACHE_ENTRY_BYTES + 1) as u64)
                .read_to_end(&mut observed)
                .map_err(|error| cache_io("verify cache temporary", &self.root.path, error))?;
            if observed != encoded
                || !self
                    .root
                    .file_entry_is(&temp_name, &retained)
                    .map_err(cache_store_error)?
            {
                return Err(ProofCacheError::InvalidLayout(
                    "cache temporary changed before publication".to_owned(),
                ));
            }
            self.root
                .rename_file(&temp_name, &final_name)
                .map_err(cache_store_error)?;
            Ok(())
        })();
        if publication.is_err() {
            let _ = self.root.unlink_file(&temp_name);
        }
        publication?;

        let mut published = false;
        visit_entries(&self.root, |id, bytes, _| {
            if id == proof.proof_id() {
                published = bytes == encoded;
            }
            Ok(())
        })?;
        if !published {
            return Err(ProofCacheError::InvalidLayout(
                "published entry changed during post-validation".to_owned(),
            ));
        }
        if !self.binding_matches() {
            return Err(ProofCacheError::Reset);
        }
        drop(operation);
        drop(locked);
        Ok(ProofCacheInsert::Inserted)
    }

    fn prepare_insert<'a>(
        &self,
        proof: &VerifiedProof,
        authorities: &[DependencyStore<'a>],
    ) -> Result<(LockedAuthorities<'a>, Vec<u8>), ProofCacheError> {
        if !self.binding_matches() {
            return Err(ProofCacheError::Reset);
        }
        if let Err(error) = validate_authority_inputs(self, authorities) {
            let _ = self.binding_matches();
            return Err(error);
        }
        let locked = match lock_authorities(authorities) {
            Ok(locked) => locked,
            Err(error) => {
                if !self.binding_matches() {
                    return Err(ProofCacheError::Reset);
                }
                return Err(error);
            }
        };
        let fresh = locked.vector();
        if let Err(error) = validate_current_source_dependency(fresh, proof) {
            if !self.binding_matches() {
                return Err(ProofCacheError::Reset);
            }
            return Err(error);
        }
        match encode_cache_entry(fresh, proof) {
            Ok(encoded) => Ok((locked, encoded)),
            Err(error) => {
                if !self.binding_matches() {
                    return Err(ProofCacheError::Reset);
                }
                Err(error)
            }
        }
    }

    /// Best-effort removal of entries containing exactly `store@old`.
    ///
    /// Lookup correctness does not depend on this optimization; lookup always re-resolves and
    /// compares the complete current dependency vector while all dependency locks are held.
    #[must_use]
    pub fn invalidate_store(
        &self,
        store: &LogicalStoreId,
        old: StoreRevisionRef,
        new: StoreRevisionRef,
    ) -> ProofCacheDisposition {
        let operation = match self.begin_operation() {
            Ok(operation) => operation,
            Err(OperationStart::Reset) => return ProofCacheDisposition::Reset,
            Err(OperationStart::Unavailable) => return ProofCacheDisposition::Unavailable,
        };
        let mut remove = Vec::new();
        if visit_entries(&self.root, |id, _, entry| {
            if old != new
                && entry
                    .dependencies
                    .entries()
                    .iter()
                    .any(|dependency| dependency.store() == store && dependency.revision() == old)
            {
                remove.push(final_name(id));
            }
            Ok(())
        })
        .is_err()
        {
            return self.failed_disposition();
        }
        for name in &remove {
            if self.root.unlink_file(name).is_err() {
                return self.failed_disposition();
            }
        }
        if visit_entries(&self.root, |_, _, _| Ok(())).is_err() {
            return self.failed_disposition();
        }
        if !self.binding_matches() {
            return ProofCacheDisposition::Reset;
        }
        drop(operation);
        if remove.is_empty() {
            ProofCacheDisposition::Unchanged
        } else {
            ProofCacheDisposition::Invalidated
        }
    }

    fn begin_operation(&self) -> Result<CacheOperation<'_>, OperationStart> {
        let local = self
            .local_lock
            .lock()
            .map_err(|_| OperationStart::Unavailable)?;
        let file = self
            .root
            .lock_file()
            .map_err(|_| OperationStart::Unavailable)?;
        file.lock().map_err(|_| OperationStart::Unavailable)?;
        if !self.binding_matches() {
            return Err(OperationStart::Reset);
        }
        cleanup_temporaries(&self.root).map_err(|_| OperationStart::Unavailable)?;
        if !self.binding_matches() {
            return Err(OperationStart::Reset);
        }
        Ok(CacheOperation {
            cache: self,
            _local: local,
            _file: file,
        })
    }

    fn binding_matches(&self) -> bool {
        if self.reset.load(Ordering::Acquire) {
            return false;
        }
        let matches = self
            .parent
            .open_dir(&self.basename)
            .ok()
            .is_some_and(|candidate| {
                require_secure_root(&self.parent, &candidate).is_ok()
                    && candidate.identity_key().ok() == Some(self.root_identity)
            });
        if !matches {
            self.reset.store(true, Ordering::Release);
        }
        matches
    }

    fn finish_failed_lookup(&self, operation: CacheOperation<'_>) -> ProofCacheLookup {
        let result = if self.binding_matches() {
            ProofCacheLookup::Unavailable
        } else {
            ProofCacheLookup::Reset
        };
        drop(operation);
        result
    }

    fn failed_disposition(&self) -> ProofCacheDisposition {
        if self.binding_matches() {
            ProofCacheDisposition::Unavailable
        } else {
            ProofCacheDisposition::Reset
        }
    }
}

struct CacheOperation<'a> {
    cache: &'a ProofCache,
    _local: std::sync::MutexGuard<'a, ()>,
    _file: File,
}

impl Drop for CacheOperation<'_> {
    fn drop(&mut self) {
        let _ = self.cache.binding_matches();
    }
}

#[derive(Debug, Clone, Copy)]
enum OperationStart {
    Reset,
    Unavailable,
}

struct LockedAuthorities<'a> {
    _guards: Vec<UnsnapshottedExclusive<'a>>,
    vector: RevisionVector,
}

impl LockedAuthorities<'_> {
    const fn vector(&self) -> &RevisionVector {
        &self.vector
    }
}

fn validate_authority_inputs(
    cache: &ProofCache,
    authorities: &[DependencyStore<'_>],
) -> Result<(), ProofCacheError> {
    if authorities.len() > crate::MAX_VECTOR_STORES {
        return Err(ProofCacheError::TooManyAuthorities);
    }
    if !authorities
        .windows(2)
        .all(|pair| pair[0].expected_store < pair[1].expected_store)
    {
        return Err(ProofCacheError::InvalidAuthorityOrder);
    }
    let mut physical = BTreeSet::new();
    for authority in authorities {
        let identity = authority
            .store
            .root_dir
            .identity_key()
            .map_err(|error| ProofCacheError::AuthorityUnavailable(error.to_string()))?;
        if identity == cache.root_identity {
            return Err(ProofCacheError::CacheAuthorityAlias);
        }
        if !physical.insert(identity) {
            return Err(ProofCacheError::AliasedAuthorityRoots);
        }
    }
    Ok(())
}

fn lock_authorities<'a>(
    authorities: &[DependencyStore<'a>],
) -> Result<LockedAuthorities<'a>, ProofCacheError> {
    let mut guards = Vec::with_capacity(authorities.len());
    for authority in authorities {
        let guard = authority
            .store
            .lock_exclusive_unsnapshotted()
            .map_err(authority_error)?;
        crate::federation::pending::clean_disposable_locked(authority.store)
            .map_err(authority_error)?;
        if crate::federation::pending::gate_without_git(authority.store).map_err(authority_error)?
            != crate::federation::pending::GateAction::Allow
        {
            return Err(ProofCacheError::AuthorityUnavailable(
                "pending/recovery gate did not converge".to_owned(),
            ));
        }
        guard.recover_transactions().map_err(authority_error)?;
        guards.push(guard);
    }

    let mut entries = Vec::with_capacity(authorities.len());
    for (authority, guard) in authorities.iter().zip(&guards) {
        let checkpoint = crate::federation::admission_checkpoint_locked(guard)
            .map_err(|error| ProofCacheError::AuthorityUnavailable(error.to_string()))?
            .ok_or_else(|| {
                ProofCacheError::AuthorityUnavailable(
                    "current durable admission checkpoint is missing".to_owned(),
                )
            })?;
        let snapshot = guard.scan_visible_locked().map_err(authority_error)?;
        let identity = snapshot.identity().ok_or_else(|| {
            ProofCacheError::AuthorityUnavailable(
                "strict initialized store identity is missing".to_owned(),
            )
        })?;
        if checkpoint.logical_store_id() != &authority.expected_store
            || identity.logical_id() != &authority.expected_store
            || checkpoint.logical_store_id() != identity.logical_id()
        {
            return Err(ProofCacheError::AuthorityUnavailable(
                "resolver, checkpoint, and strict store identities disagree".to_owned(),
            ));
        }
        if checkpoint.accepted_revision() != snapshot.revision() {
            return Err(ProofCacheError::AuthorityUnavailable(
                "checkpoint revision disagrees with the strict canonical snapshot".to_owned(),
            ));
        }
        entries.push(RevisionVectorEntry::new(
            authority.expected_store.clone(),
            checkpoint.accepted_revision(),
        ));
    }
    let vector = RevisionVector::new(entries)
        .map_err(|error| ProofCacheError::AuthorityUnavailable(error.to_string()))?;
    Ok(LockedAuthorities {
        _guards: guards,
        vector,
    })
}

fn same_dependency_stores(left: &RevisionVector, right: &RevisionVector) -> bool {
    left.entries().len() == right.entries().len()
        && left
            .entries()
            .iter()
            .zip(right.entries())
            .all(|(left, right)| left.store() == right.store())
}

fn validate_source_dependency(
    dependencies: &RevisionVector,
    proof: &VerifiedProof,
) -> Result<(), ProofCacheError> {
    let mut matching = dependencies
        .entries()
        .iter()
        .filter(|entry| entry.store() == &proof.subject().store);
    let Some(source) = matching.next() else {
        return Err(ProofCacheError::InvalidSourceDependency);
    };
    if matching.next().is_some() || source.revision() != proof.source_revision() {
        return Err(ProofCacheError::InvalidSourceDependency);
    }
    Ok(())
}

fn validate_current_source_dependency(
    dependencies: &RevisionVector,
    proof: &VerifiedProof,
) -> Result<(), ProofCacheError> {
    let source = dependencies
        .entries()
        .iter()
        .find(|entry| entry.store() == &proof.subject().store)
        .ok_or(ProofCacheError::InvalidSourceDependency)?;
    if source.revision() != proof.source_revision() {
        return Err(ProofCacheError::StaleProof);
    }
    Ok(())
}

#[derive(Debug)]
struct CacheEntry {
    dependencies: RevisionVector,
    proof: VerifiedProof,
}

fn encode_cache_entry(
    dependencies: &RevisionVector,
    proof: &VerifiedProof,
) -> Result<Vec<u8>, ProofCacheError> {
    validate_source_dependency(dependencies, proof)?;
    let dependencies = serde_json::from_slice::<Value>(
        &encode_revision_vector(dependencies)
            .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?,
    )
    .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    let proof = serde_json::from_slice::<Value>(
        &encode_verified_proof(proof)
            .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?,
    )
    .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    let mut root = Map::new();
    root.insert("dependencies".to_owned(), dependencies);
    root.insert("proof".to_owned(), proof);
    root.insert(
        "schema".to_owned(),
        Value::String(PROJECTION_CACHE_ENTRY_SCHEMA_V1.to_owned()),
    );
    let bytes = encode_pretty(&Value::Object(root))
        .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    if bytes.len() > MAX_PROOF_CACHE_ENTRY_BYTES {
        return Err(ProofCacheError::EntryTooLarge);
    }
    Ok(bytes)
}

fn decode_cache_entry(bytes: &[u8]) -> Result<CacheEntry, ProofCacheError> {
    if bytes.len() > MAX_PROOF_CACHE_ENTRY_BYTES {
        return Err(ProofCacheError::EntryTooLarge);
    }
    let value =
        decode_strict(bytes).map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    let object = value.as_object().ok_or_else(|| {
        ProofCacheError::InvalidLayout("cache entry root is not an object".to_owned())
    })?;
    if object.len() != 3
        || !object.contains_key("dependencies")
        || !object.contains_key("proof")
        || object.get("schema").and_then(Value::as_str) != Some(PROJECTION_CACHE_ENTRY_SCHEMA_V1)
    {
        return Err(ProofCacheError::InvalidLayout(
            "cache entry root is not the exact closed v1 document".to_owned(),
        ));
    }
    let dependency_bytes = encode_pretty(&object["dependencies"])
        .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    let proof_bytes = encode_pretty(&object["proof"])
        .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    let dependencies = decode_revision_vector(&dependency_bytes)
        .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    let proof = decode_verified_proof(&proof_bytes)
        .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    validate_source_dependency(&dependencies, &proof)?;
    let entry = CacheEntry {
        dependencies,
        proof,
    };
    if encode_cache_entry(&entry.dependencies, &entry.proof)? != bytes {
        return Err(ProofCacheError::InvalidLayout(
            "cache entry JSON is not canonical".to_owned(),
        ));
    }
    Ok(entry)
}

#[derive(Debug, Clone, Copy)]
struct LayoutSummary {
    entries: usize,
    total_bytes: u64,
}

fn visit_entries(
    root: &Directory,
    mut visit: impl FnMut(ProofId, &[u8], CacheEntry) -> Result<(), ProofCacheError>,
) -> Result<LayoutSummary, ProofCacheError> {
    let names = root
        .bounded_names(MAX_PROOF_CACHE_ENTRIES + 1)
        .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    if names.len() > MAX_PROOF_CACHE_ENTRIES {
        return Err(ProofCacheError::InvalidLayout(
            "cache final-entry limit exceeded".to_owned(),
        ));
    }
    let mut total_bytes = 0_u64;
    for name in &names {
        let name = std::str::from_utf8(name).map_err(|_| {
            ProofCacheError::InvalidLayout("cache filename is not canonical ASCII".to_owned())
        })?;
        let stem = name.strip_suffix(FINAL_SUFFIX).ok_or_else(|| {
            ProofCacheError::InvalidLayout("unknown cache-root entry name".to_owned())
        })?;
        if stem.len() != 64 {
            return Err(ProofCacheError::InvalidLayout(
                "cache filename is not an exact proof id".to_owned(),
            ));
        }
        let id = ProofId::parse(stem)
            .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
        let os_name = OsStr::new(name);
        let file = root
            .open_file(os_name)
            .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
        let size = require_secure_entry(root, &file, os_name)?;
        if size > MAX_PROOF_CACHE_ENTRY_BYTES as u64 {
            return Err(ProofCacheError::EntryTooLarge);
        }
        total_bytes = checked_total_bytes(total_bytes, size)?;
        let capacity = usize::try_from(size).map_err(|_| {
            ProofCacheError::InvalidLayout("cache entry size is not addressable".to_owned())
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        (&file)
            .take((MAX_PROOF_CACHE_ENTRY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| cache_io("read cache entry", &root.path, error))?;
        if bytes.len() as u64 != size
            || !root
                .file_entry_is(os_name, &file)
                .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?
        {
            return Err(ProofCacheError::InvalidLayout(
                "cache entry changed while being read".to_owned(),
            ));
        }
        let entry = decode_cache_entry(&bytes)?;
        if entry.proof.proof_id() != id {
            return Err(ProofCacheError::InvalidLayout(
                "filename and embedded proof ids disagree".to_owned(),
            ));
        }
        if !root
            .file_entry_is(os_name, &file)
            .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?
        {
            return Err(ProofCacheError::InvalidLayout(
                "cache entry changed while being decoded".to_owned(),
            ));
        }
        visit(id, &bytes, entry)?;
    }
    Ok(LayoutSummary {
        entries: names.len(),
        total_bytes,
    })
}

fn checked_total_bytes(current: u64, addition: u64) -> Result<u64, ProofCacheError> {
    let total = current.checked_add(addition).ok_or_else(|| {
        ProofCacheError::InvalidLayout("cache total-byte count overflow".to_owned())
    })?;
    if total > MAX_PROOF_CACHE_TOTAL_BYTES {
        return Err(ProofCacheError::InvalidLayout(
            "cache total-byte limit exceeded".to_owned(),
        ));
    }
    Ok(total)
}

fn cleanup_temporaries(root: &Directory) -> Result<(), ProofCacheError> {
    let names = root
        .bounded_names(MAX_PROOF_CACHE_ENTRIES + 1)
        .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
    for name in names {
        if is_private_temporary(&name) {
            root.unlink_file(OsStr::from_bytes(&name))
                .map_err(|error| ProofCacheError::InvalidLayout(error.to_string()))?;
        }
    }
    Ok(())
}

fn is_private_temporary(name: &[u8]) -> bool {
    let Some(suffix) = name.strip_prefix(TEMP_PREFIX.as_bytes()) else {
        return false;
    };
    std::str::from_utf8(suffix)
        .ok()
        .and_then(|value| value.parse::<uuid::Uuid>().ok())
        .is_some()
}

fn final_name(id: ProofId) -> OsString {
    OsString::from(format!("{id}{FINAL_SUFFIX}"))
}

fn open_or_create_root(parent: &Directory, basename: &OsStr) -> Result<Directory, ProofCacheError> {
    let created = match rfs::mkdirat(parent.file(), basename, Mode::RWXU) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(error) => {
            return Err(cache_io(
                "create cache root",
                &parent.path.join(basename),
                error.into(),
            ));
        }
    };
    let root = parent.open_dir(basename).map_err(cache_store_error)?;
    if created {
        rfs::fchmod(root.file(), Mode::RWXU).map_err(|error| {
            cache_io(
                "set cache root mode",
                &parent.path.join(basename),
                error.into(),
            )
        })?;
    }
    Ok(root)
}

fn require_secure_root(parent: &Directory, root: &Directory) -> Result<(), ProofCacheError> {
    let parent_stat = rfs::fstat(parent.file())
        .map_err(|error| cache_io("inspect retained cache parent", &parent.path, error.into()))?;
    let root_stat = rfs::fstat(root.file())
        .map_err(|error| cache_io("inspect retained cache root", &root.path, error.into()))?;
    if FileType::from_raw_mode(root_stat.st_mode) != FileType::Directory
        || root_stat.st_dev != parent_stat.st_dev
        || root_stat.st_uid != rustix::process::geteuid().as_raw()
        || root_stat.st_mode & 0o7777 != 0o700
    {
        return Err(ProofCacheError::InvalidRoot);
    }
    Ok(())
}

fn require_secure_entry(
    root: &Directory,
    file: &File,
    name: &OsStr,
) -> Result<u64, ProofCacheError> {
    let root_stat = rfs::fstat(root.file())
        .map_err(|error| cache_io("inspect cache root", &root.path, error.into()))?;
    let stat = rfs::fstat(file)
        .map_err(|error| cache_io("inspect cache entry", &root.path.join(name), error.into()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_dev != root_stat.st_dev
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(ProofCacheError::InvalidLayout(
            "cache entry is not a same-device effective-user-owned mode-0600 regular file"
                .to_owned(),
        ));
    }
    Ok(stat.st_size.max(0).cast_unsigned())
}

fn authority_error(error: StoreError) -> ProofCacheError {
    let message = error.to_string();
    drop(error);
    ProofCacheError::AuthorityUnavailable(message)
}

fn cache_store_error(error: StoreError) -> ProofCacheError {
    let message = error.to_string();
    drop(error);
    ProofCacheError::Io(message)
}

fn cache_io(operation: &'static str, path: &Path, error: io::Error) -> ProofCacheError {
    let message = format!("{operation} for {}: {error}", path.display());
    drop(error);
    ProofCacheError::Io(message)
}

#[cfg(test)]
mod tests {
    use super::{MAX_PROOF_CACHE_TOTAL_BYTES, checked_total_bytes};

    #[test]
    fn total_byte_limit_accepts_exactly_limit_and_rejects_limit_plus_one() {
        assert_eq!(
            checked_total_bytes(MAX_PROOF_CACHE_TOTAL_BYTES - 1, 1).expect("exact total limit"),
            MAX_PROOF_CACHE_TOTAL_BYTES
        );
        assert!(checked_total_bytes(MAX_PROOF_CACHE_TOTAL_BYTES, 1).is_err());
        assert!(checked_total_bytes(u64::MAX, 1).is_err());
    }
}
