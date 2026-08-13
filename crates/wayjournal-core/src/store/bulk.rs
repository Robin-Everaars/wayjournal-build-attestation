use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
};

use crate::{PathClass, Store, StoreError, classify_path, federation::pending::StagedAddition};

use super::{
    Directory,
    transaction::{ensure_synced, link_fd_no_clobber},
};

pub(crate) fn publish_addition(store: &Store, addition: &StagedAddition) -> Result<(), StoreError> {
    let (parent, name) = target_parent(store, &addition.path)?;
    link_fd_no_clobber(&addition.file, &parent, &name, &addition.bytes)?;
    parent.sync()
}

pub(crate) fn publication_rank(path: &[u8]) -> u8 {
    match classify_path(path) {
        PathClass::LegacyEvent | PathClass::JournalRecord => 0,
        PathClass::LegacyBatch | PathClass::JournalBatch => 1,
        PathClass::InvalidReserved | PathClass::NonCanonical => 2,
    }
}

fn target_parent(store: &Store, path: &[u8]) -> Result<(Directory, OsString), StoreError> {
    let components = path.split(|byte| *byte == b'/').collect::<Vec<_>>();
    match (classify_path(path), components.as_slice()) {
        (PathClass::LegacyBatch, [b"batches", file]) => Ok((
            store.batches_dir.try_clone()?,
            OsString::from_vec(file.to_vec()),
        )),
        (PathClass::LegacyEvent, [b"events", entity, file]) => {
            let entity = ensure_synced(&store.events_dir, OsStr::from_bytes(entity))?;
            Ok((entity, OsString::from_vec(file.to_vec())))
        }
        (PathClass::JournalBatch, [b"journal", b"batches", file]) => Ok((
            store.journal_batches_dir.try_clone()?,
            OsString::from_vec(file.to_vec()),
        )),
        (PathClass::JournalRecord, [b"journal", b"records", domain, entity, file]) => {
            let domain = ensure_synced(&store.records_dir, OsStr::from_bytes(domain))?;
            let entity = ensure_synced(&domain, OsStr::from_bytes(entity))?;
            Ok((entity, OsString::from_vec(file.to_vec())))
        }
        _ => Err(super::invalid_layout(
            &store.root,
            "bulk publication path is not canonical",
        )),
    }
}
