use std::{
    cell::Cell,
    cmp::Ordering,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
    rc::Rc,
};

use crate::{
    BatchError, BatchId, Digest, GenesisError, PathClass, RecordId, StoreIdentity,
    StoreRevisionRef, classify_path, decode_batch_manifest, decode_record,
};

use super::{
    CanonicalEntryBudget, Directory, LegacyEntry, LegacyEntrySource, LegacyStreamRequirement,
    RawFile, Store, StoreCorruption, StoreError, active_scan_limits, canonical_file_limit,
    invalid_layout, io_error, reserve_streamed_visible_bytes,
};

const SORT_RUN_BYTES: usize = 8 * 1024 * 1024;
const MAX_FACT_BYTES: usize = 2 * 1024;
// Canonical payloads are written once. Each semantic fact is written once to a spill run and,
// only when there are multiple runs, once to its merged file. Thirty-two canonical-size units
// conservatively cover the payload and every bounded entry/record/manifest/claim/enrichment
// stream without reducing the 1 GiB canonical capacity.
const MAX_REPLAY_TEMPORARY_BYTES: u64 = 32 * super::MAX_TOTAL_CANONICAL_BYTES;

#[derive(Clone)]
struct ReplayTempBudget {
    used: Rc<Cell<u64>>,
    maximum: u64,
}

impl ReplayTempBudget {
    fn new(maximum: u64) -> Self {
        Self {
            used: Rc::new(Cell::new(0)),
            maximum,
        }
    }

    fn reserve(&self, bytes: usize, path: &Path) -> Result<(), StoreError> {
        let bytes = u64::try_from(bytes)
            .map_err(|_| invalid_layout(path, "semantic replay temporary-byte overflow"))?;
        let used = self
            .used
            .get()
            .checked_add(bytes)
            .ok_or_else(|| invalid_layout(path, "semantic replay temporary-byte overflow"))?;
        if used > self.maximum {
            return Err(invalid_layout(
                path,
                "semantic replay exceeds temporary-byte amplification limit",
            ));
        }
        self.used.set(used);
        Ok(())
    }

    #[cfg(test)]
    fn used(&self) -> u64 {
        self.used.get()
    }
}

pub(crate) struct ValidatedStoreState {
    revision: StoreRevisionRef,
    identity: Option<StoreIdentity>,
}

impl ValidatedStoreState {
    pub(crate) const fn revision(&self) -> StoreRevisionRef {
        self.revision
    }

    pub(crate) const fn identity(&self) -> Option<&StoreIdentity> {
        self.identity.as_ref()
    }
}

type Fact = (Vec<u8>, Vec<u8>);

struct SortRecord {
    key: Vec<u8>,
    value: Vec<u8>,
}

struct ExternalSorter<'a> {
    directory: &'a Directory,
    budget: ReplayTempBudget,
    run_bytes: usize,
    buffered: Vec<SortRecord>,
    buffered_bytes: usize,
    runs: Vec<File>,
}

impl<'a> ExternalSorter<'a> {
    fn new(directory: &'a Directory, budget: ReplayTempBudget) -> Self {
        Self::with_run_bytes(directory, budget, SORT_RUN_BYTES)
    }

    fn with_run_bytes(
        directory: &'a Directory,
        budget: ReplayTempBudget,
        run_bytes: usize,
    ) -> Self {
        Self {
            directory,
            budget,
            run_bytes,
            buffered: Vec::new(),
            buffered_bytes: 0,
            runs: Vec::new(),
        }
    }

    fn push(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StoreError> {
        let bytes = key
            .len()
            .checked_add(value.len())
            .and_then(|value| value.checked_add(8))
            .ok_or_else(|| invalid_layout(&self.directory.path, "external fact size overflow"))?;
        if bytes > MAX_FACT_BYTES {
            return Err(invalid_layout(
                &self.directory.path,
                "external semantic fact exceeds byte limit",
            ));
        }
        if self.buffered_bytes.saturating_add(bytes) > self.run_bytes && !self.buffered.is_empty() {
            self.flush_run()?;
        }
        self.buffered_bytes += bytes;
        self.buffered.push(SortRecord { key, value });
        Ok(())
    }

    fn flush_run(&mut self) -> Result<(), StoreError> {
        self.buffered.sort_unstable_by(|left, right| {
            left.key.cmp(&right.key).then(left.value.cmp(&right.value))
        });
        let mut run = self.directory.temporary_file()?;
        for record in self.buffered.drain(..) {
            write_record(
                &mut run,
                &record.key,
                &record.value,
                &self.directory.path,
                &self.budget,
            )?;
        }
        run.flush().map_err(|source| {
            io_error("flush external semantic run", &self.directory.path, source)
        })?;
        run.seek(SeekFrom::Start(0)).map_err(|source| {
            io_error("rewind external semantic run", &self.directory.path, source)
        })?;
        self.runs.push(run);
        self.buffered_bytes = 0;
        Ok(())
    }

    fn finish(mut self) -> Result<SortedFacts, StoreError> {
        if !self.buffered.is_empty() || self.runs.is_empty() {
            self.flush_run()?;
        }
        if self.runs.len() == 1 {
            return Ok(SortedFacts {
                file: self.runs.pop().expect("one run"),
            });
        }
        let mut readers = self
            .runs
            .into_iter()
            .map(FactReader::new)
            .collect::<Result<Vec<_>, _>>()?;
        let mut output = self.directory.temporary_file()?;
        loop {
            let selected = readers
                .iter()
                .enumerate()
                .filter_map(|(index, reader)| reader.current.as_ref().map(|record| (index, record)))
                .min_by(|(_, left), (_, right)| left.0.cmp(&right.0).then(left.1.cmp(&right.1)))
                .map(|(index, _)| index);
            let Some(index) = selected else { break };
            let (key, value) = readers[index].current.take().expect("selected record");
            write_record(
                &mut output,
                &key,
                &value,
                &self.directory.path,
                &self.budget,
            )?;
            readers[index].advance()?;
        }
        output.flush().map_err(|source| {
            io_error("flush merged semantic facts", &self.directory.path, source)
        })?;
        output.seek(SeekFrom::Start(0)).map_err(|source| {
            io_error("rewind merged semantic facts", &self.directory.path, source)
        })?;
        Ok(SortedFacts { file: output })
    }
}

fn write_record(
    file: &mut File,
    key: &[u8],
    value: &[u8],
    path: &Path,
    budget: &ReplayTempBudget,
) -> Result<(), StoreError> {
    let key_len = u32::try_from(key.len())
        .map_err(|_| invalid_layout(path, "external fact key length overflow"))?;
    let value_len = u32::try_from(value.len())
        .map_err(|_| invalid_layout(path, "external fact value length overflow"))?;
    budget.reserve(key.len() + value.len() + 8, path)?;
    file.write_all(&key_len.to_be_bytes())
        .and_then(|()| file.write_all(&value_len.to_be_bytes()))
        .and_then(|()| file.write_all(key))
        .and_then(|()| file.write_all(value))
        .map_err(|source| io_error("write external semantic fact", path, source))
}

struct SortedFacts {
    file: File,
}

impl SortedFacts {
    fn reader(&self) -> Result<FactReader, StoreError> {
        let mut file = self
            .file
            .try_clone()
            .map_err(|source| io_error("clone semantic facts", Path::new("."), source))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| io_error("rewind semantic facts", Path::new("."), source))?;
        FactReader::new(file)
    }
}

struct FactReader {
    reader: BufReader<File>,
    current: Option<Fact>,
}

impl FactReader {
    fn new(file: File) -> Result<Self, StoreError> {
        let mut result = Self {
            reader: BufReader::new(file),
            current: None,
        };
        result.advance()?;
        Ok(result)
    }

    fn advance(&mut self) -> Result<(), StoreError> {
        self.current = read_record(&mut self.reader)?;
        Ok(())
    }

    fn take(&mut self) -> Result<Option<Fact>, StoreError> {
        let current = self.current.take();
        if current.is_some() {
            self.advance()?;
        }
        Ok(current)
    }
}

fn read_record(reader: &mut BufReader<File>) -> Result<Option<Fact>, StoreError> {
    let mut lengths = [0_u8; 8];
    let mut read = 0;
    while read < lengths.len() {
        let count = reader
            .read(&mut lengths[read..])
            .map_err(|source| io_error("read semantic fact header", Path::new("."), source))?;
        if count == 0 {
            if read == 0 {
                return Ok(None);
            }
            return Err(invalid_layout(
                Path::new("."),
                "truncated semantic fact header",
            ));
        }
        read += count;
    }
    let key_len = u32::from_be_bytes(lengths[..4].try_into().expect("four bytes")) as usize;
    let value_len = u32::from_be_bytes(lengths[4..].try_into().expect("four bytes")) as usize;
    if key_len.saturating_add(value_len).saturating_add(8) > MAX_FACT_BYTES {
        return Err(invalid_layout(
            Path::new("."),
            "semantic fact exceeds byte limit",
        ));
    }
    let mut key = vec![0; key_len];
    let mut value = vec![0; value_len];
    reader
        .read_exact(&mut key)
        .and_then(|()| reader.read_exact(&mut value))
        .map_err(|source| io_error("read semantic fact", Path::new("."), source))?;
    Ok(Some((key, value)))
}

pub(crate) struct CanonicalReplayBuilder<'a> {
    directory: &'a Directory,
    payloads: File,
    entries: ExternalSorter<'a>,
    budget: ReplayTempBudget,
    offset: u64,
    total_bytes: u64,
}

pub(crate) fn replay_builder(store: &Store) -> Result<CanonicalReplayBuilder<'_>, StoreError> {
    let budget = ReplayTempBudget::new(MAX_REPLAY_TEMPORARY_BYTES);
    Ok(CanonicalReplayBuilder {
        directory: &store.root_dir,
        payloads: store.root_dir.temporary_file()?,
        entries: ExternalSorter::new(&store.root_dir, budget.clone()),
        budget,
        offset: 0,
        total_bytes: 0,
    })
}

impl CanonicalReplayBuilder<'_> {
    pub(crate) fn push(&mut self, file: RawFile) -> Result<(), StoreError> {
        let Some(limit) = canonical_file_limit(classify_path(&file.path)) else {
            return Err(StoreError::Corrupt {
                issue: StoreCorruption::InvalidCanonicalPath { path: file.path },
            });
        };
        if file.bytes.len() > limit {
            return Err(invalid_layout(
                &self.directory.path,
                "canonical file exceeds its byte limit",
            ));
        }
        reserve_streamed_visible_bytes(&mut self.total_bytes, file.bytes.len())?;
        self.budget
            .reserve(file.bytes.len(), &self.directory.path)?;
        self.payloads.write_all(&file.bytes).map_err(|source| {
            io_error(
                "write canonical replay payload",
                &self.directory.path,
                source,
            )
        })?;
        let mut location = Vec::with_capacity(12);
        location.extend_from_slice(&self.offset.to_be_bytes());
        location.extend_from_slice(
            &u32::try_from(file.bytes.len())
                .map_err(|_| {
                    invalid_layout(&self.directory.path, "canonical payload length overflow")
                })?
                .to_be_bytes(),
        );
        self.entries.push(file.path, location)?;
        self.offset = self
            .offset
            .checked_add(file.bytes.len() as u64)
            .ok_or_else(|| {
                invalid_layout(&self.directory.path, "canonical replay offset overflow")
            })?;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<CanonicalReplay, StoreError> {
        self.payloads
            .flush()
            .map_err(|source| io_error("flush canonical replay", &self.directory.path, source))?;
        let entries = self.entries.finish()?;
        let mut reader = entries.reader()?;
        let mut budget = CanonicalEntryBudget::new();
        let limit = active_scan_limits().entries;
        while let Some((path, _)) = reader.take()? {
            budget.push_sorted_file(&path, limit).map_err(|()| {
                invalid_layout(
                    &self.directory.path,
                    "canonical store exceeds entry-count limit",
                )
            })?;
        }
        Ok(CanonicalReplay {
            payloads: self.payloads,
            entries,
            budget: self.budget,
        })
    }
}

pub(crate) struct CanonicalReplay {
    payloads: File,
    entries: SortedFacts,
    budget: ReplayTempBudget,
}

impl CanonicalReplay {
    fn cursor(&self) -> Result<ReplayCursor, StoreError> {
        Ok(ReplayCursor {
            payloads: self
                .payloads
                .try_clone()
                .map_err(|source| io_error("clone canonical replay", Path::new("."), source))?,
            entries: self.entries.reader()?,
        })
    }

    fn read_at(&self, offset: u64, length: usize, path: Vec<u8>) -> Result<RawFile, StoreError> {
        let mut payloads = self
            .payloads
            .try_clone()
            .map_err(|source| io_error("clone canonical replay", Path::new("."), source))?;
        payloads
            .seek(SeekFrom::Start(offset))
            .map_err(|source| io_error("seek canonical replay", Path::new("."), source))?;
        let mut bytes = vec![0; length];
        payloads
            .read_exact(&mut bytes)
            .map_err(|source| io_error("read canonical replay", Path::new("."), source))?;
        Ok(RawFile { path, bytes })
    }
}

struct ReplayCursor {
    payloads: File,
    entries: FactReader,
}

impl ReplayCursor {
    fn next_file(&mut self) -> Result<Option<(RawFile, u64)>, StoreError> {
        let Some((path, location)) = self.entries.take()? else {
            return Ok(None);
        };
        let (offset, length) = decode_location(&location)?;
        self.payloads
            .seek(SeekFrom::Start(offset))
            .map_err(|source| io_error("seek canonical replay", Path::new("."), source))?;
        let mut bytes = vec![0; length];
        self.payloads
            .read_exact(&mut bytes)
            .map_err(|source| io_error("read canonical replay", Path::new("."), source))?;
        Ok(Some((RawFile { path, bytes }, offset)))
    }
}

fn decode_location(value: &[u8]) -> Result<(u64, usize), StoreError> {
    if value.len() != 12 {
        return Err(invalid_layout(Path::new("."), "invalid replay location"));
    }
    let offset = u64::from_be_bytes(value[..8].try_into().expect("eight bytes"));
    let length = u32::from_be_bytes(value[8..].try_into().expect("four bytes")) as usize;
    Ok((offset, length))
}

struct ReplayLegacySource<'a> {
    cursor: ReplayCursor,
    current: Option<RawFile>,
    source_error: Option<StoreError>,
    done: bool,
    marker: std::marker::PhantomData<&'a ()>,
}

impl LegacyEntrySource for ReplayLegacySource<'_> {
    fn next_entry(&mut self) -> Result<Option<LegacyEntry<'_>>, String> {
        if self.done {
            return Ok(None);
        }
        self.current = None;
        let next = self.cursor.next_file().map_err(|error| {
            self.source_error = Some(error);
            "canonical replay source failed".to_owned()
        })?;
        let Some((file, _)) = next else {
            self.done = true;
            return Ok(None);
        };
        let class = classify_path(&file.path);
        match class {
            PathClass::LegacyEvent | PathClass::LegacyBatch => {
                self.current = Some(file);
                let file = self.current.as_ref().expect("current legacy file");
                Ok(Some(LegacyEntry::new(&file.path, &file.bytes, class)))
            }
            PathClass::JournalRecord | PathClass::JournalBatch => {
                self.done = true;
                Ok(None)
            }
            PathClass::InvalidReserved | PathClass::NonCanonical => {
                self.source_error = Some(StoreError::Corrupt {
                    issue: StoreCorruption::InvalidCanonicalPath { path: file.path },
                });
                Err("canonical replay path classification failed".to_owned())
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Location {
    offset: u64,
    length: usize,
}

struct ReplayFacts {
    revision: StoreRevisionRef,
    record_ids: SortedFacts,
    records: SortedFacts,
    idempotency: SortedFacts,
    claims: SortedFacts,
    headers: SortedFacts,
    manifest_count: usize,
    record_count: usize,
    first_batch: Option<(BatchId, usize, Option<RecordId>)>,
    unsupported_identity_schema: bool,
    genesis_count: usize,
    genesis: Option<(Vec<u8>, Location)>,
    reserved_builtin: bool,
}

pub(crate) fn validate_bounded_replay(
    store: &Store,
    replay: &CanonicalReplay,
) -> Result<ValidatedStoreState, StoreError> {
    validate_legacy(store, replay)?;
    let facts = collect_facts(store, replay)?;
    validate_duplicate_record_ids(&facts.record_ids)?;
    validate_duplicate_idempotency(&facts.idempotency)?;
    validate_ownership_and_batches(store, replay, &facts)?;
    if !store.strict_domains && facts.reserved_builtin {
        return Err(StoreError::Corrupt {
            issue: StoreCorruption::InvalidDomainFold {
                domain: "wayjournal.reserved".to_owned(),
                entity: "legacy-s1-s2".to_owned(),
                message: "S3 built-in data cannot be opened in legacy mode".to_owned(),
            },
        });
    }
    let identity = if store.strict_domains {
        let genesis_file = facts
            .genesis
            .as_ref()
            .map(|(path, location)| replay.read_at(location.offset, location.length, path.clone()))
            .transpose()?;
        let genesis_record = genesis_file
            .as_ref()
            .map(|file| decode_record(&file.bytes, &store.registry))
            .transpose()
            .map_err(|error| StoreError::Corrupt {
                issue: StoreCorruption::InvalidGenesis(GenesisError::InvalidRecord(
                    error.to_string(),
                )),
            })?;
        let genesis = genesis_file
            .as_ref()
            .zip(genesis_record.as_ref())
            .map(|(file, record)| (file.path.as_slice(), file.bytes.as_slice(), record));
        let identity = crate::identity::validate_replayed_identity(
            facts.manifest_count,
            facts.record_count,
            facts.first_batch,
            facts.unsupported_identity_schema,
            facts.genesis_count,
            genesis,
        )
        .map_err(|error| StoreError::Corrupt {
            issue: StoreCorruption::InvalidGenesis(error),
        })?;
        validate_builtin_folds_bounded(store, replay)?;
        identity
    } else {
        None
    };
    Ok(ValidatedStoreState {
        revision: facts.revision,
        identity,
    })
}

fn validate_legacy(store: &Store, replay: &CanonicalReplay) -> Result<(), StoreError> {
    let mut source = ReplayLegacySource {
        cursor: replay.cursor()?,
        current: None,
        source_error: None,
        done: false,
        marker: std::marker::PhantomData,
    };
    let validation =
        store.validate_legacy_stream(LegacyStreamRequirement::FullDomainBounded, &mut source);
    if let Some(error) = source.source_error.take() {
        return Err(error);
    }
    let mut unconsumed = false;
    loop {
        match source.next_entry() {
            Ok(Some(_)) => unconsumed = true,
            Ok(None) => break,
            Err(_) => {
                if let Some(error) = source.source_error.take() {
                    return Err(error);
                }
                return Err(StoreError::Corrupt {
                    issue: StoreCorruption::InvalidLegacy {
                        message: "bounded replay legacy source failed while checking exhaustion"
                            .to_owned(),
                    },
                });
            }
        }
    }
    if validation.is_ok() && unconsumed {
        return Err(StoreError::Corrupt {
            issue: StoreCorruption::InvalidLegacy {
                message: "bounded legacy adapter did not consume every legacy entry".to_owned(),
            },
        });
    }
    validation
}

#[allow(clippy::too_many_lines)]
fn collect_facts(store: &Store, replay: &CanonicalReplay) -> Result<ReplayFacts, StoreError> {
    let directory = &store.root_dir;
    let mut record_ids = ExternalSorter::new(directory, replay.budget.clone());
    let mut records = ExternalSorter::new(directory, replay.budget.clone());
    let mut idempotency = ExternalSorter::new(directory, replay.budget.clone());
    let mut claims = ExternalSorter::new(directory, replay.budget.clone());
    let mut headers = ExternalSorter::new(directory, replay.budget.clone());
    let mut revision = crate::revision::CanonicalRevisionAccumulator::new();
    let mut cursor = replay.cursor()?;
    let mut manifest_count = 0;
    let mut record_count = 0;
    let mut first_batch = None;
    let mut unsupported_identity_schema = false;
    let mut genesis_count = 0;
    let mut genesis = None;
    let mut reserved_builtin = false;
    while let Some((file, offset)) = cursor.next_file()? {
        revision
            .push(&file.path, &file.bytes)
            .map_err(|error| StoreError::Corrupt {
                issue: StoreCorruption::InvalidCanonicalPath {
                    path: error.to_string().into_bytes(),
                },
            })?;
        match classify_path(&file.path) {
            PathClass::LegacyEvent | PathClass::LegacyBatch => {}
            PathClass::JournalBatch => {
                let manifest =
                    decode_batch_manifest(&file.bytes).map_err(|error| StoreError::Corrupt {
                        issue: StoreCorruption::InvalidManifest {
                            path: file.path.clone(),
                            message: error.to_string(),
                        },
                    })?;
                if manifest.canonical_path().as_bytes() != file.path {
                    return Err(invalid_file(file.path));
                }
                manifest_count += 1;
                let batch = manifest.batch_id().to_string();
                if first_batch.is_none() {
                    first_batch = Some((
                        manifest.batch_id(),
                        manifest.members().len(),
                        manifest.members().first().map(crate::RecordRef::record_id),
                    ));
                }
                let mut idempotency_key = manifest.actor().as_str().as_bytes().to_vec();
                idempotency_key.push(0);
                idempotency_key.extend_from_slice(manifest.idempotency_key_digest().as_bytes());
                idempotency.push(idempotency_key, batch.as_bytes().to_vec())?;
                let header = fields(&[
                    manifest.actor().as_str().as_bytes(),
                    manifest.request_digest().to_string().as_bytes(),
                    manifest.members().len().to_string().as_bytes(),
                ]);
                headers.push(batch.as_bytes().to_vec(), header)?;
                for member in manifest.members() {
                    let claim = fields(&[
                        batch.as_bytes(),
                        manifest.actor().as_str().as_bytes(),
                        manifest.request_digest().to_string().as_bytes(),
                        member.record_id().to_string().as_bytes(),
                        member.record_schema().as_str().as_bytes(),
                        member.content_digest().to_string().as_bytes(),
                    ]);
                    claims.push(member.path().as_bytes().to_vec(), claim)?;
                }
            }
            PathClass::JournalRecord => {
                let record = decode_record(&file.bytes, &store.registry).map_err(|error| {
                    StoreError::Corrupt {
                        issue: StoreCorruption::InvalidRecord {
                            path: file.path.clone(),
                            message: error.to_string(),
                        },
                    }
                })?;
                if record.canonical_path().as_bytes() != file.path {
                    return Err(invalid_file(file.path));
                }
                record_count += 1;
                record_ids.push(record.record_id.to_string().into_bytes(), file.path.clone())?;
                let mut location = Vec::with_capacity(12);
                location.extend_from_slice(&offset.to_be_bytes());
                location.extend_from_slice(
                    &u32::try_from(file.bytes.len())
                        .expect("record payload is bounded")
                        .to_be_bytes(),
                );
                records.push(file.path.clone(), location)?;
                if matches!(
                    record.domain.as_str(),
                    "wayjournal.identity" | "wayjournal.profile" | "wayjournal.catalog"
                ) {
                    reserved_builtin = true;
                }
                if record.domain.as_str() == "wayjournal.identity"
                    && record.record_schema.as_str() != crate::IDENTITY_SCHEMA_V1
                {
                    unsupported_identity_schema = true;
                }
                if record.domain.as_str() == "wayjournal.identity"
                    && record.record_schema.as_str() == crate::IDENTITY_SCHEMA_V1
                    && record.kind.as_str() == "store.genesis"
                {
                    genesis_count += 1;
                    if genesis.is_none() {
                        genesis = Some((
                            file.path,
                            Location {
                                offset,
                                length: file.bytes.len(),
                            },
                        ));
                    }
                }
            }
            PathClass::InvalidReserved | PathClass::NonCanonical => {
                return Err(invalid_file(file.path));
            }
        }
    }
    Ok(ReplayFacts {
        revision: revision.finish(),
        record_ids: record_ids.finish()?,
        records: records.finish()?,
        idempotency: idempotency.finish()?,
        claims: claims.finish()?,
        headers: headers.finish()?,
        manifest_count,
        record_count,
        first_batch,
        unsupported_identity_schema,
        genesis_count,
        genesis,
        reserved_builtin,
    })
}

fn invalid_file(path: Vec<u8>) -> StoreError {
    StoreError::Corrupt {
        issue: StoreCorruption::InvalidCanonicalPath { path },
    }
}

fn validate_duplicate_record_ids(facts: &SortedFacts) -> Result<(), StoreError> {
    let mut reader = facts.reader()?;
    while let Some((key, first_path)) = reader.take()? {
        let mut paths = vec![first_path];
        while reader
            .current
            .as_ref()
            .is_some_and(|(candidate, _)| *candidate == key)
        {
            paths.push(reader.take()?.expect("current fact").1);
        }
        if paths.len() > 1 {
            let record_id = std::str::from_utf8(&key)
                .ok()
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| invalid_layout(Path::new("."), "invalid record-id fact"))?;
            paths.sort();
            return Err(StoreError::Corrupt {
                issue: StoreCorruption::DuplicateGlobalRecordId { record_id, paths },
            });
        }
    }
    Ok(())
}

fn validate_duplicate_idempotency(facts: &SortedFacts) -> Result<(), StoreError> {
    let mut reader = facts.reader()?;
    while let Some((key, first_batch)) = reader.take()? {
        let mut batch_ids = vec![parse_batch(&first_batch)?];
        while reader
            .current
            .as_ref()
            .is_some_and(|(candidate, _)| *candidate == key)
        {
            let (_, batch) = reader.take()?.expect("current fact");
            batch_ids.push(parse_batch(&batch)?);
        }
        if batch_ids.len() > 1 {
            return Err(StoreError::Corrupt {
                issue: StoreCorruption::GenericOwnership(
                    BatchError::DuplicateIdempotencyOwnership { batch_ids },
                ),
            });
        }
    }
    Ok(())
}

fn parse_batch(bytes: &[u8]) -> Result<BatchId, StoreError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid_layout(Path::new("."), "invalid batch fact"))
}

struct EnrichedStatus {
    path: Vec<u8>,
    claim: Vec<Vec<u8>>,
    location: Option<Location>,
}

fn validate_ownership_and_batches(
    store: &Store,
    replay: &CanonicalReplay,
    facts: &ReplayFacts,
) -> Result<(), StoreError> {
    let mut enriched = ExternalSorter::new(&store.root_dir, replay.budget.clone());
    let mut claims = facts.claims.reader()?;
    let mut records = facts.records.reader()?;
    let mut ownership_issue = None;
    loop {
        match (claims.current.as_ref(), records.current.as_ref()) {
            (None, None) => break,
            (Some((claim_path, _)), Some((record_path, _))) => match claim_path.cmp(record_path) {
                Ordering::Less => {
                    let (path, value) = claims.take()?.expect("claim");
                    push_enriched(&mut enriched, &path, &value, None)?;
                }
                Ordering::Greater => {
                    let (path, _) = records.take()?.expect("record");
                    if ownership_issue.is_none() {
                        ownership_issue = Some(BatchError::UnownedRecord { path });
                    }
                }
                Ordering::Equal => {
                    let path = claim_path.clone();
                    let (_, location_value) = records.take()?.expect("record");
                    let (offset, length) = decode_location(&location_value)?;
                    let mut owners = 0_usize;
                    while claims
                        .current
                        .as_ref()
                        .is_some_and(|(candidate, _)| *candidate == path)
                    {
                        let (_, value) = claims.take()?.expect("claim");
                        push_enriched(
                            &mut enriched,
                            &path,
                            &value,
                            Some(Location { offset, length }),
                        )?;
                        owners += 1;
                    }
                    if owners > 1 && ownership_issue.is_none() {
                        ownership_issue = Some(BatchError::MultiplyOwnedRecord { path });
                    }
                }
            },
            (Some(_), None) => {
                let (path, value) = claims.take()?.expect("claim");
                push_enriched(&mut enriched, &path, &value, None)?;
            }
            (None, Some(_)) => {
                let (path, _) = records.take()?.expect("record");
                if ownership_issue.is_none() {
                    ownership_issue = Some(BatchError::UnownedRecord { path });
                }
            }
        }
    }
    let enriched = enriched.finish()?;
    validate_batches(store, replay, &facts.headers, &enriched)?;
    if let Some(error) = ownership_issue {
        return Err(StoreError::Corrupt {
            issue: StoreCorruption::GenericOwnership(error),
        });
    }
    Ok(())
}

fn push_enriched(
    sorter: &mut ExternalSorter<'_>,
    path: &[u8],
    claim: &[u8],
    location: Option<Location>,
) -> Result<(), StoreError> {
    let claim_fields = parse_fields(claim, 6)?;
    let batch = &claim_fields[0];
    let mut key = batch.clone();
    key.push(0);
    key.extend_from_slice(path);
    let mut value = fields(&[
        path,
        &claim_fields[1],
        &claim_fields[2],
        &claim_fields[3],
        &claim_fields[4],
        &claim_fields[5],
    ]);
    match location {
        Some(location) => {
            value.push(1);
            value.extend_from_slice(&location.offset.to_be_bytes());
            value.extend_from_slice(
                &u32::try_from(location.length)
                    .expect("record payload is bounded")
                    .to_be_bytes(),
            );
        }
        None => value.push(0),
    }
    sorter.push(key, value)
}

fn validate_batches(
    store: &Store,
    replay: &CanonicalReplay,
    headers: &SortedFacts,
    enriched: &SortedFacts,
) -> Result<(), StoreError> {
    let mut headers = headers.reader()?;
    let mut statuses = enriched.reader()?;
    while let Some((batch_key, header)) = headers.take()? {
        let header = parse_fields(&header, 3)?;
        let actor = std::str::from_utf8(&header[0])
            .map_err(|_| invalid_layout(Path::new("."), "invalid actor fact"))?;
        let expected_request = parse_digest(&header[1])?;
        let member_count = parse_usize(&header[2])?;
        let mut batch_statuses = Vec::new();
        while statuses.current.as_ref().is_some_and(|(key, _)| {
            key.starts_with(&batch_key) && key.get(batch_key.len()) == Some(&0)
        }) {
            let (_, value) = statuses.take()?.expect("status");
            batch_statuses.push(parse_status(value)?);
        }
        if batch_statuses.len() != member_count {
            return Err(invalid_layout(
                Path::new("."),
                "manifest status count mismatch",
            ));
        }
        if let Some(status) = batch_statuses
            .iter()
            .find(|status| status.location.is_none())
        {
            return Err(StoreError::Corrupt {
                issue: StoreCorruption::GenericOwnership(BatchError::OwnershipMissingMember {
                    path: String::from_utf8_lossy(&status.path).into_owned(),
                }),
            });
        }
        let batch_id = parse_batch(&batch_key)?;
        let mut request = crate::batch::RequestDigestAccumulator::new();
        for status in batch_statuses {
            let location = status.location.expect("checked location");
            let file = replay.read_at(location.offset, location.length, status.path.clone())?;
            if crate::batch::content_digest(&file.bytes) != status.content_digest {
                return ownership(BatchError::MemberDigestMismatch {
                    path: String::from_utf8_lossy(&status.path).into_owned(),
                });
            }
            let record = decode_record(&file.bytes, &store.registry).map_err(|source| {
                StoreError::Corrupt {
                    issue: StoreCorruption::GenericOwnership(BatchError::InvalidStoredRecord {
                        path: status.path.clone(),
                        source,
                    }),
                }
            })?;
            if record.canonical_path().as_bytes() != status.path
                || record.record_id != status.record_id
                || record.record_schema.as_str() != status.record_schema
            {
                return ownership(BatchError::MemberIdentityMismatch {
                    path: String::from_utf8_lossy(&status.path).into_owned(),
                });
            }
            if record.batch_id != batch_id {
                return ownership(BatchError::MemberBatchMismatch {
                    path: String::from_utf8_lossy(&status.path).into_owned(),
                });
            }
            if record.actor.as_str() != actor {
                return ownership(BatchError::MemberActorMismatch {
                    path: String::from_utf8_lossy(&status.path).into_owned(),
                });
            }
            request.push(&status.path, &file.bytes);
        }
        if request.finish() != expected_request {
            return ownership(BatchError::RequestDigestMismatch);
        }
    }
    if statuses.current.is_some() {
        return Err(invalid_layout(Path::new("."), "unowned batch status facts"));
    }
    Ok(())
}

fn ownership(error: BatchError) -> Result<(), StoreError> {
    Err(StoreError::Corrupt {
        issue: StoreCorruption::GenericOwnership(error),
    })
}

struct Status {
    path: Vec<u8>,
    record_id: RecordId,
    record_schema: String,
    content_digest: Digest,
    location: Option<Location>,
}

fn parse_status(value: Vec<u8>) -> Result<Status, StoreError> {
    let enriched = parse_enriched_status(value)?;
    let record_id = std::str::from_utf8(&enriched.claim[3])
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid_layout(Path::new("."), "invalid record-id claim"))?;
    let record_schema = std::str::from_utf8(&enriched.claim[4])
        .map_err(|_| invalid_layout(Path::new("."), "invalid record-schema claim"))?
        .to_owned();
    let content_digest = parse_digest(&enriched.claim[5])?;
    Ok(Status {
        path: enriched.path,
        record_id,
        record_schema,
        content_digest,
        location: enriched.location,
    })
}

fn parse_enriched_status(mut value: Vec<u8>) -> Result<EnrichedStatus, StoreError> {
    let mut cursor = 0_usize;
    let mut values = Vec::with_capacity(6);
    for _ in 0..6 {
        if cursor + 2 > value.len() {
            return Err(invalid_layout(Path::new("."), "truncated enriched status"));
        }
        let length =
            u16::from_be_bytes(value[cursor..cursor + 2].try_into().expect("two bytes")) as usize;
        cursor += 2;
        if cursor + length > value.len() {
            return Err(invalid_layout(Path::new("."), "truncated enriched status"));
        }
        values.push(value[cursor..cursor + length].to_vec());
        cursor += length;
    }
    let tail = value.split_off(cursor);
    let location = match tail.as_slice() {
        [0] => None,
        [1, rest @ ..] if rest.len() == 12 => Some(Location {
            offset: u64::from_be_bytes(rest[..8].try_into().expect("eight bytes")),
            length: u32::from_be_bytes(rest[8..].try_into().expect("four bytes")) as usize,
        }),
        _ => {
            return Err(invalid_layout(
                Path::new("."),
                "invalid enriched status location",
            ));
        }
    };
    Ok(EnrichedStatus {
        path: values[0].clone(),
        claim: values,
        location,
    })
}

#[cfg(test)]
thread_local! {
    static RETAINED_FOLD_OPERATIONS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
fn reset_fold_retention_for_test() {
    RETAINED_FOLD_OPERATIONS.with(|value| value.set(0));
}

#[cfg(test)]
fn retained_fold_operations_for_test() -> usize {
    RETAINED_FOLD_OPERATIONS.with(Cell::get)
}

#[cfg(test)]
fn observe_fold_retention_for_test(operations: usize) {
    RETAINED_FOLD_OPERATIONS.with(|value| value.set(value.get().max(operations)));
}

struct FoldSource {
    path: Vec<u8>,
    location: Location,
}

#[derive(Default)]
struct FoldSummary {
    count: usize,
    edges: usize,
    catalog_target: Option<crate::LogicalStoreId>,
    catalog_wrong_target: Option<crate::LogicalStoreId>,
}

impl FoldSummary {
    fn observe(&mut self, domain: &str, operation: &crate::DomainOperation) {
        self.count = self.count.saturating_add(1);
        self.edges = self
            .edges
            .saturating_add(crate::CausalNode::parents(operation).len());
        if domain != "wayjournal.catalog" {
            return;
        }
        if let Some(expected) = self.catalog_target.as_ref() {
            if self.catalog_wrong_target.is_none()
                && operation.target().is_some_and(|actual| actual != expected)
            {
                self.catalog_wrong_target = operation.target().cloned();
            }
        } else {
            self.catalog_target = operation.target().cloned();
        }
    }

    const fn within_causal_limits(&self) -> bool {
        self.count <= crate::MAX_CAUSAL_OPERATIONS && self.edges <= crate::MAX_CAUSAL_EDGES
    }
}

fn validate_builtin_folds_bounded(
    store: &Store,
    replay: &CanonicalReplay,
) -> Result<(), StoreError> {
    // Collected validation converts every operation before folding any group. Preserve that
    // error precedence without retaining the converted payloads.
    validate_builtin_operation_payloads(store, replay)?;

    let mut cursor = replay.cursor()?;
    let mut group: Option<(String, String)> = None;
    let mut operations = Vec::new();
    let mut sources = Vec::new();
    let mut summary = FoldSummary::default();
    while let Some((file, offset)) = cursor.next_file()? {
        if classify_path(&file.path) != PathClass::JournalRecord {
            continue;
        }
        let record = decode_builtin_record(store, &file)?;
        if !matches!(
            record.domain.as_str(),
            "wayjournal.profile" | "wayjournal.catalog"
        ) {
            continue;
        }
        let key = (record.domain.to_string(), record.entity_id.to_string());
        if group.as_ref().is_some_and(|current| *current != key) {
            finish_fold(
                store,
                replay,
                group.take().expect("fold group"),
                &operations,
                &sources,
                std::mem::take(&mut summary),
            )?;
            operations.clear();
            sources.clear();
        }
        group = Some(key.clone());
        let operation = operation_from_record(record, &key)?;
        summary.observe(&key.0, &operation);
        if summary.within_causal_limits() {
            let source = sources.len();
            operations.push(operation.into_header(source));
            sources.push(FoldSource {
                path: file.path,
                location: Location {
                    offset,
                    length: file.bytes.len(),
                },
            });
            #[cfg(test)]
            observe_fold_retention_for_test(operations.len());
        }
    }
    if let Some(group) = group {
        finish_fold(store, replay, group, &operations, &sources, summary)?;
    }
    Ok(())
}

fn validate_builtin_operation_payloads(
    store: &Store,
    replay: &CanonicalReplay,
) -> Result<(), StoreError> {
    let mut cursor = replay.cursor()?;
    while let Some((file, _)) = cursor.next_file()? {
        if classify_path(&file.path) != PathClass::JournalRecord {
            continue;
        }
        let record = decode_builtin_record(store, &file)?;
        if !matches!(
            record.domain.as_str(),
            "wayjournal.profile" | "wayjournal.catalog"
        ) {
            continue;
        }
        let key = (record.domain.to_string(), record.entity_id.to_string());
        operation_from_record(record, &key)?;
    }
    Ok(())
}

fn decode_builtin_record(store: &Store, file: &RawFile) -> Result<crate::Record, StoreError> {
    decode_record(&file.bytes, &store.registry).map_err(|error| StoreError::Corrupt {
        issue: StoreCorruption::InvalidRecord {
            path: file.path.clone(),
            message: error.to_string(),
        },
    })
}

fn operation_from_record(
    record: crate::Record,
    (domain, entity): &(String, String),
) -> Result<crate::DomainOperation, StoreError> {
    crate::DomainOperation::try_from(record).map_err(|error| StoreError::Corrupt {
        issue: StoreCorruption::InvalidDomainFold {
            domain: domain.clone(),
            entity: entity.clone(),
            message: error.to_string(),
        },
    })
}

fn finish_fold(
    store: &Store,
    replay: &CanonicalReplay,
    (domain, entity): (String, String),
    operations: &[crate::domains::DomainOperationHeader],
    sources: &[FoldSource],
    summary: FoldSummary,
) -> Result<(), StoreError> {
    if domain == "wayjournal.catalog" {
        let Some(expected) = summary.catalog_target else {
            return Err(StoreError::Corrupt {
                issue: StoreCorruption::InvalidDomainFold {
                    domain,
                    entity,
                    message: crate::FoldError::WrongEntity.to_string(),
                },
            });
        };
        if let Some(actual) = summary.catalog_wrong_target {
            return Err(StoreError::Corrupt {
                issue: StoreCorruption::InvalidDomainFold {
                    domain,
                    entity,
                    message: crate::FoldError::WrongTarget { expected, actual }.to_string(),
                },
            });
        }
    }
    let causal_limit = if summary.count > crate::MAX_CAUSAL_OPERATIONS {
        Some(crate::CausalError::TooManyOperations {
            maximum: crate::MAX_CAUSAL_OPERATIONS,
            actual: summary.count,
        })
    } else if summary.edges > crate::MAX_CAUSAL_EDGES {
        Some(crate::CausalError::TooManyEdges {
            maximum: crate::MAX_CAUSAL_EDGES,
            actual: summary.edges,
        })
    } else {
        None
    };
    if let Some(error) = causal_limit {
        return Err(StoreError::Corrupt {
            issue: StoreCorruption::InvalidDomainFold {
                domain,
                entity,
                message: error.to_string(),
            },
        });
    }

    let result = crate::domains::validate_loaded_builtin_fold(operations, |source| {
        let source = &sources[source];
        let file = replay.read_at(
            source.location.offset,
            source.location.length,
            source.path.clone(),
        )?;
        let record = decode_builtin_record(store, &file)?;
        operation_from_record(record, &(domain.clone(), entity.clone()))
    });
    match result {
        Ok(()) => Ok(()),
        Err(crate::domains::FoldLoadError::Load(error)) => Err(error),
        Err(crate::domains::FoldLoadError::Fold(error)) => Err(StoreError::Corrupt {
            issue: StoreCorruption::InvalidDomainFold {
                domain,
                entity,
                message: error.to_string(),
            },
        }),
    }
}

fn fields(values: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    for value in values {
        output.extend_from_slice(
            &u16::try_from(value.len())
                .expect("semantic field is bounded")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
    output
}

fn parse_fields(value: &[u8], expected: usize) -> Result<Vec<Vec<u8>>, StoreError> {
    let mut cursor = 0;
    let mut output = Vec::with_capacity(expected);
    for _ in 0..expected {
        if cursor + 2 > value.len() {
            return Err(invalid_layout(Path::new("."), "truncated semantic fields"));
        }
        let length =
            u16::from_be_bytes(value[cursor..cursor + 2].try_into().expect("two bytes")) as usize;
        cursor += 2;
        if cursor + length > value.len() {
            return Err(invalid_layout(Path::new("."), "truncated semantic fields"));
        }
        output.push(value[cursor..cursor + length].to_vec());
        cursor += length;
    }
    if cursor != value.len() {
        return Err(invalid_layout(Path::new("."), "trailing semantic fields"));
    }
    Ok(output)
}

fn parse_digest(bytes: &[u8]) -> Result<Digest, StoreError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| Digest::parse(value).ok())
        .ok_or_else(|| invalid_layout(Path::new("."), "invalid digest fact"))
}

fn parse_usize(bytes: &[u8]) -> Result<usize, StoreError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid_layout(Path::new("."), "invalid count fact"))
}

#[cfg(test)]
pub(super) fn validate_raw_files_bounded(
    store: &Store,
    files: &[RawFile],
) -> Result<ValidatedStoreState, StoreError> {
    let mut builder = replay_builder(store)?;
    for file in files {
        builder.push(file.clone())?;
    }
    let replay = builder.finish()?;
    validate_bounded_replay(store, &replay)
}

#[cfg(test)]
mod semantic_parity_tests {
    use super::*;
    use crate::{
        ActorId, LegacyStreamingError, PreparedBatch, Record, StoreCorruption, prepare_batch,
        wayjournal_domain_registry,
    };
    use serde_json::json;
    use std::{fs, sync::Arc};

    #[derive(Debug)]
    struct BoundedNoLegacy;
    impl crate::LegacyStoreAdapter for BoundedNoLegacy {
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
            while source
                .next_entry()
                .map_err(LegacyStreamingError::Source)?
                .is_some()
            {}
            Ok(())
        }
    }

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wayjournal-semantic-parity-{label}-{}",
                uuid::Uuid::now_v7()
            ));
            fs::create_dir(&path).expect("test root");
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn process_high_water_bytes() -> u64 {
        fs::read_to_string("/proc/self/status")
            .expect("procfs status")
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .expect("VmHWM value")
            .parse::<u64>()
            .expect("VmHWM integer")
            * 1024
    }

    fn record(
        domain: &str,
        kind: &str,
        record_id: &str,
        entity: &str,
        batch: &str,
        parents: &[&str],
        payload: serde_json::Value,
    ) -> Record {
        Record {
            record_schema: format!("{domain}/v1").parse().unwrap(),
            domain: domain.parse().unwrap(),
            kind: kind.parse().unwrap(),
            record_id: record_id.parse().unwrap(),
            entity_id: entity.parse().unwrap(),
            batch_id: batch.parse().unwrap(),
            actor: ActorId::parse("human:robin").unwrap(),
            occurred_at: "2026-08-12T13:00:00Z".parse().unwrap(),
            recorded_at: "2026-08-12T13:00:01Z".parse().unwrap(),
            parents: parents.iter().map(|value| value.parse().unwrap()).collect(),
            payload,
        }
    }

    fn genesis() -> Record {
        record(
            "wayjournal.identity",
            "store.genesis",
            "01913f1d-8e2a-7c30-8f4a-426614174011",
            "01913f1d-8e2a-7c30-8f4a-426614174010",
            "01913f1d-8e2a-7c30-8f4a-426614174012",
            &[],
            json!({"store_kind":"wayjournal.personal","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"}),
        )
    }

    fn profile(record_id: &str, entity: &str, batch: &str, parents: &[&str]) -> Record {
        record(
            "wayjournal.profile",
            "profile.display_name.set",
            record_id,
            entity,
            batch,
            parents,
            json!({"value":"name"}),
        )
    }

    fn catalog(record_id: &str, batch: &str, parents: &[&str]) -> Record {
        record(
            "wayjournal.catalog",
            "catalog.name.set",
            record_id,
            "01913f1d-8e2a-7c30-8f4a-426614174010",
            batch,
            parents,
            json!({
                "target": {
                    "store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010",
                    "genesis_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                },
                "value":"name"
            }),
        )
    }

    fn raw(prepared: &PreparedBatch) -> Vec<RawFile> {
        let mut files = prepared
            .records()
            .iter()
            .map(|record| RawFile {
                path: record.path().as_bytes().to_vec(),
                bytes: record.bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        files.push(RawFile {
            path: prepared.manifest_path().as_bytes().to_vec(),
            bytes: prepared.manifest_bytes().to_vec(),
        });
        files
    }

    fn corruption<T>(result: Result<T, StoreError>) -> StoreCorruption {
        match result {
            Err(StoreError::Corrupt { issue }) => issue,
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("corrupt case was accepted"),
        }
    }

    #[test]
    fn external_sorter_forced_multi_run_merge_matches_in_memory_order() {
        let directory = TestDir::new("external-sorter-multi-run");
        let store = Store::open_mode(
            &directory.0,
            wayjournal_domain_registry().unwrap(),
            Arc::new(BoundedNoLegacy),
            true,
        )
        .unwrap();
        let budget = ReplayTempBudget::new(MAX_REPLAY_TEMPORARY_BYTES);
        let mut sorter = ExternalSorter::with_run_bytes(&store.root_dir, budget.clone(), 32);
        let input = [
            (b"key-c".to_vec(), b"value-2".to_vec()),
            (b"key-a".to_vec(), b"value-3".to_vec()),
            (b"key-b".to_vec(), b"value-1".to_vec()),
            (b"key-a".to_vec(), b"value-1".to_vec()),
            (b"key-c".to_vec(), b"value-1".to_vec()),
            (b"key-a".to_vec(), b"value-2".to_vec()),
        ];
        for (key, value) in &input {
            sorter.push(key.clone(), value.clone()).unwrap();
        }
        assert!(sorter.runs.len() > 1, "test must force multiple spill runs");
        let facts = sorter.finish().unwrap();
        let mut reader = facts.reader().unwrap();
        let mut actual = Vec::new();
        while let Some(fact) = reader.take().unwrap() {
            actual.push(fact);
        }
        let mut expected = input.to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected);
        let framed_input_bytes = input
            .iter()
            .map(|(key, value)| key.len() + value.len() + 8)
            .sum::<usize>();
        assert_eq!(
            budget.used(),
            u64::try_from(framed_input_bytes * 2).unwrap()
        );
        assert!(budget.used() <= MAX_REPLAY_TEMPORARY_BYTES);
    }

    #[test]
    fn temporary_amplification_limit_is_enforced_during_merge() {
        let directory = TestDir::new("external-sorter-amplification-limit");
        let store = Store::open_mode(
            &directory.0,
            wayjournal_domain_registry().unwrap(),
            Arc::new(BoundedNoLegacy),
            true,
        )
        .unwrap();
        let input = [
            (b"key-b".to_vec(), b"value-2".to_vec()),
            (b"key-a".to_vec(), b"value-1".to_vec()),
        ];
        let one_copy = input
            .iter()
            .map(|(key, value)| key.len() + value.len() + 8)
            .sum::<usize>();
        let budget = ReplayTempBudget::new(u64::try_from(one_copy).unwrap());
        let mut sorter = ExternalSorter::with_run_bytes(&store.root_dir, budget.clone(), 1);
        for (key, value) in input {
            sorter.push(key, value).unwrap();
        }
        let Err(error) = sorter.finish() else {
            panic!("merge amplification exceeded its budget");
        };
        assert!(matches!(
            error,
            StoreError::InvalidLayout { message, .. }
                if message == "semantic replay exceeds temporary-byte amplification limit"
        ));
        assert_eq!(budget.used(), u64::try_from(one_copy).unwrap());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn exact_operation_limit_large_fold_matches_collected_validation() {
        const RECORDS_PER_BATCH: usize = 64;
        const PREVIOUS_WORKING_SET_CAP: usize = 32 * 1024 * 1024;
        let registry = wayjournal_domain_registry().unwrap();
        let genesis_batch = prepare_batch(&[genesis()], "genesis", &registry).unwrap();
        let mut files = raw(&genesis_batch);
        let entity = "01913f1d-8e2a-7c30-8f4a-426614175101";
        let value = "\u{10ffff}".repeat(2048);
        let mut encoded_group_bytes = 0_usize;
        for batch_start in (0..crate::MAX_CAUSAL_OPERATIONS).step_by(RECORDS_PER_BATCH) {
            let batch = format!("01913f1d-8e2a-7c30-8f4a-426615{batch_start:06x}");
            let records = (batch_start..batch_start + RECORDS_PER_BATCH)
                .map(|ordinal| {
                    record(
                        "wayjournal.profile",
                        "profile.description.set",
                        &format!("01913f1d-8e2a-7c30-8f4a-42661419{ordinal:04x}"),
                        entity,
                        &batch,
                        &[],
                        json!({"value": value}),
                    )
                })
                .collect::<Vec<_>>();
            let prepared = prepare_batch(
                &records,
                &format!("large-exact-fold-{batch_start}"),
                &registry,
            )
            .unwrap();
            encoded_group_bytes += prepared
                .records()
                .iter()
                .map(|record| record.bytes().len())
                .sum::<usize>();
            files.extend(raw(&prepared));
        }
        assert!(encoded_group_bytes > PREVIOUS_WORKING_SET_CAP);
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let directory = TestDir::new("large-exact-fold");
        let store =
            Store::open_mode(&directory.0, registry, Arc::new(BoundedNoLegacy), true).unwrap();

        let collected = super::super::scan_collected(&store, &files, Vec::new()).unwrap();
        let collected_revision = collected.revision();
        let collected_identity = collected.identity().cloned();
        drop(collected);
        let before = process_high_water_bytes();
        let bounded = validate_raw_files_bounded(&store, &files).unwrap();
        let growth = process_high_water_bytes().saturating_sub(before);
        eprintln!("large exact fold VmHWM growth: {growth} bytes");
        assert_eq!(bounded.revision(), collected_revision);
        assert_eq!(bounded.identity(), collected_identity.as_ref());
        assert!(
            growth < 256 * 1024 * 1024,
            "large exact fold retained {growth} bytes"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn same_entity_edge_overflow_matches_collected_before_retaining_every_operation() {
        const OPERATIONS: usize = 17;
        const PARENTS: usize = 4096;
        let registry = wayjournal_domain_registry().unwrap();
        let genesis_batch = prepare_batch(&[genesis()], "genesis", &registry).unwrap();
        let mut files = raw(&genesis_batch);
        let parents = (0..PARENTS)
            .map(|ordinal| format!("01913f1d-8e2a-7c30-8f4a-{ordinal:012x}"))
            .collect::<Vec<_>>();
        let parent_refs = parents.iter().map(String::as_str).collect::<Vec<_>>();
        let batch = "01913f1d-8e2a-7c30-8f4a-426614175000";
        let entity = "01913f1d-8e2a-7c30-8f4a-426614175001";
        let records = (0..OPERATIONS)
            .map(|ordinal| {
                profile(
                    &format!("01913f1d-8e2a-7c30-8f4a-42661418{ordinal:04x}"),
                    entity,
                    batch,
                    &parent_refs,
                )
            })
            .collect::<Vec<_>>();
        let prepared = prepare_batch(&records, "edge-overflow", &registry).unwrap();
        files.extend(raw(&prepared));
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let directory = TestDir::new("same-entity-edge-overflow");
        let store =
            Store::open_mode(&directory.0, registry, Arc::new(BoundedNoLegacy), true).unwrap();
        reset_fold_retention_for_test();
        let collected = corruption(super::super::scan_collected(&store, &files, Vec::new()));
        let bounded = corruption(validate_raw_files_bounded(&store, &files));
        let expected = StoreCorruption::InvalidDomainFold {
            domain: "wayjournal.profile".to_owned(),
            entity: entity.to_owned(),
            message: crate::CausalError::TooManyEdges {
                maximum: crate::MAX_CAUSAL_EDGES,
                actual: OPERATIONS * PARENTS,
            }
            .to_string(),
        };
        assert_eq!(collected, expected);
        assert_eq!(bounded, expected);
        assert!(
            retained_fold_operations_for_test() < OPERATIONS,
            "bounded replay retained the whole rejected group"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn successful_revision_and_identity_match_collected_validation() {
        let registry = wayjournal_domain_registry().unwrap();
        let genesis_batch = prepare_batch(&[genesis()], "genesis", &registry).unwrap();
        let profile_batch = prepare_batch(
            &[profile(
                "01913f1d-8e2a-7c30-8f4a-426614174081",
                "01913f1d-8e2a-7c30-8f4a-426614174020",
                "01913f1d-8e2a-7c30-8f4a-426614174082",
                &[],
            )],
            "successful-parity",
            &registry,
        )
        .unwrap();
        let mut files = raw(&genesis_batch);
        files.extend(raw(&profile_batch));
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let directory = TestDir::new("successful-summary-parity");
        let store =
            Store::open_mode(&directory.0, registry, Arc::new(BoundedNoLegacy), true).unwrap();
        let collected = super::super::scan_collected(&store, &files, Vec::new()).unwrap();
        let bounded = validate_raw_files_bounded(&store, &files).unwrap();
        assert_eq!(bounded.revision(), collected.revision());
        assert_eq!(bounded.identity(), collected.identity());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn bounded_semantic_validation_matches_collected_validation() {
        let registry = wayjournal_domain_registry().unwrap();
        let genesis_batch = prepare_batch(&[genesis()], "genesis", &registry).unwrap();
        let base = raw(&genesis_batch);
        let entity_b = "01913f1d-8e2a-7c30-8f4a-426614174020";

        let duplicate_uuid = prepare_batch(
            &[profile(
                "01913f1d-8e2a-7c30-8f4a-426614174011",
                entity_b,
                "01913f1d-8e2a-7c30-8f4a-426614174022",
                &[],
            )],
            "duplicate-uuid",
            &registry,
        )
        .unwrap();
        let idem_a = prepare_batch(
            &[profile(
                "01913f1d-8e2a-7c30-8f4a-426614174031",
                entity_b,
                "01913f1d-8e2a-7c30-8f4a-426614174032",
                &[],
            )],
            "same-idempotency",
            &registry,
        )
        .unwrap();
        let idem_b = prepare_batch(
            &[profile(
                "01913f1d-8e2a-7c30-8f4a-426614174041",
                entity_b,
                "01913f1d-8e2a-7c30-8f4a-426614174042",
                &[],
            )],
            "same-idempotency",
            &registry,
        )
        .unwrap();
        let multiply_record = profile(
            "01913f1d-8e2a-7c30-8f4a-426614174051",
            entity_b,
            "01913f1d-8e2a-7c30-8f4a-426614174052",
            &[],
        );
        let owner_a =
            prepare_batch(std::slice::from_ref(&multiply_record), "owner-a", &registry).unwrap();
        let mut second_claim = multiply_record;
        second_claim.batch_id = "01913f1d-8e2a-7c30-8f4a-426614174053".parse().unwrap();
        let owner_b = prepare_batch(&[second_claim], "owner-b", &registry).unwrap();
        // Same batch identity and member, distinct idempotency owner: retain only owner-b's
        // manifest alongside owner-a's record to exercise the multiply-claim semantic branch.
        let profile_bad = prepare_batch(
            &[profile(
                "01913f1d-8e2a-7c30-8f4a-426614174061",
                entity_b,
                "01913f1d-8e2a-7c30-8f4a-426614174062",
                &["01913f1d-8e2a-7c30-8f4a-426614174060"],
            )],
            "bad-profile",
            &registry,
        )
        .unwrap();
        let catalog_bad = prepare_batch(
            &[catalog(
                "01913f1d-8e2a-7c30-8f4a-426614174071",
                "01913f1d-8e2a-7c30-8f4a-426614174072",
                &["01913f1d-8e2a-7c30-8f4a-426614174070"],
            )],
            "bad-catalog",
            &registry,
        )
        .unwrap();
        let resolution_batch = "01913f1d-8e2a-7c30-8f4a-426614174092";
        let resolution_a = "01913f1d-8e2a-7c30-8f4a-426614174090";
        let resolution_b = "01913f1d-8e2a-7c30-8f4a-426614174091";
        let invalid_resolution = prepare_batch(
            &[
                profile(resolution_a, entity_b, resolution_batch, &[]),
                profile(resolution_b, entity_b, resolution_batch, &[]),
                record(
                    "wayjournal.profile",
                    "profile.display_name.resolve",
                    "01913f1d-8e2a-7c30-8f4a-426614174093",
                    entity_b,
                    resolution_batch,
                    &[resolution_a, resolution_b],
                    json!({"candidates":[resolution_a],"value":"resolved"}),
                ),
            ],
            "invalid-resolution",
            &registry,
        )
        .unwrap();
        let add_id = "01913f1d-8e2a-7c30-8f4a-4266141740a0";
        let invalid_remove = prepare_batch(
            &[
                record(
                    "wayjournal.profile",
                    "profile.alias.add",
                    add_id,
                    entity_b,
                    "01913f1d-8e2a-7c30-8f4a-4266141740a2",
                    &[],
                    json!({"key":"alias","value":"one"}),
                ),
                record(
                    "wayjournal.profile",
                    "profile.alias.remove",
                    "01913f1d-8e2a-7c30-8f4a-4266141740a3",
                    entity_b,
                    "01913f1d-8e2a-7c30-8f4a-4266141740a2",
                    &[add_id],
                    json!({
                        "adds":["01913f1d-8e2a-7c30-8f4a-4266141740a1"],
                        "key":"alias"
                    }),
                ),
            ],
            "invalid-remove",
            &registry,
        )
        .unwrap();
        let wrong_catalog_target = prepare_batch(
            &[
                catalog(
                    "01913f1d-8e2a-7c30-8f4a-4266141740b0",
                    "01913f1d-8e2a-7c30-8f4a-4266141740b2",
                    &[],
                ),
                record(
                    "wayjournal.catalog",
                    "catalog.name.set",
                    "01913f1d-8e2a-7c30-8f4a-4266141740b1",
                    "01913f1d-8e2a-7c30-8f4a-426614174010",
                    "01913f1d-8e2a-7c30-8f4a-4266141740b2",
                    &[],
                    json!({
                        "target": {
                            "store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174099",
                            "genesis_fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        },
                        "value":"other"
                    }),
                ),
            ],
            "wrong-catalog-target",
            &registry,
        )
        .unwrap();

        let mut cases = Vec::<(&str, bool, Vec<RawFile>)>::new();
        let extend = |extra: &PreparedBatch| {
            let mut files = base.clone();
            files.extend(raw(extra));
            files
        };
        cases.push((
            "duplicate-global-record-uuid",
            true,
            extend(&duplicate_uuid),
        ));
        let mut duplicate_idem = base.clone();
        duplicate_idem.extend(raw(&idem_a));
        duplicate_idem.extend(raw(&idem_b));
        cases.push(("duplicate-actor-idempotency-owner", true, duplicate_idem));
        let mut missing = base.clone();
        missing.push(RawFile {
            path: idem_a.manifest_path().as_bytes().to_vec(),
            bytes: idem_a.manifest_bytes().to_vec(),
        });
        cases.push(("missing-member", true, missing));
        let mut multiply = base.clone();
        multiply.extend(raw(&owner_a));
        multiply.push(RawFile {
            path: owner_b.manifest_path().as_bytes().to_vec(),
            bytes: owner_b.manifest_bytes().to_vec(),
        });
        cases.push(("multiply-owned-member", true, multiply));
        cases.push(("invalid-genesis", true, raw(&idem_a)));
        cases.push(("reserved-domain-misuse", false, extend(&idem_a)));
        cases.push(("invalid-profile-fold", true, extend(&profile_bad)));
        cases.push(("invalid-catalog-fold", true, extend(&catalog_bad)));
        cases.push((
            "invalid-profile-resolution",
            true,
            extend(&invalid_resolution),
        ));
        cases.push(("invalid-profile-remove", true, extend(&invalid_remove)));
        cases.push(("wrong-catalog-target", true, extend(&wrong_catalog_target)));

        for (name, strict, mut files) in cases {
            files.sort_by(|left, right| left.path.cmp(&right.path));
            let directory = TestDir::new(name);
            let store = Store::open_mode(&directory.0, registry, Arc::new(BoundedNoLegacy), strict)
                .unwrap();
            let collected = corruption(super::super::scan_collected(&store, &files, Vec::new()));
            let bounded = corruption(validate_raw_files_bounded(&store, &files));
            assert_eq!(bounded, collected, "semantic parity case {name}");
        }
    }
}
