use std::{
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use wayjournal_core::{
    ActorId, DependencyStore, LegacyEntry, LegacyStoreAdapter, LogicalStoreId, ProofCache,
    ProofCacheDisposition, ProofCacheError, ProofCacheInsert, ProofCacheLookup, QualifiedEntityRef,
    Record, Store, StoreRevisionRef, prepare_batch, wayjournal_domain_registry,
};

const TRUST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[derive(Debug)]
struct NoLegacy;
impl LegacyStoreAdapter for NoLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
    }
}

struct TestDir(PathBuf);
impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wayjournal-s5-cache-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("JSON");
    bytes.push(b'\n');
    bytes
}

fn recompute_fixture_proof_id(proof: &Value) -> String {
    let fields = [
        proof["schema"].as_str().expect("schema"),
        proof["subject"]["store"]["store_uuid"]
            .as_str()
            .expect("store UUID"),
        proof["subject"]["store"]["genesis_fingerprint"]
            .as_str()
            .expect("genesis"),
        proof["subject"]["domain"].as_str().expect("domain"),
        proof["subject"]["entity_id"].as_str().expect("entity"),
        proof["record_id"].as_str().expect("record"),
        proof["source_revision"]["algorithm"]
            .as_str()
            .expect("algorithm"),
        proof["source_revision"]["digest"]
            .as_str()
            .expect("revision"),
        proof["local_trust_binding"].as_str().expect("trust"),
        proof["observed_at"].as_str().expect("observation"),
    ];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"wayjournal-proof-v1\0");
    for field in fields {
        hasher.update(
            &u64::try_from(field.len())
                .expect("bounded field")
                .to_be_bytes(),
        );
        hasher.update(field.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn record(
    store_uuid: &str,
    domain: &str,
    kind: &str,
    record_id: &str,
    batch_id: &str,
    payload: Value,
) -> Record {
    Record {
        record_schema: format!("{domain}/v1").parse().expect("schema"),
        domain: domain.parse().expect("domain"),
        kind: kind.parse().expect("kind"),
        record_id: record_id.parse().expect("record id"),
        entity_id: store_uuid.parse().expect("entity id"),
        batch_id: batch_id.parse().expect("batch id"),
        actor: ActorId::parse("human:cache-test").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("timestamp"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("timestamp"),
        parents: Vec::new(),
        payload,
    }
}

struct StoreFixture {
    directory: TestDir,
    store: Store,
    logical_store: LogicalStoreId,
    profile_id: wayjournal_core::RecordId,
}

fn initialized_store(label: &str, store_uuid: &str) -> StoreFixture {
    let directory = TestDir::new(label);
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(directory.path(), registry, Arc::new(NoLegacy)).expect("store");
    let genesis = record(
        store_uuid,
        "wayjournal.identity",
        "store.genesis",
        "01913f1d-8e2a-7c30-8f4a-426614174011",
        "01913f1d-8e2a-7c30-8f4a-426614174012",
        json!({"store_kind": "wayjournal.personal", "store_uuid": store_uuid}),
    );
    let genesis_key = format!("{label}-genesis");
    let genesis_batch = prepare_batch(&[genesis], &genesis_key, &registry).expect("genesis batch");
    store
        .append(&genesis_batch, store.read().expect("empty").revision())
        .expect("genesis append");
    let initialized = store.read().expect("initialized");
    let logical_store = initialized
        .identity()
        .expect("identity")
        .logical_id()
        .clone();
    let profile_id: wayjournal_core::RecordId = "01913f1d-8e2a-7c30-8f4a-426614174021"
        .parse()
        .expect("profile id");
    let profile = record(
        store_uuid,
        "wayjournal.profile",
        "profile.description.set",
        &profile_id.to_string(),
        "01913f1d-8e2a-7c30-8f4a-426614174022",
        json!({"value": label}),
    );
    let profile_key = format!("{label}-profile");
    let profile_batch = prepare_batch(&[profile], &profile_key, &registry).expect("profile batch");
    store
        .append(&profile_batch, initialized.revision())
        .expect("profile append");
    let current = store.read().expect("current");
    write_checkpoint(directory.path(), &logical_store, current.revision());
    StoreFixture {
        directory,
        store,
        logical_store,
        profile_id,
    }
}

fn write_checkpoint(root: &Path, store: &LogicalStoreId, revision: StoreRevisionRef) {
    let bytes = canonical(&json!({
        "accepted_commit": "0123456789abcdef0123456789abcdef01234567",
        "accepted_git_object_format": "sha1",
        "accepted_revision_algorithm": revision.algorithm().as_str(),
        "accepted_revision_digest": revision.digest().to_string(),
        "genesis_fingerprint": store.genesis_fingerprint().to_string(),
        "local_trust_binding": TRUST,
        "remote_locator": "file:///srv/git/approved.git",
        "remote_ref": "refs/heads/approved",
        "schema": "wayjournal.admission-checkpoint/v1",
        "store_uuid": store.store_uuid().to_string()
    }));
    let path = root.join(".wayjournal-local/checkpoints/admission-v1.json");
    fs::write(&path, bytes).expect("checkpoint");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("checkpoint mode");
}

fn authority(fixture: &StoreFixture) -> DependencyStore<'_> {
    DependencyStore {
        expected_store: fixture.logical_store.clone(),
        store: &fixture.store,
    }
}

fn proof(fixture: &StoreFixture) -> wayjournal_core::VerifiedProof {
    fixture
        .store
        .verified_proof(
            &QualifiedEntityRef {
                store: fixture.logical_store.clone(),
                domain: "wayjournal.profile".parse().expect("domain"),
                entity_id: fixture
                    .logical_store
                    .store_uuid()
                    .to_string()
                    .parse()
                    .expect("entity"),
            },
            fixture.profile_id,
            "2026-08-12T13:00:02Z".parse().expect("timestamp"),
        )
        .expect("proof")
}

fn cache_path(directory: &TestDir) -> PathBuf {
    directory.path().join("proof-cache")
}

fn sorted_authorities<'a>(fixtures: &[&'a StoreFixture]) -> Vec<DependencyStore<'a>> {
    let mut authorities = fixtures
        .iter()
        .map(|fixture| authority(fixture))
        .collect::<Vec<_>>();
    authorities.sort_by(|left, right| left.expected_store.cmp(&right.expected_store));
    authorities
}

#[test]
fn exact_id_insert_lookup_and_best_effort_invalidation_use_locked_checkpoint_authority() {
    let fixture = initialized_store("basic", "01913f1d-8e2a-7c30-8f4a-426614174010");
    let cache_dir = TestDir::new("basic-cache");
    let cache = ProofCache::open(cache_path(&cache_dir)).expect("cache");
    let proof = proof(&fixture);

    assert_eq!(
        cache
            .insert(&proof, &[authority(&fixture)])
            .expect("insert"),
        ProofCacheInsert::Inserted
    );
    assert_eq!(
        cache
            .insert(&proof, &[authority(&fixture)])
            .expect("repeat"),
        ProofCacheInsert::AlreadyPresent
    );
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("lookup"),
        ProofCacheLookup::Hit(proof.clone())
    );

    let unrelated = wayjournal_core::ProofId::parse(&"a".repeat(64)).expect("proof id");
    assert_eq!(
        cache
            .lookup(&unrelated, &[authority(&fixture)])
            .expect("exact miss"),
        ProofCacheLookup::Miss
    );
    assert_eq!(
        cache.invalidate_store(
            &fixture.logical_store,
            proof.source_revision(),
            StoreRevisionRef::parse(wayjournal_core::REVISION_ALGORITHM_V1, &"b".repeat(64),)
                .expect("new revision"),
        ),
        ProofCacheDisposition::Invalidated
    );
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("deleted miss"),
        ProofCacheLookup::Miss
    );
}

#[test]
fn retained_r_vector_has_no_authority_after_checkpoint_r2_and_cannot_republish() {
    let fixture = initialized_store("advance", "01913f1d-8e2a-7c30-8f4a-426614174030");
    let cache_dir = TestDir::new("advance-cache");
    let cache_root = cache_path(&cache_dir);
    let cache = ProofCache::open(&cache_root).expect("cache");
    let proof_r = proof(&fixture);
    let retained_r =
        wayjournal_core::RevisionVector::new(vec![wayjournal_core::RevisionVectorEntry::new(
            fixture.logical_store.clone(),
            proof_r.source_revision(),
        )])
        .expect("caller-created R vector");
    cache
        .insert(&proof_r, &[authority(&fixture)])
        .expect("insert R");
    let retained_entry_r = fs::read(cache_root.join(format!("{}.json", proof_r.proof_id())))
        .expect("retained cache entry R");
    let checkpoint_path = fixture
        .directory
        .path()
        .join(".wayjournal-local/checkpoints/admission-v1.json");
    let retained_checkpoint_r = fs::read(&checkpoint_path).expect("retained checkpoint R");

    let before = fixture.store.read().expect("R");
    let registry = wayjournal_domain_registry().expect("registry");
    let advance = record(
        &fixture.logical_store.store_uuid().to_string(),
        "wayjournal.profile",
        "profile.description.set",
        "01913f1d-8e2a-7c30-8f4a-426614174041",
        "01913f1d-8e2a-7c30-8f4a-426614174042",
        json!({"value": "R2"}),
    );
    let batch = prepare_batch(&[advance], "cache-R2", &registry).expect("advance batch");
    fixture
        .store
        .append(&batch, before.revision())
        .expect("advance");
    let after = fixture.store.read().expect("R2");
    assert_ne!(before.revision(), after.revision());
    write_checkpoint(
        fixture.directory.path(),
        &fixture.logical_store,
        after.revision(),
    );

    assert_eq!(
        retained_r.entries()[0].revision(),
        proof_r.source_revision()
    );
    assert!(!retained_entry_r.is_empty());
    assert_ne!(
        fs::read(&checkpoint_path).expect("checkpoint R2"),
        retained_checkpoint_r
    );
    assert_eq!(
        cache
            .lookup(&proof_r.proof_id(), &[authority(&fixture)])
            .expect("stale lookup"),
        ProofCacheLookup::Stale
    );
    assert!(matches!(
        cache.insert(&proof_r, &[authority(&fixture)]),
        Err(ProofCacheError::StaleProof)
    ));
}

#[test]
fn resolver_shape_alias_identity_and_missing_authority_fail_closed() {
    let first = initialized_store("resolver-a", "01913f1d-8e2a-7c30-8f4a-426614174050");
    let second = initialized_store("resolver-b", "01913f1d-8e2a-7c30-8f4a-426614174060");
    let cache_dir = TestDir::new("resolver-cache");
    let cache = ProofCache::open(cache_path(&cache_dir)).expect("cache");
    let proof = proof(&first);

    let duplicate = [authority(&first), authority(&first)];
    assert!(matches!(
        cache.lookup(&proof.proof_id(), &duplicate),
        Err(ProofCacheError::InvalidAuthorityOrder)
    ));
    let mut unsorted = sorted_authorities(&[&first, &second]);
    unsorted.reverse();
    assert!(matches!(
        cache.lookup(&proof.proof_id(), &unsorted),
        Err(ProofCacheError::InvalidAuthorityOrder)
    ));
    let excessive = (0..=wayjournal_core::MAX_VECTOR_STORES)
        .map(|_| authority(&first))
        .collect::<Vec<_>>();
    assert!(matches!(
        cache.lookup(&proof.proof_id(), &excessive),
        Err(ProofCacheError::TooManyAuthorities)
    ));

    let mut alias_id = first.logical_store.clone();
    if alias_id <= first.logical_store {
        alias_id = second.logical_store.clone();
    }
    let aliased = [
        authority(&first),
        DependencyStore {
            expected_store: alias_id,
            store: &first.store,
        },
    ];
    assert!(matches!(
        cache.lookup(&proof.proof_id(), &aliased),
        Err(ProofCacheError::AliasedAuthorityRoots)
    ));

    assert!(matches!(
        cache.insert(&proof, &[authority(&second)]),
        Err(ProofCacheError::InvalidSourceDependency)
    ));

    let wrong_identity = [DependencyStore {
        expected_store: first.logical_store.clone(),
        store: &second.store,
    }];
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &wrong_identity)
            .expect("identity mismatch classification"),
        ProofCacheLookup::Unavailable
    );
    assert!(matches!(
        cache.insert(&proof, &wrong_identity),
        Err(ProofCacheError::AuthorityUnavailable(_))
    ));
}

#[test]
fn complete_dependency_store_mapping_is_required_and_every_revision_change_is_stale() {
    let first = initialized_store("complete-a", "01913f1d-8e2a-7c30-8f4a-4266141740a0");
    let second = initialized_store("complete-b", "01913f1d-8e2a-7c30-8f4a-4266141740b0");
    let cache_dir = TestDir::new("complete-cache");
    let cache = ProofCache::open(cache_path(&cache_dir)).expect("cache");
    let proof = proof(&first);
    let both = sorted_authorities(&[&first, &second]);
    cache
        .insert(&proof, &both)
        .expect("multi-dependency insert");

    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&first)])
            .expect("missing resolver handle"),
        ProofCacheLookup::Unavailable
    );
    assert_eq!(
        cache.lookup(&proof.proof_id(), &[]).expect("no handles"),
        ProofCacheLookup::Unavailable
    );

    let before = second.store.read().expect("second R");
    let registry = wayjournal_domain_registry().expect("registry");
    let advance = record(
        &second.logical_store.store_uuid().to_string(),
        "wayjournal.profile",
        "profile.description.set",
        "01913f1d-8e2a-7c30-8f4a-4266141740b1",
        "01913f1d-8e2a-7c30-8f4a-4266141740b2",
        json!({"value": "second R2"}),
    );
    let batch = prepare_batch(&[advance], "cache-second-R2", &registry).expect("batch");
    second
        .store
        .append(&batch, before.revision())
        .expect("advance second");
    let after = second.store.read().expect("second R2");
    write_checkpoint(
        second.directory.path(),
        &second.logical_store,
        after.revision(),
    );
    let both_r2 = sorted_authorities(&[&first, &second]);
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &both_r2)
            .expect("changed non-source dependency"),
        ProofCacheLookup::Stale
    );
}

#[test]
fn absent_malformed_and_pending_checkpoint_authority_never_returns_a_proof() {
    let fixture = initialized_store("blocked", "01913f1d-8e2a-7c30-8f4a-426614174070");
    let cache_dir = TestDir::new("blocked-cache");
    let cache = ProofCache::open(cache_path(&cache_dir)).expect("cache");
    let proof = proof(&fixture);
    cache
        .insert(&proof, &[authority(&fixture)])
        .expect("insert");

    let checkpoint = fixture
        .directory
        .path()
        .join(".wayjournal-local/checkpoints/admission-v1.json");
    fs::remove_file(&checkpoint).expect("remove checkpoint");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("missing checkpoint"),
        ProofCacheLookup::Unavailable
    );
    fs::write(&checkpoint, b"not JSON\n").expect("malformed checkpoint");
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o600)).expect("mode");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("malformed checkpoint"),
        ProofCacheLookup::Unavailable
    );

    write_checkpoint(
        fixture.directory.path(),
        &fixture.logical_store,
        proof.source_revision(),
    );
    fs::write(
        fixture
            .directory
            .path()
            .join(".wayjournal-local/sync-pending/unknown"),
        b"hostile pending state",
    )
    .expect("pending residue");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("pending classification"),
        ProofCacheLookup::Unavailable
    );
}

#[test]
fn root_replacement_is_latched_and_restoring_detached_old_bytes_cannot_hit() {
    let fixture = initialized_store("root-reset", "01913f1d-8e2a-7c30-8f4a-426614174080");
    let cache_dir = TestDir::new("root-reset-cache");
    let root = cache_path(&cache_dir);
    let cache = ProofCache::open(&root).expect("cache");
    let proof = proof(&fixture);
    cache
        .insert(&proof, &[authority(&fixture)])
        .expect("insert");

    let detached = cache_dir.path().join("detached-old-cache");
    fs::rename(&root, &detached).expect("detach retained root");
    fs::create_dir(&root).expect("replacement root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("replacement mode");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("reset"),
        ProofCacheLookup::Reset
    );

    fs::remove_dir(&root).expect("remove replacement");
    fs::rename(&detached, &root).expect("restore old inode and bytes");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("latched reset"),
        ProofCacheLookup::Reset
    );
    assert!(matches!(
        cache.insert(&proof, &[authority(&fixture)]),
        Err(ProofCacheError::Reset)
    ));
}

#[test]
fn root_replacement_between_prevalidation_and_postvalidation_cannot_return_a_hit() {
    let fixture = initialized_store("root-toctou", "01913f1d-8e2a-7c30-8f4a-4266141740e0");
    let cache_dir = TestDir::new("root-toctou-cache");
    let root = cache_path(&cache_dir);
    let cache = ProofCache::open(&root).expect("cache");
    let proof = proof(&fixture);
    cache
        .insert(&proof, &[authority(&fixture)])
        .expect("insert");

    let original_path = root.join(format!("{}.json", proof.proof_id()));
    let original: Value =
        serde_json::from_slice(&fs::read(&original_path).expect("entry")).expect("entry JSON");
    for index in 0_u32..4_000 {
        let seconds = index + 1;
        let hour = seconds / 3_600;
        let minute = (seconds % 3_600) / 60;
        let second = seconds % 60;
        let mut entry = original.clone();
        entry["proof"]["observed_at"] =
            json!(format!("2026-08-13T{hour:02}:{minute:02}:{second:02}Z"));
        entry["proof"]["proof_id"] = json!(recompute_fixture_proof_id(&entry["proof"]));
        let id = entry["proof"]["proof_id"].as_str().expect("proof id");
        let path = root.join(format!("{id}.json"));
        fs::write(&path, canonical(&entry)).expect("cache filler");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("filler mode");
    }

    let detached = cache_dir.path().join("toctou-detached");
    let result = thread::scope(|scope| {
        let lookup = scope.spawn(|| cache.lookup(&proof.proof_id(), &[authority(&fixture)]));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let probe = File::open(&root).expect("cache root probe");
            match probe.try_lock() {
                Ok(()) => {
                    drop(probe);
                    assert!(
                        Instant::now() < deadline,
                        "lookup never acquired cache lock"
                    );
                    thread::yield_now();
                }
                Err(std::fs::TryLockError::WouldBlock) => break,
                Err(std::fs::TryLockError::Error(error)) => {
                    panic!("probe cache lock: {error}")
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
        let still_locked = File::open(&root).expect("post-prevalidation lock probe");
        assert!(matches!(
            still_locked.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        fs::rename(&root, &detached).expect("replace after prevalidation");
        fs::create_dir(&root).expect("replacement root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        lookup.join().expect("lookup thread")
    });
    assert_eq!(result.expect("lookup result"), ProofCacheLookup::Reset);
}

#[test]
fn hostile_descendants_and_entry_id_mismatches_make_lookup_unavailable() {
    let fixture = initialized_store("layout", "01913f1d-8e2a-7c30-8f4a-426614174090");
    let cache_dir = TestDir::new("layout-cache");
    let root = cache_path(&cache_dir);
    let cache = ProofCache::open(&root).expect("cache");
    let proof = proof(&fixture);
    cache
        .insert(&proof, &[authority(&fixture)])
        .expect("insert");
    let original = root.join(format!("{}.json", proof.proof_id()));
    let wrong = root.join(format!("{}.json", "a".repeat(64)));
    fs::rename(&original, &wrong).expect("wrong filename");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("filename mismatch"),
        ProofCacheLookup::Unavailable
    );

    fs::rename(&wrong, &original).expect("restore name");
    fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).expect("wrong mode");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("wrong mode"),
        ProofCacheLookup::Unavailable
    );
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).expect("restore mode");
    fs::write(root.join("unknown"), b"hostile").expect("unknown entry");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("unknown entry"),
        ProofCacheLookup::Unavailable
    );
    fs::remove_file(root.join("unknown")).expect("remove unknown");

    let outside = cache_dir.path().join("outside-entry");
    fs::copy(&original, &outside).expect("outside target");
    fs::remove_file(&original).expect("remove regular entry");
    std::os::unix::fs::symlink(&outside, &original).expect("entry symlink");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("symlink entry"),
        ProofCacheLookup::Unavailable
    );
    fs::remove_file(&original).expect("remove symlink");

    fs::create_dir(&original).expect("entry directory");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("directory entry"),
        ProofCacheLookup::Unavailable
    );
    fs::remove_dir(&original).expect("remove entry directory");

    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &original,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .expect("entry FIFO");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("FIFO entry"),
        ProofCacheLookup::Unavailable
    );
    fs::remove_file(&original).expect("remove FIFO");
}

#[test]
fn cache_entry_codec_is_closed_canonical_bounded_and_cross_bound() {
    let fixture = initialized_store("codec", "01913f1d-8e2a-7c30-8f4a-4266141740c0");
    let cache_dir = TestDir::new("codec-cache");
    let root = cache_path(&cache_dir);
    let cache = ProofCache::open(&root).expect("cache");
    let proof = proof(&fixture);
    cache
        .insert(&proof, &[authority(&fixture)])
        .expect("insert");
    let path = root.join(format!("{}.json", proof.proof_id()));
    let valid = fs::read(&path).expect("valid entry");
    let value: Value = serde_json::from_slice(&valid).expect("entry JSON");
    assert_eq!(
        value["schema"],
        wayjournal_core::PROJECTION_CACHE_ENTRY_SCHEMA_V1
    );
    assert_eq!(
        value
            .as_object()
            .expect("entry root")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["dependencies", "proof", "schema"]
    );

    let mut unknown = value.clone();
    unknown["unknown"] = json!(true);
    fs::write(&path, canonical(&unknown)).expect("unknown root key");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("unknown classification"),
        ProofCacheLookup::Unavailable
    );

    let duplicate = String::from_utf8(valid.clone())
        .expect("entry text")
        .replacen(
            "  \"schema\":",
            &format!(
                "  \"schema\": \"{}\",\n  \"schema\":",
                wayjournal_core::PROJECTION_CACHE_ENTRY_SCHEMA_V1
            ),
            1,
        );
    fs::write(&path, duplicate).expect("duplicate key");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("duplicate classification"),
        ProofCacheLookup::Unavailable
    );

    let mut missing_source = value.clone();
    missing_source["dependencies"]["entries"] = json!([]);
    fs::write(&path, canonical(&missing_source)).expect("missing source dependency");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("source cross-binding"),
        ProofCacheLookup::Unavailable
    );

    fs::write(
        &path,
        vec![b' '; wayjournal_core::MAX_PROOF_CACHE_ENTRY_BYTES + 1],
    )
    .expect("oversized entry");
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("oversized classification"),
        ProofCacheLookup::Unavailable
    );
}

#[test]
fn final_entry_count_limit_plus_one_fails_before_hostile_entry_decoding() {
    let fixture = initialized_store("count", "01913f1d-8e2a-7c30-8f4a-4266141740d0");
    let cache_dir = TestDir::new("count-cache");
    let root = cache_path(&cache_dir);
    let cache = ProofCache::open(&root).expect("cache");
    let proof = proof(&fixture);
    for index in 0..=wayjournal_core::MAX_PROOF_CACHE_ENTRIES {
        let path = root.join(format!("{index:064x}.json"));
        fs::write(&path, b"{}\n").expect("hostile entry");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("entry mode");
    }
    assert_eq!(
        cache
            .lookup(&proof.proof_id(), &[authority(&fixture)])
            .expect("limit classification"),
        ProofCacheLookup::Unavailable
    );
}

#[test]
fn open_rejects_wrong_root_mode_symlink_and_non_directory() {
    let directory = TestDir::new("open");
    let wrong_mode = directory.path().join("wrong-mode");
    fs::create_dir(&wrong_mode).expect("directory");
    fs::set_permissions(&wrong_mode, fs::Permissions::from_mode(0o755)).expect("mode");
    assert!(matches!(
        ProofCache::open(&wrong_mode),
        Err(ProofCacheError::InvalidRoot)
    ));

    let file = directory.path().join("file");
    fs::write(&file, b"not a directory").expect("file");
    assert!(ProofCache::open(&file).is_err());

    let target = directory.path().join("target");
    fs::create_dir(&target).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("target mode");
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    assert!(ProofCache::open(&link).is_err());
}

#[test]
fn public_cache_api_has_no_current_vector_parameter_or_enumeration_path() {
    let lookup: for<'a, 'b, 'c> fn(
        &'a ProofCache,
        &'b wayjournal_core::ProofId,
        &'c [DependencyStore<'c>],
    ) -> Result<ProofCacheLookup, ProofCacheError> = ProofCache::lookup;
    let insert: for<'a, 'b, 'c> fn(
        &'a ProofCache,
        &'b wayjournal_core::VerifiedProof,
        &'c [DependencyStore<'c>],
    ) -> Result<ProofCacheInsert, ProofCacheError> = ProofCache::insert;
    let _ = (lookup, insert);
}
