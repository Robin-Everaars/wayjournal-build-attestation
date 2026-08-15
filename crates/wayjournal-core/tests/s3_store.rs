use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde_json::json;
use wayjournal_core::{
    ActorId, DomainRegistration, DomainRegistry, KindId, LegacyEntry, LegacyStoreAdapter, Record,
    Store, StoreCorruption, StoreError, prepare_batch, wayjournal_domain_registry,
    wayjournal_domain_registry_with,
};

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("wayjournal-s3-store-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).expect("directory");
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

#[derive(Debug)]
struct NoLegacy;
impl LegacyStoreAdapter for NoLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
    }
}

fn record(
    domain: &str,
    kind: &str,
    record: &str,
    batch: &str,
    parents: &[&str],
    payload: serde_json::Value,
) -> Record {
    Record {
        record_schema: format!("{domain}/v1").parse().expect("schema"),
        domain: domain.parse().expect("domain"),
        kind: kind.parse().expect("kind"),
        record_id: record.parse().expect("record"),
        entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010"
            .parse()
            .expect("entity"),
        batch_id: batch.parse().expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: parents
            .iter()
            .map(|id| id.parse().expect("parent"))
            .collect(),
        payload,
    }
}

fn genesis() -> Record {
    record(
        "wayjournal.identity",
        "store.genesis",
        "01913f1d-8e2a-7c30-8f4a-426614174011",
        "01913f1d-8e2a-7c30-8f4a-426614174012",
        &[],
        json!({"store_kind":"wayjournal.personal","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"}),
    )
}

#[test]
fn strict_store_rejects_dangling_profile_history_during_publication() {
    let directory = TestDir::new();
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open_strict(directory.path(), registry, Arc::new(NoLegacy)).expect("open");
    let empty = store.read().expect("empty");
    let initialized = prepare_batch(&[genesis()], "genesis", &registry).expect("genesis");
    store
        .append(&initialized, empty.revision())
        .expect("initialize");

    let dangling = record(
        "wayjournal.profile",
        "profile.display_name.set",
        "01913f1d-8e2a-7c30-8f4a-426614174021",
        "01913f1d-8e2a-7c30-8f4a-426614174022",
        &["01913f1d-8e2a-7c30-8f4a-426614174020"],
        json!({"value":"bad"}),
    );
    let prepared = prepare_batch(&[dangling], "bad", &registry).expect("shape");
    assert!(matches!(
        store.append(&prepared, store.read().expect("read").revision()),
        Err(StoreError::Corrupt {
            issue: StoreCorruption::InvalidDomainFold { .. }
        })
    ));
}

fn validate_custom(_: &KindId, payload: &serde_json::Value) -> Result<(), String> {
    payload
        .as_object()
        .filter(|value| value.is_empty())
        .map(|_| ())
        .ok_or_else(|| "expected empty object".to_owned())
}
static CUSTOM_KINDS: &[&str] = &["custom.created"];
static CUSTOM: &[DomainRegistration] = &[DomainRegistration::new(
    "example.custom",
    "example.custom/v1",
    CUSTOM_KINDS,
    validate_custom,
)];
static RESERVED: &[DomainRegistration] = &[DomainRegistration::new(
    "wayjournal.identity",
    "wayjournal.identity/v2",
    CUSTOM_KINDS,
    validate_custom,
)];

#[test]
fn strict_registry_composes_custom_domains_and_compatibility_is_explicit() {
    let composed = wayjournal_domain_registry_with(CUSTOM).expect("composed");
    let directory = TestDir::new();
    let strict = Store::open_strict(directory.path(), composed, Arc::new(NoLegacy))
        .expect("strict composed");
    let empty = strict.read().expect("empty");
    let genesis_batch = prepare_batch(&[genesis()], "genesis-custom", &composed).expect("genesis");
    strict
        .append(&genesis_batch, empty.revision())
        .expect("genesis");
    let custom = record(
        "example.custom",
        "custom.created",
        "01913f1d-8e2a-7c30-8f4a-426614174031",
        "01913f1d-8e2a-7c30-8f4a-426614174032",
        &[],
        json!({}),
    );
    let custom_batch = prepare_batch(&[custom], "custom", &composed).expect("custom batch");
    strict
        .append(&custom_batch, strict.read().expect("read").revision())
        .expect("custom coexists");
    assert_eq!(strict.read().expect("read custom").records().len(), 2);

    assert!(matches!(
        Store::open_strict(
            TestDir::new().path(),
            DomainRegistry::new(CUSTOM).expect("custom"),
            Arc::new(NoLegacy),
        ),
        Err(StoreError::InvalidLayout { .. })
    ));
    Store::open_legacy_s1_s2(
        TestDir::new().path(),
        DomainRegistry::new(CUSTOM).expect("custom"),
        Arc::new(NoLegacy),
    )
    .expect("explicit S1/S2 compatibility mode");

    assert!(wayjournal_domain_registry_with(RESERVED).is_err());
}

#[test]
fn legacy_open_refuses_visible_s3_identity_data() {
    let directory = TestDir::new();
    let registry = wayjournal_domain_registry().expect("registry");
    let strict = Store::open(directory.path(), registry, Arc::new(NoLegacy)).expect("strict");
    let batch = prepare_batch(&[genesis()], "legacy-refusal", &registry).expect("genesis");
    strict
        .append(&batch, strict.read().expect("empty").revision())
        .expect("publish");
    drop(strict);
    assert!(matches!(
        Store::open_legacy_s1_s2(directory.path(), registry, Arc::new(NoLegacy)),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn secure_default_requires_sealed_builtins() {
    assert!(matches!(
        Store::open(
            TestDir::new().path(),
            DomainRegistry::new(CUSTOM).expect("custom"),
            Arc::new(NoLegacy),
        ),
        Err(StoreError::InvalidLayout { .. })
    ));
}

#[allow(clippy::too_many_lines)]
fn hostile_histories() -> Vec<(&'static str, Vec<Record>)> {
    let batch = "01913f1d-8e2a-7c30-8f4a-426614174099";
    let one = "01913f1d-8e2a-7c30-8f4a-426614174041";
    let two = "01913f1d-8e2a-7c30-8f4a-426614174042";
    let three = "01913f1d-8e2a-7c30-8f4a-426614174043";
    let target = json!({
        "genesis_fingerprint":"3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        "store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"
    });
    vec![
        (
            "dangling",
            vec![record(
                "wayjournal.profile",
                "profile.display_name.set",
                one,
                batch,
                &[two],
                json!({"value":"dangling"}),
            )],
        ),
        (
            "cycle",
            vec![
                record(
                    "wayjournal.profile",
                    "profile.display_name.set",
                    one,
                    batch,
                    &[two],
                    json!({"value":"one"}),
                ),
                record(
                    "wayjournal.profile",
                    "profile.display_name.set",
                    two,
                    batch,
                    &[one],
                    json!({"value":"two"}),
                ),
            ],
        ),
        (
            "wrong-domain-parent",
            vec![
                record(
                    "wayjournal.catalog",
                    "catalog.name.set",
                    one,
                    batch,
                    &[],
                    json!({"target":target,"value":"catalog"}),
                ),
                record(
                    "wayjournal.profile",
                    "profile.display_name.set",
                    two,
                    batch,
                    &[one],
                    json!({"value":"profile"}),
                ),
            ],
        ),
        (
            "fake-resolution",
            vec![
                record(
                    "wayjournal.profile",
                    "profile.display_name.set",
                    one,
                    batch,
                    &[],
                    json!({"value":"one"}),
                ),
                record(
                    "wayjournal.profile",
                    "profile.display_name.resolve",
                    two,
                    batch,
                    &[one],
                    json!({"candidates":[one,three],"value":"one"}),
                ),
            ],
        ),
        (
            "partial-resolution",
            vec![
                record(
                    "wayjournal.profile",
                    "profile.display_name.set",
                    one,
                    batch,
                    &[],
                    json!({"value":"one"}),
                ),
                record(
                    "wayjournal.profile",
                    "profile.display_name.set",
                    two,
                    batch,
                    &[],
                    json!({"value":"two"}),
                ),
                record(
                    "wayjournal.profile",
                    "profile.display_name.resolve",
                    three,
                    batch,
                    &[one, two],
                    json!({"candidates":[one],"value":"one"}),
                ),
            ],
        ),
        (
            "fake-remove",
            vec![
                record(
                    "wayjournal.profile",
                    "profile.alias.add",
                    one,
                    batch,
                    &[],
                    json!({"key":"me","value":"human:robin"}),
                ),
                record(
                    "wayjournal.profile",
                    "profile.alias.remove",
                    two,
                    batch,
                    &[one],
                    json!({"adds":[one,three],"key":"me"}),
                ),
            ],
        ),
    ]
}

fn write_prepared(root: &Path, prepared: &wayjournal_core::PreparedBatch) {
    for item in prepared.records() {
        let path = root.join(item.path());
        fs::create_dir_all(path.parent().expect("parent")).expect("parents");
        fs::write(path, item.bytes()).expect("record");
    }
    fs::write(
        root.join(prepared.manifest_path()),
        prepared.manifest_bytes(),
    )
    .expect("manifest");
}

#[test]
fn strict_store_hostile_matrix_rejects_visible_read_and_append_candidates() {
    let registry = wayjournal_domain_registry().expect("registry");
    for (name, records) in hostile_histories() {
        let append_dir = TestDir::new();
        let append_store =
            Store::open(append_dir.path(), registry, Arc::new(NoLegacy)).expect("open");
        let genesis_batch =
            prepare_batch(&[genesis()], &format!("{name}-genesis"), &registry).expect("genesis");
        append_store
            .append(
                &genesis_batch,
                append_store.read().expect("empty").revision(),
            )
            .expect("initialize");
        let bad = prepare_batch(&records, name, &registry).expect("wire-valid hostile history");
        assert!(
            matches!(
                append_store.append(&bad, append_store.read().expect("base").revision()),
                Err(StoreError::Corrupt {
                    issue: StoreCorruption::InvalidDomainFold { .. }
                })
            ),
            "append case {name}"
        );

        let read_dir = TestDir::new();
        let read_store = Store::open(read_dir.path(), registry, Arc::new(NoLegacy)).expect("open");
        write_prepared(read_dir.path(), &genesis_batch);
        write_prepared(read_dir.path(), &bad);
        assert!(
            matches!(
                read_store.read(),
                Err(StoreError::Corrupt {
                    issue: StoreCorruption::InvalidDomainFold { .. }
                })
            ),
            "read case {name}"
        );
    }
}

#[test]
fn strict_scan_rejects_visible_unsupported_identity_v2_history() {
    let directory = TestDir::new();
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(directory.path(), registry, Arc::new(NoLegacy)).expect("open");
    let genesis_batch =
        prepare_batch(&[genesis()], "identity-v2-genesis", &registry).expect("genesis");
    store
        .append(&genesis_batch, store.read().expect("empty").revision())
        .expect("genesis");
    let bytes = String::from_utf8(genesis_batch.records()[0].bytes().to_vec())
        .expect("utf8")
        .replace("wayjournal.identity/v1", "wayjournal.identity/v2")
        .replace(
            "01913f1d-8e2a-7c30-8f4a-426614174011",
            "01913f1d-8e2a-7c30-8f4a-426614174031",
        )
        .replace(
            "01913f1d-8e2a-7c30-8f4a-426614174012",
            "01913f1d-8e2a-7c30-8f4a-426614174032",
        );
    let path = directory.path().join("journal/records/wayjournal.identity/01913f1d-8e2a-7c30-8f4a-426614174010/01913f1d-8e2a-7c30-8f4a-426614174031.json");
    fs::write(path, bytes).expect("hostile record");
    assert!(matches!(
        store.read(),
        Err(StoreError::Corrupt {
            issue: StoreCorruption::InvalidRecord { .. }
        })
    ));
}
