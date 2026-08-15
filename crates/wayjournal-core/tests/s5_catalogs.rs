#[allow(dead_code)]
mod support;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use serde_json::{Value, json};
use wayjournal_core::{
    ActorId, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, CausalError, DomainOperation,
    FoldError, GitQuarantineReason, GitSyncOutcome, GitSyncRequest, LocalTrustBinding,
    LogicalStoreId, MAX_CAUSAL_EDGES, MAX_CAUSAL_OPERATIONS, MAX_REACHABILITY_STEPS,
    OperationError, Record, RecordId, Store, StoreCorruption, StoreError, StoreUuid, fold_catalog,
    fold_catalogs, prepare_batch, wayjournal_domain_registry,
};

use support::BoundedNoLegacy;

const ENTITY: &str = "01913f1d-8e2a-7c30-8f4a-426614175000";
const STORE_UUID: &str = "01913f1d-8e2a-7c30-8f4a-426614174010";
const OTHER_STORE_UUID: &str = "01913f1d-8e2a-7c30-8f4a-426614174020";
const GENESIS_FINGERPRINT: &str =
    "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15";
const MAX_REFERENCES: usize = 4096;

fn record_id(ordinal: usize) -> RecordId {
    format!("01913f1d-8e2a-7c30-8f4a-{ordinal:012x}")
        .parse()
        .expect("record ID")
}

fn target(uuid: &str) -> LogicalStoreId {
    LogicalStoreId::new(
        uuid.parse::<StoreUuid>().expect("store UUID"),
        GENESIS_FINGERPRINT.parse().expect("genesis fingerprint"),
    )
}

fn catalog_record(kind: &str, ordinal: usize, parents: &[usize], payload: Value) -> Record {
    Record {
        record_schema: "wayjournal.catalog/v1".parse().expect("schema"),
        domain: "wayjournal.catalog".parse().expect("domain"),
        kind: kind.parse().expect("kind"),
        record_id: record_id(ordinal),
        entity_id: ENTITY.parse().expect("entity"),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614176000"
            .parse()
            .expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: parents.iter().copied().map(record_id).collect(),
        payload,
    }
}

fn operation(kind: &str, ordinal: usize, parents: &[usize], payload: Value) -> DomainOperation {
    DomainOperation::try_from(catalog_record(kind, ordinal, parents, payload))
        .expect("closed catalog operation")
}

fn name(
    ordinal: usize,
    parents: &[usize],
    target: &LogicalStoreId,
    value: &str,
) -> DomainOperation {
    operation(
        "catalog.name.set",
        ordinal,
        parents,
        json!({"target": target, "value": value}),
    )
}

fn alias_add(
    ordinal: usize,
    parents: &[usize],
    target: &LogicalStoreId,
    key: &str,
    value: &str,
) -> DomainOperation {
    operation(
        "catalog.alias.add",
        ordinal,
        parents,
        json!({"key": key, "target": target, "value": value}),
    )
}

#[test]
fn complete_catalog_graph_accepts_cross_target_ancestry_and_is_deterministic() {
    let left = target(STORE_UUID);
    let right = target(OTHER_STORE_UUID);
    let operations = vec![
        name(1, &[], &left, "left-old"),
        name(2, &[1], &right, "right-old"),
        name(3, &[2], &left, "left-current"),
        operation(
            "catalog.enabled.set",
            4,
            &[3],
            json!({"target": right, "value": true}),
        ),
        alias_add(5, &[4], &left, "short", "left"),
        alias_add(6, &[5], &right, "short", "right"),
        operation(
            "catalog.alias.remove",
            7,
            &[6],
            json!({"adds": [record_id(5)], "key": "short", "target": left}),
        ),
        operation(
            "catalog.name.resolve",
            8,
            &[7],
            json!({"candidates": [record_id(2)], "target": right, "value": "right-current"}),
        ),
    ];

    let folded = fold_catalogs(&operations).expect("complete catalog fold");
    assert_eq!(folded.len(), 2);
    assert_eq!(
        folded[&left].entry_name().resolved().map(String::as_str),
        Some("left-current")
    );
    assert!(folded[&left].aliases().is_empty());
    assert_eq!(
        folded[&right].entry_name().resolved().map(String::as_str),
        Some("right-current")
    );
    assert_eq!(folded[&right].enabled().resolved(), Some(&true));
    assert_eq!(folded[&right].aliases()["short"], ["right".to_owned()]);

    let mut shuffled = operations.clone();
    shuffled.reverse();
    assert_eq!(fold_catalogs(&shuffled), Ok(folded));
}

#[test]
fn resolutions_and_observed_removes_are_partitioned_by_addressed_target() {
    let left = target(STORE_UUID);
    let right = target(OTHER_STORE_UUID);

    let valid_resolution = vec![
        name(10, &[], &left, "left"),
        name(11, &[], &right, "right"),
        operation(
            "catalog.name.resolve",
            12,
            &[10, 11],
            json!({"candidates": [record_id(10)], "target": left, "value": "resolved"}),
        ),
    ];
    let folded = fold_catalogs(&valid_resolution).expect("target-local resolution");
    assert_eq!(
        folded[&left].entry_name().resolved().map(String::as_str),
        Some("resolved")
    );
    assert_eq!(
        folded[&right].entry_name().resolved().map(String::as_str),
        Some("right")
    );

    let confused_resolution = vec![
        name(10, &[], &left, "left"),
        name(11, &[], &right, "right"),
        operation(
            "catalog.name.resolve",
            12,
            &[10, 11],
            json!({"candidates": [record_id(10), record_id(11)], "target": left, "value": "confused"}),
        ),
    ];
    assert!(matches!(
        fold_catalogs(&confused_resolution),
        Err(FoldError::InvalidResolution { record_id: actual }) if actual == record_id(12)
    ));

    let valid_remove = vec![
        alias_add(20, &[], &left, "shared", "left"),
        alias_add(21, &[], &right, "shared", "right"),
        operation(
            "catalog.alias.remove",
            22,
            &[20, 21],
            json!({"adds": [record_id(20)], "key": "shared", "target": left}),
        ),
    ];
    let folded = fold_catalogs(&valid_remove).expect("target-local observed remove");
    assert!(folded[&left].aliases().is_empty());
    assert_eq!(folded[&right].aliases()["shared"], ["right".to_owned()]);

    let confused_remove = vec![
        alias_add(20, &[], &left, "shared", "left"),
        alias_add(21, &[], &right, "shared", "right"),
        operation(
            "catalog.alias.remove",
            22,
            &[20, 21],
            json!({"adds": [record_id(20), record_id(21)], "key": "shared", "target": left}),
        ),
    ];
    assert!(matches!(
        fold_catalogs(&confused_remove),
        Err(FoldError::InvalidObservedRemove { record_id: actual }) if actual == record_id(22)
    ));
}

#[test]
fn fake_partial_resolution_and_remove_fail_closed() {
    let left = target(STORE_UUID);
    let partial_resolution = vec![
        name(30, &[], &left, "one"),
        name(31, &[], &left, "two"),
        operation(
            "catalog.name.resolve",
            32,
            &[30, 31],
            json!({"candidates": [record_id(30)], "target": left, "value": "partial"}),
        ),
    ];
    assert!(matches!(
        fold_catalogs(&partial_resolution),
        Err(FoldError::InvalidResolution { .. })
    ));

    let fake_resolution = vec![
        name(30, &[], &left, "one"),
        operation(
            "catalog.name.resolve",
            32,
            &[30],
            json!({"candidates": [record_id(30), record_id(99)], "target": left, "value": "fake"}),
        ),
    ];
    assert!(matches!(
        fold_catalogs(&fake_resolution),
        Err(FoldError::InvalidResolution { .. })
    ));

    let partial_remove = vec![
        alias_add(40, &[], &left, "alias", "one"),
        alias_add(41, &[], &left, "alias", "two"),
        operation(
            "catalog.alias.remove",
            42,
            &[40, 41],
            json!({"adds": [record_id(40)], "key": "alias", "target": left}),
        ),
    ];
    assert!(matches!(
        fold_catalogs(&partial_remove),
        Err(FoldError::InvalidObservedRemove { .. })
    ));

    let fake_remove = vec![
        alias_add(40, &[], &left, "alias", "one"),
        operation(
            "catalog.alias.remove",
            42,
            &[40],
            json!({"adds": [record_id(40), record_id(99)], "key": "alias", "target": left}),
        ),
    ];
    assert!(matches!(
        fold_catalogs(&fake_remove),
        Err(FoldError::InvalidObservedRemove { .. })
    ));
}

#[test]
fn complete_catalog_rejects_dangling_cycles_duplicates_and_wrong_entities() {
    let left = target(STORE_UUID);
    let dangling = name(51, &[50], &left, "dangling");
    assert!(matches!(
        fold_catalogs(&[dangling]),
        Err(FoldError::Causal(CausalError::DanglingParent { .. }))
    ));

    let cycle_left = name(50, &[51], &left, "left");
    let cycle_right = name(51, &[50], &left, "right");
    assert!(matches!(
        fold_catalogs(&[cycle_left, cycle_right]),
        Err(FoldError::Causal(CausalError::Cycle))
    ));

    let duplicate = name(50, &[], &left, "duplicate");
    assert!(matches!(
        fold_catalogs(&[duplicate.clone(), duplicate]),
        Err(FoldError::Causal(CausalError::DuplicateRecordId { .. }))
    ));

    let first = name(50, &[], &left, "first");
    let mut other_entity = catalog_record(
        "catalog.name.set",
        51,
        &[],
        json!({"target": left, "value": "other entity"}),
    );
    other_entity.entity_id = "01913f1d-8e2a-7c30-8f4a-426614175001"
        .parse()
        .expect("entity");
    let other_entity = DomainOperation::try_from(other_entity).expect("operation");
    assert_eq!(
        fold_catalogs(&[first, other_entity]),
        Err(FoldError::WrongEntity)
    );
}

#[test]
fn every_catalog_fold_limit_plus_one_fails_closed() {
    let left = target(STORE_UUID);
    let operation_overflow = (0..=MAX_CAUSAL_OPERATIONS)
        .map(|ordinal| name(1_000 + ordinal, &[], &left, "bounded"))
        .collect::<Vec<_>>();
    assert!(matches!(
        fold_catalogs(&operation_overflow),
        Err(FoldError::Causal(CausalError::TooManyOperations {
            maximum: MAX_CAUSAL_OPERATIONS,
            ..
        }))
    ));

    let mut remaining_edges = MAX_CAUSAL_EDGES + 1;
    let edge_overflow = (0..MAX_CAUSAL_OPERATIONS)
        .map(|index| {
            let parents = (0..remaining_edges.min(index)).collect::<Vec<_>>();
            remaining_edges -= parents.len();
            name(
                10_000 + index,
                &parents
                    .iter()
                    .map(|value| 10_000 + value)
                    .collect::<Vec<_>>(),
                &left,
                "bounded",
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(remaining_edges, 0);
    assert!(matches!(
        fold_catalogs(&edge_overflow),
        Err(FoldError::Causal(CausalError::TooManyEdges {
            maximum: MAX_CAUSAL_EDGES,
            ..
        }))
    ));

    let right = target(OTHER_STORE_UUID);
    let mut reachability_overflow = (0..1_001)
        .map(|ordinal| name(100_000 + ordinal, &[], &left, "candidate"))
        .collect::<Vec<_>>();
    for index in 0..1_000 {
        let ordinal = 102_000 + index;
        let parents = (index > 0)
            .then_some(ordinal - 1)
            .into_iter()
            .collect::<Vec<_>>();
        reachability_overflow.push(alias_add(
            ordinal,
            &parents,
            &right,
            &format!("chain-{index}"),
            "link",
        ));
    }
    reachability_overflow.push(name(103_000, &[102_999], &left, "budget overflow"));
    assert!(matches!(
        fold_catalogs(&reachability_overflow),
        Err(FoldError::Causal(CausalError::ReachabilityBudget {
            maximum: MAX_REACHABILITY_STEPS
        }))
    ));

    let references = (0..=MAX_REFERENCES).map(record_id).collect::<Vec<_>>();
    let resolution = catalog_record(
        "catalog.name.resolve",
        200_000,
        &[],
        json!({"candidates": references, "target": left, "value": "too many"}),
    );
    assert!(matches!(
        DomainOperation::try_from(resolution),
        Err(OperationError::InvalidPayload(_))
    ));

    let references = (0..=MAX_REFERENCES).map(record_id).collect::<Vec<_>>();
    let remove = catalog_record(
        "catalog.alias.remove",
        200_001,
        &[],
        json!({"adds": references, "key": "alias", "target": left}),
    );
    assert!(matches!(
        DomainOperation::try_from(remove),
        Err(OperationError::InvalidPayload(_))
    ));
}

#[test]
fn single_target_api_remains_strict_and_matches_multi_target_projection() {
    let left = target(STORE_UUID);
    let right = target(OTHER_STORE_UUID);
    let operations = vec![
        name(60, &[], &left, "one"),
        operation(
            "catalog.enabled.set",
            61,
            &[60],
            json!({"target": left, "value": false}),
        ),
    ];
    let single = fold_catalog(&operations).expect("single target API");
    assert_eq!(
        fold_catalogs(&operations).expect("multi API")[&left],
        single
    );

    assert!(matches!(
        fold_catalog(&[operations[0].clone(), name(62, &[], &right, "two")]),
        Err(FoldError::WrongTarget { .. })
    ));
    assert_eq!(fold_catalog(&[]), Err(FoldError::WrongEntity));
    assert_eq!(
        fold_catalogs(&[]).expect("empty complete catalog"),
        BTreeMap::default()
    );
}

#[test]
fn all_catalog_outputs_remain_advisory_data() {
    let left = target(STORE_UUID);
    let right = target(OTHER_STORE_UUID);
    let operations = vec![
        name(70, &[], &left, "advisory"),
        operation(
            "catalog.enabled.set",
            71,
            &[],
            json!({"target": left, "value": true}),
        ),
        operation(
            "catalog.default_store.set",
            72,
            &[],
            json!({"target": left, "value": right}),
        ),
        alias_add(73, &[], &left, "alias", "display-only"),
        operation(
            "catalog.group.add",
            74,
            &[],
            json!({"key": "group", "target": left, "value": "advisory-group"}),
        ),
        operation(
            "catalog.remote.add",
            75,
            &[],
            json!({"key": "origin", "target": left, "value": {
                "locator": "ssh://untrusted.invalid/journal",
                "requires_identity_validation": true
            }}),
        ),
        operation(
            "catalog.relation.add",
            76,
            &[],
            json!({"key": "related", "target": left, "value": {
                "kind": "qualified",
                "reference": {"domain": "wayjournal.profile", "entity_id": ENTITY, "store": right}
            }}),
        ),
    ];
    let entries = fold_catalogs(&operations).expect("advisory catalog");
    let entry = &entries[&left];
    assert_eq!(entry.enabled().resolved(), Some(&true));
    assert_eq!(entry.implicit_destination(), Some(&right));
    assert_eq!(entry.aliases()["alias"], ["display-only".to_owned()]);
    assert_eq!(entry.groups()["group"], ["advisory-group".to_owned()]);
    assert_eq!(
        entry.candidate_remotes()["origin"][0].locator(),
        "ssh://untrusted.invalid/journal"
    );
    assert_eq!(entry.store_relations().len(), 1);
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wayjournal-s5-catalogs-{label}-{}",
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

fn genesis() -> Record {
    Record {
        record_schema: "wayjournal.identity/v1".parse().expect("schema"),
        domain: "wayjournal.identity".parse().expect("domain"),
        kind: "store.genesis".parse().expect("kind"),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174011"
            .parse()
            .expect("record"),
        entity_id: STORE_UUID.parse().expect("entity"),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174012"
            .parse()
            .expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: Vec::new(),
        payload: json!({"store_kind": "wayjournal.personal", "store_uuid": STORE_UUID}),
    }
}

fn valid_cross_target_records() -> Vec<Record> {
    let left = target(STORE_UUID);
    let right = target(OTHER_STORE_UUID);
    vec![
        catalog_record(
            "catalog.name.set",
            300,
            &[],
            json!({"target": left, "value": "left"}),
        ),
        catalog_record(
            "catalog.enabled.set",
            301,
            &[300],
            json!({"target": right, "value": true}),
        ),
        catalog_record(
            "catalog.group.add",
            302,
            &[301],
            json!({"key": "group", "target": left, "value": "cross-target ancestry"}),
        ),
    ]
}

#[test]
fn collected_append_and_store_read_accept_cross_target_parent_chains() {
    let directory = TestDir::new("collected");
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(directory.path(), registry, Arc::new(BoundedNoLegacy)).expect("store");
    let genesis = prepare_batch(&[genesis()], "genesis", &registry).expect("genesis batch");
    store
        .append(&genesis, store.read().expect("empty").revision())
        .expect("initialize");
    let catalog = prepare_batch(
        &valid_cross_target_records(),
        "multi-target-catalog",
        &registry,
    )
    .expect("catalog batch");
    store
        .append(&catalog, store.read().expect("base").revision())
        .expect("collected candidate validation");
    assert_eq!(store.read().expect("visible read").records().len(), 4);
}

fn git() -> PathBuf {
    PathBuf::from(std::env::var_os("WAYJOURNAL_TEST_GIT").expect("WAYJOURNAL_TEST_GIT"))
}

fn run(cwd: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new(git())
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("Git command");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn configure(cwd: &Path) {
    run(cwd, &["config", "user.name", "Wayjournal Test"]);
    run(cwd, &["config", "user.email", "wayjournal@example.invalid"]);
}

fn write_prepared(root: &Path, prepared: &wayjournal_core::PreparedBatch) {
    for record in prepared.records() {
        let path = root.join(record.path());
        fs::create_dir_all(path.parent().expect("record parent")).expect("record directories");
        fs::write(path, record.bytes()).expect("record bytes");
    }
    let manifest = root.join(prepared.manifest_path());
    fs::create_dir_all(manifest.parent().expect("manifest parent")).expect("manifest directories");
    fs::write(manifest, prepared.manifest_bytes()).expect("manifest bytes");
}

fn sync_request(remote: &Path) -> GitSyncRequest {
    GitSyncRequest::new(
        git(),
        LocalTrustBinding::parse(GENESIS_FINGERPRINT).expect("trust"),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(
                url::Url::from_file_path(remote).expect("file URL").as_str(),
            )
            .expect("remote"),
            ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
    )
    .expect("request")
}

#[test]
#[allow(clippy::too_many_lines)]
fn admitted_git_tree_streaming_matches_collected_multi_target_validation() {
    let root = TestDir::new("git-tree");
    let remote = root.path().join("remote.git");
    run(
        root.path(),
        &["init", "--bare", remote.to_str().expect("remote path")],
    );
    let local = root.path().join("local");
    fs::create_dir(&local).expect("local");
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(&local, registry, Arc::new(BoundedNoLegacy)).expect("store");
    let genesis = prepare_batch(&[genesis()], "genesis", &registry).expect("genesis batch");
    store
        .append(&genesis, store.read().expect("empty").revision())
        .expect("initialize");
    run(&local, &["init", "-b", "main"]);
    configure(&local);
    run(&local, &["add", "events", "batches", "journal"]);
    run(&local, &["commit", "-m", "genesis"]);
    run(
        &local,
        &[
            "push",
            remote.to_str().expect("remote path"),
            "HEAD:refs/heads/main",
        ],
    );
    run(
        root.path(),
        &[
            "--git-dir",
            remote.to_str().expect("remote path"),
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ],
    );
    let request = sync_request(&remote);
    store
        .bootstrap_git_admission(&request)
        .expect("bootstrap admission");

    let writer = root.path().join("writer");
    run(
        root.path(),
        &[
            "clone",
            remote.to_str().expect("remote path"),
            writer.to_str().expect("writer path"),
        ],
    );
    configure(&writer);
    let catalog = prepare_batch(
        &valid_cross_target_records(),
        "remote-multi-target-catalog",
        &registry,
    )
    .expect("catalog batch");
    write_prepared(&writer, &catalog);
    run(&writer, &["add", "journal"]);
    run(&writer, &["commit", "-m", "multi-target catalog"]);
    run(&writer, &["push", "origin", "HEAD:refs/heads/main"]);

    let reference = Store::open(&writer, registry, Arc::new(BoundedNoLegacy)).expect("reference");
    let reference_revision = reference.read().expect("collected reference").revision();
    let outcome = store.sync_git_union(&request).expect("streaming admission");
    assert!(matches!(
        outcome,
        GitSyncOutcome::Advanced { revision, .. } if revision == reference_revision
    ));
    assert_eq!(
        store.read().expect("admitted read").revision(),
        reference_revision
    );

    let left = target(STORE_UUID);
    let right = target(OTHER_STORE_UUID);
    let mut confused = vec![
        catalog_record(
            "catalog.name.set",
            310,
            &[],
            json!({"target": left, "value": "left"}),
        ),
        catalog_record(
            "catalog.name.set",
            311,
            &[310],
            json!({"target": right, "value": "right"}),
        ),
        catalog_record(
            "catalog.name.resolve",
            312,
            &[311],
            json!({
                "candidates": [record_id(310), record_id(311)],
                "target": left,
                "value": "target confusion"
            }),
        ),
    ];
    for record in &mut confused {
        record.batch_id = "01913f1d-8e2a-7c30-8f4a-426614176001"
            .parse()
            .expect("batch");
    }
    let confused = prepare_batch(&confused, "target-confusion", &registry).expect("wire batch");
    write_prepared(&writer, &confused);
    let collected_confusion = reference.read();
    assert!(
        matches!(
            collected_confusion,
            Err(StoreError::Corrupt {
                issue: StoreCorruption::InvalidDomainFold { .. }
            })
        ),
        "unexpected collected result: {collected_confusion:?}"
    );
    run(&writer, &["add", "journal"]);
    run(&writer, &["commit", "-m", "target confusion"]);
    run(&writer, &["push", "origin", "HEAD:refs/heads/main"]);
    assert!(matches!(
        store.sync_git_union(&request).expect("closed rejection"),
        GitSyncOutcome::Quarantined {
            reason: GitQuarantineReason::InvalidCommitSnapshot,
            ..
        }
    ));
}
