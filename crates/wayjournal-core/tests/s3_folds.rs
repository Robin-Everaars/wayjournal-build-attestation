use serde_json::json;
use wayjournal_core::{
    ActorId, AdvisoryProfile, CatalogEntry, CausalError, DomainOperation, FoldError,
    LogicalStoreId, Record, RecordId, StoreUuid, fold_catalog, fold_profile,
};

const ENTITY: &str = "123e4567-e89b-42d3-a456-426614174000";
const TARGET_UUID: &str = "01913f1d-8e2a-7c30-8f4a-426614174010";
const TARGET_FP: &str = "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15";

fn id(suffix: u16) -> RecordId {
    format!("01913f1d-8e2a-7c30-8f4a-42661417{suffix:04}")
        .parse()
        .expect("id")
}

fn target() -> LogicalStoreId {
    LogicalStoreId::new(
        TARGET_UUID.parse::<StoreUuid>().expect("uuid"),
        TARGET_FP.parse().expect("fingerprint"),
    )
}

fn operation(
    domain: &str,
    kind: &str,
    suffix: u16,
    parents: &[u16],
    payload: serde_json::Value,
) -> DomainOperation {
    let record = Record {
        record_schema: format!("{domain}/v1").parse().expect("schema"),
        domain: domain.parse().expect("domain"),
        kind: kind.parse().expect("kind"),
        record_id: id(suffix),
        entity_id: ENTITY.parse().expect("entity"),
        batch_id: format!("01913f1d-8e2a-7c30-8f4a-42661418{suffix:04}")
            .parse()
            .expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: parents.iter().copied().map(id).collect(),
        payload,
    };
    DomainOperation::try_from(record).expect("typed closed operation")
}

#[test]
fn causal_graph_rejects_incomplete_cycle_duplicate_and_fake_resolution() {
    let dangling = operation(
        "wayjournal.profile",
        "profile.display_name.set",
        2,
        &[1],
        json!({"value": "name"}),
    );
    assert_eq!(
        fold_profile(&[dangling]),
        Err(FoldError::Causal(CausalError::DanglingParent {
            record_id: id(2),
            parent: id(1),
        }))
    );

    let first = operation(
        "wayjournal.profile",
        "profile.display_name.set",
        1,
        &[2],
        json!({"value": "one"}),
    );
    let second = operation(
        "wayjournal.profile",
        "profile.display_name.set",
        2,
        &[1],
        json!({"value": "two"}),
    );
    assert!(matches!(
        fold_profile(&[first, second]),
        Err(FoldError::Causal(CausalError::Cycle))
    ));

    let duplicate = operation(
        "wayjournal.profile",
        "profile.display_name.set",
        1,
        &[],
        json!({"value": "one"}),
    );
    assert!(matches!(
        fold_profile(&[duplicate.clone(), duplicate]),
        Err(FoldError::Causal(CausalError::DuplicateRecordId { .. }))
    ));

    let set = operation(
        "wayjournal.profile",
        "profile.display_name.set",
        1,
        &[],
        json!({"value": "one"}),
    );
    let fake = operation(
        "wayjournal.profile",
        "profile.display_name.resolve",
        2,
        &[1],
        json!({"candidates": [id(1), id(3)], "value": "chosen"}),
    );
    assert!(matches!(
        fold_profile(&[set, fake]),
        Err(FoldError::InvalidResolution { .. })
    ));

    let invalid_parents = DomainOperation::try_from(Record {
        parents: vec![id(2), id(1)],
        record_id: id(4),
        ..Record {
            record_schema: "wayjournal.profile/v1".parse().expect("schema"),
            domain: "wayjournal.profile".parse().expect("domain"),
            kind: "profile.display_name.set".parse().expect("kind"),
            record_id: id(4),
            entity_id: ENTITY.parse().expect("entity"),
            batch_id: "01913f1d-8e2a-7c30-8f4a-426614180004"
                .parse()
                .expect("batch"),
            actor: ActorId::parse("human:robin").expect("actor"),
            occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
            recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
            parents: Vec::new(),
            payload: json!({"value": "bad"}),
        }
    })
    .expect("operation shape");
    assert!(matches!(
        fold_profile(&[invalid_parents]),
        Err(FoldError::Causal(CausalError::InvalidParents { .. }))
    ));
}

#[test]
fn causal_graph_bounds_reject_oversized_histories_before_reachability_work() {
    let operations = (0..=wayjournal_core::MAX_CAUSAL_OPERATIONS)
        .map(|index| {
            operation(
                "wayjournal.profile",
                "profile.display_name.set",
                u16::try_from(index).expect("bounded"),
                &[],
                json!({"value": "bounded"}),
            )
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        fold_profile(&operations),
        Err(FoldError::Causal(CausalError::TooManyOperations { .. }))
    ));
}

#[test]
fn mv_register_coalesces_equal_concurrency_and_exposes_distinct_conflict() {
    let left = operation(
        "wayjournal.profile",
        "profile.display_name.set",
        1,
        &[],
        json!({"value": "Robin"}),
    );
    let equal = operation(
        "wayjournal.profile",
        "profile.display_name.set",
        2,
        &[],
        json!({"value": "Robin"}),
    );
    let profile = fold_profile(&[left.clone(), equal]).expect("fold");
    assert_eq!(profile.display_name().values(), &["Robin".to_owned()]);
    assert!(!profile.display_name().is_conflicted());

    let distinct = operation(
        "wayjournal.profile",
        "profile.display_name.set",
        3,
        &[],
        json!({"value": "R."}),
    );
    let conflicted = fold_profile(&[left.clone(), distinct.clone()]).expect("fold");
    assert_eq!(
        conflicted.display_name().values(),
        &["R.".to_owned(), "Robin".to_owned()]
    );
    assert!(conflicted.display_name().is_conflicted());

    let partial = operation(
        "wayjournal.profile",
        "profile.display_name.resolve",
        4,
        &[1, 3],
        json!({"candidates": [id(1)], "value": "Robin"}),
    );
    assert!(matches!(
        fold_profile(&[left, distinct, partial]),
        Err(FoldError::InvalidResolution { .. })
    ));
}

#[test]
fn observed_remove_names_seen_adds_and_concurrent_add_survives_without_resurrection() {
    let add_one = operation(
        "wayjournal.profile",
        "profile.alias.add",
        1,
        &[],
        json!({"key": "me", "value": "human:robin"}),
    );
    let remove = operation(
        "wayjournal.profile",
        "profile.alias.remove",
        2,
        &[1],
        json!({"adds": [id(1)], "key": "me"}),
    );
    let descendant = operation(
        "wayjournal.profile",
        "profile.description.set",
        5,
        &[2],
        json!({"value": "after removal"}),
    );
    let add_concurrent = operation(
        "wayjournal.profile",
        "profile.alias.add",
        3,
        &[],
        json!({"key": "me", "value": "human:other"}),
    );
    let profile = fold_profile(&[
        descendant.clone(),
        remove.clone(),
        add_concurrent.clone(),
        add_one.clone(),
    ])
    .expect("deterministic fold");
    assert_eq!(
        profile.actor_aliases().get("me").map(Vec::as_slice),
        Some(&["human:other".to_owned()][..])
    );

    let shuffled =
        fold_profile(&[add_one.clone(), add_concurrent, remove, descendant]).expect("shuffle");
    assert_eq!(profile, shuffled);

    let unseen_remove = operation(
        "wayjournal.profile",
        "profile.alias.remove",
        4,
        &[1],
        json!({"adds": [id(1), id(3)], "key": "me"}),
    );
    assert!(matches!(
        fold_profile(&[add_one, unseen_remove]),
        Err(FoldError::InvalidObservedRemove { .. })
    ));
}

#[test]
fn profile_is_explicitly_advisory_and_folds_all_closed_fields() {
    fn assert_advisory(_: &AdvisoryProfile) {}
    let operations = [
        operation(
            "wayjournal.profile",
            "profile.description.set",
            1,
            &[],
            json!({"value": "personal"}),
        ),
        operation(
            "wayjournal.profile",
            "profile.application.set",
            2,
            &[],
            json!({"value": "waytask"}),
        ),
        operation(
            "wayjournal.profile",
            "profile.remote.add",
            3,
            &[],
            json!({"key": "origin", "value": {"locator": "ssh://example/repo", "requires_identity_validation": true}}),
        ),
        operation(
            "wayjournal.profile",
            "profile.relation.add",
            4,
            &[],
            json!({"key": "tasks", "value": {"domain": "waytask.task", "entity_id": ENTITY, "store": target()}}),
        ),
        operation(
            "wayjournal.profile",
            "profile.capability.add",
            5,
            &[],
            json!({"key": "codec", "value": "wayjournal.json/v1"}),
        ),
        operation(
            "wayjournal.profile",
            "profile.policy_hint.add",
            6,
            &[],
            json!({"key": "example.retention", "value": "archive"}),
        ),
    ];
    let profile = fold_profile(&operations).expect("profile");
    assert_advisory(&profile);
    assert_eq!(
        profile.description().resolved().map(String::as_str),
        Some("personal")
    );
    assert_eq!(
        profile
            .application_identity()
            .resolved()
            .map(String::as_str),
        Some("waytask")
    );
    assert_eq!(profile.recommended_remotes().len(), 1);
    assert_eq!(profile.store_relations().len(), 1);
    assert_eq!(profile.capability_hints().len(), 1);
    assert_eq!(profile.advisory_policy_hints().len(), 1);
}

#[test]
fn catalog_requires_one_target_and_conflicted_defaults_have_no_destination() {
    let one = operation(
        "wayjournal.catalog",
        "catalog.default_store.set",
        1,
        &[],
        json!({"target": target(), "value": target()}),
    );
    let mut other = target();
    other = LogicalStoreId::new(
        "01913f1d-8e2a-7c30-8f4a-426614174020"
            .parse()
            .expect("uuid"),
        other.genesis_fingerprint(),
    );
    let two = operation(
        "wayjournal.catalog",
        "catalog.default_store.set",
        2,
        &[],
        json!({"target": target(), "value": other}),
    );
    let entry = fold_catalog(&[one.clone(), two]).expect("catalog");
    assert!(entry.contextual_default_store().is_conflicted());
    assert_eq!(entry.implicit_destination(), None);

    let wrong_target = operation(
        "wayjournal.catalog",
        "catalog.name.set",
        3,
        &[],
        json!({"target": other, "value": "other"}),
    );
    assert!(matches!(
        fold_catalog(&[one, wrong_target]),
        Err(FoldError::WrongTarget { .. })
    ));
}

#[test]
fn catalog_aliases_are_ambiguous_not_identity_and_locators_have_no_credentials() {
    fn assert_catalog(_: &CatalogEntry) {}
    let alias_one = operation(
        "wayjournal.catalog",
        "catalog.alias.add",
        1,
        &[],
        json!({"key": "work", "target": target(), "value": "primary"}),
    );
    let alias_two = operation(
        "wayjournal.catalog",
        "catalog.alias.add",
        2,
        &[],
        json!({"key": "work", "target": target(), "value": "secondary"}),
    );
    let locator = operation(
        "wayjournal.catalog",
        "catalog.remote.add",
        3,
        &[],
        json!({"key": "origin", "target": target(), "value": {"locator": "ssh://example/repo", "requires_identity_validation": true}}),
    );
    let relation = operation(
        "wayjournal.catalog",
        "catalog.relation.add",
        4,
        &[],
        json!({"key": "private.task_run", "target": target(), "value": {"kind": "private.task_run_pair", "left": {"domain": "waytask.task", "entity_id": ENTITY, "store": target()}, "right": {"domain": "waystation.run", "entity_id": ENTITY, "store": target()}}}),
    );
    let entry = fold_catalog(&[relation, locator, alias_two, alias_one]).expect("catalog");
    assert_catalog(&entry);
    assert_eq!(entry.aliases()["work"].len(), 2);
    assert!(entry.alias_is_ambiguous("work"));
    assert!(entry.candidate_remotes()["origin"][0].requires_identity_validation());
    assert_eq!(entry.store_relations().len(), 1);
}
