use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;

use crate::{
    CausalError, CausalGraph, CausalNode, DomainId, EntityId, KindId, LogicalStoreId,
    QualifiedEntityRef, Record, RecordId,
};

pub const PROFILE_SCHEMA_V1: &str = "wayjournal.profile/v1";
pub const CATALOG_SCHEMA_V1: &str = "wayjournal.catalog/v1";

const MAX_TEXT: usize = 4096;
const MAX_KEY: usize = 128;
const MAX_LOCATOR: usize = 2048;
const MAX_REFERENCES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteLocator {
    locator: String,
    requires_identity_validation: bool,
}

impl RemoteLocator {
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }

    #[must_use]
    pub const fn requires_identity_validation(&self) -> bool {
        self.requires_identity_validation
    }

    fn validate(&self) -> Result<(), String> {
        bounded(&self.locator, MAX_LOCATOR, "locator")?;
        if !self.requires_identity_validation {
            return Err("catalog/profile locators must require identity validation".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum CatalogRelation {
    #[serde(rename = "qualified")]
    Qualified { reference: QualifiedEntityRef },
    #[serde(rename = "private.task_run_pair")]
    PrivateTaskRunPair {
        left: QualifiedEntityRef,
        right: QualifiedEntityRef,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScalarValue {
    Text(String),
    Bool(bool),
    Store(LogicalStoreId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SetValue {
    Text(String),
    Remote(RemoteLocator),
    Qualified(QualifiedEntityRef),
    Relation(CatalogRelation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ScalarField {
    DisplayName,
    Description,
    Application,
    EntryName,
    Enabled,
    DefaultStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SetField {
    Remote,
    Relation,
    Capability,
    Alias,
    Policy,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OperationKind {
    ScalarSet {
        field: ScalarField,
        value: ScalarValue,
    },
    ScalarResolve {
        field: ScalarField,
        value: ScalarValue,
        candidates: Vec<RecordId>,
    },
    Add {
        field: SetField,
        key: String,
        value: SetValue,
    },
    Remove {
        field: SetField,
        key: String,
        adds: Vec<RecordId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainOperation {
    record_id: RecordId,
    entity_id: EntityId,
    parents: Vec<RecordId>,
    domain: DomainId,
    target: Option<LogicalStoreId>,
    kind: OperationKind,
}

impl CausalNode for DomainOperation {
    fn record_id(&self) -> RecordId {
        self.record_id
    }

    fn parents(&self) -> &[RecordId] {
        &self.parents
    }
}

#[derive(Debug)]
pub(crate) struct DomainOperationHeader {
    source: usize,
    record_id: RecordId,
    entity_id: EntityId,
    parents: Vec<RecordId>,
    domain: DomainId,
}

impl CausalNode for DomainOperationHeader {
    fn record_id(&self) -> RecordId {
        self.record_id
    }

    fn parents(&self) -> &[RecordId] {
        &self.parents
    }
}

impl DomainOperation {
    pub(crate) fn into_header(self, source: usize) -> DomainOperationHeader {
        DomainOperationHeader {
            source,
            record_id: self.record_id,
            entity_id: self.entity_id,
            parents: self.parents,
            domain: self.domain,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OperationError {
    #[error("unsupported profile/catalog domain schema or kind")]
    Unsupported,
    #[error("invalid closed operation payload: {0}")]
    InvalidPayload(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScalarPayload<T> {
    value: T,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvePayload<T> {
    candidates: Vec<RecordId>,
    value: T,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddPayload<T> {
    key: String,
    value: T,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovePayload {
    adds: Vec<RecordId>,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogScalarPayload<T> {
    target: LogicalStoreId,
    value: T,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogResolvePayload<T> {
    candidates: Vec<RecordId>,
    target: LogicalStoreId,
    value: T,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogAddPayload<T> {
    key: String,
    target: LogicalStoreId,
    value: T,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogRemovePayload {
    adds: Vec<RecordId>,
    key: String,
    target: LogicalStoreId,
}

fn parse<T: DeserializeOwned>(value: Value) -> Result<T, OperationError> {
    serde_json::from_value(value).map_err(|error| OperationError::InvalidPayload(error.to_string()))
}

fn bounded(value: &str, maximum: usize, name: &str) -> Result<(), String> {
    if value.is_empty() || value.chars().count() > maximum || value.chars().any(char::is_control) {
        Err(format!(
            "{name} must be nonempty, bounded, and contain no controls"
        ))
    } else {
        Ok(())
    }
}

fn validate_ids(ids: &[RecordId], name: &str) -> Result<(), OperationError> {
    if ids.is_empty() || ids.len() > MAX_REFERENCES || !ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(OperationError::InvalidPayload(format!(
            "{name} must be nonempty, bounded, sorted, and duplicate-free"
        )));
    }
    Ok(())
}

fn text(value: String) -> Result<ScalarValue, OperationError> {
    bounded(&value, MAX_TEXT, "value").map_err(OperationError::InvalidPayload)?;
    Ok(ScalarValue::Text(value))
}

fn text_set(value: String) -> Result<SetValue, OperationError> {
    bounded(&value, MAX_TEXT, "value").map_err(OperationError::InvalidPayload)?;
    Ok(SetValue::Text(value))
}

fn key(value: String) -> Result<String, OperationError> {
    bounded(&value, MAX_KEY, "key").map_err(OperationError::InvalidPayload)?;
    Ok(value)
}

#[allow(clippy::too_many_lines)]
fn profile_operation(record: Record) -> Result<DomainOperation, OperationError> {
    let operation = match record.kind.as_str() {
        "profile.display_name.set" => {
            let raw: ScalarPayload<String> = parse(record.payload)?;
            OperationKind::ScalarSet {
                field: ScalarField::DisplayName,
                value: text(raw.value)?,
            }
        }
        "profile.description.set" => {
            let raw: ScalarPayload<String> = parse(record.payload)?;
            OperationKind::ScalarSet {
                field: ScalarField::Description,
                value: text(raw.value)?,
            }
        }
        "profile.application.set" => {
            let raw: ScalarPayload<String> = parse(record.payload)?;
            OperationKind::ScalarSet {
                field: ScalarField::Application,
                value: text(raw.value)?,
            }
        }
        "profile.display_name.resolve"
        | "profile.description.resolve"
        | "profile.application.resolve" => {
            let raw: ResolvePayload<String> = parse(record.payload)?;
            validate_ids(&raw.candidates, "candidates")?;
            let field = match record.kind.as_str() {
                "profile.display_name.resolve" => ScalarField::DisplayName,
                "profile.description.resolve" => ScalarField::Description,
                _ => ScalarField::Application,
            };
            OperationKind::ScalarResolve {
                field,
                value: text(raw.value)?,
                candidates: raw.candidates,
            }
        }
        "profile.remote.add" => {
            let raw: AddPayload<RemoteLocator> = parse(record.payload)?;
            raw.value
                .validate()
                .map_err(OperationError::InvalidPayload)?;
            OperationKind::Add {
                field: SetField::Remote,
                key: key(raw.key)?,
                value: SetValue::Remote(raw.value),
            }
        }
        "profile.relation.add" => {
            let raw: AddPayload<QualifiedEntityRef> = parse(record.payload)?;
            OperationKind::Add {
                field: SetField::Relation,
                key: key(raw.key)?,
                value: SetValue::Qualified(raw.value),
            }
        }
        "profile.capability.add" | "profile.alias.add" | "profile.policy_hint.add" => {
            let raw: AddPayload<String> = parse(record.payload)?;
            let field = match record.kind.as_str() {
                "profile.capability.add" => SetField::Capability,
                "profile.alias.add" => SetField::Alias,
                _ => SetField::Policy,
            };
            let key = if field == SetField::Policy {
                raw.key
                    .parse::<DomainId>()
                    .map_err(|error| OperationError::InvalidPayload(error.to_string()))?
                    .to_string()
            } else {
                key(raw.key)?
            };
            OperationKind::Add {
                field,
                key,
                value: text_set(raw.value)?,
            }
        }
        "profile.remote.remove"
        | "profile.relation.remove"
        | "profile.capability.remove"
        | "profile.alias.remove"
        | "profile.policy_hint.remove" => {
            let raw: RemovePayload = parse(record.payload)?;
            validate_ids(&raw.adds, "adds")?;
            let field = match record.kind.as_str() {
                "profile.remote.remove" => SetField::Remote,
                "profile.relation.remove" => SetField::Relation,
                "profile.capability.remove" => SetField::Capability,
                "profile.alias.remove" => SetField::Alias,
                _ => SetField::Policy,
            };
            let key = if field == SetField::Policy {
                raw.key
                    .parse::<DomainId>()
                    .map_err(|error| OperationError::InvalidPayload(error.to_string()))?
                    .to_string()
            } else {
                key(raw.key)?
            };
            OperationKind::Remove {
                field,
                key,
                adds: raw.adds,
            }
        }
        _ => return Err(OperationError::Unsupported),
    };
    Ok(DomainOperation {
        record_id: record.record_id,
        entity_id: record.entity_id,
        parents: record.parents,
        domain: record.domain,
        target: None,
        kind: operation,
    })
}

#[allow(clippy::too_many_lines)]
fn catalog_operation(record: Record) -> Result<DomainOperation, OperationError> {
    let (target, operation) = match record.kind.as_str() {
        "catalog.name.set" => {
            let raw: CatalogScalarPayload<String> = parse(record.payload)?;
            (
                raw.target,
                OperationKind::ScalarSet {
                    field: ScalarField::EntryName,
                    value: text(raw.value)?,
                },
            )
        }
        "catalog.enabled.set" => {
            let raw: CatalogScalarPayload<bool> = parse(record.payload)?;
            (
                raw.target,
                OperationKind::ScalarSet {
                    field: ScalarField::Enabled,
                    value: ScalarValue::Bool(raw.value),
                },
            )
        }
        "catalog.default_store.set" => {
            let raw: CatalogScalarPayload<LogicalStoreId> = parse(record.payload)?;
            (
                raw.target,
                OperationKind::ScalarSet {
                    field: ScalarField::DefaultStore,
                    value: ScalarValue::Store(raw.value),
                },
            )
        }
        "catalog.name.resolve" => {
            let raw: CatalogResolvePayload<String> = parse(record.payload)?;
            validate_ids(&raw.candidates, "candidates")?;
            (
                raw.target,
                OperationKind::ScalarResolve {
                    field: ScalarField::EntryName,
                    value: text(raw.value)?,
                    candidates: raw.candidates,
                },
            )
        }
        "catalog.enabled.resolve" => {
            let raw: CatalogResolvePayload<bool> = parse(record.payload)?;
            validate_ids(&raw.candidates, "candidates")?;
            (
                raw.target,
                OperationKind::ScalarResolve {
                    field: ScalarField::Enabled,
                    value: ScalarValue::Bool(raw.value),
                    candidates: raw.candidates,
                },
            )
        }
        "catalog.default_store.resolve" => {
            let raw: CatalogResolvePayload<LogicalStoreId> = parse(record.payload)?;
            validate_ids(&raw.candidates, "candidates")?;
            (
                raw.target,
                OperationKind::ScalarResolve {
                    field: ScalarField::DefaultStore,
                    value: ScalarValue::Store(raw.value),
                    candidates: raw.candidates,
                },
            )
        }
        "catalog.remote.add" => {
            let raw: CatalogAddPayload<RemoteLocator> = parse(record.payload)?;
            raw.value
                .validate()
                .map_err(OperationError::InvalidPayload)?;
            (
                raw.target,
                OperationKind::Add {
                    field: SetField::Remote,
                    key: key(raw.key)?,
                    value: SetValue::Remote(raw.value),
                },
            )
        }
        "catalog.relation.add" => {
            let raw: CatalogAddPayload<CatalogRelation> = parse(record.payload)?;
            (
                raw.target,
                OperationKind::Add {
                    field: SetField::Relation,
                    key: key(raw.key)?,
                    value: SetValue::Relation(raw.value),
                },
            )
        }
        "catalog.alias.add" | "catalog.group.add" => {
            let raw: CatalogAddPayload<String> = parse(record.payload)?;
            let field = if record.kind.as_str() == "catalog.alias.add" {
                SetField::Alias
            } else {
                SetField::Group
            };
            (
                raw.target,
                OperationKind::Add {
                    field,
                    key: key(raw.key)?,
                    value: text_set(raw.value)?,
                },
            )
        }
        "catalog.remote.remove"
        | "catalog.relation.remove"
        | "catalog.alias.remove"
        | "catalog.group.remove" => {
            let raw: CatalogRemovePayload = parse(record.payload)?;
            validate_ids(&raw.adds, "adds")?;
            let field = match record.kind.as_str() {
                "catalog.remote.remove" => SetField::Remote,
                "catalog.relation.remove" => SetField::Relation,
                "catalog.alias.remove" => SetField::Alias,
                _ => SetField::Group,
            };
            (
                raw.target,
                OperationKind::Remove {
                    field,
                    key: key(raw.key)?,
                    adds: raw.adds,
                },
            )
        }
        _ => return Err(OperationError::Unsupported),
    };
    Ok(DomainOperation {
        record_id: record.record_id,
        entity_id: record.entity_id,
        parents: record.parents,
        domain: record.domain,
        target: Some(target),
        kind: operation,
    })
}

impl TryFrom<Record> for DomainOperation {
    type Error = OperationError;

    fn try_from(record: Record) -> Result<Self, Self::Error> {
        match (record.domain.as_str(), record.record_schema.as_str()) {
            ("wayjournal.profile", PROFILE_SCHEMA_V1) => profile_operation(record),
            ("wayjournal.catalog", CATALOG_SCHEMA_V1) => catalog_operation(record),
            _ => Err(OperationError::Unsupported),
        }
    }
}

pub(crate) fn validate_profile_payload(kind: &KindId, payload: &Value) -> Result<(), String> {
    validate_payload("wayjournal.profile", PROFILE_SCHEMA_V1, kind, payload)
}

pub(crate) fn validate_catalog_payload(kind: &KindId, payload: &Value) -> Result<(), String> {
    validate_payload("wayjournal.catalog", CATALOG_SCHEMA_V1, kind, payload)
}

fn validate_payload(
    domain: &str,
    schema: &str,
    kind: &KindId,
    payload: &Value,
) -> Result<(), String> {
    let fake = Record {
        record_schema: schema
            .parse()
            .map_err(|error: crate::IdentifierError| error.to_string())?,
        domain: domain
            .parse()
            .map_err(|error: crate::IdentifierError| error.to_string())?,
        kind: kind.clone(),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174001"
            .parse()
            .map_err(|error: crate::IdentifierError| error.to_string())?,
        entity_id: "123e4567-e89b-42d3-a456-426614174000"
            .parse()
            .map_err(|error: crate::IdentifierError| error.to_string())?,
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174002"
            .parse()
            .map_err(|error: crate::IdentifierError| error.to_string())?,
        actor: crate::ActorId::parse("system:validator").map_err(|error| error.to_string())?,
        occurred_at: "2026-01-01T00:00:00Z"
            .parse()
            .map_err(|error: crate::IdentifierError| error.to_string())?,
        recorded_at: "2026-01-01T00:00:00Z"
            .parse()
            .map_err(|error: crate::IdentifierError| error.to_string())?,
        parents: Vec::new(),
        payload: payload.clone(),
    };
    DomainOperation::try_from(fake)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FoldError {
    #[error(transparent)]
    Causal(#[from] CausalError),
    #[error("operation domain or entity does not match the fold")]
    WrongEntity,
    #[error("catalog operation targets {actual:?}, expected {expected:?}")]
    WrongTarget {
        expected: LogicalStoreId,
        actual: LogicalStoreId,
    },
    #[error("resolution {record_id} does not name exactly all observed maximal candidates")]
    InvalidResolution { record_id: RecordId },
    #[error("remove {record_id} does not name exactly all observed adds for its key")]
    InvalidObservedRemove { record_id: RecordId },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MvRegister<T> {
    values: Vec<T>,
}

impl<T> MvRegister<T> {
    #[must_use]
    pub fn values(&self) -> &[T] {
        &self.values
    }
    #[must_use]
    pub fn is_conflicted(&self) -> bool {
        self.values.len() > 1
    }
    #[must_use]
    pub fn resolved(&self) -> Option<&T> {
        (self.values.len() == 1).then(|| &self.values[0])
    }
}

type Values<T> = BTreeMap<String, Vec<T>>;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdvisoryProfile {
    display_name: MvRegister<String>,
    description: MvRegister<String>,
    application_identity: MvRegister<String>,
    recommended_remotes: Values<RemoteLocator>,
    store_relations: Values<QualifiedEntityRef>,
    capability_hints: Values<String>,
    actor_aliases: Values<String>,
    advisory_policy_hints: Values<String>,
}

impl AdvisoryProfile {
    #[must_use]
    pub const fn display_name(&self) -> &MvRegister<String> {
        &self.display_name
    }
    #[must_use]
    pub const fn description(&self) -> &MvRegister<String> {
        &self.description
    }
    #[must_use]
    pub const fn application_identity(&self) -> &MvRegister<String> {
        &self.application_identity
    }
    #[must_use]
    pub const fn recommended_remotes(&self) -> &Values<RemoteLocator> {
        &self.recommended_remotes
    }
    #[must_use]
    pub const fn store_relations(&self) -> &Values<QualifiedEntityRef> {
        &self.store_relations
    }
    #[must_use]
    pub const fn capability_hints(&self) -> &Values<String> {
        &self.capability_hints
    }
    #[must_use]
    pub const fn actor_aliases(&self) -> &Values<String> {
        &self.actor_aliases
    }
    #[must_use]
    pub const fn advisory_policy_hints(&self) -> &Values<String> {
        &self.advisory_policy_hints
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    target: LogicalStoreId,
    entry_name: MvRegister<String>,
    enabled: MvRegister<bool>,
    contextual_default_store: MvRegister<LogicalStoreId>,
    aliases: Values<String>,
    candidate_remotes: Values<RemoteLocator>,
    groups: Values<String>,
    store_relations: Values<CatalogRelation>,
}

impl CatalogEntry {
    #[must_use]
    pub const fn target(&self) -> &LogicalStoreId {
        &self.target
    }
    #[must_use]
    pub const fn entry_name(&self) -> &MvRegister<String> {
        &self.entry_name
    }
    #[must_use]
    pub const fn enabled(&self) -> &MvRegister<bool> {
        &self.enabled
    }
    #[must_use]
    pub const fn contextual_default_store(&self) -> &MvRegister<LogicalStoreId> {
        &self.contextual_default_store
    }
    #[must_use]
    pub fn implicit_destination(&self) -> Option<&LogicalStoreId> {
        self.contextual_default_store.resolved()
    }
    #[must_use]
    pub const fn aliases(&self) -> &Values<String> {
        &self.aliases
    }
    #[must_use]
    pub fn alias_is_ambiguous(&self, alias: &str) -> bool {
        self.aliases
            .get(alias)
            .is_some_and(|values| values.len() > 1)
    }
    #[must_use]
    pub const fn candidate_remotes(&self) -> &Values<RemoteLocator> {
        &self.candidate_remotes
    }
    #[must_use]
    pub const fn groups(&self) -> &Values<String> {
        &self.groups
    }
    #[must_use]
    pub const fn store_relations(&self) -> &Values<CatalogRelation> {
        &self.store_relations
    }
}

#[derive(Default)]
struct FoldState {
    registers: BTreeMap<ScalarField, BTreeMap<RecordId, ScalarValue>>,
    adds: BTreeMap<(SetField, String), BTreeMap<RecordId, SetValue>>,
}

trait FoldAccumulator {
    fn register_ids(&self, field: ScalarField) -> Vec<RecordId>;
    fn remove_register(&mut self, field: ScalarField, record_id: RecordId);
    fn insert_register(&mut self, field: ScalarField, record_id: RecordId, value: &ScalarValue);
    fn add_ids(&self, field: SetField, key: &str) -> Vec<RecordId>;
    fn remove_add(&mut self, field: SetField, key: &str, record_id: RecordId);
    fn insert_add(&mut self, field: SetField, key: &str, record_id: RecordId, value: &SetValue);
}

impl FoldAccumulator for FoldState {
    fn register_ids(&self, field: ScalarField) -> Vec<RecordId> {
        self.registers
            .get(&field)
            .into_iter()
            .flat_map(BTreeMap::keys)
            .copied()
            .collect()
    }

    fn remove_register(&mut self, field: ScalarField, record_id: RecordId) {
        if let Some(active) = self.registers.get_mut(&field) {
            active.remove(&record_id);
        }
    }

    fn insert_register(&mut self, field: ScalarField, record_id: RecordId, value: &ScalarValue) {
        self.registers
            .entry(field)
            .or_default()
            .insert(record_id, value.clone());
    }

    fn add_ids(&self, field: SetField, key: &str) -> Vec<RecordId> {
        self.adds
            .get(&(field, key.to_owned()))
            .into_iter()
            .flat_map(BTreeMap::keys)
            .copied()
            .collect()
    }

    fn remove_add(&mut self, field: SetField, key: &str, record_id: RecordId) {
        if let Some(active) = self.adds.get_mut(&(field, key.to_owned())) {
            active.remove(&record_id);
        }
    }

    fn insert_add(&mut self, field: SetField, key: &str, record_id: RecordId, value: &SetValue) {
        self.adds
            .entry((field, key.to_owned()))
            .or_default()
            .insert(record_id, value.clone());
    }
}

fn apply_operation<T: CausalNode, S: FoldAccumulator>(
    graph: &CausalGraph<'_, T>,
    operation: &DomainOperation,
    state: &mut S,
    reachability_budget: &mut usize,
    reachability_exceeded: &mut bool,
) -> Result<(), FoldError> {
    let record_id = operation.record_id;
    match &operation.kind {
        OperationKind::ScalarSet { field, value } => {
            let observed = state
                .register_ids(*field)
                .into_iter()
                .filter(|candidate| {
                    graph.observes_bounded(
                        record_id,
                        *candidate,
                        reachability_budget,
                        reachability_exceeded,
                    )
                })
                .collect::<Vec<_>>();
            ensure_reachability_budget(*reachability_exceeded)?;
            for candidate in observed {
                state.remove_register(*field, candidate);
            }
            state.insert_register(*field, record_id, value);
        }
        OperationKind::ScalarResolve {
            field,
            value,
            candidates,
        } => {
            let observed = state
                .register_ids(*field)
                .into_iter()
                .filter(|candidate| {
                    graph.observes_bounded(
                        record_id,
                        *candidate,
                        reachability_budget,
                        reachability_exceeded,
                    )
                })
                .collect::<Vec<_>>();
            ensure_reachability_budget(*reachability_exceeded)?;
            if &observed != candidates {
                return Err(FoldError::InvalidResolution { record_id });
            }
            for candidate in candidates {
                state.remove_register(*field, *candidate);
            }
            state.insert_register(*field, record_id, value);
        }
        OperationKind::Add { field, key, value } => {
            state.insert_add(*field, key, record_id, value);
        }
        OperationKind::Remove { field, key, adds } => {
            let observed = state
                .add_ids(*field, key)
                .into_iter()
                .filter(|candidate| {
                    graph.observes_bounded(
                        record_id,
                        *candidate,
                        reachability_budget,
                        reachability_exceeded,
                    )
                })
                .collect::<Vec<_>>();
            ensure_reachability_budget(*reachability_exceeded)?;
            if &observed != adds {
                return Err(FoldError::InvalidObservedRemove { record_id });
            }
            for add in adds {
                state.remove_add(*field, key, *add);
            }
        }
    }
    Ok(())
}

fn ensure_reachability_budget(exceeded: bool) -> Result<(), FoldError> {
    if exceeded {
        Err(CausalError::ReachabilityBudget {
            maximum: crate::MAX_REACHABILITY_STEPS,
        }
        .into())
    } else {
        Ok(())
    }
}

fn apply_catalog_operation<T: CausalNode, S: FoldAccumulator + Default>(
    graph: &CausalGraph<'_, T>,
    operation: &DomainOperation,
    states: &mut BTreeMap<LogicalStoreId, S>,
    reachability_budget: &mut usize,
    reachability_exceeded: &mut bool,
) -> Result<(), FoldError> {
    let target = operation.target.clone().ok_or(FoldError::WrongEntity)?;
    apply_operation(
        graph,
        operation,
        states.entry(target).or_default(),
        reachability_budget,
        reachability_exceeded,
    )
}

fn fold(operations: &[DomainOperation], expected_domain: &str) -> Result<FoldState, FoldError> {
    let graph = CausalGraph::new(operations)?;
    let entity = operations.first().map(|op| op.entity_id);
    if operations
        .iter()
        .any(|op| op.domain.as_str() != expected_domain || Some(op.entity_id) != entity)
    {
        return Err(FoldError::WrongEntity);
    }
    let mut state = FoldState::default();
    let mut reachability_budget = crate::MAX_REACHABILITY_STEPS;
    let mut reachability_exceeded = false;
    for operation in graph.ordered() {
        apply_operation(
            &graph,
            operation,
            &mut state,
            &mut reachability_budget,
            &mut reachability_exceeded,
        )?;
    }
    Ok(state)
}

#[derive(Default)]
struct ValidationFoldState {
    registers: BTreeMap<ScalarField, BTreeSet<RecordId>>,
    adds: BTreeMap<(SetField, String), BTreeSet<RecordId>>,
}

impl FoldAccumulator for ValidationFoldState {
    fn register_ids(&self, field: ScalarField) -> Vec<RecordId> {
        self.registers
            .get(&field)
            .into_iter()
            .flat_map(BTreeSet::iter)
            .copied()
            .collect()
    }

    fn remove_register(&mut self, field: ScalarField, record_id: RecordId) {
        if let Some(active) = self.registers.get_mut(&field) {
            active.remove(&record_id);
        }
    }

    fn insert_register(&mut self, field: ScalarField, record_id: RecordId, _: &ScalarValue) {
        self.registers.entry(field).or_default().insert(record_id);
    }

    fn add_ids(&self, field: SetField, key: &str) -> Vec<RecordId> {
        self.adds
            .get(&(field, key.to_owned()))
            .into_iter()
            .flat_map(BTreeSet::iter)
            .copied()
            .collect()
    }

    fn remove_add(&mut self, field: SetField, key: &str, record_id: RecordId) {
        if let Some(active) = self.adds.get_mut(&(field, key.to_owned())) {
            active.remove(&record_id);
        }
    }

    fn insert_add(&mut self, field: SetField, key: &str, record_id: RecordId, _: &SetValue) {
        self.adds
            .entry((field, key.to_owned()))
            .or_default()
            .insert(record_id);
    }
}

pub(crate) enum FoldLoadError<E> {
    Fold(FoldError),
    Load(E),
}

/// Validates a built-in fold while loading only the current operation's payload.
///
/// The compact headers retain the complete causal graph, while scalar/set values and
/// resolution/remove reference vectors can be discarded after each state transition.
pub(crate) fn validate_loaded_builtin_fold<E>(
    operations: &[DomainOperationHeader],
    mut load: impl FnMut(usize) -> Result<DomainOperation, E>,
) -> Result<(), FoldLoadError<E>> {
    let Some(first) = operations.first() else {
        return Ok(());
    };
    let expected_domain = first.domain.to_string();
    let graph = CausalGraph::new(operations)
        .map_err(FoldError::from)
        .map_err(FoldLoadError::Fold)?;
    let entity = operations.first().map(|operation| operation.entity_id);
    if operations.iter().any(|operation| {
        operation.domain.as_str() != expected_domain || Some(operation.entity_id) != entity
    }) {
        return Err(FoldLoadError::Fold(FoldError::WrongEntity));
    }

    let mut profile_state = ValidationFoldState::default();
    let mut catalog_states = BTreeMap::<LogicalStoreId, ValidationFoldState>::new();
    let mut reachability_budget = crate::MAX_REACHABILITY_STEPS;
    let mut reachability_exceeded = false;
    for header in graph.ordered() {
        let operation = load(header.source).map_err(FoldLoadError::Load)?;
        if expected_domain == "wayjournal.catalog" {
            apply_catalog_operation(
                &graph,
                &operation,
                &mut catalog_states,
                &mut reachability_budget,
                &mut reachability_exceeded,
            )
            .map_err(FoldLoadError::Fold)?;
        } else {
            apply_operation(
                &graph,
                &operation,
                &mut profile_state,
                &mut reachability_budget,
                &mut reachability_exceeded,
            )
            .map_err(FoldLoadError::Fold)?;
        }
    }
    Ok(())
}

fn register<T: Ord>(
    state: &FoldState,
    field: ScalarField,
    convert: impl Fn(&ScalarValue) -> Option<T>,
) -> MvRegister<T> {
    let mut values = state
        .registers
        .get(&field)
        .into_iter()
        .flat_map(BTreeMap::values)
        .filter_map(convert)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    MvRegister { values }
}

fn values<T: Ord>(
    state: &FoldState,
    field: SetField,
    convert: impl Fn(&SetValue) -> Option<T>,
) -> Values<T> {
    state
        .adds
        .iter()
        .filter(|((candidate, _), _)| *candidate == field)
        .filter_map(|((_, key), adds)| {
            let mut values = adds.values().filter_map(&convert).collect::<Vec<_>>();
            values.sort();
            values.dedup();
            (!values.is_empty()).then(|| (key.clone(), values))
        })
        .collect()
}

/// Deterministically folds closed profile operations into explicitly advisory state.
/// # Errors
/// Rejects incomplete/invalid causal graphs, fake/partial resolution, and invalid removes.
pub fn fold_profile(operations: &[DomainOperation]) -> Result<AdvisoryProfile, FoldError> {
    let state = fold(operations, "wayjournal.profile")?;
    Ok(AdvisoryProfile {
        display_name: register(&state, ScalarField::DisplayName, |v| {
            if let ScalarValue::Text(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        description: register(&state, ScalarField::Description, |v| {
            if let ScalarValue::Text(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        application_identity: register(&state, ScalarField::Application, |v| {
            if let ScalarValue::Text(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        recommended_remotes: values(&state, SetField::Remote, |v| {
            if let SetValue::Remote(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        store_relations: values(&state, SetField::Relation, |v| {
            if let SetValue::Qualified(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        capability_hints: values(&state, SetField::Capability, |v| {
            if let SetValue::Text(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        actor_aliases: values(&state, SetField::Alias, |v| {
            if let SetValue::Text(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        advisory_policy_hints: values(&state, SetField::Policy, |v| {
            if let SetValue::Text(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
    })
}

fn catalog_entry(target: LogicalStoreId, state: &FoldState) -> CatalogEntry {
    CatalogEntry {
        target,
        entry_name: register(state, ScalarField::EntryName, |v| {
            if let ScalarValue::Text(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        enabled: register(state, ScalarField::Enabled, |v| {
            if let ScalarValue::Bool(v) = v {
                Some(*v)
            } else {
                None
            }
        }),
        contextual_default_store: register(state, ScalarField::DefaultStore, |v| {
            if let ScalarValue::Store(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        aliases: values(state, SetField::Alias, |v| {
            if let SetValue::Text(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        candidate_remotes: values(state, SetField::Remote, |v| {
            if let SetValue::Remote(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        groups: values(state, SetField::Group, |v| {
            if let SetValue::Text(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
        store_relations: values(state, SetField::Relation, |v| {
            if let SetValue::Relation(v) = v {
                Some(v.clone())
            } else {
                None
            }
        }),
    }
}

/// Deterministically folds a complete catalog entity into target-partitioned advisory state.
///
/// The causal graph spans every target, so cross-target parents are valid ancestry. Register
/// resolutions and observed removes affect only the active values of the addressed target.
/// # Errors
/// Rejects mixed entities, invalid causal graphs, fake/partial resolutions, and invalid removes.
pub fn fold_catalogs(
    operations: &[DomainOperation],
) -> Result<BTreeMap<LogicalStoreId, CatalogEntry>, FoldError> {
    let graph = CausalGraph::new(operations)?;
    let entity = operations.first().map(|operation| operation.entity_id);
    if operations.iter().any(|operation| {
        operation.domain.as_str() != "wayjournal.catalog" || Some(operation.entity_id) != entity
    }) {
        return Err(FoldError::WrongEntity);
    }

    let mut states = BTreeMap::<LogicalStoreId, FoldState>::new();
    let mut reachability_budget = crate::MAX_REACHABILITY_STEPS;
    let mut reachability_exceeded = false;
    for operation in graph.ordered() {
        apply_catalog_operation(
            &graph,
            operation,
            &mut states,
            &mut reachability_budget,
            &mut reachability_exceeded,
        )?;
    }
    Ok(states
        .into_iter()
        .map(|(target, state)| {
            let entry = catalog_entry(target.clone(), &state);
            (target, entry)
        })
        .collect())
}

/// Deterministically folds one target's closed catalog operations.
/// # Errors
/// Rejects mixed targets/entities, invalid causal graphs, resolutions, and removes.
pub fn fold_catalog(operations: &[DomainOperation]) -> Result<CatalogEntry, FoldError> {
    let target = operations
        .first()
        .and_then(|operation| operation.target.clone())
        .ok_or(FoldError::WrongEntity)?;
    if let Some(actual) = operations
        .iter()
        .filter_map(|operation| operation.target.as_ref())
        .find(|actual| **actual != target)
    {
        return Err(FoldError::WrongTarget {
            expected: target,
            actual: actual.clone(),
        });
    }
    fold_catalogs(operations)?
        .remove(&target)
        .ok_or(FoldError::WrongEntity)
}
