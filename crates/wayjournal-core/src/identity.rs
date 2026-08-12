use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Digest, DomainId, DomainRegistry, EntityId, KindId, RecordId, StoreRevisionRef, StoreUuid,
    StoredMember, hash::update_frame, record::decode_record, validate_batch_members,
};

pub const IDENTITY_SCHEMA_V1: &str = "wayjournal.identity/v1";
const GENESIS_FINGERPRINT_DOMAIN: &[u8] = b"wayjournal-genesis-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalStoreId {
    store_uuid: StoreUuid,
    genesis_fingerprint: Digest,
}

impl LogicalStoreId {
    #[must_use]
    pub const fn new(store_uuid: StoreUuid, genesis_fingerprint: Digest) -> Self {
        Self {
            store_uuid,
            genesis_fingerprint,
        }
    }

    #[must_use]
    pub const fn store_uuid(&self) -> StoreUuid {
        self.store_uuid
    }

    #[must_use]
    pub const fn genesis_fingerprint(&self) -> Digest {
        self.genesis_fingerprint
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedEntityRef {
    pub store: LogicalStoreId,
    pub domain: DomainId,
    pub entity_id: EntityId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkProvenance {
    pub parent: LogicalStoreId,
    pub parent_revision: StoreRevisionRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreIdentity {
    logical_id: LogicalStoreId,
    store_kind: KindId,
    forked_from: Option<ForkProvenance>,
    genesis_record_id: RecordId,
}

impl StoreIdentity {
    #[must_use]
    pub const fn logical_id(&self) -> &LogicalStoreId {
        &self.logical_id
    }

    #[must_use]
    pub const fn store_kind(&self) -> &KindId {
        &self.store_kind
    }

    #[must_use]
    pub const fn fork_provenance(&self) -> Option<&ForkProvenance> {
        self.forked_from.as_ref()
    }

    #[must_use]
    pub const fn genesis_record_id(&self) -> RecordId {
        self.genesis_record_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRelation {
    Replica,
    UuidCollision,
    Distinct,
}

#[must_use]
pub fn classify_logical_identity(
    left: &LogicalStoreId,
    right: &LogicalStoreId,
) -> IdentityRelation {
    if left == right {
        IdentityRelation::Replica
    } else if left.store_uuid == right.store_uuid {
        IdentityRelation::UuidCollision
    } else {
        IdentityRelation::Distinct
    }
}

#[must_use]
pub fn genesis_fingerprint(path: &[u8], bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(GENESIS_FINGERPRINT_DOMAIN);
    update_frame(&mut hasher, path);
    update_frame(&mut hasher, bytes);
    Digest::from_hash(hasher.finalize())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GenesisError {
    #[error("generic store has records but no store.genesis record")]
    MissingGenesis,
    #[error("generic store has more than one store.genesis record")]
    DuplicateGenesis,
    #[error("store.genesis is not in the first generic batch")]
    GenesisNotFirst,
    #[error("store.genesis entity id does not equal its store UUID")]
    EntityMismatch,
    #[error("logical fork must mint a store UUID distinct from its parent")]
    ForkReusesParentUuid,
    #[error("identity record member is invalid: {0}")]
    InvalidRecord(String),
    #[error("identity member path/envelope identity mismatch")]
    MemberIdentityMismatch,
    #[error("identity member actor differs from its manifest")]
    MemberActorMismatch,
    #[error("identity member batch differs from its manifest")]
    MemberBatchMismatch,
    #[error("duplicate stored identity member path")]
    DuplicateMember,
    #[error("manifest/member identity input is incomplete")]
    IncompleteMembers,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisPayload {
    store_kind: KindId,
    store_uuid: StoreUuid,
    #[serde(default)]
    forked_from: Option<ForkProvenance>,
}

pub(crate) fn validate_identity_payload(kind: &KindId, payload: &Value) -> Result<(), String> {
    if kind.as_str() != "store.genesis" {
        return Err("identity schema supports only store.genesis".to_owned());
    }
    let parsed: GenesisPayload = serde_json::from_value(payload.clone())
        .map_err(|error| format!("invalid closed genesis payload: {error}"))?;
    if parsed
        .forked_from
        .as_ref()
        .is_some_and(|fork| fork.parent.store_uuid == parsed.store_uuid)
    {
        return Err("logical fork must mint a new store UUID".to_owned());
    }
    Ok(())
}

/// Validates the exactly-once, first-generic-batch genesis invariant and derives identity.
///
/// An entirely generic-empty store is uninitialized and returns `Ok(None)`.
///
/// # Errors
/// Returns [`GenesisError`] for missing, duplicate, late, malformed, or invalid-fork genesis.
#[allow(clippy::too_many_lines)]
pub fn validate_store_identity(
    manifests: &[crate::BatchManifest],
    members: &[StoredMember<'_>],
    registry: &DomainRegistry,
) -> Result<Option<StoreIdentity>, GenesisError> {
    if manifests.is_empty() && members.is_empty() {
        return Ok(None);
    }
    let by_path = members
        .iter()
        .map(|member| (member.path().to_vec(), member.bytes()))
        .collect::<BTreeMap<_, _>>();
    if by_path.len() != members.len() {
        return Err(GenesisError::DuplicateMember);
    }
    let mut manifest_ids = BTreeSet::new();
    let mut sorted_manifests = manifests.iter().collect::<Vec<_>>();
    sorted_manifests.sort_by_key(|manifest| manifest.canonical_path());
    for manifest in &sorted_manifests {
        if !manifest_ids.insert(manifest.batch_id()) {
            return Err(GenesisError::IncompleteMembers);
        }
        let batch_members = manifest
            .members()
            .iter()
            .map(|reference| {
                by_path
                    .get(reference.path().as_bytes())
                    .map(|bytes| StoredMember::new(reference.path().as_bytes(), bytes))
                    .ok_or(GenesisError::IncompleteMembers)
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_batch_members(manifest, &batch_members, registry).map_err(
            |error| match error {
                crate::BatchError::MemberIdentityMismatch { .. } => {
                    GenesisError::MemberIdentityMismatch
                }
                crate::BatchError::MemberActorMismatch { .. } => GenesisError::MemberActorMismatch,
                crate::BatchError::MemberBatchMismatch { .. } => GenesisError::MemberBatchMismatch,
                other => GenesisError::InvalidRecord(other.to_string()),
            },
        )?;
    }
    let manifest_paths = manifests
        .iter()
        .flat_map(crate::BatchManifest::members)
        .map(|member| member.path().as_bytes().to_vec())
        .collect::<BTreeSet<_>>();
    if manifest_paths != by_path.keys().cloned().collect() {
        return Err(GenesisError::IncompleteMembers);
    }

    let mut decoded = Vec::with_capacity(members.len());
    for member in members {
        let record = decode_record(member.bytes(), registry)
            .map_err(|error| GenesisError::InvalidRecord(error.to_string()))?;
        if record.canonical_path().as_bytes() != member.path() {
            return Err(GenesisError::InvalidRecord(
                "member path does not equal record canonical path".to_owned(),
            ));
        }
        decoded.push((member.path(), member.bytes(), record));
    }
    if decoded.iter().any(|(_, _, record)| {
        record.domain.as_str() == "wayjournal.identity"
            && record.record_schema.as_str() != IDENTITY_SCHEMA_V1
    }) {
        return Err(GenesisError::InvalidRecord(
            "unsupported record in reserved identity domain".to_owned(),
        ));
    }
    let genesis = decoded
        .iter()
        .filter(|(_, _, record)| {
            record.domain.as_str() == "wayjournal.identity"
                && record.record_schema.as_str() == IDENTITY_SCHEMA_V1
                && record.kind.as_str() == "store.genesis"
        })
        .collect::<Vec<_>>();
    let [(path, bytes, record)] = genesis.as_slice() else {
        return if genesis.is_empty() {
            Err(GenesisError::MissingGenesis)
        } else {
            Err(GenesisError::DuplicateGenesis)
        };
    };
    let first_batch = sorted_manifests
        .first()
        .ok_or(GenesisError::MissingGenesis)?
        .batch_id();
    if record.batch_id != first_batch {
        return Err(GenesisError::GenesisNotFirst);
    }
    let first_manifest = sorted_manifests
        .first()
        .ok_or(GenesisError::MissingGenesis)?;
    if first_manifest.members().len() != 1
        || first_manifest.members()[0].record_id() != record.record_id
    {
        return Err(GenesisError::GenesisNotFirst);
    }
    let payload: GenesisPayload = serde_json::from_value(record.payload.clone())
        .map_err(|error| GenesisError::InvalidRecord(error.to_string()))?;
    if record.entity_id.as_uuid() != payload.store_uuid.as_uuid() {
        return Err(GenesisError::EntityMismatch);
    }
    if payload
        .forked_from
        .as_ref()
        .is_some_and(|fork| fork.parent.store_uuid == payload.store_uuid)
    {
        return Err(GenesisError::ForkReusesParentUuid);
    }
    Ok(Some(StoreIdentity {
        logical_id: LogicalStoreId::new(payload.store_uuid, genesis_fingerprint(path, bytes)),
        store_kind: payload.store_kind,
        forked_from: payload.forked_from,
        genesis_record_id: record.record_id,
    }))
}

#[cfg(test)]
mod branch_tests {
    use super::*;
    use crate::{ActorId, Record, prepare_batch, wayjournal_domain_registry};
    use serde_json::json;

    fn genesis() -> Record {
        Record {
            record_schema: IDENTITY_SCHEMA_V1.parse().unwrap(),
            domain: "wayjournal.identity".parse().unwrap(),
            kind: "store.genesis".parse().unwrap(),
            record_id: "01913f1d-8e2a-7c30-8f4a-426614174011".parse().unwrap(),
            entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010".parse().unwrap(),
            batch_id: "01913f1d-8e2a-7c30-8f4a-426614174012".parse().unwrap(),
            actor: ActorId::parse("test:identity").unwrap(),
            occurred_at: "2026-08-12T13:00:00Z".parse().unwrap(),
            recorded_at: "2026-08-12T13:00:01Z".parse().unwrap(),
            parents: vec![],
            payload: json!({"store_kind":"wayjournal.personal","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"}),
        }
    }
    #[test]
    fn exact_identity_member_ownership_error_branches_are_reached() {
        let registry = wayjournal_domain_registry().unwrap();
        let prepared = prepare_batch(&[genesis()], "branches", &registry).unwrap();
        let original = StoredMember::new(
            prepared.records()[0].path().as_bytes(),
            prepared.records()[0].bytes(),
        );
        assert_eq!(
            validate_store_identity(
                &[prepared.manifest().clone()],
                &[original, original],
                &registry
            ),
            Err(GenesisError::DuplicateMember)
        );

        let mut wrong_actor = genesis();
        wrong_actor.actor = ActorId::parse("test:other").unwrap();
        let mut manifest = prepared.manifest().clone();
        let actor_member = manifest.replace_only_member_for_test(&wrong_actor, &registry, false);
        assert_eq!(
            validate_store_identity(
                &[manifest],
                &[StoredMember::new(
                    actor_member.path().as_bytes(),
                    actor_member.bytes()
                )],
                &registry
            ),
            Err(GenesisError::MemberActorMismatch)
        );

        let mut wrong_batch = genesis();
        wrong_batch.batch_id = "01913f1d-8e2a-7c30-8f4a-426614174099".parse().unwrap();
        let mut manifest = prepared.manifest().clone();
        let batch_member = manifest.replace_only_member_for_test(&wrong_batch, &registry, false);
        assert_eq!(
            validate_store_identity(
                &[manifest],
                &[StoredMember::new(
                    batch_member.path().as_bytes(),
                    batch_member.bytes()
                )],
                &registry
            ),
            Err(GenesisError::MemberBatchMismatch)
        );

        let mut wrong_path = genesis();
        wrong_path.record_id = "01913f1d-8e2a-7c30-8f4a-426614174099".parse().unwrap();
        let mut manifest = prepared.manifest().clone();
        let path_member = manifest.replace_only_member_for_test(&wrong_path, &registry, true);
        assert_eq!(
            validate_store_identity(
                &[manifest],
                &[StoredMember::new(
                    path_member.path().as_bytes(),
                    path_member.bytes()
                )],
                &registry
            ),
            Err(GenesisError::MemberIdentityMismatch)
        );
    }
}
