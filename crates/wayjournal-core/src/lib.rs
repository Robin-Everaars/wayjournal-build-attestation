#![doc = "Domain-neutral wire and layout primitives for Wayjournal."]

mod artifacts;
mod batch;
mod builtin;
mod causal;
mod domains;
mod federation;
mod hash;
mod identity;
mod ids;
mod json;
mod layout;
mod record;
mod revision;
mod store;

pub use artifacts::{CAPABILITY_MANIFEST, CapabilityManifest, generated_schemas};
pub use batch::{
    BATCH_SCHEMA_V1, BatchError, BatchManifest, IdempotencyDecision, MAX_BATCH_BYTES,
    PreparedBatch, PreparedRecord, RecordRef, StoredMember, classify_idempotency,
    decode_batch_manifest, prepare_batch, validate_batch_members, validate_batch_ownership,
};
pub use builtin::{wayjournal_domain_registry, wayjournal_domain_registry_with};
pub use causal::{
    CausalError, CausalGraph, CausalNode, MAX_CAUSAL_EDGES, MAX_CAUSAL_OPERATIONS,
    MAX_REACHABILITY_STEPS,
};
pub use domains::{
    AdvisoryProfile, CATALOG_SCHEMA_V1, CatalogEntry, CatalogRelation, DomainOperation, FoldError,
    MvRegister, OperationError, PROFILE_SCHEMA_V1, RemoteLocator, fold_catalog, fold_profile,
};
pub use federation::{
    AdmissionCheckpoint, ApprovalError, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator,
    CheckpointError, GitAdmissionError, GitAdmissionOutcome, GitCommandError, GitObjectFormat,
    GitOid, GitOidError, GitSyncRequest, LocalTrustBinding,
};
pub use hash::{Digest, DigestError};
pub use identity::{
    ForkProvenance, GenesisError, IDENTITY_SCHEMA_V1, IdentityRelation, LogicalStoreId,
    QualifiedEntityRef, StoreIdentity, classify_logical_identity, genesis_fingerprint,
    validate_store_identity,
};
pub use ids::{
    ActorId, BatchId, DomainId, EntityId, IdentifierError, KindId, RecordId, RecordSchemaId,
    RecordTimestamp, StoreUuid,
};
pub use json::JSON_CODEC_V1;
pub use layout::{CanonicalPath, PathClass, PathError, classify_path};
pub use record::{
    DomainRegistration, DomainRegistry, DomainValidator, MAX_RECORD_BYTES, RECORD_SCHEMA_V1,
    Record, RecordCodecError, RegistryError, decode_record, encode_record,
};
pub use revision::{
    LEGACY_REVISION_ALGORITHM_V1, REVISION_ALGORITHM_V1, RevisionAlgorithm, RevisionAlgorithmError,
    RevisionEntry, RevisionError, StoreRevisionParseError, StoreRevisionRef,
    compute_store_revision,
};
pub use store::{
    CommitOutcome, ExclusiveSnapshot, LegacyEntry, LegacyStoreAdapter, MAX_LEGACY_FILE_BYTES,
    Store, StoreCorruption, StoreError, StoreSnapshot,
};
