#![doc = r"Domain-neutral wire, store, and federation primitives for Wayjournal.

S5 preserves three separate planes: canonical Git journal bytes; durable local checkpoint,
pending, and quarantine authority; and disposable local proofs, projections, and cache. A verified
proof is a locally observed record-presence projection, not a signature or freshness claim.
Serialized revision vectors never supply freshness authority. `ProofCache` instead resolves at
most 256 dependencies from current durable admission checkpoints while retaining every distinct
store root lock in logical order. Entries are exact-id-only, at most 64 KiB each, with at most
16,384 entries and 256 MiB total; malformed authority is unavailable, revision drift is stale, and
a changed cache-root binding permanently resets the opened handle.

`sync_stores` accepts 1 through 256 strictly ordered, unique targets. Its all-target preflight
checks current checkpoint/store/expected/handshake identity, the complete sealed checkpoint,
request trust and approved remote/ref, and negotiated Git union/CAS support before any transfer.
Each target repeats those checks under its exact transfer lock and retains that lock continuously
through Git, pending, and CAS work. Its per-target result uses additive `AuthorizedGitSyncError`
without changing the finalized S4 `GitSyncError` variants. Projection wire data is bounded to
8 MiB, 256 revision entries,
and 4,096 proofs; capability offers are bounded to 64 KiB and 64 entries per set. Profile and
catalog values, proofs, vectors, caches, and consumer-retained bytes confer no identity, trust,
remote, checkpoint, credential, transfer, or current-revision authority."]

mod artifacts;
mod batch;
mod builtin;
mod capability;
mod causal;
mod domains;
mod federation;
mod hash;
mod identity;
mod ids;
mod json;
mod layout;
mod projection;
mod proof_cache;
mod record;
mod revision;
mod store;

pub use artifacts::{
    CAPABILITY_MANIFEST, CapabilityManifest, S5_CAPABILITY_MANIFEST, S5CapabilityManifest,
    all_generated_schemas, generated_s5_schemas, generated_schemas,
};
pub use batch::{
    BATCH_SCHEMA_V1, BatchError, BatchManifest, IdempotencyDecision, MAX_BATCH_BYTES,
    PreparedBatch, PreparedRecord, RecordRef, StoredMember, classify_idempotency,
    decode_batch_manifest, prepare_batch, validate_batch_members, validate_batch_ownership,
};
pub use builtin::{wayjournal_domain_registry, wayjournal_domain_registry_with};
pub use capability::{
    CAPABILITY_OFFER_SCHEMA_V1, CapabilityId, CapabilityIdError, CapabilityOffer,
    CapabilityOfferError, GIT_UNION_CAS_CAPABILITY, HandshakeRequirements,
    MAX_CAPABILITY_OFFER_BYTES, MAX_CAPABILITY_SET_ENTRIES, NegotiatedHandshake, NegotiationError,
    PROOF_VECTOR_PROJECTION_ID, ProjectionId, ProjectionKind, REVISION_VECTOR_PROJECTION_ID,
    S5_CAPABILITIES, S5_PROJECTIONS, VERIFIED_PROOF_PROJECTION_ID, decode_capability_offer,
    encode_capability_offer, negotiate_handshake,
};
pub use causal::{
    CausalError, CausalGraph, CausalNode, MAX_CAUSAL_EDGES, MAX_CAUSAL_OPERATIONS,
    MAX_REACHABILITY_STEPS,
};
pub use domains::{
    AdvisoryProfile, CATALOG_SCHEMA_V1, CatalogEntry, CatalogRelation, DomainOperation, FoldError,
    MvRegister, OperationError, PROFILE_SCHEMA_V1, RemoteLocator, fold_catalog, fold_catalogs,
    fold_profile,
};
pub use federation::{
    AdmissionCheckpoint, ApprovalError, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator,
    AuthorizedGitSyncError, CheckpointError, CheckpointObservationError, GitAdmissionError,
    GitAdmissionOutcome, GitCommandError, GitCommandFailureKind, GitObjectFormat, GitOid,
    GitOidError, GitQuarantineReason, GitSyncError, GitSyncOperationId, GitSyncOutcome,
    GitSyncPendingPhase, GitSyncRequest, LocalTrustBinding, MAX_MULTI_SYNC_TARGETS,
    MultiStoreSyncError, PerStoreSyncResult, QuarantineError, QuarantineIncidentId,
    StoreSyncTarget, sync_stores,
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
pub use projection::{
    ContradictionRef, MAX_PROJECTION_BYTES, MAX_PROOFS, MAX_VECTOR_STORES, PROOF_VECTOR_SCHEMA_V1,
    ProjectionError, ProofError, ProofId, ProofVector, REVISION_VECTOR_SCHEMA_V1, RevisionVector,
    RevisionVectorEntry, VERIFIED_PROOF_SCHEMA_V1, VerifiedProof, decode_proof_vector,
    decode_revision_vector, decode_verified_proof, encode_proof_vector, encode_revision_vector,
    encode_verified_proof,
};
pub use proof_cache::{
    DependencyStore, MAX_PROOF_CACHE_ENTRIES, MAX_PROOF_CACHE_ENTRY_BYTES,
    MAX_PROOF_CACHE_TOTAL_BYTES, PROJECTION_CACHE_ENTRY_SCHEMA_V1, ProofCache,
    ProofCacheDisposition, ProofCacheError, ProofCacheInsert, ProofCacheLookup,
};
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
    CommitOutcome, ExclusiveSnapshot, LegacyEntry, LegacyEntrySource, LegacyStoreAdapter,
    LegacyStreamRequirement, LegacyStreamingError, MAX_LEGACY_FILE_BYTES, Store, StoreCorruption,
    StoreError, StoreSnapshot,
};
