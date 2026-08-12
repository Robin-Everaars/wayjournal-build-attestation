#![doc = "Domain-neutral wire and layout primitives for Wayjournal."]

mod artifacts;
mod batch;
mod hash;
mod ids;
mod json;
mod layout;
mod record;
mod revision;

pub use artifacts::{CAPABILITY_MANIFEST, CapabilityManifest, generated_schemas};
pub use batch::{
    BATCH_SCHEMA_V1, BatchError, BatchManifest, IdempotencyDecision, MAX_BATCH_BYTES,
    PreparedBatch, PreparedRecord, RecordRef, StoredMember, classify_idempotency,
    decode_batch_manifest, prepare_batch, validate_batch_members, validate_batch_ownership,
};
pub use hash::{Digest, DigestError};
pub use ids::{
    ActorId, BatchId, DomainId, EntityId, IdentifierError, KindId, RecordId, RecordSchemaId,
    RecordTimestamp,
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
