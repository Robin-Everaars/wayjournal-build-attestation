use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde_json::{Value, json};
use wayjournal_core::{
    ActorId, CapabilityId, CapabilityOffer, CapabilityOfferError, HandshakeRequirements,
    LegacyEntry, LegacyStoreAdapter, LocalTrustBinding, LogicalStoreId, MAX_CAPABILITY_OFFER_BYTES,
    MAX_CAPABILITY_SET_ENTRIES, NegotiationError, PROOF_VECTOR_PROJECTION_ID, ProjectionId,
    REVISION_VECTOR_PROJECTION_ID, Record, S5_CAPABILITIES, Store, VERIFIED_PROOF_PROJECTION_ID,
    decode_capability_offer, encode_capability_offer, negotiate_handshake, prepare_batch,
    wayjournal_domain_registry,
};

const STORE_UUID: &str = "01913f1d-8e2a-7c30-8f4a-426614174010";
const OTHER_STORE_UUID: &str = "01913f1d-8e2a-7c30-8f4a-426614174020";
const TRUST: &str = "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15";
const OTHER_TRUST: &str = "4c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15";
const SYNC: &str = "wayjournal.sync/git-union-cas-v1";
const JSON: &str = "wayjournal.json/v1";
const RECORD: &str = "wayjournal.record/v1";
const UNKNOWN_CAPABILITY: &str = "unknown.vendor/optional-v1";
const UNKNOWN_PROJECTION: &str = "unknown.vendor/projection-v1";

#[derive(Debug)]
struct NoLegacy;

impl LegacyStoreAdapter for NoLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
    }
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("wayjournal-s5-handshake-{}", uuid::Uuid::now_v7()));
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

struct Fixture {
    directory: TestDir,
    store: Store,
    logical_store: LogicalStoreId,
}

fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("JSON");
    bytes.push(b'\n');
    bytes
}

fn record(domain: &str, kind: &str, record_id: &str, batch_id: &str, payload: Value) -> Record {
    Record {
        record_schema: format!("{domain}/v1").parse().expect("schema"),
        domain: domain.parse().expect("domain"),
        kind: kind.parse().expect("kind"),
        record_id: record_id.parse().expect("record id"),
        entity_id: STORE_UUID.parse().expect("entity id"),
        batch_id: batch_id.parse().expect("batch id"),
        actor: ActorId::parse("human:handshake-test").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: Vec::new(),
        payload,
    }
}

fn initialized_store(with_advisory_hints: bool) -> Fixture {
    let directory = TestDir::new();
    let registry = wayjournal_domain_registry().expect("registry");
    let store = Store::open(directory.path(), registry, Arc::new(NoLegacy)).expect("store");
    let genesis = record(
        "wayjournal.identity",
        "store.genesis",
        "01913f1d-8e2a-7c30-8f4a-426614174011",
        "01913f1d-8e2a-7c30-8f4a-426614174012",
        json!({"store_kind": "wayjournal.personal", "store_uuid": STORE_UUID}),
    );
    let batch = prepare_batch(&[genesis], "handshake-genesis", &registry).expect("batch");
    store
        .append(&batch, store.read().expect("empty").revision())
        .expect("append genesis");
    let logical_store = store
        .read()
        .expect("initialized")
        .identity()
        .expect("identity")
        .logical_id()
        .clone();

    if with_advisory_hints {
        let hints = [
            record(
                "wayjournal.profile",
                "profile.capability.add",
                "01913f1d-8e2a-7c30-8f4a-426614174021",
                "01913f1d-8e2a-7c30-8f4a-426614174031",
                json!({"key": "sync", "value": SYNC}),
            ),
            record(
                "wayjournal.catalog",
                "catalog.alias.add",
                "01913f1d-8e2a-7c30-8f4a-426614174022",
                "01913f1d-8e2a-7c30-8f4a-426614174031",
                json!({"key": "capability-looking", "target": logical_store, "value": SYNC}),
            ),
            record(
                "wayjournal.catalog",
                "catalog.remote.add",
                "01913f1d-8e2a-7c30-8f4a-426614174023",
                "01913f1d-8e2a-7c30-8f4a-426614174031",
                json!({
                    "key": "unapproved",
                    "target": logical_store,
                    "value": {
                        "locator": "file:///tmp/wayjournal-transfer-probe-must-not-run",
                        "requires_identity_validation": true
                    }
                }),
            ),
        ];
        let batch = prepare_batch(&hints, "handshake-advisory", &registry).expect("hints");
        store
            .append(&batch, store.read().expect("before hints").revision())
            .expect("append hints");
    }

    write_checkpoint(directory.path(), &logical_store, &store, TRUST, '0');
    Fixture {
        directory,
        store,
        logical_store,
    }
}

fn write_checkpoint(
    root: &Path,
    logical_store: &LogicalStoreId,
    store: &Store,
    trust: &str,
    commit_digit: char,
) {
    let revision = store.read().expect("snapshot").revision();
    let bytes = canonical(&json!({
        "accepted_commit": commit_digit.to_string().repeat(40),
        "accepted_git_object_format": "sha1",
        "accepted_revision_algorithm": revision.algorithm().as_str(),
        "accepted_revision_digest": revision.digest().to_string(),
        "genesis_fingerprint": logical_store.genesis_fingerprint().to_string(),
        "local_trust_binding": trust,
        "remote_locator": "file:///srv/git/approved.git",
        "remote_ref": "refs/heads/approved",
        "schema": "wayjournal.admission-checkpoint/v1",
        "store_uuid": logical_store.store_uuid().to_string()
    }));
    let path = root.join(".wayjournal-local/checkpoints/admission-v1.json");
    fs::write(&path, bytes).expect("checkpoint");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("checkpoint mode");
}

fn caps(values: &[&str]) -> Vec<CapabilityId> {
    let mut values: Vec<_> = values
        .iter()
        .map(|value| CapabilityId::parse(value).expect("capability"))
        .collect();
    values.sort();
    values
}

fn projections(values: &[&str]) -> Vec<ProjectionId> {
    let mut values: Vec<_> = values
        .iter()
        .map(|value| ProjectionId::parse(value).expect("projection"))
        .collect();
    values.sort();
    values
}

fn local(
    required_capabilities: &[&str],
    required_projections: &[&str],
    supported_capabilities: &[&str],
    supported_projections: &[&str],
) -> HandshakeRequirements {
    HandshakeRequirements::new(
        caps(required_capabilities),
        projections(required_projections),
        caps(supported_capabilities),
        projections(supported_projections),
    )
    .expect("local requirements")
}

fn offer(
    store: &LogicalStoreId,
    required_capabilities: &[&str],
    required_projections: &[&str],
    supported_capabilities: &[&str],
    supported_projections: &[&str],
) -> CapabilityOffer {
    CapabilityOffer::new(
        store.clone(),
        caps(required_capabilities),
        projections(required_projections),
        caps(supported_capabilities),
        projections(supported_projections),
    )
    .expect("offer")
}

fn trust(value: &str) -> LocalTrustBinding {
    LocalTrustBinding::parse(value).expect("trust")
}

#[test]
fn identifiers_and_exact_offer_codec_are_closed_canonical_and_bounded() {
    for value in [
        "wayjournal.json/v1",
        "a.b/0",
        "a_b.c-d/version_1.2",
        "a.b/0-._",
    ] {
        assert_eq!(CapabilityId::parse(value).unwrap().as_str(), value);
        assert_eq!(ProjectionId::parse(value).unwrap().as_str(), value);
    }
    for value in [
        "",
        "wayjournal/v1",
        ".wayjournal.json/v1",
        "wayjournal..json/v1",
        "Wayjournal.json/v1",
        "wayjournal.json/V1",
        "wayjournal.json/-v1",
        "wayjournal.json/v1/extra",
        &format!("a.{}/v1", "b".repeat(64)),
        &format!("a.b/{}", "v".repeat(65)),
        &format!("a.{}/v1", "b".repeat(124)),
    ] {
        assert!(CapabilityId::parse(value).is_err(), "{value}");
        assert!(ProjectionId::parse(value).is_err(), "{value}");
    }

    let fixture = initialized_store(false);
    let exact = offer(
        &fixture.logical_store,
        &[JSON, SYNC],
        &[REVISION_VECTOR_PROJECTION_ID],
        &[JSON, RECORD, SYNC, "wayjournal.verified-proof/v1"],
        &[
            PROOF_VECTOR_PROJECTION_ID,
            REVISION_VECTOR_PROJECTION_ID,
            VERIFIED_PROOF_PROJECTION_ID,
        ],
    );
    let encoded = encode_capability_offer(&exact).expect("encode");
    let expected = canonical(&json!({
        "logical_store_id": fixture.logical_store,
        "required_capabilities": caps(&[JSON, SYNC]),
        "required_projections": projections(&[REVISION_VECTOR_PROJECTION_ID]),
        "schema": "wayjournal.capability-offer/v1",
        "supported_capabilities": caps(&[JSON, RECORD, SYNC, "wayjournal.verified-proof/v1"]),
        "supported_projections": projections(&[
            PROOF_VECTOR_PROJECTION_ID,
            REVISION_VECTOR_PROJECTION_ID,
            VERIFIED_PROOF_PROJECTION_ID
        ])
    }));
    assert_eq!(encoded, expected);
    assert_eq!(decode_capability_offer(&encoded).unwrap(), exact);

    let text = String::from_utf8(encoded).unwrap();
    for hostile in [
        text.replacen("{\n", "{\n  \"extra\": true,\n", 1),
        text.replacen(
            "  \"schema\":",
            "  \"logical_store_id\": {},\n  \"schema\":",
            1,
        ),
        text.replace(
            "wayjournal.capability-offer/v1",
            "wayjournal.capability-offer/v2",
        ),
        text.replace("{\n", "{ \n"),
    ] {
        assert!(decode_capability_offer(hostile.as_bytes()).is_err());
    }
    assert!(decode_capability_offer(b"1.0").is_err());
    assert!(matches!(
        decode_capability_offer(&vec![b' '; MAX_CAPABILITY_OFFER_BYTES + 1]),
        Err(CapabilityOfferError::TooLarge)
    ));
}

#[test]
fn all_four_wire_sets_reject_unsorted_duplicates_and_limit_plus_one() {
    let fixture = initialized_store(false);
    let store = serde_json::to_value(&fixture.logical_store).unwrap();
    for set in [
        "required_capabilities",
        "required_projections",
        "supported_capabilities",
        "supported_projections",
    ] {
        let is_projection = set.contains("projections");
        let (first, second) = if is_projection {
            (REVISION_VECTOR_PROJECTION_ID, VERIFIED_PROOF_PROJECTION_ID)
        } else {
            (JSON, RECORD)
        };
        for entries in [json!([second, first]), json!([first, first])] {
            let mut root = json!({
                "logical_store_id": store,
                "required_capabilities": [],
                "required_projections": [],
                "schema": "wayjournal.capability-offer/v1",
                "supported_capabilities": [],
                "supported_projections": []
            });
            root[set] = entries;
            assert!(matches!(
                decode_capability_offer(&canonical(&root)),
                Err(CapabilityOfferError::InvalidSetOrder { .. })
            ));
        }

        let entries: Vec<_> = (0..=MAX_CAPABILITY_SET_ENTRIES)
            .map(|index| {
                if is_projection {
                    format!("example.projection/id-{index:02}")
                } else {
                    format!("example.capability/id-{index:02}")
                }
            })
            .collect();
        let mut root = json!({
            "logical_store_id": store,
            "required_capabilities": [],
            "required_projections": [],
            "schema": "wayjournal.capability-offer/v1",
            "supported_capabilities": [],
            "supported_projections": []
        });
        root[set] = serde_json::to_value(entries).unwrap();
        assert!(matches!(
            decode_capability_offer(&canonical(&root)),
            Err(CapabilityOfferError::TooManyEntries { .. })
        ));
    }
}

#[test]
fn exact_negotiation_is_deterministic_and_returns_only_supported_intersections() {
    let fixture = initialized_store(false);
    let local = local(
        &[JSON],
        &[REVISION_VECTOR_PROJECTION_ID],
        &[JSON, RECORD, SYNC, "wayjournal.proof-vector/v1"],
        &[
            PROOF_VECTOR_PROJECTION_ID,
            REVISION_VECTOR_PROJECTION_ID,
            VERIFIED_PROOF_PROJECTION_ID,
        ],
    );
    let remote = offer(
        &fixture.logical_store,
        &[RECORD],
        &[PROOF_VECTOR_PROJECTION_ID],
        &[JSON, RECORD, SYNC, UNKNOWN_CAPABILITY],
        &[
            PROOF_VECTOR_PROJECTION_ID,
            REVISION_VECTOR_PROJECTION_ID,
            UNKNOWN_PROJECTION,
        ],
    );
    let first = negotiate_handshake(
        &fixture.store,
        &fixture.logical_store,
        trust(TRUST),
        &local,
        &remote,
    )
    .expect("negotiation");
    let second = negotiate_handshake(
        &fixture.store,
        &fixture.logical_store,
        trust(TRUST),
        &local,
        &remote,
    )
    .expect("deterministic negotiation");
    assert_eq!(first, second);
    assert_eq!(first.logical_store_id(), &fixture.logical_store);
    assert_eq!(first.capabilities(), caps(&[JSON, RECORD, SYNC]));
    assert_eq!(
        first.projections(),
        projections(&[PROOF_VECTOR_PROJECTION_ID, REVISION_VECTOR_PROJECTION_ID])
    );
    assert!(first.supports_capability(&CapabilityId::parse(SYNC).unwrap()));
    assert!(!first.supports_capability(&CapabilityId::parse(UNKNOWN_CAPABILITY).unwrap()));
    assert!(first.supports_projection(&ProjectionId::parse(PROOF_VECTOR_PROJECTION_ID).unwrap()));
    assert!(!first.supports_projection(&ProjectionId::parse(UNKNOWN_PROJECTION).unwrap()));
}

#[test]
fn each_bidirectional_subset_direction_fails_independently_before_transfer() {
    let fixture = initialized_store(false);
    let marker = fixture.directory.path().join("transfer-probe");
    let cases = [
        (
            local(&[SYNC], &[], &[JSON, SYNC], &[]),
            offer(&fixture.logical_store, &[], &[], &[JSON], &[]),
            "local capability",
        ),
        (
            local(&[], &[], &[JSON], &[]),
            offer(&fixture.logical_store, &[SYNC], &[], &[JSON, SYNC], &[]),
            "remote capability",
        ),
        (
            local(
                &[],
                &[VERIFIED_PROOF_PROJECTION_ID],
                &[JSON],
                &[VERIFIED_PROOF_PROJECTION_ID],
            ),
            offer(&fixture.logical_store, &[], &[], &[JSON], &[]),
            "local projection",
        ),
        (
            local(&[], &[], &[JSON], &[REVISION_VECTOR_PROJECTION_ID]),
            offer(
                &fixture.logical_store,
                &[],
                &[VERIFIED_PROOF_PROJECTION_ID],
                &[JSON],
                &[REVISION_VECTOR_PROJECTION_ID, VERIFIED_PROOF_PROJECTION_ID],
            ),
            "remote projection",
        ),
    ];
    for (local, remote, direction) in cases {
        let error = negotiate_handshake(
            &fixture.store,
            &fixture.logical_store,
            trust(TRUST),
            &local,
            &remote,
        )
        .expect_err(direction);
        match direction {
            "local capability" => {
                assert!(matches!(
                    error,
                    NegotiationError::LocalCapabilityRequirement(_)
                ));
            }
            "remote capability" => {
                assert!(matches!(
                    error,
                    NegotiationError::RemoteCapabilityRequirement(_)
                ));
            }
            "local projection" => {
                assert!(matches!(
                    error,
                    NegotiationError::LocalProjectionRequirement(_)
                ));
            }
            _ => assert!(matches!(
                error,
                NegotiationError::RemoteProjectionRequirement(_)
            )),
        }
        assert!(!marker.exists(), "{direction} reached transfer probe");
    }
}

#[test]
fn unknown_required_identifiers_and_absent_sync_fail_while_unknown_optional_support_is_inert() {
    let fixture = initialized_store(false);
    let base_local = local(&[], &[], &[JSON, SYNC], &[REVISION_VECTOR_PROJECTION_ID]);

    let unknown_capability = offer(
        &fixture.logical_store,
        &[UNKNOWN_CAPABILITY],
        &[],
        &[JSON, SYNC, UNKNOWN_CAPABILITY],
        &[],
    );
    assert!(matches!(
        negotiate_handshake(
            &fixture.store,
            &fixture.logical_store,
            trust(TRUST),
            &base_local,
            &unknown_capability,
        ),
        Err(NegotiationError::UnknownRequiredCapability(_))
    ));

    let unknown_projection = offer(
        &fixture.logical_store,
        &[],
        &[UNKNOWN_PROJECTION],
        &[JSON],
        &[UNKNOWN_PROJECTION],
    );
    assert!(matches!(
        negotiate_handshake(
            &fixture.store,
            &fixture.logical_store,
            trust(TRUST),
            &base_local,
            &unknown_projection,
        ),
        Err(NegotiationError::UnknownRequiredProjection(_))
    ));

    let sync_required = local(&[SYNC], &[], &[JSON, SYNC], &[]);
    let no_sync = offer(&fixture.logical_store, &[], &[], &[JSON], &[]);
    assert!(matches!(
        negotiate_handshake(
            &fixture.store,
            &fixture.logical_store,
            trust(TRUST),
            &sync_required,
            &no_sync,
        ),
        Err(NegotiationError::LocalCapabilityRequirement(_))
    ));

    let optional_unknown = offer(
        &fixture.logical_store,
        &[],
        &[],
        &[JSON, UNKNOWN_CAPABILITY],
        &[UNKNOWN_PROJECTION],
    );
    let negotiated = negotiate_handshake(
        &fixture.store,
        &fixture.logical_store,
        trust(TRUST),
        &base_local,
        &optional_unknown,
    )
    .expect("unknown optional support is inert");
    assert_eq!(negotiated.capabilities(), caps(&[JSON]));
    assert!(negotiated.projections().is_empty());

    assert!(
        HandshakeRequirements::new(vec![], vec![], caps(&[JSON, UNKNOWN_CAPABILITY]), vec![],)
            .is_err()
    );
    assert!(
        HandshakeRequirements::new(
            vec![],
            vec![],
            caps(&[JSON]),
            projections(&[UNKNOWN_PROJECTION]),
        )
        .is_err()
    );
    assert_eq!(S5_CAPABILITIES.len(), 16);
}

#[test]
fn checkpoint_identity_trust_missing_authority_and_stale_binding_fail_closed() {
    let fixture = initialized_store(false);
    let local = local(&[], &[], &[JSON], &[]);
    let remote = offer(&fixture.logical_store, &[], &[], &[JSON], &[]);
    let first = negotiate_handshake(
        &fixture.store,
        &fixture.logical_store,
        trust(TRUST),
        &local,
        &remote,
    )
    .expect("first checkpoint binding");

    assert!(matches!(
        negotiate_handshake(
            &fixture.store,
            &fixture.logical_store,
            trust(OTHER_TRUST),
            &local,
            &remote,
        ),
        Err(NegotiationError::TrustMismatch)
    ));

    let other_store = LogicalStoreId::new(
        OTHER_STORE_UUID.parse().expect("UUID"),
        fixture.logical_store.genesis_fingerprint(),
    );
    let other_remote = offer(&other_store, &[], &[], &[JSON], &[]);
    assert!(matches!(
        negotiate_handshake(
            &fixture.store,
            &fixture.logical_store,
            trust(TRUST),
            &local,
            &other_remote,
        ),
        Err(NegotiationError::RemoteStoreMismatch)
    ));
    assert!(matches!(
        negotiate_handshake(
            &fixture.store,
            &other_store,
            trust(TRUST),
            &local,
            &other_remote,
        ),
        Err(NegotiationError::ExpectedStoreMismatch)
    ));

    write_checkpoint(
        fixture.directory.path(),
        &fixture.logical_store,
        &fixture.store,
        TRUST,
        '1',
    );
    let second = negotiate_handshake(
        &fixture.store,
        &fixture.logical_store,
        trust(TRUST),
        &local,
        &remote,
    )
    .expect("second checkpoint binding");
    assert_ne!(
        first, second,
        "a token remains bound to the complete checkpoint that created it"
    );

    fs::remove_file(
        fixture
            .directory
            .path()
            .join(".wayjournal-local/checkpoints/admission-v1.json"),
    )
    .expect("remove checkpoint");
    assert!(matches!(
        negotiate_handshake(
            &fixture.store,
            &fixture.logical_store,
            trust(TRUST),
            &local,
            &remote,
        ),
        Err(NegotiationError::MissingCheckpoint)
    ));
}

#[test]
fn profile_and_catalog_hints_cannot_supply_capabilities_or_transfer_authority() {
    let fixture = initialized_store(true);
    let transfer_marker = Path::new("/tmp/wayjournal-transfer-probe-must-not-run");
    let _ = fs::remove_file(transfer_marker);
    let local = local(&[SYNC], &[], &[JSON, SYNC], &[]);
    let remote_without_sync = offer(&fixture.logical_store, &[], &[], &[JSON], &[]);
    assert!(matches!(
        negotiate_handshake(
            &fixture.store,
            &fixture.logical_store,
            trust(TRUST),
            &local,
            &remote_without_sync,
        ),
        Err(NegotiationError::LocalCapabilityRequirement(_))
    ));
    assert!(
        !transfer_marker.exists(),
        "advisory remote/capability values must never trigger transfer"
    );
}
