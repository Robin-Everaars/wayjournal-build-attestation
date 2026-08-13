use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};

use serde_json::json;
use wayjournal_core::{
    ActorId, GitAdmissionError, LegacyEntry, LegacyStoreAdapter, Record, Store, StoreError,
    prepare_batch, wayjournal_domain_registry,
};

#[derive(Debug)]
struct NoLegacy;
impl LegacyStoreAdapter for NoLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
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
        entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010"
            .parse()
            .expect("entity"),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174012"
            .parse()
            .expect("batch"),
        actor: ActorId::parse("human:robin").expect("actor"),
        occurred_at: "2026-08-12T13:00:00Z".parse().expect("time"),
        recorded_at: "2026-08-12T13:00:01Z".parse().expect("time"),
        parents: Vec::new(),
        payload: json!({"store_kind":"wayjournal.personal","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"}),
    }
}

fn pending_document(phase: &str) -> Vec<u8> {
    let oid = |digit: char| json!({"format":"sha1","hex":digit.to_string().repeat(40)});
    let revision = |digit: char| {
        json!({
            "algorithm":"wayjournal.store/blake3-framed-v1",
            "digest":format!("{digit}c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15")
        })
    };
    let value = json!({
        "schema":"wayjournal.sync-pending/v1",
        "operation_id":"01913f1d-8e2a-7c30-8f4a-426614174090",
        "phase":phase,
        "logical_store_id":{
            "store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010",
            "genesis_fingerprint":"7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447"
        },
        "local_trust_binding":"3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        "approved_remote":{"locator":"file:///srv/git/store.git","reference":"refs/heads/main"},
        "object_format":"sha1",
        "original_base_commit":oid('1'),
        "original_base_revision":revision('1'),
        "advance_from_commit":oid('1'),
        "advance_from_revision":revision('1'),
        "observed_local_tip":oid('2'),
        "expected_remote_tip":oid('3'),
        "candidate_commit":oid('4'),
        "candidate_revision":revision('4'),
        "candidate_parents":[oid('2'),oid('3')],
        "additions_count":0,
        "additions_total_bytes":0,
        "additions_index_digest":"5c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        "predecessor_operation_id":null,
        "stale_remote_oid":if phase == "remote_cas_stale" { oid('5') } else { serde_json::Value::Null }
    });
    let mut bytes = serde_json::to_vec_pretty(&value).expect("JSON");
    bytes.push(b'\n');
    bytes
}

#[test]
fn all_non_git_store_apis_block_for_every_durable_pending_phase() {
    for phase in [
        "prepared",
        "files_published",
        "local_ref_published",
        "checkpoint_published",
        "remote_cas_stale",
        "remote_cas_confirmed",
    ] {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-s4b-gate-{phase}-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root).expect("root");
        let registry = wayjournal_domain_registry().expect("registry");
        let store = Store::open(&root, registry, Arc::new(NoLegacy)).expect("store");
        let expected = store.read().expect("initial").revision();
        let prepared = prepare_batch(&[genesis()], phase, &registry).expect("batch");
        let operation =
            root.join(".wayjournal-local/sync-pending/01913f1d-8e2a-7c30-8f4a-426614174090");
        fs::create_dir(&operation).expect("operation");
        let pending = operation.join("pending.json");
        fs::write(&pending, pending_document(phase)).expect("pending");
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).expect("mode");

        assert!(
            matches!(store.read(), Err(StoreError::GitSyncPending { .. })),
            "read {phase}"
        );
        assert!(
            matches!(
                store.append(&prepared, expected),
                Err(StoreError::GitSyncPending { .. })
            ),
            "append {phase}"
        );
        assert!(
            matches!(
                store.exclusive_snapshot(),
                Err(StoreError::GitSyncPending { .. })
            ),
            "exclusive {phase}"
        );
        assert!(
            matches!(
                store.admission_checkpoint(),
                Err(GitAdmissionError::Store(StoreError::GitSyncPending { .. }))
            ),
            "checkpoint {phase}"
        );
        fs::remove_dir_all(root).expect("cleanup");
    }
}
