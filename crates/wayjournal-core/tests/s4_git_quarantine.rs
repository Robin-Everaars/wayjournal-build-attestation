use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde_json::json;
use wayjournal_core::{
    ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, GitQuarantineReason, GitSyncOutcome,
    GitSyncRequest, LegacyEntry, LegacyStoreAdapter, LocalTrustBinding, Store,
    wayjournal_domain_registry,
};

#[derive(Debug)]
struct NoLegacy;
impl LegacyStoreAdapter for NoLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
    }
}

fn git() -> PathBuf {
    PathBuf::from(std::env::var_os("WAYJOURNAL_TEST_GIT").expect("Git"))
}

fn request(remote: &Path) -> GitSyncRequest {
    GitSyncRequest::new(
        git(),
        LocalTrustBinding::parse(
            "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        )
        .expect("trust"),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(url::Url::from_file_path(remote).expect("URL").as_str())
                .expect("locator"),
            ApprovedRef::parse("refs/heads/main").expect("ref"),
        ),
    )
    .expect("request")
}

#[test]
fn durable_incident_blocks_retry_before_transfer() {
    quarantine_codec_is_closed_private_and_immutable();
}

#[test]
fn quarantine_codec_is_closed_private_and_immutable() {
    let root = std::env::temp_dir().join(format!(
        "wayjournal-s4b-quarantine-{}",
        uuid::Uuid::now_v7()
    ));
    fs::create_dir(&root).expect("root");
    let store = Store::open(
        &root,
        wayjournal_domain_registry().expect("registry"),
        Arc::new(NoLegacy),
    )
    .expect("store");
    let remote = root.join("remote.git");
    fs::create_dir(&remote).expect("remote placeholder");
    let request = request(&remote);
    let incident_id = "01913f1d-8e2a-7c30-8f4a-426614174091";
    let value = json!({
        "schema":"wayjournal.git-quarantine/v1",
        "incident_id":incident_id,
        "reason":"malformed_history",
        "logical_store_id":{
            "store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010",
            "genesis_fingerprint":"7b9565665e24d18788f1a681d7cea3e2a07da23bea8f9861911f0e84023a9447"
        },
        "local_trust_binding":"3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        "approved_remote":request.approved_remote(),
        "checkpoint_commit":{"format":"sha1","hex":"1".repeat(40)},
        "checkpoint_revision":{
            "algorithm":"wayjournal.store/blake3-framed-v1",
            "digest":"1c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
        },
        "observed_commit":null,
        "evidence_digest":"5c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15"
    });
    let mut bytes = serde_json::to_vec_pretty(&value).expect("JSON");
    bytes.push(b'\n');
    let path = root.join(format!(".wayjournal-local/quarantine/{incident_id}.json"));
    fs::write(&path, bytes).expect("incident");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");

    for active in [
        &store,
        &Store::open(
            &root,
            wayjournal_domain_registry().expect("registry"),
            Arc::new(NoLegacy),
        )
        .expect("reopen"),
    ] {
        assert!(matches!(
            active.sync_git_union(&request).expect("typed quarantine"),
            GitSyncOutcome::Quarantined { incident_id: found, reason: GitQuarantineReason::MalformedHistory }
                if found.to_string() == incident_id
        ));
    }
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(root).expect("cleanup");
}
