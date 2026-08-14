#[allow(dead_code)]
mod support;

use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use wayjournal_core::{
    ActorId, ApprovedRef, ApprovedRemote, ApprovedRemoteLocator, GitSyncOutcome, GitSyncRequest,
    LocalTrustBinding, Record, Store, prepare_batch, wayjournal_domain_registry,
};

use support::BoundedNoLegacy as NoLegacy;
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let p =
            std::env::temp_dir().join(format!("wayjournal-s4b-pending-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn git() -> PathBuf {
    PathBuf::from(std::env::var_os("WAYJOURNAL_TEST_GIT").unwrap())
}
fn run(c: &Path, a: &[&str]) {
    let o = Command::new(git()).current_dir(c).args(a).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}
fn genesis() -> Record {
    Record {
        record_schema: "wayjournal.identity/v1".parse().unwrap(),
        domain: "wayjournal.identity".parse().unwrap(),
        kind: "store.genesis".parse().unwrap(),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174011".parse().unwrap(),
        entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010".parse().unwrap(),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174012".parse().unwrap(),
        actor: ActorId::parse("human:robin").unwrap(),
        occurred_at: "2026-08-12T13:00:00Z".parse().unwrap(),
        recorded_at: "2026-08-12T13:00:01Z".parse().unwrap(),
        parents: vec![],
        payload: json!({"store_kind":"wayjournal.personal","store_uuid":"01913f1d-8e2a-7c30-8f4a-426614174010"}),
    }
}
fn profile() -> Record {
    Record {
        record_schema: "wayjournal.profile/v1".parse().unwrap(),
        domain: "wayjournal.profile".parse().unwrap(),
        kind: "profile.display_name.set".parse().unwrap(),
        record_id: "01913f1d-8e2a-7c30-8f4a-426614174021".parse().unwrap(),
        entity_id: "01913f1d-8e2a-7c30-8f4a-426614174010".parse().unwrap(),
        batch_id: "01913f1d-8e2a-7c30-8f4a-426614174022".parse().unwrap(),
        actor: ActorId::parse("human:robin").unwrap(),
        occurred_at: "2026-08-12T13:01:00Z".parse().unwrap(),
        recorded_at: "2026-08-12T13:01:01Z".parse().unwrap(),
        parents: vec![],
        payload: json!({"value":"pending"}),
    }
}
#[test]
fn prepared_recovery_completes_exact_candidate() {
    let d = Dir::new();
    let remote = d.0.join("remote.git");
    run(&d.0, &["init", "--bare", remote.to_str().unwrap()]);
    let local = d.0.join("local");
    fs::create_dir(&local).unwrap();
    let reg = wayjournal_domain_registry().unwrap();
    let store = Store::open(&local, reg, Arc::new(NoLegacy)).unwrap();
    let g = prepare_batch(&[genesis()], "g", &reg).unwrap();
    store.append(&g, store.read().unwrap().revision()).unwrap();
    run(&local, &["init", "-b", "main"]);
    run(&local, &["config", "user.name", "Wayjournal"]);
    run(&local, &["config", "user.email", "w@example.invalid"]);
    run(&local, &["add", "journal", "events", "batches"]);
    run(&local, &["commit", "-m", "g"]);
    run(
        &local,
        &["push", remote.to_str().unwrap(), "HEAD:refs/heads/main"],
    );
    run(
        &d.0,
        &[
            "--git-dir",
            remote.to_str().unwrap(),
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ],
    );
    let req = GitSyncRequest::new(
        git(),
        LocalTrustBinding::parse(
            "3c4835897266c2b72f1ad9528309c6002f388071b0e9c780827bedbfaa35ce15",
        )
        .unwrap(),
        ApprovedRemote::new(
            ApprovedRemoteLocator::parse(url::Url::from_file_path(&remote).unwrap().as_str())
                .unwrap(),
            ApprovedRef::parse("refs/heads/main").unwrap(),
        ),
    )
    .unwrap();
    store.bootstrap_git_admission(&req).unwrap();
    let p = prepare_batch(&[profile()], "p", &reg).unwrap();
    store.append(&p, store.read().unwrap().revision()).unwrap();
    run(&local, &["add", "journal"]);
    run(&local, &["commit", "-m", "p"]);
    assert!(matches!(
        store.sync_git_union(&req).unwrap(),
        GitSyncOutcome::Advanced { .. }
    ));
    assert!(local.join(p.manifest_path()).is_file());
    assert_eq!(
        fs::read_dir(local.join(".wayjournal-local/sync-pending"))
            .unwrap()
            .count(),
        0
    );
}
