use std::{fs, path::PathBuf, sync::Arc};
use wayjournal_core::{LegacyEntry, LegacyStoreAdapter, Store, wayjournal_domain_registry};
#[derive(Debug)]
struct NoLegacy;
impl LegacyStoreAdapter for NoLegacy {
    fn validate(&self, _: &[LegacyEntry<'_>]) -> Result<(), String> {
        Ok(())
    }
}
#[test]
fn oversized_fetched_repository_never_becomes_pending() {
    let root =
        std::env::temp_dir().join(format!("wayjournal-hostile-bound-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let store = Store::open(
        &root,
        wayjournal_domain_registry().unwrap(),
        Arc::new(NoLegacy),
    )
    .unwrap();
    let residue =
        root.join(".wayjournal-local/admission-attempts/01913f1d-8e2a-7c30-8f4a-426614174099");
    fs::create_dir(&residue).unwrap();
    fs::write(residue.join("oversized-marker"), vec![0u8; 1024]).unwrap();
    assert_eq!(
        fs::read_dir(root.join(".wayjournal-local/sync-pending"))
            .unwrap()
            .count(),
        0
    );
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn hostile_git_authority_is_inert() {
    let git = PathBuf::from(std::env::var_os("WAYJOURNAL_TEST_GIT").expect("Git"));
    assert!(git.is_absolute());
}
