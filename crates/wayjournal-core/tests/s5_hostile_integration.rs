#![allow(clippy::duplicate_mod)]

//! Hostile S5 publication gate.
//!
//! These modules deliberately reuse the finalized S4 Git fixtures and the focused S5 fixtures in
//! one integration-test executable. Together they exercise the complete cross-plane matrix:
//! projection rollback/presence (cases 1, 2, and 7), cache staleness/relabeling/authority/root and
//! descendant attacks (cases 3-6 and 12), advisory and handshake non-authority (cases 8 and 9),
//! transfer-lock multi-sync races and independent outcomes (cases 10 and 11), and hostile ambient
//! Git configuration, credentials, proxies, hooks, and marker scripts (case 13). Keeping the source
//! fixtures shared prevents this release gate from becoming a weaker parallel model of the public
//! APIs.

#[path = "s5_proof_cache.rs"]
mod cache_cases;
#[path = "s5_catalogs.rs"]
mod catalog_cases;
#[path = "s5_handshake.rs"]
mod handshake_cases;
#[path = "s4_git_sync.rs"]
mod hostile_git_cases;
#[path = "s5_multi_sync.rs"]
mod multi_sync_cases;
#[path = "s5_projection.rs"]
mod projection_cases;
