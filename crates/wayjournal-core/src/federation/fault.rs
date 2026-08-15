//! Process-level fault seam for durability verification.
//!
//! The seam is intentionally closed: only named S4b durability points are accepted, activation
//! requires the exact internal environment variable, and the only effect is immediate process
//! termination. It is compiled into production so integration tests can exercise fresh-process
//! recovery against the same code, but is not part of the public API.

use std::{ffi::OsStr, time::Duration};

pub(super) const EXIT_CODE: i32 = 86;

pub(super) fn hit(point: &'static str) {
    if std::env::var_os("WAYJOURNAL_INTERNAL_S4B_FAULT")
        .as_deref()
        .is_some_and(|configured| configured == OsStr::new(point))
    {
        std::process::exit(EXIT_CODE);
    }
}

/// Internal deterministic concurrency seam used only by the S5 transfer-authorization race test.
///
/// A configured directory receives a `ready` marker, after which this waits for a `release`
/// marker. The exact environment variable is intentionally not part of the public API, just like
/// the process-level S4 durability seam above.
pub(super) fn multi_preflight_barrier() {
    let Some(directory) = std::env::var_os("WAYJOURNAL_INTERNAL_S5_MULTI_BARRIER") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    if std::fs::write(directory.join("ready"), b"").is_err() {
        return;
    }
    for _ in 0..3_000 {
        if directory.join("release").is_file() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
