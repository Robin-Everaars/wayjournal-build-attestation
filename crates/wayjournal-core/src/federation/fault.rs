//! Process-level fault seam for durability verification.
//!
//! The seam is intentionally closed: only named S4b durability points are accepted, activation
//! requires the exact internal environment variable, and the only effect is immediate process
//! termination. It is compiled into production so integration tests can exercise fresh-process
//! recovery against the same code, but is not part of the public API.

use std::ffi::OsStr;

pub(super) const EXIT_CODE: i32 = 86;

pub(super) fn hit(point: &'static str) {
    if std::env::var_os("WAYJOURNAL_INTERNAL_S4B_FAULT")
        .as_deref()
        .is_some_and(|configured| configured == OsStr::new(point))
    {
        std::process::exit(EXIT_CODE);
    }
}
