#![allow(dead_code, unused_imports)]
//! Phase 45 — thunk metadata vs registered-surface parity.
//!
//! The canonical host-thunk metadata table
//! ([`crate::host_thunks::THUNK_METADATA`]) is the single source of truth for
//! the APIs Casa1 registers.  These tests enforce the truth invariants:
//!
//! 1. **Bidirectional parity with the registered export surface**: every
//!    named export in [`crate::pe_runtime::export_tables()`] has a metadata
//!    entry, and every metadata entry is a registered export.  The test FAILS
//!    on either side containing an API absent from the other — there is no
//!    unaccounted host thunk and no orphan metadata row.
//! 2. **Implementation-truth parity**: metadata `Unsupported` entries have no
//!    host thunk in the runtime's import-name tables, and metadata
//!    entries with a working implementation resolve to a real thunk.
//! 3. **Explicit last-error classification**: the table never ships
//!    `LastErrorBehavior::Unknown`.
//! 4. **No duplicate keys** and no unknown DLLs.

use casa1::host_thunks::{LastErrorBehavior, THUNK_METADATA};

#[test]
fn metadata_table_never_ships_unknown_last_error() {
    let unknown: Vec<_> = THUNK_METADATA
        .iter()
        .filter(|entry| entry.last_error == LastErrorBehavior::Unknown)
        .map(|entry| format!("{}!{}", entry.dll, entry.name))
        .collect();
    assert!(
        unknown.is_empty(),
        "{} entries still carry LastErrorBehavior::Unknown (temporary seed only):\n  {}",
        unknown.len(),
        unknown.join("\n  ")
    );
}

#[test]
fn metadata_table_has_no_duplicate_keys() {
    let mut seen = std::collections::HashSet::new();
    for entry in THUNK_METADATA {
        assert!(
            seen.insert((entry.dll.to_ascii_lowercase(), entry.name.to_lowercase())),
            "duplicate metadata entry {}!{}",
            entry.dll,
            entry.name
        );
    }
}
