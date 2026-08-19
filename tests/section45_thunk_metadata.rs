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

use casa1::api_database::WindowsVersion;
use casa1::host_thunks::{ArchMask, ImplementationLevel, LastErrorBehavior, THUNK_METADATA};
use casa1::pe_runtime::{export_tables, registered_export_implementation_level};

#[test]
fn thunk_metadata_matches_registered_export_surface_bidirectionally() {
    // The registered export surface: every named export the runtime
    // registers (ordinal-only exports have no metadata name and are not part
    // of the name-keyed accounting).
    let exports = export_tables();
    let mut registered = std::collections::BTreeSet::new();
    for (dll, symbols) in &exports {
        for symbol in symbols {
            if let Some(name) = &symbol.name {
                registered.insert((dll.to_ascii_lowercase(), name.clone()));
            }
        }
    }

    let mut metadata = std::collections::BTreeSet::new();
    for entry in THUNK_METADATA {
        metadata.insert((entry.dll.to_ascii_lowercase(), entry.name.to_string()));
    }

    // Every registered export must have a metadata entry.
    let missing_from_metadata: Vec<_> = registered.difference(&metadata).collect();
    assert!(
        missing_from_metadata.is_empty(),
        "{} registered exports have NO metadata entry — every exported API Casa1 \
         registers must be covered by THUNK_METADATA:\n  {}",
        missing_from_metadata.len(),
        missing_from_metadata
            .iter()
            .map(|(dll, name)| format!("{dll}!{name}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    // Every metadata entry must be a registered export.
    let missing_from_exports: Vec<_> = metadata.difference(&registered).collect();
    assert!(
        missing_from_exports.is_empty(),
        "{} metadata entries are NOT registered exports — the runtime must register \
         every API the metadata covers:\n  {}",
        missing_from_exports.len(),
        missing_from_exports
            .iter()
            .map(|(dll, name)| format!("{dll}!{name}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    assert_eq!(registered.len(), metadata.len());
}

#[test]
fn metadata_implementation_matches_runtime_import_name_tables() {
    // The runtime's import-name tables (HostThunk::from_import) are the
    // registration list the dispatch layer actually uses.  The metadata must
    // not claim a thunk where the runtime has none, and must not mark an API
    // Unsupported while the runtime dispatches it.
    let mut mismatches = Vec::new();
    for entry in THUNK_METADATA {
        let runtime_level = registered_export_implementation_level(entry.dll, entry.name);
        match entry.implementation {
            ImplementationLevel::Unsupported => {
                if runtime_level != ImplementationLevel::Unsupported {
                    mismatches.push(format!(
                        "{}!{} is marked Unsupported but the runtime dispatches it ({:?})",
                        entry.dll, entry.name, runtime_level
                    ));
                }
            }
            ImplementationLevel::Implemented
            | ImplementationLevel::Partial
            | ImplementationLevel::Stub => {
                if runtime_level == ImplementationLevel::Unsupported {
                    mismatches.push(format!(
                        "{}!{} claims a working implementation ({:?}) but the runtime has \
                         no host thunk for it",
                        entry.dll, entry.name, entry.implementation
                    ));
                }
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} metadata/runtime truth mismatches:\n  {}",
        mismatches.len(),
        mismatches.join("\n  ")
    );
}

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

#[test]
fn metadata_fields_are_explicit_everywhere() {
    for entry in THUNK_METADATA {
        assert_ne!(entry.dll, "", "{} must carry a DLL", entry.name);
        assert_ne!(entry.name, "", "{} must carry a name", entry.dll);
        // Architecture masks and Windows versions must be recorded.
        let _ = ArchMask::ANY;
        let _ = WindowsVersion::Any;
        assert!(
            entry.architectures.x86 || entry.architectures.x64,
            "{}!{} must support at least one guest architecture",
            entry.dll,
            entry.name
        );
        assert!(
            matches!(
                entry.min_windows_version,
                WindowsVersion::Win10 | WindowsVersion::Win11 | WindowsVersion::Any
            ),
            "{}!{} must carry a Windows version",
            entry.dll,
            entry.name
        );
        assert!(
            matches!(
                entry.support_policy,
                casa1::host_thunks::SupportPolicy::Required
                    | casa1::host_thunks::SupportPolicy::OptionalFeature
                    | casa1::host_thunks::SupportPolicy::OutsideUserModeProfile
            ),
            "{}!{} must carry a support policy",
            entry.dll,
            entry.name
        );
    }
}

#[test]
fn registered_surface_covers_all_metadata_dlls() {
    // The DLL keys of the metadata table must all be registered module keys
    // in the export surface (or synthesizeable).
    let exports = export_tables();
    for entry in THUNK_METADATA {
        let key = entry.dll.to_ascii_lowercase();
        assert!(
            exports
                .keys()
                .any(|registered| registered.to_ascii_lowercase() == key),
            "{}!{}: DLL {} is not a registered module",
            entry.dll,
            entry.name,
            key
        );
    }
}
