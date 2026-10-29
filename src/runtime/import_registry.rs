//! Module registry and import-resolution surface.

use super::*;

/// Returns `true` if the runtime has a concrete dispatch handler for the given
/// (dll, symbol) import.  Used by integration tests to produce coverage reports.
pub fn is_import_supported(dll: &str, symbol: &ImportSymbol) -> bool {
    let import = ResolvedImport {
        requested_module: dll.to_string(),
        resolved_module: dll.to_string(),
        symbol: symbol.clone(),
        iat_rva: 0,
        export: synthetic_export_symbol(symbol),
    };
    let thunk = HostThunk::from_import(&import);
    !matches!(thunk, HostThunk::Unsupported { .. })
}

/// The implementation level the runtime ACTUALLY provides for a (dll, name)
/// export, resolved through the canonical import-name tables
/// ([`HostThunk::from_import`]).
///
/// This is the runtime-truth counterpart of the static
/// [`ThunkMetadata`] table: `Implemented` when the import-name tables
/// dispatch a concrete host thunk for the export, `Unsupported` when the
/// export falls through to `HostThunk::Unsupported` (no host thunk exists).
/// Some APIs (the ws2_32/wsock32 byte-order helpers) are registered by
/// ordinal only; the ordinal table is probed as a fallback.
pub fn registered_export_implementation_level(dll: &str, name: &str) -> ImplementationLevel {
    let by_name = ImportSymbol::ByName {
        hint: 0,
        name: name.to_string(),
    };
    let import = ResolvedImport {
        requested_module: dll.to_string(),
        resolved_module: dll.to_string(),
        symbol: by_name,
        iat_rva: 0,
        export: synthetic_export_symbol(&ImportSymbol::ByName {
            hint: 0,
            name: name.to_string(),
        }),
    };
    match HostThunk::from_import(&import) {
        HostThunk::Unsupported { .. } => match ordinal_for_registered_export(dll, name) {
            Some(ordinal) => {
                let import = ResolvedImport {
                    requested_module: dll.to_string(),
                    resolved_module: dll.to_string(),
                    symbol: ImportSymbol::ByOrdinal { ordinal },
                    iat_rva: 0,
                    export: synthetic_export_symbol(&ImportSymbol::ByOrdinal { ordinal }),
                };
                match HostThunk::from_import(&import) {
                    HostThunk::Unsupported { .. } => ImplementationLevel::Unsupported,
                    _ => ImplementationLevel::Implemented,
                }
            }
            None => ImplementationLevel::Unsupported,
        },
        _ => ImplementationLevel::Implemented,
    }
}

/// Reverse of [`ordinal_import_name`]: the ordinal(s) the runtime registers
/// a name under, where the registration is ordinal-only (used by
/// [`registered_export_implementation_level`] as a fallback).
pub(crate) fn ordinal_for_registered_export(dll: &str, name: &str) -> Option<u16> {
    let dll_stem = dll.strip_suffix(".dll").unwrap_or(dll).to_ascii_lowercase();
    match (dll_stem.as_str(), name) {
        ("ws2_32" | "wsock32", "htonl") => Some(8),
        ("ws2_32" | "wsock32", "htons") => Some(9),
        ("ws2_32" | "wsock32", "ntohl") => Some(14),
        ("ws2_32" | "wsock32", "ntohs") => Some(15),
        _ => None,
    }
}

/// Diagnostics: classify a (dll, symbol) import against the canonical thunk
/// implementation-quality metadata ([`ThunkMetadata`] /
/// [`crate::host_thunks::THUNK_METADATA`]).
///
/// Returns the [`ImplementationLevel`] and the generic user-mode
/// [`SupportPolicy`] for the import.  Ordinal-only imports are resolved
/// through [`ordinal_import_name`]; imports with no metadata entry are
/// classified [`ImplementationLevel::Unsupported`] (no host thunk / no
/// metadata) with [`SupportPolicy::OptionalFeature`].
///
/// This is the metadata-consuming diagnostic used by the generic import
/// coverage ([`crate::import_coverage::coverage_for_pe`]) and by the
/// section24 integration model.
pub fn import_implementation_quality(
    dll: &str,
    symbol: &ImportSymbol,
) -> (ImplementationLevel, crate::host_thunks::SupportPolicy) {
    let api = match symbol {
        ImportSymbol::ByName { name, .. } => name.clone(),
        ImportSymbol::ByOrdinal { ordinal } => ordinal_import_name(dll, *ordinal)
            .map(str::to_string)
            .unwrap_or_else(|| format!("ordinal#{ordinal}")),
    };
    match lookup_thunk_metadata(dll, &api) {
        Some(metadata) => (metadata.implementation, metadata.support_policy),
        None => (
            ImplementationLevel::Unsupported,
            crate::host_thunks::SupportPolicy::OptionalFeature,
        ),
    }
}

pub(crate) fn resolve_imports_for_runtime(
    image: &pe::ParsedPe,
    resolver: &ApiSetResolver,
) -> Vec<ResolvedImport> {
    image
        .imports
        .iter()
        .flat_map(|descriptor| {
            let resolved_module = resolver.resolve(&descriptor.dll_name);
            descriptor.imports.iter().map(move |thunk| ResolvedImport {
                requested_module: descriptor.dll_name.clone(),
                resolved_module: resolved_module.clone(),
                symbol: thunk.symbol.clone(),
                iat_rva: thunk.iat_rva,
                export: synthetic_export_symbol(&thunk.symbol),
            })
        })
        .collect()
}

/// Prepare delay-load import thunks for lazy resolution.
///
/// Unlike regular imports (which are eagerly resolved and bound at startup),
/// delay-loaded imports receive a [`HostThunk::DelayLoadResolve`] trampoline
/// that resolves the import on first call, patches the IAT, and forwards to
/// the real thunk.
pub(crate) fn resolve_delay_imports_for_runtime(
    image: &pe::ParsedPe,
    resolver: &ApiSetResolver,
    selected_base: u64,
) -> Vec<HostThunk> {
    let mut thunks = Vec::new();
    for descriptor in &image.delay_imports {
        let resolved_module = resolver.resolve(&descriptor.dll_name);
        for thunk in &descriptor.imports {
            thunks.push(HostThunk::DelayLoadResolve {
                resolved_module: resolved_module.clone(),
                symbol: thunk.symbol.clone(),
                iat_rva: thunk.iat_rva,
                selected_base,
            });
        }
    }
    thunks
}

pub(crate) fn synthetic_export_symbol(symbol: &ImportSymbol) -> ExportSymbol {
    match symbol {
        ImportSymbol::ByName { name, .. } => ExportSymbol {
            ordinal: 0,
            name: Some(name.clone()),
            target: ExportTarget::Rva(0),
        },
        ImportSymbol::ByOrdinal { ordinal } => ExportSymbol {
            ordinal: *ordinal as u32,
            name: None,
            target: ExportTarget::Rva(0),
        },
    }
}
