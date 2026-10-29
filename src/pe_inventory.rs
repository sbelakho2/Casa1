//! Real-application PE export/import inventory.
//!
//! The inventory is the ground truth for *what real Windows binaries actually
//! import*.  It is parsed exclusively with the production [`crate::pe`] parser
//! (never a test-only parser) and diffed against Casa1's API registry so the
//! audit can distinguish two different risks:
//!
//! * **unmodeled imports** — a real binary imports a symbol Casa1 has no row
//!   for at all;
//! * **coverage bias** — the registry models rows that no real corpus title
//!   imports, so registry-driven completeness numbers overstate reality.
//!
//! Everything is ordered by path/name so identical inputs produce byte-identical
//! JSON.

use crate::api_database::ApiDatabase;
use crate::error::{AppError, AppResult};
use crate::pe::{self, ApiSetResolver, ExportTarget, ImportSymbol};
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Schema version for `inventory.json`.
pub const INVENTORY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryFile {
    pub schema_version: u32,
    /// SHA-256 over every discovered PE file (relative path + content hash).
    pub corpus_fingerprint: String,
    /// Number of PE files discovered (including files that failed to parse).
    pub pe_file_count: usize,
    pub modules: Vec<InventoryModule>,
    /// PE-looking files that did not parse.  Kept in the report so a corpus
    /// cannot silently lose coverage because one title is malformed.
    pub errors: Vec<InventoryError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryModule {
    /// Corpus-relative path using `/` separators (deterministic across hosts).
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    /// `PE32` or `PE32+`.
    pub format: String,
    pub machine: u16,
    pub exports: Vec<InventoryExport>,
    /// Both eager and delay-load imports; `delay_load` distinguishes them.
    pub imports: Vec<InventoryImport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryExport {
    pub ordinal: u32,
    pub name: Option<String>,
    /// `Some("KERNELBASE.Sleep")` for a forwarded export.
    pub forwarder: Option<String>,
    /// `Some(rva)` for a normal code/data export.
    pub rva: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryImport {
    pub dll: String,
    pub delay_load: bool,
    pub symbols: Vec<InventorySymbol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InventorySymbol {
    Name { name: String, hint: u16 },
    Ordinal { ordinal: u16 },
}

impl InventorySymbol {
    fn sort_key(&self) -> (u8, String) {
        match self {
            Self::Name { name, .. } => (0, name.to_ascii_lowercase()),
            Self::Ordinal { ordinal } => (1, format!("{ordinal:010}")),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Self::Name { name, .. } => name.clone(),
            Self::Ordinal { ordinal } => format!("#{ordinal}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryError {
    pub path: String,
    pub reason_code: u32,
    pub reason_name: String,
    pub message: String,
}

/// One imported symbol that the registry does not model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnmodeledImport {
    /// The DLL name exactly as written in the import descriptor.
    pub dll: String,
    /// Canonical host DLL after API-set resolution.
    pub canonical_dll: String,
    /// Symbol name, or `#ordinal` when the import is ordinal-only.
    pub symbol: String,
    /// `name` or `ordinal`.
    pub symbol_kind: String,
    /// `None` when a name import was looked up directly; `Some(reason)` when
    /// an ordinal import could not be resolved to a name from the corpus.
    pub resolution_note: Option<String>,
    pub modules: Vec<String>,
}

/// One modeled registry row that the corpus never imports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnimportedRegistryRow {
    pub dll: String,
    pub export: String,
}

/// One observed DLL-name alias (API-set contract or module-name alias).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DllAlias {
    pub observed: String,
    pub resolved: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryDiffSummary {
    pub imported_symbol_count: usize,
    pub modeled_import_count: usize,
    pub unmodeled_import_count: usize,
    pub registry_row_count: usize,
    pub unimported_registry_row_count: usize,
    pub alias_count: usize,
    pub parse_error_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryDiff {
    pub corpus_fingerprint: String,
    /// (a) imported symbols Casa1 does not model at all.
    pub unmodeled_imports: Vec<UnmodeledImport>,
    /// (b) modeled rows never imported by the corpus (coverage bias).
    pub unimported_registry_rows: Vec<UnimportedRegistryRow>,
    /// (c) DLL-name/API-set aliasing observed in the corpus.
    pub aliases: Vec<DllAlias>,
    pub summary: InventoryDiffSummary,
}

/// Complete machine-readable inventory plus its registry diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryReport {
    pub schema_version: u32,
    pub inventory: InventoryFile,
    pub diff: InventoryDiff,
    /// Deterministic human-readable summary (also printed by the CLI).
    pub human_summary: String,
}

/// Parse one PE file into an inventory module.
///
/// The exact [`crate::reason::ReasonCode`]/message from the production parser
/// is preserved on failure; callers must not replace it with a generic error.
pub fn inventory_bytes(
    relative_path: &str,
    sha256: &str,
    size_bytes: u64,
    bytes: &[u8],
) -> AppResult<InventoryModule> {
    let parsed = pe::parse(bytes)?;
    let format = if parsed.optional_header_magic == 0x20b {
        "PE32+"
    } else {
        "PE32"
    };
    let mut exports = parsed
        .exports
        .iter()
        .map(|export| {
            let (forwarder, rva) = match &export.target {
                ExportTarget::Forwarder(value) => (Some(value.clone()), None),
                ExportTarget::Rva(value) => (None, Some(*value)),
            };
            InventoryExport {
                ordinal: export.ordinal,
                name: export.name.clone(),
                forwarder,
                rva,
            }
        })
        .collect::<Vec<_>>();
    exports.sort_by(|left, right| {
        left.ordinal
            .cmp(&right.ordinal)
            .then_with(|| left.name.cmp(&right.name))
    });

    let mut imports = parsed
        .imports
        .iter()
        .chain(parsed.delay_imports.iter())
        .map(inventory_import)
        .collect::<Vec<_>>();
    imports.sort_by(|left, right| {
        left.dll
            .to_ascii_lowercase()
            .cmp(&right.dll.to_ascii_lowercase())
            .then_with(|| left.delay_load.cmp(&right.delay_load))
            .then_with(|| {
                left.symbols
                    .iter()
                    .map(InventorySymbol::sort_key)
                    .cmp(right.symbols.iter().map(InventorySymbol::sort_key))
            })
    });

    Ok(InventoryModule {
        path: relative_path.to_string(),
        sha256: sha256.to_string(),
        size_bytes,
        format: format.to_string(),
        machine: parsed.machine,
        exports,
        imports,
    })
}

fn inventory_import(descriptor: &pe::ImportDescriptor) -> InventoryImport {
    let mut symbols = descriptor
        .imports
        .iter()
        .map(|thunk| match &thunk.symbol {
            ImportSymbol::ByName { hint, name } => InventorySymbol::Name {
                name: name.clone(),
                hint: *hint,
            },
            ImportSymbol::ByOrdinal { ordinal } => InventorySymbol::Ordinal { ordinal: *ordinal },
        })
        .collect::<Vec<_>>();
    symbols.sort_by_key(InventorySymbol::sort_key);
    InventoryImport {
        dll: descriptor.dll_name.clone(),
        delay_load: descriptor.delay_load,
        symbols,
    }
}

/// Walk `root` and inventory every PE32/PE32+ file (MZ-prefixed) beneath it.
///
/// Non-PE files are ignored.  A malformed PE is recorded in [`InventoryFile::errors`]
/// with the parser's exact reason code/message and does not abort the walk.
pub fn inventory_directory(root: &Path) -> AppResult<InventoryFile> {
    if !root.is_dir() {
        return Err(AppError::new(
            crate::reason::ReasonCode::RcFsNotFound,
            format!("PE directory not found: {}", root.display()),
        ));
    }
    let mut entries = Vec::new();
    let mut walk_errors = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                walk_errors.push(format!("{error}"));
                continue;
            }
        };
        if entry.file_type().is_file() {
            entries.push(entry.path().to_path_buf());
        }
    }
    entries.sort();

    let mut modules = Vec::new();
    let mut errors = Vec::new();
    let mut fingerprints = Vec::new();
    for path in entries {
        let relative = relative_slash(root, &path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(InventoryError {
                    path: relative,
                    reason_code: crate::reason::ReasonCode::RcIo.as_u32(),
                    reason_name: crate::reason::ReasonCode::RcIo.name().to_string(),
                    message: format!("failed to read {}: {error}", path.display()),
                });
                continue;
            }
        };
        let sha256 = util::sha256_bytes(&bytes);
        if !is_pe_looking(&bytes) {
            continue;
        }
        fingerprints.push(format!("{relative}\0{sha256}"));
        match inventory_bytes(&relative, &sha256, bytes.len() as u64, &bytes) {
            Ok(module) => modules.push(module),
            Err(error) => errors.push(InventoryError {
                path: relative,
                reason_code: error.code.as_u32(),
                reason_name: error.code.name().to_string(),
                message: error.message,
            }),
        }
    }
    for message in walk_errors {
        errors.push(InventoryError {
            path: String::new(),
            reason_code: crate::reason::ReasonCode::RcIo.as_u32(),
            reason_name: crate::reason::ReasonCode::RcIo.name().to_string(),
            message,
        });
    }
    fingerprints.sort();
    errors.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.reason_code.cmp(&right.reason_code))
            .then_with(|| left.message.cmp(&right.message))
    });
    modules.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(InventoryFile {
        schema_version: INVENTORY_SCHEMA_VERSION,
        corpus_fingerprint: util::sha256_bytes(fingerprints.join("\n").as_bytes()),
        pe_file_count: fingerprints.len(),
        modules,
        errors,
    })
}

fn is_pe_looking(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z'
}

fn relative_slash(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Build a full report (inventory + registry diff + human summary).
pub fn build_report(pe_dir: &Path, database: &ApiDatabase) -> AppResult<InventoryReport> {
    let inventory = inventory_directory(pe_dir)?;
    let diff = diff_against_registry(&inventory, database);
    let human_summary = human_summary(&inventory, &diff);
    Ok(InventoryReport {
        schema_version: INVENTORY_SCHEMA_VERSION,
        inventory,
        diff,
        human_summary,
    })
}

/// Canonicalize a DLL name for comparison: basename, lowercase, no `.dll`.
pub fn canonical_dll(name: &str) -> String {
    let trimmed = name.trim().replace('\\', "/");
    let base = trimmed.rsplit('/').next().unwrap_or(&trimmed).trim();
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".dll").unwrap_or(&lower).to_string()
}

fn is_api_set(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("api-ms-win-") || lower.starts_with("ext-ms-win-")
}

/// Diff the inventory against the API registry.
///
/// Matching is case-insensitive, tolerates the `.dll` suffix, and resolves
/// API-set contract names through the same [`ApiSetResolver`] the runtime
/// loader uses.  Ordinal-only imports are resolved to a name only when the
/// corpus itself contains an export table with that ordinal; otherwise they
/// are reported as unmodeled with an explicit resolution note
/// (`ordinal-not-in-corpus-exports`).
pub fn diff_against_registry(inventory: &InventoryFile, database: &ApiDatabase) -> InventoryDiff {
    let resolver = ApiSetResolver::new();

    // Registry rows keyed by (canonical dll, lowercase export).  Duplicate
    // (arch, winver) rows collapse to one coverage unit.
    let mut registry = BTreeMap::<(String, String), UnimportedRegistryRow>::new();
    for entry in database.entries() {
        let key = (canonical_dll(&entry.dll), entry.export.to_ascii_lowercase());
        registry
            .entry(key)
            .or_insert_with(|| UnimportedRegistryRow {
                dll: entry.dll.clone(),
                export: entry.export.clone(),
            });
    }
    let registry_row_count = registry.len();

    // Export ordinal -> name index for corpus modules, keyed by canonical
    // module name.  This lets ordinal-only imports be matched when the corpus
    // is self-describing.
    let mut corpus_exports = BTreeMap::<(String, u32), Option<String>>::new();
    for module in &inventory.modules {
        let module_name = module
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&module.path)
            .to_string();
        let key = canonical_dll(&module_name);
        for export in &module.exports {
            if export.name.is_some() {
                corpus_exports.insert((key.clone(), export.ordinal), export.name.clone());
            }
        }
    }

    let mut covered = BTreeSet::<(String, String)>::new();
    let mut unmodeled =
        BTreeMap::<(String, String, String), (Option<String>, BTreeSet<String>)>::new();
    let mut aliases = BTreeMap::<String, DllAlias>::new();
    let mut imported_symbol_count = 0usize;
    let mut modeled_import_count = 0usize;

    for module in &inventory.modules {
        for descriptor in &module.imports {
            let resolved = resolver.resolve(&descriptor.dll);
            let canonical = canonical_dll(&resolved);
            let observed_canonical = canonical_dll(&descriptor.dll);
            if canonical != observed_canonical {
                aliases
                    .entry(descriptor.dll.to_ascii_lowercase())
                    .or_insert_with(|| DllAlias {
                        observed: descriptor.dll.clone(),
                        resolved: resolved.clone(),
                        kind: if is_api_set(&descriptor.dll) {
                            "api_set".to_string()
                        } else {
                            "module_alias".to_string()
                        },
                    });
            }
            for symbol in &descriptor.symbols {
                imported_symbol_count += 1;
                match symbol {
                    InventorySymbol::Name { name, .. } => {
                        let key = (canonical.clone(), name.to_ascii_lowercase());
                        if registry.contains_key(&key) {
                            covered.insert(key);
                            modeled_import_count += 1;
                        } else {
                            unmodeled
                                .entry((descriptor.dll.clone(), canonical.clone(), name.clone()))
                                .or_insert_with(|| (None, BTreeSet::new()))
                                .1
                                .insert(module.path.clone());
                        }
                    }
                    InventorySymbol::Ordinal { ordinal } => {
                        let resolved_name = corpus_exports
                            .get(&(canonical.clone(), u32::from(*ordinal)))
                            .and_then(|name| name.clone());
                        match resolved_name {
                            Some(name) => {
                                let key = (canonical.clone(), name.to_ascii_lowercase());
                                if registry.contains_key(&key) {
                                    covered.insert(key);
                                    modeled_import_count += 1;
                                } else {
                                    unmodeled
                                        .entry((
                                            descriptor.dll.clone(),
                                            canonical.clone(),
                                            format!("#{ordinal}"),
                                        ))
                                        .or_insert_with(|| {
                                            (
                                                Some("ordinal-resolved-from-corpus".to_string()),
                                                BTreeSet::new(),
                                            )
                                        })
                                        .1
                                        .insert(module.path.clone());
                                }
                            }
                            None => {
                                unmodeled
                                    .entry((
                                        descriptor.dll.clone(),
                                        canonical.clone(),
                                        format!("#{ordinal}"),
                                    ))
                                    .or_insert_with(|| {
                                        (
                                            Some("ordinal-not-in-corpus-exports".to_string()),
                                            BTreeSet::new(),
                                        )
                                    })
                                    .1
                                    .insert(module.path.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    let unmodeled_imports = unmodeled
        .into_iter()
        .map(
            |((dll, canonical_dll, symbol), (resolution_note, modules))| UnmodeledImport {
                dll,
                canonical_dll,
                symbol_kind: if symbol.starts_with('#') {
                    "ordinal".to_string()
                } else {
                    "name".to_string()
                },
                symbol,
                resolution_note,
                modules: modules.into_iter().collect(),
            },
        )
        .collect::<Vec<_>>();

    let unimported_registry_rows = registry
        .into_iter()
        .filter(|(key, _)| !covered.contains(key))
        .map(|(_, row)| row)
        .collect::<Vec<_>>();

    let aliases = aliases.into_values().collect::<Vec<_>>();

    InventoryDiff {
        corpus_fingerprint: inventory.corpus_fingerprint.clone(),
        summary: InventoryDiffSummary {
            imported_symbol_count,
            modeled_import_count,
            unmodeled_import_count: unmodeled_imports.len(),
            registry_row_count,
            unimported_registry_row_count: unimported_registry_rows.len(),
            alias_count: aliases.len(),
            parse_error_count: inventory.errors.len(),
        },
        unmodeled_imports,
        unimported_registry_rows,
        aliases,
    }
}

/// Deterministic human-readable summary for CI logs and operator review.
pub fn human_summary(inventory: &InventoryFile, diff: &InventoryDiff) -> String {
    let mut lines = Vec::new();
    lines.push("Casa1 PE inventory".to_string());
    lines.push(format!(
        "  corpus: {} PE file(s), {} parsed module(s), {} error(s)",
        inventory.pe_file_count,
        inventory.modules.len(),
        inventory.errors.len()
    ));
    lines.push(format!("  fingerprint: {}", inventory.corpus_fingerprint));
    lines.push(format!(
        "  imports: {} symbol(s), {} modeled, {} unmodeled",
        diff.summary.imported_symbol_count,
        diff.summary.modeled_import_count,
        diff.summary.unmodeled_import_count
    ));
    lines.push(format!(
        "  registry: {} modeled row(s), {} never imported by this corpus",
        diff.summary.registry_row_count, diff.summary.unimported_registry_row_count
    ));
    lines.push(format!(
        "  aliases: {} DLL name/API-set alias(es)",
        diff.summary.alias_count
    ));
    if !diff.unmodeled_imports.is_empty() {
        lines.push("  unmodeled imports:".to_string());
        for import in &diff.unmodeled_imports {
            let note = import
                .resolution_note
                .as_deref()
                .map(|note| format!(" ({note})"))
                .unwrap_or_default();
            lines.push(format!(
                "    {}/{} as {}{} in {}",
                import.dll,
                import.symbol,
                import.canonical_dll,
                note,
                import.modules.join(", ")
            ));
        }
    }
    if !diff.unimported_registry_rows.is_empty() {
        lines.push("  coverage bias (first 25 modeled rows never imported):".to_string());
        for row in diff.unimported_registry_rows.iter().take(25) {
            lines.push(format!("    {}/{}", row.dll, row.export));
        }
        if diff.unimported_registry_rows.len() > 25 {
            lines.push(format!(
                "    ... and {} more",
                diff.unimported_registry_rows.len() - 25
            ));
        }
    }
    if !diff.aliases.is_empty() {
        lines.push("  DLL aliases:".to_string());
        for alias in &diff.aliases {
            lines.push(format!(
                "    {} -> {} [{}]",
                alias.observed, alias.resolved, alias.kind
            ));
        }
    }
    for error in &inventory.errors {
        lines.push(format!(
            "  parse error: {}: {} ({})",
            error.path, error.message, error.reason_name
        ));
    }
    lines.join("\n")
}

/// Helper for CLI callers: write the deterministic JSON (with trailing newline).
pub fn write_report(report: &InventoryReport, out: &Path) -> AppResult<()> {
    let json = serde_json::to_string_pretty(report).map_err(|error| {
        AppError::new(
            crate::reason::ReasonCode::RcIo,
            "failed to encode inventory report",
        )
        .with_hint(error.to_string())
    })?;
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| {
            AppError::from_io(
                crate::reason::ReasonCode::RcIo,
                format!("failed to create {}", parent.display()),
                &error,
            )
        })?;
    }
    fs::write(out, format!("{json}\n")).map_err(|error| {
        AppError::from_io(
            crate::reason::ReasonCode::RcIo,
            format!("failed to write {}", out.display()),
            &error,
        )
    })
}

/// Default inventory output path used by callers that omit `--out`.
pub fn default_out_path() -> PathBuf {
    PathBuf::from("casa1-pe-inventory.json")
}
