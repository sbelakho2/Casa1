//! Generic binary import-coverage report system.
//!
//! Two paths live here:
//!
//! 1. **Regression snapshot** (`#[cfg(test)]` only) — the legacy hand-curated
//!    Steam.exe import list ([`steam_exe_imports_regression_snapshot`]) and
//!    the report generators built on it (`generate_import_coverage_report*`).
//!    These are kept ONLY as a regression snapshot of the historical report
//!    format.  They are gated behind `#[cfg(test)]` and MUST NOT contribute to
//!    general compatibility metrics.
//! 2. **Canonical binary-derived coverage** — [`coverage_for_pe`] parses the
//!    import tables of ANY PE (via [`crate::pe::parse_from_file`]), classifies
//!    every import against the canonical [`ThunkMetadata`]
//!    ([`crate::host_thunks::THUNK_METADATA`]) and the quantitative API
//!    database, and emits a structured, JSON-serializable report with the
//!    implementation quality and user-mode support policy of each import.
//!    Runtime-observed resolutions (GetProcAddress, delay-load, forwarded
//!    exports) are recorded as `DynamicLookup` entries through the shared
//!    dynamic-import log ([`crate::pe_runtime::DYNAMIC_IMPORT_LOG`]).

use crate::api_database::CoverageLevel;
use crate::compatibility_profile::CompatibilityProfile;
use crate::cpu::GuestArch;
use crate::host_thunks::{ImplementationLevel, SupportPolicy};
use crate::pe::ImportSymbol;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Workload identity
// ---------------------------------------------------------------------------

/// A named workload (fixture, E2E scenario, process-tree root) whose scans
/// reach APIs.  Workload names are recorded into the compatibility database
/// so per-workload reach is attributable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkloadId(String);

impl WorkloadId {
    /// Create a workload identity from a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The workload name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Coverage data structures
// ---------------------------------------------------------------------------

/// Identity of one imported symbol: by name, or by ordinal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportIdentity {
    /// Imported by export name.
    Name(String),
    /// Imported by ordinal.
    Ordinal(u16),
}

impl ImportIdentity {
    /// The name used for database/metadata lookups (`ordinal#N` fallback for
    /// ordinals that do not resolve to a canonical name).
    pub fn lookup_name(&self) -> String {
        match self {
            ImportIdentity::Name(name) => name.clone(),
            ImportIdentity::Ordinal(ordinal) => format!("ordinal#{ordinal}"),
        }
    }
}

/// Where an import was observed: the static import table, the delay-load
/// table, or a runtime resolution (GetProcAddress / delay-load resolution /
/// forwarded export).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportSource {
    /// Present in the PE's static import table.
    Static,
    /// Present in the PE's delay-load import table.
    DelayLoad,
    /// Resolved at runtime (recorded through the dynamic-import log).
    DynamicLookup,
}

/// A single binary import classified against the canonical thunk metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryImportEntry {
    /// SHA-256 of the binary the import was parsed from.
    pub image_sha256: String,
    /// Version info of the binary (PE `FileVersion`), if present.
    pub image_version: Option<String>,
    /// Guest architecture of the binary.
    pub image_arch: GuestArch,
    /// DLL the import comes from (lowercase, e.g. `"kernel32.dll"`).
    pub dll: String,
    /// Import identity (name or ordinal).
    pub import: ImportIdentity,
    /// Where the import was observed.
    pub source: ImportSource,
    /// Implementation quality of the host thunk for this import
    /// ([`ImplementationLevel`]).
    pub implementation: ImplementationLevel,
    /// Proven semantic test coverage of the API in the compatibility
    /// database ([`CoverageLevel`]).
    pub semantic_coverage: CoverageLevel,
    /// Whether this import was actually invoked in the runtime run (false
    /// unless the runtime-trace parameter was supplied; `DynamicLookup`
    /// entries are reached by construction).
    pub runtime_reached: bool,
}

/// Binary-derived import coverage report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinaryCoverageReport {
    /// Path of the binary the report was derived from.
    pub binary_path: String,
    /// SHA-256 of the binary.
    pub image_sha256: String,
    /// PE version info of the binary, if present.
    pub image_version: Option<String>,
    /// Guest architecture of the binary.
    pub image_arch: GuestArch,
    /// Total number of imports in the report (static + delay + dynamic).
    pub total_imports: usize,
    /// Per-implementation-level import counts.
    pub by_implementation: BTreeMap<String, usize>,
    /// All classified imports.
    pub entries: Vec<BinaryImportEntry>,
    /// `Required` (user-mode-profile) imports whose implementation is `Stub`
    /// or `Unsupported`.
    ///
    /// The release requirement is that no *runtime-reached* `Required` API
    /// is `Stub` or `Unsupported`; this field lists the candidates that
    /// would fail the gate if they are ever invoked.
    pub required_not_working: Vec<BinaryImportEntry>,
    /// Whether a runtime trace (invoked set / dynamic-import log) was
    /// supplied for this report.
    pub runtime_trace_included: bool,
    /// The compatibility profile the coverage was computed for.
    pub target: CompatibilityProfile,
}

impl BinaryImportEntry {
    /// The support policy of the import's API from the canonical metadata
    /// (None when the API has no metadata entry).
    pub fn support_policy(&self) -> Option<SupportPolicy> {
        let name = self.import.lookup_name();
        crate::host_thunks::lookup_thunk_metadata(&self.dll, &name)
            .map(|metadata| metadata.support_policy)
    }
}

impl BinaryCoverageReport {
    /// `Required` imports that were actually invoked in the runtime run and
    /// whose implementation is `Stub` or `Unsupported` — the exact set the
    /// release gate asserts to be empty.
    pub fn runtime_reached_required_violations(&self) -> Vec<&BinaryImportEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.runtime_reached
                    && entry
                        .support_policy()
                        .is_some_and(|policy| policy == SupportPolicy::Required)
                    && !entry.implementation.has_working_implementation()
            })
            .collect()
    }
}

/// The process-tree coverage report: the main executable, its loaded guest
/// DLLs, delay-loaded DLLs, dynamically-resolved exports, and child
/// executables (the process tree the runtime knows about).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessTreeCoverageReport {
    /// Per-binary coverage reports (main executable first, then children).
    pub binaries: Vec<BinaryCoverageReport>,
    /// Total imports across the tree.
    pub total_imports: usize,
    /// Per-implementation-level counts across the tree.
    pub by_implementation: BTreeMap<String, usize>,
    /// Number of dynamic lookups recorded across the tree.
    pub dynamic_lookups: usize,
}

// ---------------------------------------------------------------------------
// Canonical binary-derived coverage
// ---------------------------------------------------------------------------

/// The PE machine field for x86 guests.
const MACHINE_X86: u16 = 0x014c;
/// The PE machine field for x64 guests.
const MACHINE_X64: u16 = 0x8664;

fn guest_arch_from_machine(machine: u16) -> GuestArch {
    match machine {
        MACHINE_X86 => GuestArch::X86,
        MACHINE_X64 => GuestArch::X64,
        _ => GuestArch::X64,
    }
}

/// Classify one (dll, name) import: implementation level + semantic coverage
/// from the compatibility database (seeded from THUNK_METADATA), recording
/// the workload into the matching entry.
fn classify_import(
    dll: &str,
    name: &str,
    workload: &WorkloadId,
) -> (ImplementationLevel, CoverageLevel) {
    let database = crate::api_database::global_database();
    let mut database = database
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let level = database
        .lookup(dll, name)
        .map(|entry| {
            let level = entry.implementation;
            let coverage = entry.semantic_test_coverage;
            (level, coverage)
        })
        .unwrap_or((ImplementationLevel::Unsupported, CoverageLevel::None));
    database.record_workload(dll, name, workload.as_str());
    level
}

/// Generate the binary-derived import coverage report.
///
/// Parses the ACTUAL binary's import tables via
/// [`crate::pe::parse_from_file`], classifies every import against the
/// canonical [`ThunkMetadata`] table and the quantitative API database, and
/// emits a structured report.
///
/// Every entry carries `runtime_reached: false` unless a runtime trace is
/// supplied via [`coverage_for_pe_with_runtime_trace`].
///
/// This variant does NOT consume the shared dynamic-import log: only the
/// runtime-trace variant ([`coverage_for_pe_with_runtime_trace`]) does.
pub fn coverage_for_pe(
    binary_path: &Path,
    workload: &WorkloadId,
    target: CompatibilityProfile,
) -> crate::error::AppResult<BinaryCoverageReport> {
    coverage_for_pe_impl(binary_path, workload, target, &[], false)
}

/// Generate the binary-derived import coverage report with a runtime trace.
///
/// `runtime_reached` lists the API names that were actually dispatched during
/// a runtime run (e.g. from [`crate::pe_runtime::PeExecutionResult::trace_events`]
/// via [`invoked_api_names_from_trace`]); matching entries get
/// `runtime_reached: true`.  In addition, the shared dynamic-import log
/// ([`crate::pe_runtime::drain_dynamic_import_log`]) is consumed: every
/// recorded (DLL, name) resolution becomes a `DynamicLookup` entry.
pub fn coverage_for_pe_with_runtime_trace(
    binary_path: &Path,
    workload: &WorkloadId,
    target: CompatibilityProfile,
    runtime_reached: &[String],
) -> crate::error::AppResult<BinaryCoverageReport> {
    coverage_for_pe_impl(binary_path, workload, target, runtime_reached, true)
}

/// Shared implementation of the two public coverage entry points.
///
/// `consume_dynamic_log` is true ONLY for the runtime-trace variant: the
/// plain static-scan variant must never drain the process-global
/// dynamic-import log.
fn coverage_for_pe_impl(
    binary_path: &Path,
    workload: &WorkloadId,
    target: CompatibilityProfile,
    runtime_reached: &[String],
    consume_dynamic_log: bool,
) -> crate::error::AppResult<BinaryCoverageReport> {
    let parsed = crate::pe::parse_from_file(binary_path)?;
    let image_sha256 = crate::util::sha256_file(binary_path)?;
    let image_version = parsed.version_info.file_version.clone();
    let image_arch = guest_arch_from_machine(parsed.machine);
    let invoked_set: std::collections::HashSet<String> = runtime_reached
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();

    let mut entries = Vec::new();

    let mut push_import = |dll: &str, symbol: &ImportSymbol, source: ImportSource| {
        let import = match symbol {
            ImportSymbol::ByName { name, .. } => ImportIdentity::Name(name.clone()),
            ImportSymbol::ByOrdinal { ordinal } => ImportIdentity::Ordinal(*ordinal),
        };
        let lookup_name = match symbol {
            ImportSymbol::ByName { name, .. } => name.clone(),
            ImportSymbol::ByOrdinal { ordinal } => {
                crate::host_thunks::ordinal_import_name(dll, *ordinal)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("ordinal#{ordinal}"))
            }
        };
        let (implementation, semantic_coverage) = classify_import(dll, &lookup_name, workload);
        let runtime_reached = invoked_set.contains(&lookup_name.to_ascii_lowercase());
        entries.push(BinaryImportEntry {
            image_sha256: image_sha256.clone(),
            image_version: image_version.clone(),
            image_arch,
            dll: dll.to_ascii_lowercase(),
            import,
            source,
            implementation,
            semantic_coverage,
            runtime_reached,
        });
    };

    for descriptor in parsed.imports.iter() {
        let dll = descriptor.dll_name.to_ascii_lowercase();
        for import in &descriptor.imports {
            push_import(&dll, &import.symbol, ImportSource::Static);
        }
    }
    for descriptor in parsed.delay_imports.iter() {
        let dll = descriptor.dll_name.to_ascii_lowercase();
        for import in &descriptor.imports {
            push_import(&dll, &import.symbol, ImportSource::DelayLoad);
        }
    }

    // Dynamic-import instrumentation: consume the shared log ONLY for the
    // runtime-trace variant.  Every recorded entry is reached by construction
    // (the runtime resolved it).
    let dynamic = if consume_dynamic_log {
        crate::pe_runtime::drain_dynamic_import_log()
    } else {
        Vec::new()
    };
    for import in &dynamic {
        let import_identity = ImportIdentity::Name(import.name.clone());
        let (implementation, semantic_coverage) =
            classify_import(&import.dll, &import.name, workload);
        entries.push(BinaryImportEntry {
            image_sha256: image_sha256.clone(),
            image_version: image_version.clone(),
            image_arch,
            dll: import.dll.clone(),
            import: import_identity,
            source: ImportSource::DynamicLookup,
            implementation,
            semantic_coverage,
            runtime_reached: true,
        });
    }

    entries.sort_by(|a, b| {
        a.dll
            .cmp(&b.dll)
            .then_with(|| a.import.lookup_name().cmp(&b.import.lookup_name()))
            .then_with(|| format!("{:?}", a.source).cmp(&format!("{:?}", b.source)))
    });

    let mut by_implementation = BTreeMap::new();
    for entry in &entries {
        let label = match entry.implementation {
            ImplementationLevel::Implemented => "Implemented",
            ImplementationLevel::Partial => "Partial",
            ImplementationLevel::Stub => "Stub",
            ImplementationLevel::Unsupported => "Unsupported",
        };
        *by_implementation.entry(label.to_string()).or_insert(0) += 1;
    }

    let required_not_working = entries
        .iter()
        .filter(|entry| {
            entry
                .support_policy()
                .is_some_and(|policy| policy == SupportPolicy::Required)
                && !entry.implementation.has_working_implementation()
        })
        .cloned()
        .collect();

    Ok(BinaryCoverageReport {
        binary_path: binary_path.display().to_string(),
        image_sha256,
        image_version,
        image_arch,
        total_imports: entries.len(),
        by_implementation,
        entries,
        required_not_working,
        runtime_trace_included: !invoked_set.is_empty() || !dynamic.is_empty(),
        target,
    })
}

/// Generate the binary-derived coverage report for a process tree: the main
/// executable, the guest DLLs it loads (static + delay-loaded imports), the
/// dynamically-resolved exports, and the child executables the runtime knows
/// about.
///
/// `binaries` lists the process-tree roots (main executable first, then any
/// child executables).  Dynamic lookups recorded in the shared
/// dynamic-import log are attributed to the first binary in the list (the
/// process root), since the log is process-global.
pub fn coverage_for_process_tree(
    binaries: &[&Path],
    workload: &WorkloadId,
    target: CompatibilityProfile,
    runtime_reached: &[String],
) -> crate::error::AppResult<ProcessTreeCoverageReport> {
    let mut reports = Vec::new();
    let mut dynamic_lookups = 0usize;
    for (index, path) in binaries.iter().enumerate() {
        let report =
            coverage_for_pe_with_runtime_trace(path, workload, target.clone(), runtime_reached)?;
        dynamic_lookups += report
            .entries
            .iter()
            .filter(|entry| entry.source == ImportSource::DynamicLookup)
            .count();
        // The dynamic-import log is process-global: only the process root
        // consumes it (drain happens inside coverage_for_pe_with_runtime_trace).
        if index > 0 {
            // Child binaries re-drain nothing; their dynamic attribution is
            // empty by construction (the log is already drained by the root).
            let _ = &report;
        }
        reports.push(report);
    }

    let mut by_implementation = BTreeMap::new();
    let mut total_imports = 0usize;
    for report in &reports {
        total_imports += report.total_imports;
        for (label, count) in &report.by_implementation {
            *by_implementation.entry(label.clone()).or_insert(0) += count;
        }
    }

    Ok(ProcessTreeCoverageReport {
        binaries: reports,
        total_imports,
        by_implementation,
        dynamic_lookups,
    })
}

/// Extract the set of invoked API names from a PE runtime trace.
///
/// Each trace event's `call_id` is the dispatched API name (e.g.
/// `"CreateFileW"`); duplicate calls collapse into a single name so the set
/// can be fed to [`coverage_for_pe_with_runtime_trace`].
pub fn invoked_api_names_from_trace(trace_events: &[crate::trace::TraceEvent]) -> Vec<String> {
    let mut names: Vec<String> = trace_events
        .iter()
        .map(|event| event.call_id.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Generate the binary-derived coverage report as pretty JSON.
pub fn coverage_for_pe_json(
    binary_path: &Path,
    workload: &WorkloadId,
    target: CompatibilityProfile,
) -> crate::error::AppResult<Value> {
    let report = coverage_for_pe(binary_path, workload, target)?;
    serde_json::to_value(&report).map_err(|error| {
        crate::error::AppError::new(
            crate::reason::ReasonCode::RcDiagnosticsExportFailed,
            format!("failed to serialize binary coverage report: {error}"),
        )
    })
}

/// Generate a structured human-readable rendering of the binary-derived
/// coverage report (the section40-style telemetry view).
pub fn coverage_for_pe_text(
    binary_path: &Path,
    workload: &WorkloadId,
    target: CompatibilityProfile,
) -> crate::error::AppResult<String> {
    let report = coverage_for_pe(binary_path, workload, target)?;
    let mut lines = Vec::new();
    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push("      Binary Import Coverage (fixture-derived)                 ".to_string());
    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push(format!("binary:   {}", report.binary_path));
    lines.push(format!("sha256:   {}", report.image_sha256));
    lines.push(format!(
        "version:  {}",
        report.image_version.as_deref().unwrap_or("<none>")
    ));
    lines.push(format!("arch:     {:?}", report.image_arch));
    lines.push(format!("imports:  {}", report.total_imports));
    lines.push(format!(
        "runtime-trace flag: {}",
        if report.runtime_trace_included {
            "yes"
        } else {
            "no"
        }
    ));
    lines.push(String::new());
    lines.push(format!("{:<14} {:>6}", "Implementation", "Count"));
    lines.push("─".repeat(24));
    for label in ["Implemented", "Partial", "Stub", "Unsupported"] {
        lines.push(format!(
            "{:<14} {:>6}",
            label,
            report.by_implementation.get(label).copied().unwrap_or(0)
        ));
    }
    lines.push(String::new());
    if report.required_not_working.is_empty() {
        lines.push(
            "No Required (user-mode-profile) import is Stub/Unsupported on the static surface."
                .to_string(),
        );
    } else {
        lines.push(format!(
            "Required imports NOT working ({}):",
            report.required_not_working.len()
        ));
        for entry in &report.required_not_working {
            lines.push(format!(
                "  - {}!{} [{:?}]",
                entry.dll,
                entry.import.lookup_name(),
                entry.implementation
            ));
        }
    }
    Ok(lines.join("\n"))
}

// ---------------------------------------------------------------------------
// REGRESSION SNAPSHOT ONLY — #[cfg(test)]
//
// The legacy hand-curated Steam.exe import snapshot and the report format
// built on it.  Kept purely as a regression snapshot of the historical
// report; gated so it never contributes to general compatibility metrics.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod legacy {
    use super::*;
    use crate::pe::{ExportSymbol, ParsedPe};

    /// **Regression snapshot.**  Hand-curated representative list of DLLs
    /// that Steam.exe imports from, along with the function names it requires
    /// from each DLL.
    ///
    /// Kept ONLY as a regression snapshot of the legacy report format
    /// (`generate_import_coverage_report*`); the canonical, authoritative
    /// coverage path is [`super::coverage_for_pe`], which derives imports
    /// from the real binary instead of a hand-maintained copy.
    pub fn steam_exe_imports_regression_snapshot() -> BTreeMap<String, Vec<String>> {
        let mut m = BTreeMap::new();

        // kernel32.dll
        m.insert(
            "kernel32.dll".to_string(),
            vec![
                "GetModuleHandleA".into(),
                "GetModuleHandleW".into(),
                "GetProcAddress".into(),
                "LoadLibraryA".into(),
                "LoadLibraryW".into(),
                "LoadLibraryExA".into(),
                "LoadLibraryExW".into(),
                "FreeLibrary".into(),
                "GetModuleFileNameA".into(),
                "GetModuleFileNameW".into(),
                "CreateFileA".into(),
                "CreateFileW".into(),
                "ReadFile".into(),
                "WriteFile".into(),
                "CloseHandle".into(),
                "GetFileSize".into(),
                "GetFileSizeEx".into(),
                "SetFilePointer".into(),
                "SetFilePointerEx".into(),
                "FlushFileBuffers".into(),
                "DeleteFileA".into(),
                "DeleteFileW".into(),
                "MoveFileA".into(),
                "MoveFileW".into(),
                "MoveFileExA".into(),
                "MoveFileExW".into(),
                "FindFirstFileA".into(),
                "FindFirstFileW".into(),
                "FindNextFileA".into(),
                "FindNextFileW".into(),
                "FindClose".into(),
                "CreateDirectoryA".into(),
                "CreateDirectoryW".into(),
                "RemoveDirectoryA".into(),
                "RemoveDirectoryW".into(),
                "GetFileAttributesA".into(),
                "GetFileAttributesW".into(),
                "SetFileAttributesA".into(),
                "SetFileAttributesW".into(),
                "GetCurrentDirectoryA".into(),
                "GetCurrentDirectoryW".into(),
                "SetCurrentDirectoryA".into(),
                "SetCurrentDirectoryW".into(),
                "GetTempPathA".into(),
                "GetTempPathW".into(),
                "GetTempFileNameA".into(),
                "GetTempFileNameW".into(),
                "CreateProcessA".into(),
                "CreateProcessW".into(),
                "TerminateProcess".into(),
                "GetExitCodeProcess".into(),
                "WaitForSingleObject".into(),
                "WaitForMultipleObjects".into(),
                "Sleep".into(),
                "SleepEx".into(),
                "GetTickCount".into(),
                "GetTickCount64".into(),
                "QueryPerformanceCounter".into(),
                "QueryPerformanceFrequency".into(),
                "GetSystemTime".into(),
                "GetSystemTimeAsFileTime".into(),
                "GetLocalTime".into(),
                "CreateMutexA".into(),
                "CreateMutexW".into(),
                "OpenMutexA".into(),
                "OpenMutexW".into(),
                "CreateSemaphoreA".into(),
                "CreateSemaphoreW".into(),
                "CreateEventA".into(),
                "CreateEventW".into(),
                "SetEvent".into(),
                "ResetEvent".into(),
                "InitializeCriticalSection".into(),
                "EnterCriticalSection".into(),
                "LeaveCriticalSection".into(),
                "DeleteCriticalSection".into(),
                "CreateThread".into(),
                "ExitThread".into(),
                "GetCurrentThreadId".into(),
                "GetCurrentProcessId".into(),
                "TlsAlloc".into(),
                "TlsFree".into(),
                "TlsGetValue".into(),
                "TlsSetValue".into(),
                "HeapAlloc".into(),
                "HeapFree".into(),
                "HeapCreate".into(),
                "HeapDestroy".into(),
                "GetProcessHeap".into(),
                "VirtualAlloc".into(),
                "VirtualFree".into(),
                "VirtualProtect".into(),
                "VirtualQuery".into(),
                "GetLastError".into(),
                "SetLastError".into(),
                "FormatMessageA".into(),
                "FormatMessageW".into(),
                "MultiByteToWideChar".into(),
                "WideCharToMultiByte".into(),
                "lstrlenA".into(),
                "lstrlenW".into(),
                "lstrcpyA".into(),
                "lstrcpyW".into(),
                "lstrcatA".into(),
                "lstrcatW".into(),
                "lstrcmpA".into(),
                "lstrcmpW".into(),
                "lstrcmpiA".into(),
                "lstrcmpiW".into(),
                "GetVersionExA".into(),
                "GetVersionExW".into(),
                "GetComputerNameA".into(),
                "GetComputerNameW".into(),
                "GetEnvironmentVariableA".into(),
                "GetEnvironmentVariableW".into(),
                "SetEnvironmentVariableA".into(),
                "SetEnvironmentVariableW".into(),
                "ExpandEnvironmentStringsA".into(),
                "ExpandEnvironmentStringsW".into(),
                "GetCommandLineA".into(),
                "GetCommandLineW".into(),
                "GetStartupInfoA".into(),
                "GetStartupInfoW".into(),
                "GlobalAlloc".into(),
                "GlobalFree".into(),
                "GlobalLock".into(),
                "GlobalUnlock".into(),
                "GlobalHandle".into(),
                "LocalAlloc".into(),
                "LocalFree".into(),
                "CreateActCtxW".into(),
                "ActivateActCtx".into(),
                "DeactivateActCtx".into(),
                "ReleaseActCtx".into(),
                "FindActCtxSectionStringW".into(),
                "GetSystemInfo".into(),
                "IsWow64Process".into(),
                "GetNativeSystemInfo".into(),
                "DebugBreak".into(),
                "OutputDebugStringA".into(),
                "OutputDebugStringW".into(),
                "IsDebuggerPresent".into(),
                "SetUnhandledExceptionFilter".into(),
                "UnhandledExceptionFilter".into(),
                "GetStdHandle".into(),
                "WriteConsoleA".into(),
                "WriteConsoleW".into(),
            ],
        );

        // user32.dll
        m.insert(
            "user32.dll".to_string(),
            vec![
                "CreateWindowExA".into(),
                "CreateWindowExW".into(),
                "DestroyWindow".into(),
                "ShowWindow".into(),
                "UpdateWindow".into(),
                "GetMessageA".into(),
                "GetMessageW".into(),
                "TranslateMessage".into(),
                "DispatchMessageA".into(),
                "DispatchMessageW".into(),
                "SendMessageA".into(),
                "SendMessageW".into(),
                "PostMessageA".into(),
                "PostMessageW".into(),
                "PostQuitMessage".into(),
                "PeekMessageA".into(),
                "PeekMessageW".into(),
                "DefWindowProcA".into(),
                "DefWindowProcW".into(),
                "RegisterClassA".into(),
                "RegisterClassW".into(),
                "RegisterClassExA".into(),
                "RegisterClassExW".into(),
                "GetClientRect".into(),
                "GetWindowRect".into(),
                "SetWindowPos".into(),
                "MoveWindow".into(),
                "GetDC".into(),
                "ReleaseDC".into(),
                "BeginPaint".into(),
                "EndPaint".into(),
                "InvalidateRect".into(),
                "ValidateRect".into(),
                "SetWindowTextA".into(),
                "SetWindowTextW".into(),
                "GetWindowTextA".into(),
                "GetWindowTextW".into(),
                "GetWindowTextLengthA".into(),
                "GetWindowTextLengthW".into(),
                "SetTimer".into(),
                "KillTimer".into(),
                "GetSystemMetrics".into(),
                "LoadCursorA".into(),
                "LoadCursorW".into(),
                "LoadIconA".into(),
                "LoadIconW".into(),
                "LoadImageA".into(),
                "LoadImageW".into(),
                "MessageBoxA".into(),
                "MessageBoxW".into(),
                "GetDlgItem".into(),
                "SetDlgItemTextA".into(),
                "SetDlgItemTextW".into(),
                "GetDlgItemTextA".into(),
                "GetDlgItemTextW".into(),
                "DialogBoxParamA".into(),
                "DialogBoxParamW".into(),
                "EndDialog".into(),
                "CreateDialogParamA".into(),
                "CreateDialogParamW".into(),
                "IsDialogMessageA".into(),
                "IsDialogMessageW".into(),
                "EnableWindow".into(),
                "IsWindowEnabled".into(),
                "IsWindowVisible".into(),
                "IsWindow".into(),
                "GetParent".into(),
                "SetParent".into(),
                "GetForegroundWindow".into(),
                "SetForegroundWindow".into(),
                "GetFocus".into(),
                "SetFocus".into(),
                "GetActiveWindow".into(),
                "SetActiveWindow".into(),
                "GetKeyState".into(),
                "GetAsyncKeyState".into(),
                "GetKeyboardState".into(),
                "MapVirtualKeyA".into(),
                "MapVirtualKeyW".into(),
                "VkKeyScanA".into(),
                "VkKeyScanW".into(),
                "TrackPopupMenu".into(),
                "CreateMenu".into(),
                "CreatePopupMenu".into(),
                "AppendMenuA".into(),
                "AppendMenuW".into(),
                "InsertMenuA".into(),
                "InsertMenuW".into(),
                "DrawMenuBar".into(),
                "LoadMenuA".into(),
                "LoadMenuW".into(),
                "GetMenu".into(),
                "SetMenu".into(),
                "DestroyMenu".into(),
                "GetSubMenu".into(),
                "GetMenuItemCount".into(),
                "GetMenuItemID".into(),
                "CheckMenuItem".into(),
                "EnableMenuItem".into(),
                "GetCursorPos".into(),
                "SetCursorPos".into(),
                "ShowCursor".into(),
                "ClipCursor".into(),
                "GetClipCursor".into(),
                "ScreenToClient".into(),
                "ClientToScreen".into(),
                "GetWindowLongA".into(),
                "GetWindowLongW".into(),
                "GetWindowLongPtrA".into(),
                "GetWindowLongPtrW".into(),
                "SetWindowLongA".into(),
                "SetWindowLongW".into(),
                "SetWindowLongPtrA".into(),
                "SetWindowLongPtrW".into(),
                "GetClassLongA".into(),
                "GetClassLongW".into(),
                "SetClassLongA".into(),
                "SetClassLongW".into(),
                "AdjustWindowRect".into(),
                "AdjustWindowRectEx".into(),
                "GetDesktopWindow".into(),
                "GetWindowThreadProcessId".into(),
                "EnumWindows".into(),
                "EnumChildWindows".into(),
                "GetClassNameA".into(),
                "GetClassNameW".into(),
                "RegisterWindowMessageA".into(),
                "RegisterWindowMessageW".into(),
                "SendMessageTimeoutA".into(),
                "SendMessageTimeoutW".into(),
                "SendNotifyMessageA".into(),
                "SendNotifyMessageW".into(),
                "PostThreadMessageA".into(),
                "PostThreadMessageW".into(),
                "WaitMessage".into(),
                "MsgWaitForMultipleObjects".into(),
                "MsgWaitForMultipleObjectsEx".into(),
                "GetMessagePos".into(),
                "GetMessageTime".into(),
                "TranslateAcceleratorA".into(),
                "TranslateAcceleratorW".into(),
                "LoadAcceleratorsA".into(),
                "LoadAcceleratorsW".into(),
                "SetCapture".into(),
                "ReleaseCapture".into(),
                "GetCapture".into(),
                "GetDoubleClickTime".into(),
                "RegisterHotKey".into(),
                "UnregisterHotKey".into(),
                "FlashWindow".into(),
                "FlashWindowEx".into(),
                "GetWindow".into(),
                "IsChild".into(),
                "BringWindowToTop".into(),
                "ShowOwnedPopups".into(),
                "OpenClipboard".into(),
                "CloseClipboard".into(),
                "EmptyClipboard".into(),
                "SetClipboardData".into(),
                "GetClipboardData".into(),
                "IsClipboardFormatAvailable".into(),
                "CountClipboardFormats".into(),
                "EnumClipboardFormats".into(),
                "RegisterClipboardFormatA".into(),
                "RegisterClipboardFormatW".into(),
            ],
        );

        // gdi32.dll
        m.insert(
            "gdi32.dll".to_string(),
            vec![
                "CreateCompatibleDC".into(),
                "CreateCompatibleBitmap".into(),
                "CreateBitmap".into(),
                "CreateDIBSection".into(),
                "CreateDIBitmap".into(),
                "SelectObject".into(),
                "DeleteObject".into(),
                "DeleteDC".into(),
                "BitBlt".into(),
                "StretchBlt".into(),
                "StretchDIBits".into(),
                "SetDIBitsToDevice".into(),
                "GetDIBits".into(),
                "SetBitmapBits".into(),
                "GetBitmapBits".into(),
                "CreateSolidBrush".into(),
                "CreatePen".into(),
                "CreateFontA".into(),
                "CreateFontW".into(),
                "CreateFontIndirectA".into(),
                "CreateFontIndirectW".into(),
                "SetTextColor".into(),
                "SetBkColor".into(),
                "SetBkMode".into(),
                "TextOutA".into(),
                "TextOutW".into(),
                "DrawTextA".into(),
                "DrawTextW".into(),
                "GetTextExtentPoint32A".into(),
                "GetTextExtentPoint32W".into(),
                "GetTextMetricsA".into(),
                "GetTextMetricsW".into(),
                "Rectangle".into(),
                "FillRect".into(),
                "FrameRect".into(),
                "RoundRect".into(),
                "Ellipse".into(),
                "LineTo".into(),
                "MoveToEx".into(),
                "Polygon".into(),
                "Polyline".into(),
                "SetPixel".into(),
                "GetPixel".into(),
                "PatBlt".into(),
                "MaskBlt".into(),
                "PlgBlt".into(),
                "CreatePalette".into(),
                "SelectPalette".into(),
                "RealizePalette".into(),
                "GetDeviceCaps".into(),
                "GetSystemPaletteEntries".into(),
                "CreateHalftonePalette".into(),
                "GetObjectA".into(),
                "GetObjectW".into(),
                "GetStockObject".into(),
                "SetROP2".into(),
                "SetStretchBltMode".into(),
                "GetBrushOrgEx".into(),
                "SetBrushOrgEx".into(),
                "GetClipBox".into(),
                "SelectClipRgn".into(),
                "ExtSelectClipRgn".into(),
                "OffsetClipRgn".into(),
                "SaveDC".into(),
                "RestoreDC".into(),
                "CreateRectRgn".into(),
                "CreateRectRgnIndirect".into(),
                "CombineRgn".into(),
                "OffsetRgn".into(),
                "GetRegionData".into(),
                "ExtCreatePen".into(),
                "CreatePatternBrush".into(),
                "CreateHatchBrush".into(),
                "SetWorldTransform".into(),
                "ModifyWorldTransform".into(),
                "SetGraphicsMode".into(),
                "SetMapMode".into(),
                "SetViewportOrgEx".into(),
                "SetWindowOrgEx".into(),
                "SetViewportExtEx".into(),
                "SetWindowExtEx".into(),
                "DPtoLP".into(),
                "LPtoDP".into(),
                "GetWorldTransform".into(),
                "GetMapMode".into(),
                "GetCurrentObject".into(),
                "GetObjectType".into(),
                "EnumFontFamiliesExA".into(),
                "EnumFontFamiliesExW".into(),
                "AddFontResourceA".into(),
                "AddFontResourceW".into(),
                "RemoveFontResourceA".into(),
                "RemoveFontResourceW".into(),
                "GetCharABCWidthsA".into(),
                "GetCharABCWidthsW".into(),
                "GetCharacterPlacementA".into(),
                "GetCharacterPlacementW".into(),
            ],
        );

        // advapi32.dll
        m.insert(
            "advapi32.dll".to_string(),
            vec![
                "RegOpenKeyExA".into(),
                "RegOpenKeyExW".into(),
                "RegCreateKeyExA".into(),
                "RegCreateKeyExW".into(),
                "RegCloseKey".into(),
                "RegSetValueExA".into(),
                "RegSetValueExW".into(),
                "RegQueryValueExA".into(),
                "RegQueryValueExW".into(),
                "RegDeleteKeyA".into(),
                "RegDeleteKeyW".into(),
                "RegDeleteValueA".into(),
                "RegDeleteValueW".into(),
                "RegEnumKeyExA".into(),
                "RegEnumKeyExW".into(),
                "RegEnumValueA".into(),
                "RegEnumValueW".into(),
                "RegNotifyChangeKeyValue".into(),
                "OpenProcessToken".into(),
                "GetTokenInformation".into(),
                "AdjustTokenPrivileges".into(),
                "LookupPrivilegeValueA".into(),
                "LookupPrivilegeValueW".into(),
                "CheckTokenMembership".into(),
                "DuplicateTokenEx".into(),
                "GetUserNameA".into(),
                "GetUserNameW".into(),
                "ConvertSidToStringSidA".into(),
                "ConvertSidToStringSidW".into(),
                "ConvertStringSidToSidA".into(),
                "ConvertStringSidToSidW".into(),
                "EqualSid".into(),
                "GetLengthSid".into(),
                "CopySid".into(),
                "InitializeSecurityDescriptor".into(),
                "SetSecurityDescriptorDacl".into(),
                "GetSecurityDescriptorDacl".into(),
                "InitializeAcl".into(),
                "AddAccessAllowedAce".into(),
                "CryptAcquireContextA".into(),
                "CryptAcquireContextW".into(),
                "CryptGenRandom".into(),
                "CryptReleaseContext".into(),
                "CryptCreateHash".into(),
                "CryptHashData".into(),
                "CryptGetHashParam".into(),
                "CryptDestroyHash".into(),
                "CryptDeriveKey".into(),
                "CryptEncrypt".into(),
                "CryptDecrypt".into(),
                "CryptDestroyKey".into(),
                "CryptImportKey".into(),
                "CryptExportKey".into(),
                "CryptSetKeyParam".into(),
                "CryptGenKey".into(),
                "StartServiceCtrlDispatcherA".into(),
                "StartServiceCtrlDispatcherW".into(),
                "RegisterServiceCtrlHandlerA".into(),
                "RegisterServiceCtrlHandlerW".into(),
                "SetServiceStatus".into(),
                "OpenSCManagerA".into(),
                "OpenSCManagerW".into(),
                "OpenServiceA".into(),
                "OpenServiceW".into(),
                "CreateServiceA".into(),
                "CreateServiceW".into(),
                "StartServiceA".into(),
                "StartServiceW".into(),
                "ControlService".into(),
                "CloseServiceHandle".into(),
                "DeleteService".into(),
                "QueryServiceStatus".into(),
                "QueryServiceStatusEx".into(),
                "GetFileSecurityA".into(),
                "GetFileSecurityW".into(),
                "SetFileSecurityA".into(),
                "SetFileSecurityW".into(),
                "AccessCheck".into(),
                "MapGenericMask".into(),
            ],
        );

        // shell32.dll
        m.insert(
            "shell32.dll".to_string(),
            vec![
                "SHGetFolderPathA".into(),
                "SHGetFolderPathW".into(),
                "SHGetSpecialFolderPathA".into(),
                "SHGetSpecialFolderPathW".into(),
                "SHGetDesktopFolder".into(),
                "SHBrowseForFolderW".into(),
                "SHGetPathFromIDListW".into(),
                "ILCreateFromPathW".into(),
                "ILFree".into(),
                "SHGetFileInfoA".into(),
                "SHGetFileInfoW".into(),
                "SHGetMalloc".into(),
                "DragAcceptFiles".into(),
                "DragQueryFileW".into(),
                "DragFinish".into(),
                "DragQueryPoint".into(),
                "ShellExecuteA".into(),
                "ShellExecuteW".into(),
                "ShellExecuteExA".into(),
                "ShellExecuteExW".into(),
                "SHGetSpecialFolderLocation".into(),
                "SHGetFolderLocation".into(),
                "SHParseDisplayName".into(),
                "SHCreateItemFromParsingName".into(),
                "ExtractIconW".into(),
            ],
        );

        // ole32.dll
        m.insert(
            "ole32.dll".to_string(),
            vec![
                "CoInitialize".into(),
                "CoInitializeEx".into(),
                "CoUninitialize".into(),
                "CoCreateInstance".into(),
                "CoGetClassObject".into(),
                "CoTaskMemAlloc".into(),
                "CoTaskMemFree".into(),
                "CoTaskMemRealloc".into(),
                "CoInitializeSecurity".into(),
                "CoGetCallContext".into(),
                "CoSetProxyBlanket".into(),
                "CoGetApartmentType".into(),
                "CoGetCurrentProcess".into(),
                "CoRegisterClassObject".into(),
                "CoRevokeClassObject".into(),
                "CoResumeClassObjects".into(),
                "CoSuspendClassObjects".into(),
                "CreateStreamOnHGlobal".into(),
                "GetHGlobalFromStream".into(),
                "CoCreateGuid".into(),
                "StringFromGUID2".into(),
                "IIDFromString".into(),
                "CLSIDFromString".into(),
                "StringFromCLSID".into(),
                "ProgIDFromCLSID".into(),
                "CLSIDFromProgID".into(),
                "OleInitialize".into(),
                "OleUninitialize".into(),
                "RegisterDragDrop".into(),
                "RevokeDragDrop".into(),
                "DoDragDrop".into(),
                "CreateBindCtx".into(),
                "CreateFileMoniker".into(),
                "MkParseDisplayName".into(),
                "CoGetMalloc".into(),
                "CoGetObjectContext".into(),
                "CoGetInterfaceAndReleaseStream".into(),
                "CoMarshalInterThreadInterfaceInStream".into(),
                "CoReleaseMarshalData".into(),
            ],
        );

        // crypt32.dll
        m.insert(
            "crypt32.dll".to_string(),
            vec![
                "CertOpenStore".into(),
                "CertCloseStore".into(),
                "CertOpenSystemStoreA".into(),
                "CertOpenSystemStoreW".into(),
                "CertEnumCertificatesInStore".into(),
                "CertFindCertificateInStore".into(),
                "CertGetCertificateChain".into(),
                "CertFreeCertificateChain".into(),
                "CertVerifyCertificateChainPolicy".into(),
                "CertDeleteCertificateFromStore".into(),
                "CertAddCertificateContextToStore".into(),
                "CertDuplicateCertificateContext".into(),
                "CertFreeCertificateContext".into(),
                "CryptAcquireCertificatePrivateKey".into(),
                "PFXImportCertStore".into(),
                "PFXIsPFXBlob".into(),
                "CertFindExtension".into(),
                "CertGetNameStringA".into(),
                "CertGetNameStringW".into(),
                "CertGetIssuerCertificateFromStore".into(),
                "CertEnumCRLsInStore".into(),
                "CertFindCRLInStore".into(),
            ],
        );

        // winhttp.dll
        m.insert(
            "winhttp.dll".to_string(),
            vec![
                "WinHttpOpen".into(),
                "WinHttpConnect".into(),
                "WinHttpOpenRequest".into(),
                "WinHttpSendRequest".into(),
                "WinHttpReceiveResponse".into(),
                "WinHttpReadData".into(),
                "WinHttpWriteData".into(),
                "WinHttpCloseHandle".into(),
                "WinHttpSetOption".into(),
                "WinHttpQueryOption".into(),
                "WinHttpQueryHeaders".into(),
                "WinHttpAddRequestHeaders".into(),
                "WinHttpSetCredentials".into(),
                "WinHttpSetTimeouts".into(),
                "WinHttpGetProxyForUrl".into(),
                "WinHttpCrackUrl".into(),
                "WinHttpCreateUrl".into(),
                "WinHttpDetectAutoProxyConfigUrl".into(),
                "WinHttpGetIEProxyConfigForCurrentUser".into(),
                "WinHttpWebSocketCompleteUpgrade".into(),
                "WinHttpWebSocketSend".into(),
                "WinHttpWebSocketReceive".into(),
                "WinHttpWebSocketClose".into(),
                "WinHttpWebSocketQueryCloseStatus".into(),
                "WinHttpGetProxySettingsVersion".into(),
                "WinHttpSetProxySettingsPerUser".into(),
            ],
        );

        // wininet.dll
        m.insert(
            "wininet.dll".to_string(),
            vec![
                "InternetOpenA".into(),
                "InternetOpenW".into(),
                "InternetConnectA".into(),
                "InternetConnectW".into(),
                "HttpOpenRequestA".into(),
                "HttpOpenRequestW".into(),
                "HttpSendRequestA".into(),
                "HttpSendRequestW".into(),
                "InternetReadFile".into(),
                "InternetWriteFile".into(),
                "InternetCloseHandle".into(),
                "InternetSetOptionA".into(),
                "InternetSetOptionW".into(),
                "InternetQueryOptionA".into(),
                "InternetQueryOptionW".into(),
                "HttpQueryInfoA".into(),
                "HttpQueryInfoW".into(),
                "HttpAddRequestHeadersA".into(),
                "HttpAddRequestHeadersW".into(),
                "InternetSetCookieA".into(),
                "InternetSetCookieW".into(),
                "InternetGetCookieA".into(),
                "InternetGetCookieW".into(),
                "InternetSetStatusCallback".into(),
                "InternetErrorDlg".into(),
                "InternetCanonicalizeUrlA".into(),
                "InternetCanonicalizeUrlW".into(),
                "InternetCrackUrlA".into(),
                "InternetCrackUrlW".into(),
                "InternetCreateUrlA".into(),
                "InternetCreateUrlW".into(),
                "FindFirstUrlCacheEntryA".into(),
                "FindFirstUrlCacheEntryW".into(),
                "FindNextUrlCacheEntryA".into(),
                "FindNextUrlCacheEntryW".into(),
                "FindCloseUrlCache".into(),
                "DeleteUrlCacheEntryA".into(),
                "DeleteUrlCacheEntryW".into(),
                "FtpOpenFileA".into(),
                "FtpOpenFileW".into(),
                "FtpGetFileA".into(),
                "FtpGetFileW".into(),
                "FtpPutFileA".into(),
                "FtpPutFileW".into(),
                "FtpDeleteFileA".into(),
                "FtpDeleteFileW".into(),
                "FtpRenameFileA".into(),
                "FtpRenameFileW".into(),
                "FtpCreateDirectoryA".into(),
                "FtpCreateDirectoryW".into(),
                "FtpRemoveDirectoryA".into(),
                "FtpRemoveDirectoryW".into(),
                "FtpFindFirstFileA".into(),
                "FtpFindFirstFileW".into(),
                "InternetGetConnectedState".into(),
                "InternetAutodial".into(),
                "InternetAttemptConnect".into(),
            ],
        );

        // ws2_32.dll
        m.insert(
            "ws2_32.dll".to_string(),
            vec![
                "WSAStartup".into(),
                "WSACleanup".into(),
                "socket".into(),
                "closesocket".into(),
                "connect".into(),
                "bind".into(),
                "listen".into(),
                "accept".into(),
                "send".into(),
                "recv".into(),
                "sendto".into(),
                "recvfrom".into(),
                "select".into(),
                "ioctlsocket".into(),
                "getsockopt".into(),
                "setsockopt".into(),
                "getsockname".into(),
                "getpeername".into(),
                "gethostbyname".into(),
                "getaddrinfo".into(),
                "freeaddrinfo".into(),
                "getnameinfo".into(),
                "WSAGetLastError".into(),
                "WSASetLastError".into(),
                "WSARecv".into(),
                "WSASend".into(),
                "WSARecvFrom".into(),
                "WSASendTo".into(),
                "WSASocketA".into(),
                "WSASocketW".into(),
                "WSAIoctl".into(),
                "WSAEventSelect".into(),
                "WSAEnumNetworkEvents".into(),
                "WSACreateEvent".into(),
                "WSACloseEvent".into(),
                "WSAWaitForMultipleEvents".into(),
                "WSAResetEvent".into(),
                "WSAConnect".into(),
                "htons".into(),
                "ntohs".into(),
                "htonl".into(),
                "ntohl".into(),
                "inet_addr".into(),
                "inet_ntoa".into(),
                "inet_pton".into(),
                "inet_ntop".into(),
                "shutdown".into(),
                "WSAAddressToStringA".into(),
                "WSAAddressToStringW".into(),
                "WSAStringToAddressA".into(),
                "WSAStringToAddressW".into(),
            ],
        );

        // dinput8.dll
        m.insert("dinput8.dll".to_string(), vec!["DirectInput8Create".into()]);

        // xinput1_4.dll
        m.insert(
            "xinput1_4.dll".to_string(),
            vec![
                "XInputGetState".into(),
                "XInputSetState".into(),
                "XInputGetCapabilities".into(),
                "XInputGetDSoundAudioDeviceGuids".into(),
                "XInputEnable".into(),
                "XInputGetBatteryInformation".into(),
                "XInputGetKeystroke".into(),
                "XInputGetAudioDeviceIds".into(),
            ],
        );

        // version.dll
        m.insert(
            "version.dll".to_string(),
            vec![
                "GetFileVersionInfoA".into(),
                "GetFileVersionInfoW".into(),
                "GetFileVersionInfoSizeA".into(),
                "GetFileVersionInfoSizeW".into(),
                "VerQueryValueA".into(),
                "VerQueryValueW".into(),
            ],
        );

        // imm32.dll
        m.insert(
            "imm32.dll".to_string(),
            vec![
                "ImmGetContext".into(),
                "ImmReleaseContext".into(),
                "ImmGetCompositionStringA".into(),
                "ImmGetCompositionStringW".into(),
                "ImmSetCompositionStringA".into(),
                "ImmSetCompositionStringW".into(),
                "ImmGetCandidateListA".into(),
                "ImmGetCandidateListW".into(),
                "ImmGetCandidateListCountA".into(),
                "ImmGetCandidateListCountW".into(),
                "ImmNotifyIME".into(),
                "ImmAssociateContext".into(),
                "ImmAssociateContextEx".into(),
            ],
        );

        // msacm32.dll
        m.insert(
            "msacm32.dll".to_string(),
            vec![
                "acmDriverEnum".into(),
                "acmDriverDetailsA".into(),
                "acmDriverDetailsW".into(),
                "acmFormatTagDetailsA".into(),
                "acmFormatTagDetailsW".into(),
                "acmFormatEnumA".into(),
                "acmFormatEnumW".into(),
                "acmStreamOpen".into(),
                "acmStreamClose".into(),
                "acmStreamConvert".into(),
                "acmStreamSize".into(),
                "acmStreamPrepareHeader".into(),
                "acmStreamUnprepareHeader".into(),
            ],
        );

        // winmm.dll
        m.insert(
            "winmm.dll".to_string(),
            vec![
                "timeBeginPeriod".into(),
                "timeEndPeriod".into(),
                "timeGetTime".into(),
                "timeGetDevCaps".into(),
                "waveOutOpen".into(),
                "waveOutClose".into(),
                "waveOutWrite".into(),
                "waveOutPrepareHeader".into(),
                "waveOutUnprepareHeader".into(),
                "waveOutGetDevCapsA".into(),
                "waveOutGetDevCapsW".into(),
                "waveOutGetNumDevs".into(),
                "waveOutGetVolume".into(),
                "waveOutSetVolume".into(),
                "waveOutPause".into(),
                "waveOutRestart".into(),
                "waveOutReset".into(),
                "waveOutGetPosition".into(),
                "midiOutOpen".into(),
                "midiOutClose".into(),
                "midiOutShortMsg".into(),
                "midiOutLongMsg".into(),
                "midiOutGetDevCapsA".into(),
                "midiOutGetDevCapsW".into(),
                "midiOutGetNumDevs".into(),
                "midiOutReset".into(),
                "PlaySoundA".into(),
                "PlaySoundW".into(),
                "auxGetNumDevs".into(),
                "mixerOpen".into(),
                "mixerClose".into(),
                "mixerGetControlDetailsA".into(),
                "mixerGetControlDetailsW".into(),
                "mixerGetDevCapsA".into(),
                "mixerGetDevCapsW".into(),
                "mixerGetID".into(),
                "mixerGetLineControlsA".into(),
                "mixerGetLineControlsW".into(),
                "mixerGetLineInfoA".into(),
                "mixerGetLineInfoW".into(),
                "mixerGetNumDevs".into(),
                "mixerMessage".into(),
                "mixerSetControlDetails".into(),
            ],
        );

        m
    }

    /// Coverage status for a single import function.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ImportCoverageEntry {
        /// The DLL name (lowercase).
        pub dll: String,
        /// The function name.
        pub function: String,
        /// Whether the function has a real (non-stub) implementation.
        pub covered: bool,
        /// A note about the implementation status (e.g. "stub", "real", "partial").
        pub status: String,
    }

    /// Per-DLL coverage summary.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct DllCoverageReport {
        /// DLL name.
        pub dll: String,
        /// Total number of imports required from this DLL.
        pub total: usize,
        /// Number of imports that have real implementations.
        pub covered: usize,
        /// Number of imports that are stubs or missing.
        pub missing: usize,
        /// Coverage percentage (0.0–100.0).
        pub coverage_percent: f64,
        /// List of covered function names.
        pub covered_functions: Vec<String>,
        /// List of missing function names.
        pub missing_functions: Vec<String>,
    }

    /// Overall import coverage report.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ImportCoverageReport {
        /// Total number of imports across all DLLs.
        pub total_imports: usize,
        /// Total number of covered imports.
        pub covered_imports: usize,
        /// Total number of missing imports.
        pub missing_imports: usize,
        /// Overall coverage percentage (0.0–100.0).
        pub overall_coverage_percent: f64,
        /// Per-DLL coverage breakdown.
        pub dll_reports: Vec<DllCoverageReport>,
        /// Individual import entries.
        pub entries: Vec<ImportCoverageEntry>,
    }

    /// Generate an import coverage report by cross-referencing the regression
    /// snapshot of known Steam.exe imports with the PE runtime's registered
    /// export tables.
    ///
    /// "Covered" is derived from the authoritative runtime export registry
    /// ([`crate::pe_runtime::export_tables`]), so the report reflects the actual
    /// state of the implemented API surface instead of a hand-maintained copy.
    ///
    /// Regression-snapshot only: the canonical binary-derived coverage is
    /// [`super::coverage_for_pe`].
    pub fn generate_import_coverage_report() -> ImportCoverageReport {
        let steam_imports = steam_exe_imports_regression_snapshot();

        // Pre-index the runtime's registered export names (lowercased) per DLL
        // so each import lookup is O(1) instead of a linear scan.
        let covered_by_dll: std::collections::HashMap<String, std::collections::HashSet<String>> =
            crate::pe_runtime::export_tables()
                .into_iter()
                .map(|(dll, exports)| {
                    let names = exports
                        .into_iter()
                        .filter_map(|e| e.name)
                        .map(|n| n.to_lowercase())
                        .collect();
                    (dll.to_lowercase(), names)
                })
                .collect();

        let mut entries = Vec::new();
        let mut dll_reports = Vec::new();
        let mut total_imports = 0usize;
        let mut total_covered = 0usize;
        let mut total_missing = 0usize;

        for (dll, functions) in &steam_imports {
            let dll_covered = covered_by_dll.get(&dll.to_lowercase());

            let mut dll_total = 0usize;
            let mut dll_covered_count = 0usize;
            let mut dll_missing_count = 0usize;
            let mut dll_covered_functions = Vec::new();
            let mut dll_missing_functions = Vec::new();

            for func in functions {
                dll_total += 1;
                let func_lower = func.to_lowercase();
                let is_covered = dll_covered.is_some_and(|names| names.contains(&func_lower));

                let status = if is_covered {
                    "real".to_string()
                } else {
                    "missing".to_string()
                };

                entries.push(ImportCoverageEntry {
                    dll: dll.clone(),
                    function: func.clone(),
                    covered: is_covered,
                    status,
                });

                if is_covered {
                    dll_covered_count += 1;
                    dll_covered_functions.push(func.clone());
                } else {
                    dll_missing_count += 1;
                    dll_missing_functions.push(func.clone());
                }
            }

            let coverage_percent = if dll_total > 0 {
                (dll_covered_count as f64 / dll_total as f64) * 100.0
            } else {
                0.0
            };

            total_imports += dll_total;
            total_covered += dll_covered_count;
            total_missing += dll_missing_count;

            dll_reports.push(DllCoverageReport {
                dll: dll.clone(),
                total: dll_total,
                covered: dll_covered_count,
                missing: dll_missing_count,
                coverage_percent,
                covered_functions: dll_covered_functions,
                missing_functions: dll_missing_functions,
            });
        }

        let overall_coverage_percent = if total_imports > 0 {
            (total_covered as f64 / total_imports as f64) * 100.0
        } else {
            0.0
        };

        ImportCoverageReport {
            total_imports,
            covered_imports: total_covered,
            missing_imports: total_missing,
            overall_coverage_percent,
            dll_reports,
            entries,
        }
    }

    /// Generate the import coverage report as a `serde_json::Value`
    /// (regression-snapshot format).
    pub fn generate_import_coverage_json() -> Value {
        let report = generate_import_coverage_report();

        let mut dll_map = serde_json::Map::new();
        for dll_report in &report.dll_reports {
            let mut dll_obj = serde_json::Map::new();
            dll_obj.insert("total".into(), Value::Number(dll_report.total.into()));
            dll_obj.insert("covered".into(), Value::Number(dll_report.covered.into()));
            dll_obj.insert("missing".into(), Value::Number(dll_report.missing.into()));
            dll_obj.insert(
                "coverage_percent".into(),
                Value::from(
                    serde_json::Number::from_f64(dll_report.coverage_percent)
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                ),
            );
            dll_obj.insert(
                "covered_functions".into(),
                Value::Array(
                    dll_report
                        .covered_functions
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect(),
                ),
            );
            dll_obj.insert(
                "missing_functions".into(),
                Value::Array(
                    dll_report
                        .missing_functions
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect(),
                ),
            );
            dll_map.insert(dll_report.dll.clone(), Value::Object(dll_obj));
        }

        let mut root = serde_json::Map::new();
        root.insert(
            "total_imports".into(),
            Value::Number(report.total_imports.into()),
        );
        root.insert(
            "covered_imports".into(),
            Value::Number(report.covered_imports.into()),
        );
        root.insert(
            "missing_imports".into(),
            Value::Number(report.missing_imports.into()),
        );
        root.insert(
            "overall_coverage_percent".into(),
            Value::from(
                serde_json::Number::from_f64(report.overall_coverage_percent)
                    .unwrap_or_else(|| serde_json::Number::from(0)),
            ),
        );
        root.insert("dlls".into(), Value::Object(dll_map));
        root.insert(
            "entries".into(),
            serde_json::to_value(&report.entries).unwrap_or(Value::Array(vec![])),
        );

        Value::Object(root)
    }

    /// Generate a human-readable coverage report as a string
    /// (regression-snapshot format).
    pub fn generate_import_coverage_text() -> String {
        let report = generate_import_coverage_report();
        let mut lines = Vec::new();

        lines.push("═══════════════════════════════════════════════════════════════".to_string());
        lines.push("              Steam.exe Import Coverage Report                ".to_string());
        lines.push("═══════════════════════════════════════════════════════════════".to_string());
        lines.push(format!(
            "Overall: {}/{} imports covered ({:.1}%)",
            report.covered_imports, report.total_imports, report.overall_coverage_percent
        ));
        lines.push(String::new());
        lines.push(format!(
            "{:<20} {:>8} {:>8} {:>8} {:>10}",
            "DLL", "Total", "Covered", "Missing", "Coverage%"
        ));
        lines.push("─".repeat(60));

        for dll_report in &report.dll_reports {
            lines.push(format!(
                "{:<20} {:>8} {:>8} {:>8} {:>9.1}%",
                dll_report.dll,
                dll_report.total,
                dll_report.covered,
                dll_report.missing,
                dll_report.coverage_percent
            ));
        }

        lines.push("─".repeat(60));
        lines.push(format!(
            "{:<20} {:>8} {:>8} {:>8} {:>9.1}%",
            "TOTAL",
            report.total_imports,
            report.covered_imports,
            report.missing_imports,
            report.overall_coverage_percent
        ));

        // Show missing functions for DLLs with < 100% coverage
        for dll_report in &report.dll_reports {
            if !dll_report.missing_functions.is_empty() {
                lines.push(String::new());
                lines.push(format!(
                    "Missing from {} ({} functions):",
                    dll_report.dll,
                    dll_report.missing_functions.len()
                ));
                for func in &dll_report.missing_functions {
                    lines.push(format!("  - {}", func));
                }
            }
        }

        lines.join("\n")
    }

    /// Per-DLL lookup index over an export table, built once per DLL so that
    /// per-thunk coverage checks are O(log n)/O(1) instead of linear scans.
    struct ExportIndex {
        names: std::collections::HashSet<String>,
        ordinals: std::collections::HashSet<u32>,
    }

    impl ExportIndex {
        fn new(exports: &[ExportSymbol]) -> Self {
            let mut names = std::collections::HashSet::new();
            let mut ordinals = std::collections::HashSet::new();
            for export in exports {
                ordinals.insert(export.ordinal);
                if let Some(name) = &export.name {
                    names.insert(name.clone());
                }
            }
            Self { names, ordinals }
        }

        fn contains(&self, symbol: &ImportSymbol) -> bool {
            match symbol {
                ImportSymbol::ByName { name, .. } => self.names.contains(name),
                ImportSymbol::ByOrdinal { ordinal } => self.ordinals.contains(&(*ordinal as u32)),
            }
        }
    }

    /// Generate a coverage report from a parsed PE file's imports
    /// (regression-snapshot format).
    pub fn generate_pe_coverage_report(
        pe: &ParsedPe,
        export_tables: &BTreeMap<String, Vec<ExportSymbol>>,
    ) -> ImportCoverageReport {
        let mut entries = Vec::new();
        let mut dll_reports_map: BTreeMap<String, DllCoverageReportBuilder> = BTreeMap::new();

        // Collect all imports from the PE
        for import_desc in &pe.imports {
            let dll_lower = import_desc.dll_name.to_lowercase();
            let export_index = export_tables
                .get(&dll_lower)
                .map(|exports| ExportIndex::new(exports));
            let builder = dll_reports_map
                .entry(dll_lower.clone())
                .or_insert_with(|| DllCoverageReportBuilder::new(dll_lower.clone()));

            for thunk in &import_desc.imports {
                let func_name = match &thunk.symbol {
                    ImportSymbol::ByName { name, .. } => name.clone(),
                    ImportSymbol::ByOrdinal { ordinal } => format!("#{}", ordinal),
                };

                let is_covered = export_index
                    .as_ref()
                    .is_some_and(|index| index.contains(&thunk.symbol));

                let status = if is_covered {
                    "real".to_string()
                } else {
                    "missing".to_string()
                };

                entries.push(ImportCoverageEntry {
                    dll: dll_lower.clone(),
                    function: func_name.clone(),
                    covered: is_covered,
                    status,
                });

                builder.add(func_name, is_covered);
            }
        }

        // Also check delay imports
        for import_desc in &pe.delay_imports {
            let dll_lower = import_desc.dll_name.to_lowercase();
            let export_index = export_tables
                .get(&dll_lower)
                .map(|exports| ExportIndex::new(exports));
            let builder = dll_reports_map
                .entry(dll_lower.clone())
                .or_insert_with(|| DllCoverageReportBuilder::new(dll_lower.clone()));

            for thunk in &import_desc.imports {
                let func_name = match &thunk.symbol {
                    ImportSymbol::ByName { name, .. } => name.clone(),
                    ImportSymbol::ByOrdinal { ordinal } => format!("#{}", ordinal),
                };

                let is_covered = export_index
                    .as_ref()
                    .is_some_and(|index| index.contains(&thunk.symbol));

                builder.add(func_name, is_covered);
            }
        }

        // Build final report
        let mut dll_reports: Vec<DllCoverageReport> =
            dll_reports_map.into_values().map(|b| b.build()).collect();
        dll_reports.sort_by(|a, b| a.dll.cmp(&b.dll));

        let total_imports: usize = dll_reports.iter().map(|d| d.total).sum();
        let covered_imports: usize = dll_reports.iter().map(|d| d.covered).sum();
        let missing_imports: usize = dll_reports.iter().map(|d| d.missing).sum();
        let overall_coverage_percent = if total_imports > 0 {
            (covered_imports as f64 / total_imports as f64) * 100.0
        } else {
            0.0
        };

        ImportCoverageReport {
            total_imports,
            covered_imports,
            missing_imports,
            overall_coverage_percent,
            dll_reports,
            entries,
        }
    }

    // Helper builder for DllCoverageReport
    pub struct DllCoverageReportBuilder {
        dll: String,
        covered_functions: Vec<String>,
        missing_functions: Vec<String>,
    }

    impl DllCoverageReportBuilder {
        pub fn new(dll: String) -> Self {
            Self {
                dll,
                covered_functions: Vec::new(),
                missing_functions: Vec::new(),
            }
        }

        pub fn add(&mut self, function: String, covered: bool) {
            if covered {
                self.covered_functions.push(function);
            } else {
                self.missing_functions.push(function);
            }
        }

        pub fn build(self) -> DllCoverageReport {
            let total = self.covered_functions.len() + self.missing_functions.len();
            let covered = self.covered_functions.len();
            let missing = self.missing_functions.len();
            let coverage_percent = if total > 0 {
                (covered as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            DllCoverageReport {
                dll: self.dll,
                total,
                covered,
                missing,
                coverage_percent,
                covered_functions: self.covered_functions,
                missing_functions: self.missing_functions,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::legacy::{
        DllCoverageReportBuilder, generate_import_coverage_json, generate_import_coverage_text,
        generate_pe_coverage_report, steam_exe_imports_regression_snapshot,
    };
    use super::*;
    use serde_json::json;

    fn default_target() -> CompatibilityProfile {
        CompatibilityProfile::win11_native_desktop()
    }

    #[test]
    fn test_coverage_report_is_not_empty() {
        let report = legacy::generate_import_coverage_report();
        assert!(report.total_imports > 0, "report should have imports");
        assert!(
            report.covered_imports > 0,
            "report should have covered imports"
        );
        assert!(
            !report.dll_reports.is_empty(),
            "report should have per-DLL breakdowns"
        );
    }

    #[test]
    fn test_coverage_json_is_valid() {
        let json = generate_import_coverage_json();
        assert!(json.is_object(), "JSON should be an object");
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("total_imports"));
        assert!(obj.contains_key("covered_imports"));
        assert!(obj.contains_key("missing_imports"));
        assert!(obj.contains_key("overall_coverage_percent"));
        assert!(obj.contains_key("dlls"));
        assert!(obj.contains_key("entries"));
    }

    #[test]
    fn test_coverage_text_is_readable() {
        let text = generate_import_coverage_text();
        assert!(text.contains("Steam.exe Import Coverage Report"));
        assert!(text.contains("Overall:"));
        assert!(text.contains("DLL"));
    }

    #[test]
    fn test_steam_exe_imports_contains_known_dlls() {
        let imports = steam_exe_imports_regression_snapshot();
        assert!(imports.contains_key("kernel32.dll"));
        assert!(imports.contains_key("user32.dll"));
        assert!(imports.contains_key("gdi32.dll"));
        assert!(imports.contains_key("advapi32.dll"));
        assert!(imports.contains_key("shell32.dll"));
        assert!(imports.contains_key("ole32.dll"));
        assert!(imports.contains_key("crypt32.dll"));
    }

    #[test]
    fn test_steam_exe_imports_are_unique_and_attributed() {
        let imports = steam_exe_imports_regression_snapshot();
        for (dll, functions) in &imports {
            let mut seen = std::collections::HashSet::new();
            for func in functions {
                assert!(seen.insert(func), "duplicate import {func} in {dll}");
            }
        }

        let kernel32 = imports.get("kernel32.dll").unwrap();
        assert_eq!(
            kernel32
                .iter()
                .filter(|f| *f == "WaitForSingleObject")
                .count(),
            1,
            "WaitForSingleObject must not be duplicated"
        );
        assert_eq!(
            kernel32.iter().filter(|f| *f == "GetTickCount64").count(),
            1,
            "GetTickCount64 must not be duplicated"
        );
        assert!(
            !kernel32.contains(&"GetUserNameA".to_string())
                && !kernel32.contains(&"GetUserNameW".to_string()),
            "GetUserNameA/W are advapi32 exports, not kernel32"
        );

        let shell32 = imports.get("shell32.dll").unwrap();
        assert!(
            !shell32.contains(&"DoDragDrop".to_string()),
            "DoDragDrop is an ole32 export, not shell32"
        );

        let advapi32 = imports.get("advapi32.dll").unwrap();
        assert!(
            advapi32.contains(&"GetUserNameA".to_string())
                && advapi32.contains(&"GetUserNameW".to_string()),
            "GetUserNameA/W must be listed under advapi32"
        );

        let ole32 = imports.get("ole32.dll").unwrap();
        assert!(
            ole32.contains(&"DoDragDrop".to_string()),
            "DoDragDrop must be listed under ole32"
        );
    }

    #[test]
    fn test_kernel32_has_core_functions() {
        let imports = steam_exe_imports_regression_snapshot();
        let kernel32 = imports.get("kernel32.dll").unwrap();
        assert!(kernel32.contains(&"GetProcAddress".to_string()));
        assert!(kernel32.contains(&"LoadLibraryA".to_string()));
        assert!(kernel32.contains(&"CreateFileW".to_string()));
        assert!(kernel32.contains(&"GetLastError".to_string()));
    }

    #[test]
    fn test_pe_coverage_report_with_empty_pe() {
        let pe = crate::pe::ParsedPe {
            machine: 0,
            number_of_sections: 0,
            characteristics: 0,
            optional_header_magic: 0,
            subsystem: 0,
            dll_characteristics: 0,
            address_of_entry_point: 0,
            image_base: 0,
            size_of_image: 0,
            size_of_headers: 0,
            section_alignment: 0,
            file_alignment: 0,
            data_directories: vec![],
            sections: vec![],
            debug_entries: vec![],
            load_config: None,
            imports: vec![],
            delay_imports: vec![],
            exports: vec![],
            relocations: vec![],
            tls_directory: None,
            version_info: crate::pe::VersionInfo::default(),
            embedded_manifest: None,
            external_manifest: None,
            is_dotnet: false,
            clr_header: None,
            bound_imports: vec![],
        };
        let export_tables = BTreeMap::new();
        let report = generate_pe_coverage_report(&pe, &export_tables);
        assert_eq!(report.total_imports, 0);
        assert_eq!(report.covered_imports, 0);
        assert_eq!(report.missing_imports, 0);
    }

    #[test]
    fn test_dll_coverage_report_builder() {
        let mut builder = DllCoverageReportBuilder::new("test.dll".to_string());
        builder.add("Func1".to_string(), true);
        builder.add("Func2".to_string(), false);
        builder.add("Func3".to_string(), true);
        let report = builder.build();
        assert_eq!(report.dll, "test.dll");
        assert_eq!(report.total, 3);
        assert_eq!(report.covered, 2);
        assert_eq!(report.missing, 1);
        assert!((report.coverage_percent - 66.66666666666667).abs() < 0.01);
    }

    // -----------------------------------------------------------------
    // Canonical binary-derived coverage tests
    // -----------------------------------------------------------------

    /// Path to the tracked Steam.exe fixture (committed to the repo).
    fn tracked_steam_fixture() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("ges")
            .join("steam")
            .join("drive_c")
            .join("Steam")
            .join("Steam.exe")
    }

    #[test]
    fn test_tracked_steam_fixture_parses() {
        let path = tracked_steam_fixture();
        assert!(
            path.is_file(),
            "tracked Steam fixture missing at {}",
            path.display()
        );
        let pe = crate::pe::parse_from_file(&path).expect("parse Steam.exe");
        assert!(pe.machine != 0, "PE machine field must be set");
        assert!(
            !pe.imports.is_empty(),
            "Steam.exe must import from at least one DLL"
        );
    }

    #[test]
    fn test_coverage_for_pe_covers_all_imports() {
        let workload = WorkloadId::new("steam-fixture");
        let report = coverage_for_pe(&tracked_steam_fixture(), &workload, default_target())
            .expect("coverage report");
        assert!(
            report.total_imports > 300,
            "unexpectedly small import surface"
        );
        assert!(!report.image_sha256.is_empty());
        assert_eq!(report.image_arch, GuestArch::X86);
        assert!(
            report.by_implementation.values().sum::<usize>() == report.total_imports,
            "by_implementation must account for every import"
        );
        assert!(
            report
                .entries
                .iter()
                .all(|e| !e.import.lookup_name().is_empty()),
            "every entry must carry an import identity"
        );
        assert!(
            report.entries.iter().all(|e| !e.runtime_reached),
            "runtime_reached must be false without a runtime trace"
        );
        assert!(
            report
                .entries
                .iter()
                .all(|e| e.source != ImportSource::DynamicLookup),
            "no dynamic lookups without a runtime trace"
        );
    }

    #[test]
    fn test_coverage_for_pe_json_roundtrip() {
        let workload = WorkloadId::new("steam-fixture");
        let json = coverage_for_pe_json(&tracked_steam_fixture(), &workload, default_target())
            .expect("json report");
        let obj = json.as_object().expect("object");
        for key in [
            "binary_path",
            "image_sha256",
            "image_version",
            "image_arch",
            "total_imports",
            "by_implementation",
            "entries",
            "required_not_working",
            "runtime_trace_included",
        ] {
            assert!(obj.contains_key(key), "missing report field {key}");
        }
        let entries = obj["entries"].as_array().expect("entries array");
        let first = entries.first().expect("at least one entry");
        for key in [
            "image_sha256",
            "image_version",
            "image_arch",
            "dll",
            "import",
            "source",
            "implementation",
            "semantic_coverage",
            "runtime_reached",
        ] {
            assert!(
                first.as_object().unwrap().contains_key(key),
                "missing entry field {key}"
            );
        }
    }

    #[test]
    fn test_coverage_for_pe_with_runtime_trace_marks_entries() {
        let _guard = DYNAMIC_LOG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let workload = WorkloadId::new("steam-fixture");
        let invoked = vec!["CreateFileW".to_string(), "GetProcAddress".to_string()];
        let report = coverage_for_pe_with_runtime_trace(
            &tracked_steam_fixture(),
            &workload,
            default_target(),
            &invoked,
        )
        .expect("coverage report");
        assert!(report.runtime_trace_included);
        // The invoked set marks static/delay-load imports; dynamic lookups
        // recorded by other dispatch activity are reached by construction
        // and attributed separately.
        let marked: Vec<_> = report
            .entries
            .iter()
            .filter(|entry| entry.runtime_reached && entry.source != ImportSource::DynamicLookup)
            .map(|entry| entry.import.lookup_name())
            .collect();
        assert_eq!(marked, vec!["CreateFileW", "GetProcAddress"]);
        // No violation may be reported for these two implemented APIs.
        assert!(
            report.runtime_reached_required_violations().is_empty(),
            "implemented APIs must not violate the release gate"
        );
    }

    #[test]
    fn test_invoked_api_names_from_trace_dedups() {
        let events = vec![
            crate::trace::TraceEvent {
                event_index: 1,
                category: "process".to_string(),
                call_id: "GetModuleHandleW".to_string(),
                parameters: BTreeMap::new(),
                return_value: json!(0),
                get_last_error: None,
                side_effect_hashes: vec![],
            },
            crate::trace::TraceEvent {
                event_index: 2,
                category: "process".to_string(),
                call_id: "GetModuleHandleW".to_string(),
                parameters: BTreeMap::new(),
                return_value: json!(0),
                get_last_error: None,
                side_effect_hashes: vec![],
            },
            crate::trace::TraceEvent {
                event_index: 3,
                category: "file".to_string(),
                call_id: "CreateFileW".to_string(),
                parameters: BTreeMap::new(),
                return_value: json!(1),
                get_last_error: None,
                side_effect_hashes: vec![],
            },
        ];
        let names = invoked_api_names_from_trace(&events);
        assert_eq!(
            names,
            vec!["CreateFileW".to_string(), "GetModuleHandleW".to_string()]
        );
    }

    #[test]
    fn test_coverage_for_pe_text_is_structured() {
        let workload = WorkloadId::new("steam-fixture");
        let text = coverage_for_pe_text(&tracked_steam_fixture(), &workload, default_target())
            .expect("text report");
        assert!(text.contains("Binary Import Coverage (fixture-derived)"));
        assert!(text.contains("sha256:"));
        assert!(text.contains("Implemented"));
        assert!(text.contains("Unsupported"));
    }

    #[test]
    fn test_required_not_working_invariant_and_release_gate() {
        let workload = WorkloadId::new("steam-fixture");
        let report = coverage_for_pe(&tracked_steam_fixture(), &workload, default_target())
            .expect("coverage report");
        // Every entry in required_not_working must be Required-policy with a
        // non-working implementation.
        assert!(report.required_not_working.iter().all(|entry| {
            entry
                .support_policy()
                .is_some_and(|policy| policy == SupportPolicy::Required)
                && !entry.implementation.has_working_implementation()
        }));
        // The static surface may legitimately import Required-policy stubs
        // (canned-answer APIs like DeregisterEventSource); the release gate
        // is encoded ONLY over the runtime-reached set, which is empty here —
        // trivially satisfied but reported.
        assert!(
            report.runtime_reached_required_violations().is_empty(),
            "runtime-reached required violations must be empty"
        );
        // Sanity: Required-policy entries ARE present and marked.
        let create_file = report
            .entries
            .iter()
            .find(|entry| entry.import.lookup_name() == "CreateFileW")
            .expect("CreateFileW import");
        assert_eq!(create_file.support_policy(), Some(SupportPolicy::Required));
        assert_eq!(create_file.implementation, ImplementationLevel::Implemented);
    }

    /// Serializes access to the shared dynamic-import log across the tests
    /// that consume it (the log is process-global; the runtime records into
    /// it while real dispatch tests run).
    static DYNAMIC_LOG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_dynamic_lookups_recorded_from_shared_log() {
        let _guard = DYNAMIC_LOG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The shared log is process-wide: clear it so this test is
        // deterministic regardless of what ran before.
        crate::pe_runtime::clear_dynamic_import_log_static();
        // Seed the shared dynamic-import log as the runtime would (e.g. via
        // GetProcAddress) and verify the report consumes it as DynamicLookup
        // entries keyed by (DLL, name).
        crate::pe_runtime::record_dynamic_import("kernel32.dll", "GetProcAddress");
        crate::pe_runtime::record_dynamic_import("user32.dll", "MessageBoxW");
        crate::pe_runtime::record_dynamic_import("kernel32.dll", "GetProcAddress");
        let workload = WorkloadId::new("dynamic-test");
        let report = coverage_for_pe_with_runtime_trace(
            &tracked_steam_fixture(),
            &workload,
            default_target(),
            &[],
        )
        .expect("coverage report");
        let dynamic: Vec<_> = report
            .entries
            .iter()
            .filter(|entry| entry.source == ImportSource::DynamicLookup)
            .map(|entry| (entry.dll.clone(), entry.import.lookup_name()))
            .collect();
        assert_eq!(
            dynamic,
            vec![
                ("kernel32.dll".to_string(), "GetProcAddress".to_string()),
                ("user32.dll".to_string(), "MessageBoxW".to_string()),
            ],
            "dynamic lookups are recorded by (DLL, name), deduplicated"
        );
        // Dynamic lookups are reached by construction.
        assert!(
            report
                .entries
                .iter()
                .filter(|entry| entry.source == ImportSource::DynamicLookup)
                .all(|entry| entry.runtime_reached)
        );
    }

    #[test]
    fn test_coverage_for_process_tree_walks_children() {
        let _guard = DYNAMIC_LOG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::pe_runtime::clear_dynamic_import_log_static();
        let workload = WorkloadId::new("process-tree");
        let root = tracked_steam_fixture();
        let report = coverage_for_process_tree(&[&root, &root], &workload, default_target(), &[])
            .expect("process-tree report");
        assert_eq!(report.binaries.len(), 2);
        assert!(report.total_imports > 0);
        // Dynamic lookups are runtime observations recorded into a shared
        // log: concurrent dispatch tests may legitimately record entries, so
        // the process-tree scan asserts the structural invariant (every
        // dynamic entry is keyed by DLL+name and is reachable) rather than a
        // zero count that only holds in a fully isolated process.
        let all_entries = report
            .binaries
            .iter()
            .flat_map(|binary| binary.entries.iter())
            .collect::<Vec<_>>();
        {
            let dynamic = all_entries
                .iter()
                .filter(|entry| entry.source == ImportSource::DynamicLookup)
                .collect::<Vec<_>>();
            assert!(
                dynamic
                    .iter()
                    .all(|entry| !entry.dll.is_empty() && entry.runtime_reached),
                "every dynamic lookup is keyed by DLL and marked reached"
            );
        }
        assert!(report.by_implementation.values().sum::<usize>() == report.total_imports);
    }
}
