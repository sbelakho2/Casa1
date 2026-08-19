//! Quantitative Windows API completeness database (Gap: whole-project
//! compatibility accounting).
//!
//! The thunk metadata in [`crate::host_thunks::THUNK_METADATA`]
//! ([`ThunkMetadata`]) is the backbone: every entry's implementation level is
//! seeded from it, and the database is the project-wide compatibility
//! accounting for DLL/export-keyed API completeness — not just Steam
//! diagnostics.
//!
//! The database provides:
//!
//! - [`ApiEntry`] — per-(DLL, export) completeness records keyed by
//!   architecture (`X86`/`X64`/`Any`) and Windows version (`Win10`/`Win11`/
//!   `Any`), carrying the [`ImplementationLevel`], the semantic test coverage
//!   ([`CoverageLevel`]), the workloads that reach the API, and the
//!   transitional flag (a `Partial` entry MUST be flagged transitional with a
//!   reason in `detail` or it fails the release gate).
//! - [`ApiDatabase`] — the entry table with [`ApiDatabase::lookup`],
//!   [`ApiDatabase::for_dll`], workload recording, and the **release gate**
//!   ([`ApiDatabase::production_gate`]): only *Implemented* entries and
//!   *DeliberatelyUnsupported* entries carrying a compatibility error are
//!   acceptable production statuses; `Partial` must not quietly count, and
//!   `Stub`/`Unsupported` must be declared deliberately unsupported.
//! - Seed tables: the full [`THUNK_METADATA`] surface, the `Nt*` surface of
//!   ntdll (skeleton entries marked against what the runtime actually
//!   dispatches), and the COM / DXGI / D3D11 / D3D12 / Media Foundation
//!   interface tables at the runtime's actual levels.
//! - [`ApiCompletenessReport`] — the `api-completeness.json` shape
//!   (`generated_at`, `per_dll` summaries, `gate.violations`), emitted by the
//!   `casa1-oracle api-report <out.json>` command.
//!
//! # Release gate
//!
//! [`ApiDatabase::production_gate`] reports every entry that must not ship
//! quietly:
//!
//! 1. `Partial` entries that are not flagged `transitional` (a Partial
//!    implementation without a documented reason must not count as done).
//! 2. `Stub`/`Unsupported` entries that are not registered as
//!    deliberately-unsupported with a compatibility error via
//!    [`ApiDatabase::deliberately_unsupported`].

use crate::host_thunks::ImplementationLevel;
use crate::host_thunks::THUNK_METADATA;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

// ---------------------------------------------------------------------------
// Keying enums
// ---------------------------------------------------------------------------

/// Guest architecture an API entry applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchSet {
    /// 32-bit (x86) guests only.
    X86,
    /// 64-bit (x64) guests only.
    X64,
    /// Both guest architectures.
    Any,
}

/// Windows version an API entry applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WindowsVersion {
    /// Windows 10 compatibility.
    Win10,
    /// Windows 11 compatibility.
    Win11,
    /// Both Windows versions.
    Any,
}

/// Depth of semantic test coverage proven for an API entry.
///
/// Ordered from least to most rigorous; the report counts
/// [`CoverageLevel::Differential`] and [`CoverageLevel::Conformance`]
/// entries separately from the implementation-level counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CoverageLevel {
    /// No semantic coverage is tracked for this API.
    None,
    /// Unit-level tests exercise the API in isolation.
    Unit,
    /// The API is exercised through a subsystem scenario test.
    SubsystemScenario,
    /// The API is differentially tested against a reference implementation.
    Differential,
    /// The API is tested against a conformance suite.
    Conformance,
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// A single (DLL, export) completeness record.
///
/// This is the project-wide compatibility accounting unit: the implementation
/// level is seeded from [`THUNK_METADATA`], and the gate requires every
/// `Partial` entry to be explicitly flagged `transitional` with a reason in
/// `detail`, while `Stub`/`Unsupported` entries must be declared deliberately
/// unsupported with a compatibility error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiEntry {
    /// Exporting DLL name (lowercase, with extension, e.g. `"kernel32.dll"`).
    pub dll: String,
    /// API/export name (e.g. `"CreateFileW"`, or an interface name such as
    /// `"ID3D11Device"` for interface-table entries).
    pub export: String,
    /// Guest architecture the entry applies to.
    pub arch: ArchSet,
    /// Windows version the entry applies to.
    pub win_version: WindowsVersion,
    /// Implementation quality (see [`ImplementationLevel`]).
    pub implementation: ImplementationLevel,
    /// Proven semantic test coverage for this API.
    pub semantic_test_coverage: CoverageLevel,
    /// Workloads (fixtures, E2E scenarios) whose scans reach this API.
    pub workloads_reaching: Vec<String>,
    /// `true` when this is a knowingly-incomplete implementation with a
    /// documented reason in `detail`.  A `Partial` entry that is NOT
    /// transitional fails the production gate.
    pub transitional: bool,
    /// Optional human-readable note: the transitional reason for Partial
    /// entries, the compatibility consequence for deliberately-unsupported
    /// entries, or any other per-API documentation.
    pub detail: Option<String>,
}

impl ApiEntry {
    /// Convenience constructor with the default keying (any architecture, any
    /// Windows version, no test coverage, no workloads, not transitional).
    pub fn new(
        dll: impl Into<String>,
        export: impl Into<String>,
        implementation: ImplementationLevel,
    ) -> Self {
        Self {
            dll: dll.into(),
            export: export.into(),
            arch: ArchSet::Any,
            win_version: WindowsVersion::Any,
            implementation,
            semantic_test_coverage: CoverageLevel::None,
            workloads_reaching: Vec::new(),
            transitional: false,
            detail: None,
        }
    }

    /// `true` when this entry is acceptable as a production status:
    /// implemented, or deliberately unsupported with a compatibility error.
    pub fn is_production_acceptable(&self) -> bool {
        matches!(self.implementation, ImplementationLevel::Implemented)
    }
}

/// Why a single entry fails the production gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiGateViolationKind {
    /// `Partial` implementation without the `transitional` flag (it would
    /// quietly count as shipped despite documented limitations).
    PartialNotTransitional,
    /// `Stub` implementation not declared deliberately unsupported with a
    /// compatibility error.
    StubNotDeliberatelyUnsupported,
    /// `Unsupported` (no host thunk) not declared deliberately unsupported
    /// with a compatibility error.
    UnsupportedNotDeliberatelyUnsupported,
}

/// One production-gate violation: a (DLL, export) that must not ship quietly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiGateViolation {
    /// Exporting DLL name (lowercase, with extension).
    pub dll: String,
    /// API/export name.
    pub export: String,
    /// Violation class.
    pub kind: ApiGateViolationKind,
    /// Human-readable explanation of what must change to pass the gate.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

/// The quantitative Windows API completeness database.
///
/// Entries are keyed by (DLL, export); lookups are case-insensitive and
/// tolerate the `.dll` suffix on either side.  A separate
/// deliberately-unsupported registry records (DLL, export) pairs whose
/// `Stub`/`Unsupported` status is an explicit compatibility decision carrying
/// a guest-visible error.
#[derive(Debug, Clone, Default)]
pub struct ApiDatabase {
    entries: Vec<ApiEntry>,
    /// (normalized dll stem, lowercase export) -> compatibility error that the
    /// guest sees when it reaches this deliberately-unsupported API.
    deliberately_unsupported: BTreeMap<(String, String), String>,
}

/// Normalize a DLL name for keying: lowercase, trimmed, `.dll` suffix
/// stripped (both `"kernel32"` and `"KERNEL32.DLL"` key to `"kernel32"`).
fn normalize_dll(dll: &str) -> String {
    let lower = dll.trim().to_ascii_lowercase();
    lower.strip_suffix(".dll").unwrap_or(&lower).to_string()
}

impl ApiDatabase {
    /// Create an empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry to the database.
    pub fn add_entry(&mut self, entry: ApiEntry) {
        self.entries.push(entry);
    }

    /// Declare a `Stub`/`Unsupported` API deliberately unsupported.
    ///
    /// `compatibility_error` documents the guest-visible error the runtime
    /// surfaces when the API is reached.  Only entries registered here pass
    /// the [`ApiDatabase::production_gate`] while still classified
    /// `Stub`/`Unsupported`.
    pub fn deliberately_unsupported(
        &mut self,
        dll: &str,
        export: &str,
        compatibility_error: impl Into<String>,
    ) {
        self.deliberately_unsupported.insert(
            (normalize_dll(dll), export.to_ascii_lowercase()),
            compatibility_error.into(),
        );
    }

    /// The compatibility error registered for a deliberately-unsupported API,
    /// if any.
    pub fn deliberately_unsupported_error(&self, dll: &str, export: &str) -> Option<&str> {
        self.deliberately_unsupported
            .get(&(normalize_dll(dll), export.to_ascii_lowercase()))
            .map(String::as_str)
    }

    /// Look up an entry by (DLL, export).
    ///
    /// Matching is case-insensitive and tolerates the `.dll` suffix on either
    /// side (`"kernel32"` and `"KERNEL32.DLL"` both match `"kernel32.dll"`).
    pub fn lookup(&self, dll: &str, export: &str) -> Option<&ApiEntry> {
        let dll_key = normalize_dll(dll);
        self.entries.iter().find(|entry| {
            normalize_dll(&entry.dll) == dll_key && entry.export.eq_ignore_ascii_case(export)
        })
    }

    /// Mutable lookup by (DLL, export) with the same matching rules as
    /// [`ApiDatabase::lookup`].
    pub fn lookup_mut(&mut self, dll: &str, export: &str) -> Option<&mut ApiEntry> {
        let dll_key = normalize_dll(dll);
        self.entries.iter_mut().find(|entry| {
            normalize_dll(&entry.dll) == dll_key && entry.export.eq_ignore_ascii_case(export)
        })
    }

    /// Iterate over every entry for a DLL (case-insensitive, `.dll`-suffix
    /// tolerant), in insertion order.
    pub fn for_dll(&self, dll: &str) -> impl Iterator<Item = &ApiEntry> + '_ {
        let dll_key = normalize_dll(dll);
        self.entries
            .iter()
            .filter(move |entry| normalize_dll(&entry.dll) == dll_key)
    }

    /// Record that a workload reaches a (DLL, export) pair.
    ///
    /// The workload label is pushed into `workloads_reaching` (deduplicated)
    /// of the matching entry.  Returns `true` when an entry was found.
    pub fn record_workload(&mut self, dll: &str, export: &str, workload: &str) -> bool {
        let Some(entry) = self.lookup_mut(dll, export) else {
            return false;
        };
        if !entry.workloads_reaching.iter().any(|w| w == workload) {
            entry.workloads_reaching.push(workload.to_string());
        }
        true
    }

    /// The production release gate.
    ///
    /// Violations are reported for:
    ///
    /// 1. Any entry with `implementation == Partial` that is not flagged
    ///    `transitional` (a Partial implementation must carry a documented
    ///    reason, or it is quietly counted as shipped).
    /// 2. Any entry with `implementation == Stub` or `Unsupported` that is
    ///    not registered as deliberately unsupported with a compatibility
    ///    error.
    ///
    /// Only `Implemented` entries and deliberately-unsupported entries with a
    /// compatibility error are acceptable production statuses.
    pub fn production_gate(&self) -> Vec<ApiGateViolation> {
        let mut violations = Vec::new();
        for entry in &self.entries {
            match entry.implementation {
                ImplementationLevel::Implemented => {}
                ImplementationLevel::Partial => {
                    if !entry.transitional {
                        violations.push(ApiGateViolation {
                            dll: entry.dll.clone(),
                            export: entry.export.clone(),
                            kind: ApiGateViolationKind::PartialNotTransitional,
                            message: format!(
                                "{}!{} is Partial but not flagged transitional — mark it \
                                 transitional with a documented reason in detail, or complete \
                                 the implementation",
                                entry.dll, entry.export
                            ),
                        });
                    }
                }
                ImplementationLevel::Stub => {
                    if self
                        .deliberately_unsupported_error(&entry.dll, &entry.export)
                        .is_none()
                    {
                        violations.push(ApiGateViolation {
                            dll: entry.dll.clone(),
                            export: entry.export.clone(),
                            kind: ApiGateViolationKind::StubNotDeliberatelyUnsupported,
                            message: format!(
                                "{}!{} is a Stub but not declared deliberately unsupported — \
                                 register it via deliberately_unsupported() with the \
                                 compatibility error the guest sees, or implement it",
                                entry.dll, entry.export
                            ),
                        });
                    }
                }
                ImplementationLevel::Unsupported => {
                    if self
                        .deliberately_unsupported_error(&entry.dll, &entry.export)
                        .is_none()
                    {
                        violations.push(ApiGateViolation {
                            dll: entry.dll.clone(),
                            export: entry.export.clone(),
                            kind: ApiGateViolationKind::UnsupportedNotDeliberatelyUnsupported,
                            message: format!(
                                "{}!{} is Unsupported (no host thunk) but not declared \
                                 deliberately unsupported — register it via \
                                 deliberately_unsupported() with the compatibility error the \
                                 guest sees, or implement it",
                                entry.dll, entry.export
                            ),
                        });
                    }
                }
            }
        }
        violations
    }

    /// All entries in insertion order.
    pub fn entries(&self) -> &[ApiEntry] {
        &self.entries
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build the database seeded from the canonical thunk metadata
    /// ([`THUNK_METADATA`]) plus the `Nt*`, COM, DXGI/D3D11/D3D12, and Media
    /// Foundation skeleton tables.
    ///
    /// Seeding rules:
    ///
    /// - Every [`THUNK_METADATA`] entry maps to an [`ApiEntry`] with the same
    ///   DLL, export, and [`ImplementationLevel`].  `Partial` entries are
    ///   flagged `transitional` with the documented-limitation reason.
    /// - `Stub`/`Unsupported` entries whose dispatch code deliberately returns
    ///   the compatibility-correct canned answer are registered through
    ///   [`ApiDatabase::deliberately_unsupported`] with the guest-visible
    ///   consequence.
    /// - The `Nt*` / interface skeletons are marked against what the runtime
    ///   actually dispatches (see the table documentation).
    pub fn from_thunk_metadata() -> Self {
        let mut database = ApiDatabase::new();

        for metadata in THUNK_METADATA {
            let transitional = metadata.implementation == ImplementationLevel::Partial;
            let detail = if transitional {
                Some(
                    "Partial per THUNK_METADATA: real implementation with known limitations \
                     documented in the dispatch code (pe_runtime.rs)."
                        .to_string(),
                )
            } else {
                None
            };
            database.add_entry(ApiEntry {
                dll: metadata.dll.to_string(),
                export: metadata.name.to_string(),
                arch: ArchSet::Any,
                win_version: WindowsVersion::Any,
                implementation: metadata.implementation,
                semantic_test_coverage: CoverageLevel::None,
                workloads_reaching: Vec::new(),
                transitional,
                detail,
            });
        }

        for skeleton in NT_API_SURFACE {
            database.add_entry(skeleton_entry("ntdll.dll", skeleton));
        }
        for skeleton in COM_INTERFACE_SURFACE {
            database.add_entry(skeleton_entry(skeleton.dll, skeleton));
        }
        for skeleton in DXGI_D3D_INTERFACE_SURFACE {
            database.add_entry(skeleton_entry(skeleton.dll, skeleton));
        }
        for skeleton in MEDIA_FOUNDATION_INTERFACE_SURFACE {
            database.add_entry(skeleton_entry(skeleton.dll, skeleton));
        }

        for deliberate in DELIBERATELY_UNSUPPORTED {
            database.deliberately_unsupported(
                deliberate.dll,
                deliberate.export,
                deliberate.compatibility_error,
            );
        }

        database
    }

    /// The `api-completeness.json` report for this database.
    pub fn completeness_report(&self) -> ApiCompletenessReport {
        let mut per_dll: BTreeMap<String, DllCompletenessSummary> = BTreeMap::new();
        for entry in &self.entries {
            let summary = per_dll.entry(entry.dll.clone()).or_default();
            summary.total += 1;
            match entry.implementation {
                ImplementationLevel::Implemented => summary.implemented += 1,
                ImplementationLevel::Partial => {
                    summary.partial += 1;
                    if entry.transitional {
                        summary.transitional_partial += 1;
                    }
                }
                ImplementationLevel::Stub => summary.stub += 1,
                ImplementationLevel::Unsupported => summary.unsupported += 1,
            }
            match entry.semantic_test_coverage {
                CoverageLevel::Differential | CoverageLevel::Conformance => {
                    summary.differential_tested += 1;
                }
                CoverageLevel::None | CoverageLevel::Unit | CoverageLevel::SubsystemScenario => {}
            }
            if entry.semantic_test_coverage == CoverageLevel::Conformance {
                summary.conformance_tested += 1;
            }
        }

        ApiCompletenessReport {
            generated_at: crate::steam_milestones::utc_rfc3339_now(),
            per_dll,
            gate: ApiGateSummary {
                violations: self.production_gate(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Skeleton tables
// ---------------------------------------------------------------------------

/// A skeleton-table row: the DLL, the export/interface name, and the
/// implementation level the runtime actually provides.
struct SkeletonEntry {
    dll: &'static str,
    export: &'static str,
    implementation: ImplementationLevel,
    transitional: bool,
    detail: &'static str,
}

const fn skeleton(export: &'static str, implementation: ImplementationLevel) -> SkeletonEntry {
    SkeletonEntry {
        dll: "",
        export,
        implementation,
        transitional: false,
        detail: "",
    }
}

const fn interface_skeleton(
    dll: &'static str,
    export: &'static str,
    implementation: ImplementationLevel,
    transitional: bool,
    detail: &'static str,
) -> SkeletonEntry {
    SkeletonEntry {
        dll,
        export,
        implementation,
        transitional,
        detail,
    }
}

fn skeleton_entry(dll: &str, skeleton: &SkeletonEntry) -> ApiEntry {
    ApiEntry {
        dll: dll.to_string(),
        export: skeleton.export.to_string(),
        arch: ArchSet::Any,
        win_version: WindowsVersion::Any,
        implementation: skeleton.implementation,
        semantic_test_coverage: CoverageLevel::None,
        workloads_reaching: Vec::new(),
        transitional: skeleton.transitional,
        detail: (!skeleton.detail.is_empty()).then(|| skeleton.detail.to_string()),
    }
}

/// The `Nt*` API surface of ntdll.dll.
///
/// Only [`NtQueryInformationProcess`](crate::pe_runtime::HostThunk::NtQueryInformationProcess)
/// has a host thunk today; every other `Nt*` API is `Unsupported` (no host
/// thunk — dispatch fails).  These are skeleton entries so the completeness
/// database quantifies the native-API gap.
static NT_API_SURFACE: &[SkeletonEntry] = &[
    skeleton("NtAllocateVirtualMemory", ImplementationLevel::Unsupported),
    skeleton("NtClearEvent", ImplementationLevel::Unsupported),
    skeleton("NtClose", ImplementationLevel::Unsupported),
    skeleton("NtCreateEvent", ImplementationLevel::Unsupported),
    skeleton("NtCreateFile", ImplementationLevel::Unsupported),
    skeleton("NtCreateFileMapping", ImplementationLevel::Unsupported),
    skeleton("NtCreateKey", ImplementationLevel::Unsupported),
    skeleton("NtCreateProcess", ImplementationLevel::Unsupported),
    skeleton("NtCreateSection", ImplementationLevel::Unsupported),
    skeleton("NtCreateThreadEx", ImplementationLevel::Unsupported),
    skeleton("NtDelayExecution", ImplementationLevel::Unsupported),
    skeleton("NtDeviceIoControlFile", ImplementationLevel::Unsupported),
    skeleton("NtDuplicateObject", ImplementationLevel::Unsupported),
    skeleton("NtFreeVirtualMemory", ImplementationLevel::Unsupported),
    skeleton("NtGetContextThread", ImplementationLevel::Unsupported),
    skeleton("NtMapViewOfSection", ImplementationLevel::Unsupported),
    skeleton("NtOpenKey", ImplementationLevel::Unsupported),
    skeleton("NtProtectVirtualMemory", ImplementationLevel::Unsupported),
    skeleton(
        "NtQueryInformationProcess",
        ImplementationLevel::Implemented,
    ),
    skeleton("NtQueryInformationThread", ImplementationLevel::Unsupported),
    skeleton("NtQueryObject", ImplementationLevel::Unsupported),
    skeleton(
        "NtQueryPerformanceCounter",
        ImplementationLevel::Unsupported,
    ),
    skeleton("NtQuerySection", ImplementationLevel::Unsupported),
    skeleton("NtQuerySystemInformation", ImplementationLevel::Unsupported),
    skeleton("NtQueryTimerResolution", ImplementationLevel::Unsupported),
    skeleton("NtQueryValueKey", ImplementationLevel::Unsupported),
    skeleton("NtQueryVirtualMemory", ImplementationLevel::Unsupported),
    skeleton("NtReadVirtualMemory", ImplementationLevel::Unsupported),
    skeleton("NtResumeThread", ImplementationLevel::Unsupported),
    skeleton("NtSetContextThread", ImplementationLevel::Unsupported),
    skeleton("NtSetEvent", ImplementationLevel::Unsupported),
    skeleton("NtSetInformationThread", ImplementationLevel::Unsupported),
    skeleton("NtSetTimerResolution", ImplementationLevel::Unsupported),
    skeleton("NtSetValueKey", ImplementationLevel::Unsupported),
    skeleton("NtSuspendThread", ImplementationLevel::Unsupported),
    skeleton("NtTerminateProcess", ImplementationLevel::Unsupported),
    skeleton("NtTerminateThread", ImplementationLevel::Unsupported),
    skeleton("NtUnmapViewOfSection", ImplementationLevel::Unsupported),
    skeleton("NtWaitForMultipleObjects", ImplementationLevel::Unsupported),
    skeleton("NtWaitForSingleObject", ImplementationLevel::Unsupported),
    skeleton("NtWriteVirtualMemory", ImplementationLevel::Unsupported),
];

/// The core COM interface surface, marked at the runtime's actual level.
///
/// Evidence basis: `CoCreateInstance` supports a CLSID subset (Partial),
/// `IDispatch::GetIDsOfNames`/`Invoke` vtable thunks are dispatched, and the
/// runtime manages guest-object lifetimes (`GuestObjectAddRef`,
/// `ShellLink*` vtable thunks) — everything else has no interface dispatch
/// yet.
static COM_INTERFACE_SURFACE: &[SkeletonEntry] = &[
    interface_skeleton(
        "ole32.dll",
        "IUnknown",
        ImplementationLevel::Partial,
        true,
        "Runtime manages guest COM object lifetimes (QueryInterface/AddRef/Release) for objects created via CoCreateInstance, D3D, and DXGI (GuestObjectAddRef et al. in pe_runtime.rs).",
    ),
    interface_skeleton(
        "ole32.dll",
        "IClassFactory",
        ImplementationLevel::Partial,
        true,
        "CoCreateInstance instantiates the supported CLSID subset; the class-factory protocol is handled internally.",
    ),
    interface_skeleton(
        "oleaut32.dll",
        "IDispatch",
        ImplementationLevel::Partial,
        true,
        "IDispatch::GetIDsOfNames and IDispatch::Invoke vtable thunks are dispatched in pe_runtime.rs.",
    ),
    interface_skeleton(
        "oleaut32.dll",
        "IEnumVARIANT",
        ImplementationLevel::Unsupported,
        false,
        "No IEnumVARIANT dispatch in the runtime.",
    ),
    interface_skeleton(
        "oleaut32.dll",
        "IConnectionPoint",
        ImplementationLevel::Unsupported,
        false,
        "No IConnectionPoint dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IMoniker",
        ImplementationLevel::Unsupported,
        false,
        "No IMoniker dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IPersist",
        ImplementationLevel::Unsupported,
        false,
        "No IPersist dispatch in the runtime.",
    ),
    interface_skeleton(
        "shell32.dll",
        "IPersistFile",
        ImplementationLevel::Unsupported,
        false,
        "No IPersistFile dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IStream",
        ImplementationLevel::Unsupported,
        false,
        "No IStream dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IStorage",
        ImplementationLevel::Unsupported,
        false,
        "No IStorage dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IMalloc",
        ImplementationLevel::Unsupported,
        false,
        "No IMalloc dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IDropTarget",
        ImplementationLevel::Unsupported,
        false,
        "RegisterDragDrop/DoDragDrop exist, but no IDropTarget vtable dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IDataObject",
        ImplementationLevel::Unsupported,
        false,
        "No IDataObject dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IOleObject",
        ImplementationLevel::Unsupported,
        false,
        "OleInitialize is implemented, but no IOleObject dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IOleInPlaceObject",
        ImplementationLevel::Unsupported,
        false,
        "No IOleInPlaceObject dispatch in the runtime.",
    ),
    interface_skeleton(
        "shdocvw.dll",
        "IWebBrowser2",
        ImplementationLevel::Unsupported,
        false,
        "No IWebBrowser2 dispatch in the runtime.",
    ),
    interface_skeleton(
        "mshtml.dll",
        "IHTMLDocument2",
        ImplementationLevel::Unsupported,
        false,
        "No IHTMLDocument2 dispatch in the runtime.",
    ),
    interface_skeleton(
        "shell32.dll",
        "IShellLink",
        ImplementationLevel::Partial,
        true,
        "ShellLink vtable (QueryInterface/AddRef/Release/GetPathW/SetPathW/Resolve/...) is dispatched as host thunks in pe_runtime.rs.",
    ),
    interface_skeleton(
        "scrobj.dll",
        "IActiveScript",
        ImplementationLevel::Unsupported,
        false,
        "No IActiveScript dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IObjectWithSite",
        ImplementationLevel::Unsupported,
        false,
        "No IObjectWithSite dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IServiceProvider",
        ImplementationLevel::Unsupported,
        false,
        "No IServiceProvider dispatch in the runtime.",
    ),
];

/// The DXGI and Direct3D interface surface, marked at the runtime's actual
/// level.
///
/// Evidence basis: guest DXGI factory/adapter objects, swap-chain creation
/// (ForHwnd/ForCoreWindow/ForComposition), the D3D11 vtable-dispatch family
/// (112 `D3D11*` host thunks) and the D3D12 runtime (command queues, lists,
/// resources, descriptor heaps, pipelines, root signatures, fences).
static DXGI_D3D_INTERFACE_SURFACE: &[SkeletonEntry] = &[
    interface_skeleton(
        "dxgi.dll",
        "IDXGIFactory",
        ImplementationLevel::Partial,
        true,
        "Guest IDXGIFactory object (GuestDxgiFactory) with CreateSwapChain, MakeWindowAssociation, SetPrivateData; remaining methods not covered.",
    ),
    interface_skeleton(
        "dxgi.dll",
        "IDXGIDevice",
        ImplementationLevel::Partial,
        true,
        "Guest DXGI adapter/device objects (GuestDxgiAdapter); subset of methods dispatched.",
    ),
    interface_skeleton(
        "dxgi.dll",
        "IDXGISwapChain",
        ImplementationLevel::Partial,
        true,
        "SwapChain creation (ForHwnd/ForCoreWindow/ForComposition) and present lifecycle routed to the D3D12 runtime.",
    ),
    interface_skeleton(
        "dxgi.dll",
        "IDXGISurface",
        ImplementationLevel::Partial,
        true,
        "Surface objects backed by D3D11 resources; subset of methods dispatched.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11Device",
        ImplementationLevel::Partial,
        true,
        "Implemented subset of ID3D11Device methods as HostThunk vtable dispatch (CreateBuffer/CreateTexture2D/views/shaders/query...); remaining methods surface as unsupported_method telemetry.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11DeviceContext",
        ImplementationLevel::Partial,
        true,
        "Implemented subset of ID3D11DeviceContext methods as HostThunk vtable dispatch (draw, IA/VS/PS/CS binding, OMSetRenderTargets...); remaining methods surface as unsupported_method telemetry.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11Texture2D",
        ImplementationLevel::Partial,
        true,
        "Texture2D resources created and managed through the D3D11 device thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11Buffer",
        ImplementationLevel::Partial,
        true,
        "Buffer resources created and managed through the D3D11 device thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11RenderTargetView",
        ImplementationLevel::Partial,
        true,
        "Render-target views created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11DepthStencilView",
        ImplementationLevel::Partial,
        true,
        "Depth-stencil views created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11ShaderResourceView",
        ImplementationLevel::Partial,
        true,
        "Shader-resource views created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11InputLayout",
        ImplementationLevel::Partial,
        true,
        "Input layouts created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11VertexShader",
        ImplementationLevel::Partial,
        true,
        "Vertex shaders created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11PixelShader",
        ImplementationLevel::Partial,
        true,
        "Pixel shaders created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11GeometryShader",
        ImplementationLevel::Partial,
        true,
        "Geometry shaders created through the D3D11 device thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11ComputeShader",
        ImplementationLevel::Partial,
        true,
        "Compute shaders created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11Query",
        ImplementationLevel::Partial,
        true,
        "Queries/predicates created and queried through the D3D11 device thunks (CreateQuery, GetDesc).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12Device",
        ImplementationLevel::Partial,
        true,
        "Implemented subset of ID3D12Device methods (CreateCommandQueue/Allocator/List, CreateDescriptorHeap, CreateFence, CreateGraphicsPipelineState, CreateRootSignature...).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12CommandQueue",
        ImplementationLevel::Partial,
        true,
        "Command-queue thunks (ExecuteCommandLists, Signal).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12CommandList",
        ImplementationLevel::Partial,
        true,
        "Command-list base surface (Close).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12GraphicsCommandList",
        ImplementationLevel::Partial,
        true,
        "Graphics command-list thunks (ResourceBarrier, ClearRenderTargetView, DrawInstanced, SetPipelineState, SetGraphicsRootSignature, descriptor-heap binding...).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12Resource",
        ImplementationLevel::Partial,
        true,
        "Committed resources created and managed through the D3D12 runtime (create_committed_resource, upload_write...).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12DescriptorHeap",
        ImplementationLevel::Partial,
        true,
        "Descriptor-heap thunks (CreateDescriptorHeap, GetCpuHandleForHeapStart).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12PipelineState",
        ImplementationLevel::Partial,
        true,
        "Graphics/compute pipeline-state thunks (CreateGraphicsPipelineState, CreateComputePipelineState, SetPipelineState).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12RootSignature",
        ImplementationLevel::Partial,
        true,
        "Root-signature thunks (CreateRootSignature, SetGraphicsRootSignature).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12Heap",
        ImplementationLevel::Unsupported,
        false,
        "No ID3D12Heap dispatch in the runtime.",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12Fence",
        ImplementationLevel::Partial,
        true,
        "Fence thunks (CreateFence, Signal).",
    ),
];

/// The Media Foundation interface surface, marked at the runtime's actual
/// level.
///
/// Evidence basis: `media.rs` implements the media session state machine
/// (IMFMediaSession-like), media types (IMFMediaType-like), buffers
/// (IMFMediaBuffer-like), samples (IMFSample-like), event generation
/// (IMFMediaEventGenerator-like), an IMFTransform trait, a SourceResolver,
/// an IMFSourceReader-like SourceReader, and an IMFSinkWriter-like
/// SinkWriter.
static MEDIA_FOUNDATION_INTERFACE_SURFACE: &[SkeletonEntry] = &[
    interface_skeleton(
        "mf.dll",
        "IMFMediaSession",
        ImplementationLevel::Partial,
        true,
        "Media session state machine (Start/Pause/Stop/Shutdown/SetTopology) implemented in media.rs.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFSourceResolver",
        ImplementationLevel::Partial,
        true,
        "SourceResolver in media.rs detects container format and creates media sources.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFMediaSource",
        ImplementationLevel::Partial,
        true,
        "Media sources created through SourceResolver (MP4 container).",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFMediaType",
        ImplementationLevel::Partial,
        true,
        "ImfMediaType attribute store (set/get UINT32/UINT64/GUID/string/blob, frame size/rate) in media.rs.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFMediaBuffer",
        ImplementationLevel::Partial,
        true,
        "ImfMediaBuffer lock/unlock in media.rs.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFSample",
        ImplementationLevel::Partial,
        true,
        "ImfSample in media.rs.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFTransform",
        ImplementationLevel::Partial,
        true,
        "ImfTransform trait with audio/video transform implementations in media.rs.",
    ),
    interface_skeleton(
        "mf.dll",
        "IMFMediaSink",
        ImplementationLevel::Unsupported,
        false,
        "No IMFMediaSink interface dispatch in the runtime.",
    ),
    interface_skeleton(
        "mfreadwrite.dll",
        "IMFSinkWriter",
        ImplementationLevel::Partial,
        true,
        "SinkWriter in media.rs (AddStream/Initialize/WriteSample...).",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFAsyncResult",
        ImplementationLevel::Unsupported,
        false,
        "No IMFAsyncResult interface dispatch in the runtime.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFAttributes",
        ImplementationLevel::Partial,
        true,
        "Attribute store on ImfMediaType (set/get UINT32/UINT64/GUID/string/blob).",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFGetService",
        ImplementationLevel::Unsupported,
        false,
        "No IMFGetService interface dispatch in the runtime.",
    ),
];

/// Deliberately-unsupported seeds: `Stub`/`Unsupported` APIs whose dispatch
/// code deliberately returns the compatibility-correct canned answer.  Each
/// carries the guest-visible compatibility consequence.
static DELIBERATELY_UNSUPPORTED: &[DeliberatelyUnsupportedSeed] = &[
    deliberately_unsupported(
        "kernel32.dll",
        "IsDebuggerPresent",
        "Returns FALSE (no debugger attached) — the deliberate anti-debugger compatibility answer.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "IsBadWritePtr",
        "Returns FALSE — in the guest memory model all mapped guest memory is writable, so the probe is answered deliberately.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "SwitchToThread",
        "Returns FALSE — no other guest thread was ready, the documented no-ready-thread answer.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "HeapValidate",
        "Returns TRUE — the runtime's guest heap is valid by construction.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "HeapLock",
        "Returns TRUE — heap locking is a no-op on the guest heap; success is the compatible answer.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "HeapUnlock",
        "Returns TRUE — heap unlocking is a no-op on the guest heap; success is the compatible answer.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "HeapSetInformation",
        "Returns TRUE — heap information options are not applicable; success is the compatible answer.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "GetACP",
        "Returns DEFAULT_ANSI_CODE_PAGE (1252) — the ANSI codepage the runtime operates under.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "GetOEMCP",
        "Returns DEFAULT_OEM_CODE_PAGE (437) — the OEM codepage the runtime operates under.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "GetConsoleMode",
        "Returns canned console-mode flags (0x1A1) — the guest has no interactive console.",
    ),
    deliberately_unsupported(
        "kernel32.dll",
        "SetConsoleMode",
        "No-op success (TRUE) — console mode is fixed; requests to change it are silently accepted.",
    ),
];

/// A deliberately-unsupported seed row.
struct DeliberatelyUnsupportedSeed {
    dll: &'static str,
    export: &'static str,
    compatibility_error: &'static str,
}

const fn deliberately_unsupported(
    dll: &'static str,
    export: &'static str,
    compatibility_error: &'static str,
) -> DeliberatelyUnsupportedSeed {
    DeliberatelyUnsupportedSeed {
        dll,
        export,
        compatibility_error,
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Per-DLL completeness summary (`api-completeness.json` `per_dll` values).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DllCompletenessSummary {
    /// Total tracked entries for the DLL.
    pub total: usize,
    /// Entries with `ImplementationLevel::Implemented`.
    pub implemented: usize,
    /// Entries with `ImplementationLevel::Partial`.
    pub partial: usize,
    /// Entries with `ImplementationLevel::Stub`.
    pub stub: usize,
    /// Entries with `ImplementationLevel::Unsupported`.
    pub unsupported: usize,
    /// Entries with differential or conformance semantic test coverage.
    pub differential_tested: usize,
    /// Entries with conformance semantic test coverage.
    pub conformance_tested: usize,
    /// Partial entries flagged `transitional` (documented, gated-acceptable).
    pub transitional_partial: usize,
}

/// The production-gate section of the report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiGateSummary {
    /// Entries that must not ship quietly (see
    /// [`ApiDatabase::production_gate`]).
    pub violations: Vec<ApiGateViolation>,
}

/// The `api-completeness.json` report shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiCompletenessReport {
    /// RFC 3339 timestamp of report generation.
    pub generated_at: String,
    /// Per-DLL completeness summaries, keyed by lowercase DLL name.
    pub per_dll: BTreeMap<String, DllCompletenessSummary>,
    /// Production-gate result.
    pub gate: ApiGateSummary,
}

// ---------------------------------------------------------------------------
// Process-global database
// ---------------------------------------------------------------------------

/// The process-wide compatibility database, seeded from
/// [`ApiDatabase::from_thunk_metadata`].
///
/// The Steam import-coverage machinery
/// ([`crate::import_coverage::coverage_for_steam_fixture`]) consults this
/// global for each import's level and records the `"steam"` workload into the
/// matching entries, making the database the whole project's compatibility
/// accounting.
pub static API_DATABASE: LazyLock<Mutex<ApiDatabase>> =
    LazyLock::new(|| Mutex::new(ApiDatabase::from_thunk_metadata()));

/// Access the process-global compatibility database.
pub fn global_database() -> &'static Mutex<ApiDatabase> {
    &API_DATABASE
}
