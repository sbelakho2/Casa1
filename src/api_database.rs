//! Quantitative Windows API completeness database (Gap: whole-project
//! compatibility accounting).
//!
//! The thunk metadata in [`crate::host_thunks::THUNK_METADATA`]
//! ([`ThunkMetadata`]) is the backbone: every entry's implementation level is
//! seeded from it, and the database is the project-wide compatibility
//! accounting for DLL/export-keyed API completeness — not just Steam
//! diagnostics.
//! The database provides:
//!
//! - [`ApiEntry`] — per-(DLL, export, architecture, Windows version)
//!   completeness records carrying the [`ImplementationLevel`], the semantic
//!   test coverage ([`CoverageLevel`]), the workloads that reach the API, and
//!   the transitional flag (a `Partial` entry is transitional ONLY when it
//!   carries a specific, concrete documented reason in `detail`).
//! - The semantic axes — [`SemanticFidelity`] (does the dispatch perform the
//!   real documented operation, a restricted subset, an approximation, an
//!   honest environment model, or a canned response?) and
//!   [`SubsystemCapability`] (is the backing Windows subsystem available?).
//!   The audit's "meaning of Implemented" problem: an export may be callable
//!   without being exact (`mscoree` answers `COR_E_CLRNOTAVAILABLE` for a
//!   machine with no CLR — dispatch callable, capability absent), and a
//!   no-op must never claim real semantics (the canned `X3DAudioCalculate`
//!   is now real spatial math; remaining no-ops are documented stubs).  Seed-time overrides
//!   ([`SEMANTIC_OVERRIDES`]) record the audited truth on both axes, and the
//!   report and the generated `KNOWN_LIMITATIONS.compat.md` ledger surface
//!   them.
//! - [`ApiDatabase`] — the entry table with full-key lookup
//!   ([`ApiDatabase::lookup_entry`]), the legacy (DLL, export) convenience
//!   lookup ([`ApiDatabase::lookup`], `None` on ambiguity), workload
//!   recording, and the two gates:
//!   - [`ApiDatabase::shipping_gate`] — the CI gate.  Allows explicitly
//!     documented `Partial` entries (transitional with a specific reason).
//!     Violations: `Partial` without a specific reason, `Stub`/`Unsupported`
//!     not declared deliberately unsupported with a compatibility error,
//!     `Implemented` entries with no semantic coverage at all
//!     ([`CoverageLevel::None`]), and duplicate full keys (lookup
//!     ambiguity).
//!   - [`ApiDatabase::completeness_gate`] — the release gate.  Requires
//!     `Implemented` entries with Differential or Conformance coverage, or
//!     `DeliberatelyUnsupported` entries with a precise compatibility
//!     consequence.  `Partial` NEVER passes this gate.
//! - Seed tables: the full [`THUNK_METADATA`] surface (with a seed-time
//!   classification pass that marks each `Partial` entry transitional ONLY
//!   when its dispatch implementation carries a specific documented
//!   limitation), the `Nt*` surface of ntdll (skeleton entries marked against
//!   what the runtime actually dispatches), and the COM / DXGI / D3D11 /
//!   D3D12 / Media Foundation interface tables at the runtime's actual
//!   levels.
//! - [`ApiCompletenessReport`] — the `api-completeness.json` shape
//!   (`generated_at`, `per_dll` summaries, `gate` with both gate results and
//!   violation counts), emitted by the `casa1-oracle api-report` command.
//!
//! # Gates
//!
//! The completeness-gate violation count is the project's total-compatibility
//! progress number: it counts every entry that still blocks full completeness
//! (any `Partial`, any `Implemented` entry without Differential/Conformance
//! coverage, any undeclared `Stub`/`Unsupported`).  The shipping gate is the
//! weaker, CI-enforced bar: explicitly documented `Partial` entries are
//! allowed, but `Implemented` entries must have at least Unit coverage and
//! every `Stub`/`Unsupported` must be declared deliberately unsupported with
//! a guest-visible compatibility consequence.

use crate::api_coverage::COVERAGE_EVIDENCE;
use crate::compatibility_profile::CompatibilityProfile;
use crate::host_thunks::THUNK_METADATA;
use crate::host_thunks::{ImplementationLevel, SupportPolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

// ---------------------------------------------------------------------------
// Keying enums
// ---------------------------------------------------------------------------

/// Guest architecture an API entry applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ArchSet {
    /// 32-bit (x86) guests only.
    X86,
    /// 64-bit (x64) guests only.
    X64,
    /// Both guest architectures.
    Any,
}

/// Windows version an API entry applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

/// The compatibility tier a completeness evaluation runs under.
///
/// - [`CompatibilityTier::NativeUserMode`] — the full user-mode profile:
///   `Required` and `OptionalFeature` APIs are evaluated (optionals only when
///   the profile does not exclude them); kernel/DRM-tier
///   (`OutsideUserModeProfile`) APIs are exempt.
/// - [`CompatibilityTier::Managed`] — a managed (.NET/CLR) workload evaluated
///   against the same user-mode profile.
/// - [`CompatibilityTier::RestrictedKernel`] — the kernel/DRM tier: only
///   `OutsideUserModeProfile` APIs are evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompatibilityTier {
    /// The full user-mode profile.
    NativeUserMode,
    /// A managed (.NET/CLR) workload over the user-mode profile.
    Managed,
    /// The kernel/DRM tier.
    RestrictedKernel,
}

// ---------------------------------------------------------------------------
// Semantic axes (the audit's "meaning of Implemented" split)
// ---------------------------------------------------------------------------

/// How closely the guest-visible behavior of an entry matches the documented
/// Windows operation — the semantic-fidelity axis.
///
/// [`ImplementationLevel`] alone cannot answer both "is there a callable
/// dispatch?" and "does it perform the real operation?".  An entry may be
/// callable (level `Implemented`) while its behavior is an environment model
/// (e.g. `mscoree` answering `COR_E_CLRNOTAVAILABLE` for a machine with no
/// CLR installed), a restricted subset, or a canned response.  This axis
/// carries that truth; [`SubsystemCapability`] carries whether the Windows
/// subsystem the API belongs to is actually available in the runtime
/// environment.  Together they let the registry report export-dispatch
/// coverage, semantic fidelity, and subsystem capability independently.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum SemanticFidelity {
    /// Performs the real documented operation against runtime state and
    /// writes the genuine guest-visible results.
    #[default]
    Exact,
    /// Performs the real operation for a documented subset (formats, codes,
    /// inputs); unsupported inputs degrade gracefully.
    Restricted,
    /// Produces synthetic/plausible results that approximate the real
    /// operation without performing it.
    Approximate,
    /// Faithfully models an environment state (a service absent, a machine
    /// not domain-joined, no devices present, ...) and answers with the
    /// behavior that state produces — the operation is exact for the
    /// modeled environment.
    SyntheticEnvironment,
    /// Returns a deterministic canned response (a fixed value or error,
    /// possibly with fixed outputs) without performing the operation.
    CannedFailure,
}

/// Whether the Windows subsystem/facility an entry's operation belongs to is
/// actually available in the runtime environment.
///
/// Independent from the entry's own dispatch status: `mscoree` exports can be
/// callable with an honest failure contract while the CLR capability is
/// absent; `NetGetDCName` can be callable while no domain controller is
/// reachable.  "Implemented" never claims subsystem availability by itself.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum SubsystemCapability {
    /// The subsystem is available with full semantics.
    #[default]
    Full,
    /// The subsystem is available with documented limitations.
    Partial,
    /// The subsystem is absent from the modeled environment.
    Absent,
}

/// The default semantic fidelity for an implementation level (used when no
/// seed-time override documents otherwise).
const fn default_fidelity_for(level: ImplementationLevel) -> SemanticFidelity {
    match level {
        ImplementationLevel::Implemented => SemanticFidelity::Exact,
        ImplementationLevel::Partial => SemanticFidelity::Restricted,
        ImplementationLevel::Stub | ImplementationLevel::Unsupported => {
            SemanticFidelity::CannedFailure
        }
    }
}

/// The default subsystem capability for an implementation level.
const fn default_capability_for(level: ImplementationLevel) -> SubsystemCapability {
    match level {
        ImplementationLevel::Implemented | ImplementationLevel::Partial => {
            SubsystemCapability::Full
        }
        ImplementationLevel::Stub | ImplementationLevel::Unsupported => SubsystemCapability::Absent,
    }
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// A single (DLL, export) completeness record.
///
/// This is the project-wide compatibility accounting unit: the implementation
/// level is seeded from [`THUNK_METADATA`].  A `Partial` entry is
/// `transitional` ONLY when it carries a specific, concrete documented reason
/// in `detail` (what is missing); a `Partial` entry without such a reason
/// fails the shipping gate, and `Stub`/`Unsupported` entries must be declared
/// deliberately unsupported with a compatibility error.
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
    /// SPECIFIC, concrete documented reason in `detail`.  A `Partial` entry
    /// that is not transitional (or whose `detail` is missing) fails the
    /// shipping gate.
    pub transitional: bool,
    /// Optional human-readable note: the specific transitional reason for
    /// Partial entries (what is missing), the compatibility consequence for
    /// deliberately-unsupported entries, or any other per-API documentation.
    pub detail: Option<String>,
    /// Generic user-mode profile classification of the API
    /// ([`SupportPolicy`]): `Required` user-mode core, `OptionalFeature`
    /// subsystems, or `OutsideUserModeProfile` kernel/DRM-tier APIs that are
    /// exempt from the user-mode completeness gate.
    #[serde(default)]
    pub support_policy: SupportPolicy,
    /// Semantic fidelity of the guest-visible behavior (see
    /// [`SemanticFidelity`]): whether the dispatch performs the real
    /// documented operation, a restricted subset, a synthetic approximation,
    /// an honest environment model, or a canned response.
    #[serde(default)]
    pub semantic_fidelity: SemanticFidelity,
    /// Whether the Windows subsystem the operation belongs to is actually
    /// available in the runtime environment (see [`SubsystemCapability`]).
    #[serde(default)]
    pub subsystem_capability: SubsystemCapability,
}

impl ApiEntry {
    /// Convenience constructor with the default keying (any architecture, any
    /// Windows version, no test coverage, no workloads, not transitional,
    /// user-mode `Required` policy).
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
            support_policy: SupportPolicy::Required,
            semantic_fidelity: default_fidelity_for(implementation),
            subsystem_capability: default_capability_for(implementation),
        }
    }

    /// `true` when this entry is acceptable as a production status:
    /// implemented, or deliberately unsupported with a compatibility error.
    pub fn is_production_acceptable(&self) -> bool {
        matches!(self.implementation, ImplementationLevel::Implemented)
    }

    /// `true` when the entry carries a specific, concrete documented reason
    /// (`transitional` set AND a non-empty `detail`).
    pub fn has_specific_reason(&self) -> bool {
        self.transitional
            && self
                .detail
                .as_deref()
                .is_some_and(|detail| !detail.is_empty())
    }
}

/// Why a single entry fails a gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiGateViolationKind {
    /// `Partial` implementation without a specific, concrete documented
    /// reason (it would quietly count as shipped despite undocumented
    /// limitations).
    PartialNotTransitional,
    /// `Partial` implementation — NEVER passes the completeness gate; it must
    /// be completed and proven with Differential/Conformance coverage.
    PartialNotCompletenessReady,
    /// `Stub` implementation not declared deliberately unsupported with a
    /// compatibility error.
    StubNotDeliberatelyUnsupported,
    /// `Unsupported` (no host thunk) not declared deliberately unsupported
    /// with a compatibility error.
    UnsupportedNotDeliberatelyUnsupported,
    /// `Implemented` entry with [`CoverageLevel::None`] — no semantic test
    /// coverage at all; the shipping gate requires at least Unit coverage.
    ImplementedWithoutCoverage,
    /// `Implemented` entry without Differential or Conformance coverage —
    /// fails the completeness gate.
    ImplementedWithoutSemanticCoverage,
    /// Duplicate full keys (DLL, export, arch, winver) make even full-key
    /// lookups ambiguous.
    LookupAmbiguity,
}

/// One gate violation: a (DLL, export) that must not ship quietly.
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

    /// Whether an entry with the full key already exists: (normalized DLL,
    /// case-insensitive export, arch, Windows version).  Used at seed time to
    /// keep the database at exactly one row per full key.
    fn has_full_key(&self, entry: &ApiEntry) -> bool {
        self.entries.iter().any(|existing| {
            normalize_dll(&existing.dll) == normalize_dll(&entry.dll)
                && existing.export.eq_ignore_ascii_case(&entry.export)
                && existing.arch == entry.arch
                && existing.win_version == entry.win_version
        })
    }

    /// Declare a `Stub`/`Unsupported` API deliberately unsupported.
    ///
    /// `compatibility_error` documents the guest-visible error the runtime
    /// surfaces when the API is reached.  Only entries registered here pass
    /// the [`ApiDatabase::shipping_gate`] and
    /// [`ApiDatabase::completeness_gate`] while still classified
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

    /// Legacy (DLL, export) convenience lookup.
    ///
    /// Matching is case-insensitive and tolerates the `.dll` suffix on either
    /// side (`"kernel32"` and `"KERNEL32.DLL"` both match `"kernel32.dll"`).
    /// Returns `None` when no entry matches OR when several entries match
    /// (rows can legitimately differ by [`ArchSet`] and [`WindowsVersion`],
    /// which makes this key ambiguous).  New code should use
    /// [`ApiDatabase::lookup_entry`] with the full key.
    pub fn lookup(&self, dll: &str, export: &str) -> Option<&ApiEntry> {
        let dll_key = normalize_dll(dll);
        let mut matches = self.entries.iter().filter(|entry| {
            normalize_dll(&entry.dll) == dll_key && entry.export.eq_ignore_ascii_case(export)
        });
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    }

    /// Look up an entry by the full key: (DLL, export, architecture, Windows
    /// version).
    ///
    /// DLL matching is case-insensitive and tolerates the `.dll` suffix on
    /// either side; the export is matched case-insensitively; the arch and
    /// winver rows must match exactly.  This is the unambiguous keying once
    /// per-architecture / per-Windows-version rows exist.
    pub fn lookup_entry(
        &self,
        dll: &str,
        export: &str,
        arch: ArchSet,
        winver: WindowsVersion,
    ) -> Option<&ApiEntry> {
        let dll_key = normalize_dll(dll);
        self.entries.iter().find(|entry| {
            normalize_dll(&entry.dll) == dll_key
                && entry.export.eq_ignore_ascii_case(export)
                && entry.arch == arch
                && entry.win_version == winver
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

    /// The shipping gate — the CI-enforced bar.
    ///
    /// Explicitly documented `Partial` entries (transitional with a specific
    /// reason in `detail`) are allowed.  Violations are reported for:
    ///
    /// 1. Any entry with `implementation == Partial` that does not carry a
    ///    specific, concrete documented reason (`transitional` + non-empty
    ///    `detail`).  A Partial implementation without a documented reason
    ///    would quietly count as shipped.
    /// 2. Any entry with `implementation == Stub` or `Unsupported` that is
    ///    not registered as deliberately unsupported with a compatibility
    ///    error — UNLESS its `support_policy` is
    ///    `SupportPolicy::OutsideUserModeProfile` (kernel/DRM-tier APIs are
    ///    outside the user-mode profile and need no user-mode
    ///    compatibility error).
    /// 3. Any `Implemented` entry with `semantic_test_coverage ==
    ///    CoverageLevel::None` — an Implemented API needs at least Unit
    ///    coverage to ship.
    /// 4. Duplicate full keys (DLL, export, arch, winver) — the database
    ///    must never make even the full-key lookup ambiguous.
    pub fn shipping_gate(&self) -> Vec<ApiGateViolation> {
        let mut violations = Vec::new();
        let mut full_keys = std::collections::BTreeSet::new();
        for entry in &self.entries {
            let full_key = (
                normalize_dll(&entry.dll),
                entry.export.to_ascii_lowercase(),
                entry.arch,
                entry.win_version,
            );
            if !full_keys.insert(full_key) {
                violations.push(ApiGateViolation {
                    dll: entry.dll.clone(),
                    export: entry.export.clone(),
                    kind: ApiGateViolationKind::LookupAmbiguity,
                    message: format!(
                        "{}!{} ({:?}, {:?}) has a duplicate full key — the database must \
                         have exactly one row per (DLL, export, arch, winver)",
                        entry.dll, entry.export, entry.arch, entry.win_version
                    ),
                });
            }
            match entry.implementation {
                ImplementationLevel::Implemented => {
                    if entry.semantic_test_coverage == CoverageLevel::None {
                        violations.push(ApiGateViolation {
                            dll: entry.dll.clone(),
                            export: entry.export.clone(),
                            kind: ApiGateViolationKind::ImplementedWithoutCoverage,
                            message: format!(
                                "{}!{} is Implemented but has no semantic test coverage \
                                 (CoverageLevel::None) — an Implemented API needs at least \
                                 Unit coverage to pass the shipping gate",
                                entry.dll, entry.export
                            ),
                        });
                    }
                }
                ImplementationLevel::Partial => {
                    if !entry.has_specific_reason() {
                        violations.push(ApiGateViolation {
                            dll: entry.dll.clone(),
                            export: entry.export.clone(),
                            kind: ApiGateViolationKind::PartialNotTransitional,
                            message: format!(
                                "{}!{} is Partial without a specific, concrete documented \
                                 reason — mark it transitional with a short explanation of \
                                 what is missing in detail, or complete the implementation",
                                entry.dll, entry.export
                            ),
                        });
                    }
                }
                ImplementationLevel::Stub => {
                    let outside_profile =
                        entry.support_policy == SupportPolicy::OutsideUserModeProfile;
                    if !outside_profile
                        && self
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
                    let outside_profile =
                        entry.support_policy == SupportPolicy::OutsideUserModeProfile;
                    if !outside_profile
                        && self
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

    /// The completeness gate — the release bar, evaluated against a
    /// compatibility tier and profile.
    ///
    /// - **NativeUserMode**: `Implemented` + Differential/Conformance
    ///   coverage passes.  `Partial`/`Stub`/`Unsupported` FAIL unless
    ///   `support_policy == OutsideUserModeProfile` (kernel/DRM-tier APIs are
    ///   exempt in the user-mode tier).  `OptionalFeature` entries may pass
    ///   even below the bar when the profile explicitly excludes the feature
    ///   (`CompatibilityProfile::optional_features`).
    /// - **Managed**: the same user-mode profile evaluated for managed
    ///   (.NET/CLR) workloads.
    /// - **RestrictedKernel**: only `OutsideUserModeProfile` entries are
    ///   evaluated (they need `Implemented` + Differential/Conformance);
    ///   everything else is exempt.
    ///
    /// The violation count is the project's total-compatibility progress
    /// number: every violation is one entry that still blocks full
    /// completeness for the evaluated profile.
    pub fn completeness_gate(
        &self,
        tier: CompatibilityTier,
        profile: &CompatibilityProfile,
    ) -> Vec<ApiGateViolation> {
        let mut violations = Vec::new();
        for entry in &self.entries {
            let outside_profile = entry.support_policy == SupportPolicy::OutsideUserModeProfile;
            match tier {
                CompatibilityTier::RestrictedKernel => {
                    // Only kernel/DRM-tier entries are part of this tier.
                    if !outside_profile {
                        continue;
                    }
                }
                CompatibilityTier::NativeUserMode | CompatibilityTier::Managed => {
                    // Kernel/DRM-tier APIs are exempt from the user-mode
                    // completeness tier.
                    if outside_profile {
                        continue;
                    }
                }
            }

            // Optional features pass when the profile explicitly excludes
            // them — the feature is not part of this target's surface.
            let feature_excluded = entry.support_policy == SupportPolicy::OptionalFeature
                && optional_feature_for(&entry.dll)
                    .is_some_and(|feature| profile.excludes(feature));

            match entry.implementation {
                ImplementationLevel::Implemented => {
                    if !matches!(
                        entry.semantic_test_coverage,
                        CoverageLevel::Differential | CoverageLevel::Conformance
                    ) {
                        if feature_excluded {
                            continue;
                        }
                        violations.push(ApiGateViolation {
                            dll: entry.dll.clone(),
                            export: entry.export.clone(),
                            kind: ApiGateViolationKind::ImplementedWithoutSemanticCoverage,
                            message: format!(
                                "{}!{} is Implemented but not semantically proven — the \
                                 completeness gate requires Differential or Conformance \
                                 coverage (currently {:?})",
                                entry.dll, entry.export, entry.semantic_test_coverage
                            ),
                        });
                    }
                }
                ImplementationLevel::Partial => {
                    if feature_excluded {
                        continue;
                    }
                    violations.push(ApiGateViolation {
                        dll: entry.dll.clone(),
                        export: entry.export.clone(),
                        kind: ApiGateViolationKind::PartialNotCompletenessReady,
                        message: format!(
                            "{}!{} is Partial and NEVER passes the completeness gate — \
                             complete the implementation and prove it with Differential or \
                             Conformance coverage{}",
                            entry.dll,
                            entry.export,
                            entry
                                .detail
                                .as_deref()
                                .map(|reason| format!(" (documented limitation: {reason})"))
                                .unwrap_or_default()
                        ),
                    });
                }
                ImplementationLevel::Stub => {
                    if feature_excluded {
                        continue;
                    }
                    let deliberate = self
                        .deliberately_unsupported_error(&entry.dll, &entry.export)
                        .map(str::to_string);
                    violations.push(ApiGateViolation {
                        dll: entry.dll.clone(),
                        export: entry.export.clone(),
                        kind: ApiGateViolationKind::StubNotDeliberatelyUnsupported,
                        message: match deliberate {
                            Some(consequence) => format!(
                                "{}!{} is a documented Stub (guest-visible consequence: \
                                 {consequence}) — deliberate stubs ship, but the \
                                 completeness gate requires a working, semantically \
                                 proven implementation",
                                entry.dll, entry.export
                            ),
                            None => format!(
                                "{}!{} is a Stub — the completeness gate requires a \
                                 working, semantically proven implementation",
                                entry.dll, entry.export
                            ),
                        },
                    });
                }
                ImplementationLevel::Unsupported => {
                    if feature_excluded {
                        continue;
                    }
                    let deliberate = self
                        .deliberately_unsupported_error(&entry.dll, &entry.export)
                        .map(str::to_string);
                    violations.push(ApiGateViolation {
                        dll: entry.dll.clone(),
                        export: entry.export.clone(),
                        kind: ApiGateViolationKind::UnsupportedNotDeliberatelyUnsupported,
                        message: match deliberate {
                            Some(consequence) => format!(
                                "{}!{} is a documented Unsupported API (guest-visible \
                                 consequence: {consequence}) — deliberate absences ship, \
                                 but the completeness gate requires a working, \
                                 semantically proven implementation",
                                entry.dll, entry.export
                            ),
                            None => format!(
                                "{}!{} is Unsupported (no host thunk) — the completeness \
                                 gate requires a working, semantically proven \
                                 implementation",
                                entry.dll, entry.export
                            ),
                        },
                    });
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
    ///   flagged `transitional` ONLY when the seed-time classification pass
    ///   (see `PARTIAL_TRANSITION_REASONS` and `classify_partial_reason`
    ///   below) finds a specific, concrete documented limitation in the
    ///   thunk's actual implementation; that reason is recorded in `detail`.
    ///   A Partial without a specific reason is seeded non-transitional and
    ///   fails the shipping gate.
    /// - `Stub`/`Unsupported` entries whose dispatch code deliberately returns
    ///   the compatibility-correct canned answer are registered through
    ///   [`ApiDatabase::deliberately_unsupported`] with the guest-visible
    ///   consequence.
    /// - Every entry carries its [`SupportPolicy`] from the thunk metadata
    ///   (or the skeleton table); the `Nt*` skeletons are
    ///   `OutsideUserModeProfile`, the interface skeletons are
    ///   `OptionalFeature`.
    /// - The `Nt*` / interface skeletons are marked against what the runtime
    ///   actually dispatches (see the table documentation).
    /// - Finally [`ApiDatabase::apply_coverage_evidence`] merges the
    ///   coverage-evidence registry ([`COVERAGE_EVIDENCE`]) — differential
    ///   oracle contracts, conformance suites, and subsystem scenarios.
    pub fn from_thunk_metadata() -> Self {
        let mut database = ApiDatabase::new();

        for metadata in THUNK_METADATA {
            let reason = if metadata.implementation == ImplementationLevel::Partial {
                classify_partial_reason(metadata.dll, metadata.name)
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
                transitional: reason.is_some(),
                detail: reason.map(str::to_string),
                support_policy: metadata.support_policy,
                semantic_fidelity: default_fidelity_for(metadata.implementation),
                subsystem_capability: default_capability_for(metadata.implementation),
            });
        }

        // The skeleton tables document the interface/native surface; exports
        // the runtime registers in THUNK_METADATA own their (DLL, export)
        // key — a skeleton row whose full key already exists (COM interfaces
        // such as ole32!IOleObject, oleaut32!IEnumVARIANT and the audited
        // Nt* pair now live in the metadata surface) is documentation only
        // and must not seed a duplicate row: the database needs exactly one
        // row per (DLL, export, arch, winver).
        for skeleton in NT_API_SURFACE {
            let entry = skeleton_entry("ntdll.dll", skeleton);
            if !database.has_full_key(&entry) {
                database.add_entry(entry);
            }
        }
        for skeleton in COM_INTERFACE_SURFACE {
            let entry = skeleton_entry(skeleton.dll, skeleton);
            if !database.has_full_key(&entry) {
                database.add_entry(entry);
            }
        }
        for skeleton in DXGI_D3D_INTERFACE_SURFACE {
            let entry = skeleton_entry(skeleton.dll, skeleton);
            if !database.has_full_key(&entry) {
                database.add_entry(entry);
            }
        }
        for skeleton in MEDIA_FOUNDATION_INTERFACE_SURFACE {
            let entry = skeleton_entry(skeleton.dll, skeleton);
            if !database.has_full_key(&entry) {
                database.add_entry(entry);
            }
        }

        for deliberate in DELIBERATELY_UNSUPPORTED {
            database.deliberately_unsupported(
                deliberate.dll,
                deliberate.export,
                deliberate.compatibility_error,
            );
        }

        database.apply_coverage_evidence();

        database.apply_semantic_overrides();

        database
    }

    /// Merge the coverage-evidence registry ([`COVERAGE_EVIDENCE`]) into the
    /// database.
    ///
    /// For every evidence row whose (DLL, export, arch, Windows version) key
    /// matches an entry, the entry's [`CoverageLevel`] takes the registry's
    /// level (the strongest applicable).  Evidence is never inferred from the
    /// existence of a Rust test — each row names the actual contract behind
    /// the level: a `windows-oracle:<category>` differential capture run on
    /// real Windows, a `casa1-conformance:<suite>` suite that genuinely
    /// exercises the API, or a `casa1-scenario:<suite>` subsystem scenario
    /// test (see [`crate::api_coverage`] for the naming rules).
    pub fn apply_coverage_evidence(&mut self) {
        for row in COVERAGE_EVIDENCE {
            let matches: Vec<usize> = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| {
                    normalize_dll(&entry.dll) == normalize_dll(row.dll)
                        && entry.export.eq_ignore_ascii_case(row.export)
                        && (row.arch == ArchSet::Any || row.arch == entry.arch)
                        && (row.windows_version == WindowsVersion::Any
                            || row.windows_version == entry.win_version)
                })
                .map(|(index, _)| index)
                .collect();
            for index in matches {
                if row.level > self.entries[index].semantic_test_coverage {
                    self.entries[index].semantic_test_coverage = row.level;
                }
            }
        }
    }

    /// Apply the seed-time semantic-truth overrides ([`SEMANTIC_OVERRIDES`]).
    ///
    /// The metadata table classifies the dispatch quality; this pass records
    /// what the dispatch actually delivers on the semantic axes: whether the
    /// operation is exact, restricted, an approximation, an honest model of an
    /// absent/limited environment, or a canned response — and whether the
    /// backing Windows subsystem is available.  A row may also be demoted
    /// here (e.g. the canned no-ops are documented `Stub`s, registered
    /// deliberately unsupported with their consequence).  A `"*"` DLL
    /// matches every DLL (export-wide rules such as the shared module-class
    /// registration contract).
    pub fn apply_semantic_overrides(&mut self) {
        for seed in SEMANTIC_OVERRIDES {
            let Some(entry) = self.entries.iter_mut().find(|entry| {
                (seed.dll == "*" || normalize_dll(&entry.dll) == normalize_dll(seed.dll))
                    && entry.export.eq_ignore_ascii_case(seed.export)
                    && entry.arch == ArchSet::Any
                    && entry.win_version == WindowsVersion::Any
            }) else {
                continue;
            };
            entry.semantic_fidelity = seed.fidelity;
            entry.subsystem_capability = seed.capability;
            entry.detail = Some(seed.note.to_string());
            if let Some(level) = seed.level {
                entry.implementation = level;
                // A demotion to Partial must carry its specific reason or the
                // shipping gate rejects it as an undocumented partial.
                entry.transitional = level == ImplementationLevel::Partial;
            }
        }
        // Every demoted Stub must be registered deliberately unsupported with
        // its guest-visible consequence, or the shipping gate rejects it.
        // The override note above IS that consequence (what the guest sees).
        let stubs: Vec<(String, String)> = self
            .entries
            .iter()
            .filter(|entry| entry.implementation == ImplementationLevel::Stub)
            .filter(|entry| {
                entry.support_policy != SupportPolicy::OutsideUserModeProfile
                    && self
                        .deliberately_unsupported_error(&entry.dll, &entry.export)
                        .is_none()
            })
            .map(|entry| (entry.dll.clone(), entry.export.clone()))
            .collect();
        for (dll, export) in stubs {
            let consequence = self
                .entries
                .iter()
                .find(|entry| entry.dll == dll && entry.export == export)
                .and_then(|entry| entry.detail.clone())
                .unwrap_or_else(|| {
                    "Documented stub: the dispatch returns a canned response without \
                     performing the operation"
                        .to_string()
                });
            self.deliberately_unsupported(&dll, &export, consequence);
        }
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
            match entry.semantic_fidelity {
                SemanticFidelity::Exact => summary.exact += 1,
                SemanticFidelity::Restricted => summary.restricted += 1,
                SemanticFidelity::Approximate => summary.approximate += 1,
                SemanticFidelity::SyntheticEnvironment => summary.synthetic_environment += 1,
                SemanticFidelity::CannedFailure => summary.canned_failure += 1,
            }
            match entry.subsystem_capability {
                SubsystemCapability::Full => summary.capability_full += 1,
                SubsystemCapability::Partial => summary.capability_partial += 1,
                SubsystemCapability::Absent => summary.capability_absent += 1,
            }
        }

        let shipping_violations = self.shipping_gate();
        // The report's completeness evaluation runs the full native
        // user-mode profile (nothing excluded): the strictest default.
        let profile = CompatibilityProfile::win11_native_desktop();
        let completeness_violations =
            self.completeness_gate(CompatibilityTier::NativeUserMode, &profile);
        let shipping_violation_count = shipping_violations.len();
        let completeness_violation_count = completeness_violations.len();
        ApiCompletenessReport {
            generated_at: crate::steam_milestones::utc_rfc3339_now(),
            per_dll,
            gate: ApiGateSummary {
                shipping_violations,
                shipping_violation_count,
                completeness_violations,
                completeness_violation_count,
            },
            registry: self
                .entries
                .iter()
                .map(|entry| ApiRegistryRow {
                    dll: entry.dll.clone(),
                    export: entry.export.clone(),
                    implementation: entry.implementation,
                    semantic_test_coverage: entry.semantic_test_coverage,
                    support_policy: entry.support_policy,
                    semantic_fidelity: entry.semantic_fidelity,
                    subsystem_capability: entry.subsystem_capability,
                    detail: entry.detail.clone(),
                })
                .collect(),
        }
    }

    /// Render the compatibility-limitations fragment (`KNOWN_LIMITATIONS`
    /// generated section) from the database's semantic axes.
    ///
    /// The generated document is the authoritative per-API statement of what
    /// is NOT exact: rows whose dispatch is restricted, approximate, an
    /// environment model, or a canned response, rows whose backing subsystem
    /// is absent or partial, and the documented `Partial` entries — with the
    /// specific reason each carries.  It is emitted by
    /// `casa1-oracle api-limitations` and included by `KNOWN_LIMITATIONS.md`
    /// so the limitations document can never disagree with the registry.
    pub fn compatibility_limitations_markdown(&self) -> String {
        let mut entries: Vec<&ApiEntry> = self
            .entries
            .iter()
            .filter(|entry| {
                entry.semantic_fidelity != SemanticFidelity::Exact
                    || entry.subsystem_capability != SubsystemCapability::Full
            })
            .collect();
        entries.sort_by(|a, b| a.dll.cmp(&b.dll).then_with(|| a.export.cmp(&b.export)));

        let mut total = 0usize;
        let mut by_fidelity: BTreeMap<SemanticFidelity, usize> = BTreeMap::new();
        let mut by_capability: BTreeMap<SubsystemCapability, usize> = BTreeMap::new();
        for entry in &entries {
            total += 1;
            *by_fidelity.entry(entry.semantic_fidelity).or_default() += 1;
            *by_capability.entry(entry.subsystem_capability).or_default() += 1;
        }

        let mut out = String::new();
        out.push_str("<!-- GENERATED by `casa1-oracle api-limitations --out <file>`.\n");
        out.push_str("     Do not edit by hand: regenerate after any dispatch/metadata change.\n");
        out.push_str(
            "     Source of truth: ApiDatabase::from_thunk_metadata + SEMANTIC_OVERRIDES. -->\n",
        );
        out.push_str("\n");
        out.push_str("## API-Compatibility Ledger (generated)\n\n");
        out.push_str("Every tracked export whose dispatch is not exact or whose backing subsystem is not fully available, per the semantic axes of the API database (level = dispatch quality; fidelity = how close the guest-visible behavior is to the documented operation; capability = whether the Windows subsystem the operation belongs to exists in the modeled environment).\n\n");
        out.push_str(&format!(
            "**Counts**: {total} entries deviate from exact/full — fidelity {fidelity_counts}, capability {capability_counts}.\n\n",
            fidelity_counts = by_fidelity
                .iter()
                .map(|(f, c)| format!("{f:?} {c}"))
                .collect::<Vec<_>>()
                .join(", "),
            capability_counts = by_capability
                .iter()
                .map(|(c, n)| format!("{c:?} {n}"))
                .collect::<Vec<_>>()
                .join(", "),
        ));

        let mut current_dll = String::new();
        for entry in &entries {
            if entry.dll != current_dll {
                current_dll = entry.dll.clone();
                out.push_str(&format!("\n### {current_dll}\n\n"));
            }
            let note = entry.detail.as_deref().unwrap_or("");
            out.push_str(&format!(
                "- `{}` — level `{:?}`, fidelity `{:?}`, capability `{:?}`{}",
                entry.export,
                entry.implementation,
                entry.semantic_fidelity,
                entry.subsystem_capability,
                if note.is_empty() {
                    String::new()
                } else {
                    format!(" — {note}")
                },
            ));
            out.push('\n');
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Seed-time classification pass
// ---------------------------------------------------------------------------

/// Classify a `Partial` thunk from [`THUNK_METADATA`] at seed time.
///
/// Returns the SPECIFIC, concrete documented limitation (what is missing) of
/// the thunk's actual implementation, or `None` when no specific reason is
/// carried anywhere.  A `Partial` entry is seeded `transitional` iff this
/// returns a reason; otherwise the entry is non-transitional and fails the
/// shipping gate — the gate must never convert "Partial must not count" into
/// "all Partial automatically pass".
///
/// The reasons below were derived from the dispatch code in `pe_runtime.rs`
/// (the documented limitations in each `HostThunk::*` arm) and from the
/// skeleton-table evidence in this module; each entry names what is missing.
fn classify_partial_reason(dll: &str, export: &str) -> Option<&'static str> {
    PARTIAL_TRANSITION_REASONS
        .iter()
        .find(|(entry_dll, entry_export, _)| *entry_dll == dll && *entry_export == export)
        .map(|(_, _, reason)| *reason)
}

/// Seed-time specific reasons for every `Partial` thunk in
/// [`THUNK_METADATA`]: (dll, export, what is missing).
///
/// Each reason is the concrete limitation documented in the thunk's dispatch
/// implementation (pe_runtime.rs); a Partial entry may only be transitional
/// with one of these (or an equivalent specific reason in the skeleton
/// tables' `detail`).
static PARTIAL_TRANSITION_REASONS: &[(&str, &str, &str)] = &[];

// ---------------------------------------------------------------------------
// Semantic-truth overrides
// ---------------------------------------------------------------------------

/// Seed-time semantic-truth row: (DLL, export) -> the fidelity and
/// subsystem-capability truth of the dispatch, plus an optional level
/// demotion.
struct SemanticOverrideSeed {
    dll: &'static str,
    export: &'static str,
    level: Option<ImplementationLevel>,
    fidelity: SemanticFidelity,
    capability: SubsystemCapability,
    note: &'static str,
}

const fn semantic_override(
    dll: &'static str,
    export: &'static str,
    level: Option<ImplementationLevel>,
    fidelity: SemanticFidelity,
    capability: SubsystemCapability,
    note: &'static str,
) -> SemanticOverrideSeed {
    SemanticOverrideSeed {
        dll,
        export,
        level,
        fidelity,
        capability,
        note,
    }
}

/// The audited semantic-truth overrides: exports whose dispatch does not
/// perform the real Windows operation, either because the backing subsystem
/// is absent from the modeled environment (the environment model is itself
/// exact — `mscoree` answering `COR_E_CLRNOTAVAILABLE` on a machine with no
/// CLR installed) or because the dispatch is a restricted/approximate/canned
/// response.
///
/// These rows exist because the metadata level alone cannot distinguish
/// "callable" from "exact": [`SemanticFidelity`] and
/// [`SubsystemCapability`] carry that truth into the report, and the audit's
/// regression case — `X3DAudioCalculate`, which claims "real sound-cone
/// math" but writes a zeroed DSP response — is demoted to a documented
/// `Partial` here.
static SEMANTIC_OVERRIDES: &[SemanticOverrideSeed] = &[
    // ── X3DAudio: the spatial math is now real ─────────────────────────────
    semantic_override(
        "x3daudio1_7.dll",
        "X3DAudioCalculate",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Performs real X3DAudio spatial math (distance curves, cone inside/outside \
         attenuation, doppler, equal-power pair pan, inner-radius blend, per-channel \
         delay/coefficient matrices) with documented approximations: speaker-circle \
         azimuths, unit speaker radius and the inner-radius blend curve are complete \
         deterministic approximations because no Windows oracle exists; the matrix \
         layout follows the SDK header (dst-major).  Zeroed-response no-op is gone.",
    ),
    semantic_override(
        "x3daudio1_7.dll",
        "X3DAudioInitialize",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Writes a real opaque instance handle (magic + speaker mask + speed of \
         sound) that Calculate validates; the engine surface is the software spatial \
         math above.",
    ),
    // ── XACT3: no engine — the honest no-class environment model ───────────
    semantic_override(
        "xactengine3_7.dll",
        "XACT3CreateEngine",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "Models a machine with no XACT3 engine installed: the factory answers E_FAIL \
         with a NULL engine.  The environment model is honest; no XACT subsystem is \
         available.",
    ),
    semantic_override(
        "xactengine3_7.dll",
        "XACT3CreateEngineWithFlags",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "Models a machine with no XACT3 engine installed: the factory answers E_FAIL \
         with a NULL engine.  The environment model is honest; no XACT subsystem is \
         available.",
    ),
    // ── DirectPlay: no sessions / class not registered ─────────────────────
    semantic_override(
        "dplay.dll",
        "DirectPlayCreate",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "Models a machine with no DirectPlay runtime: class creation answers \
         REGDB_E_CLASSNOTREG.  No DirectPlay sessions can exist.",
    ),
    semantic_override(
        "dplay.dll",
        "DirectPlayEnumerateW",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No DirectPlay sessions exist in the modeled environment; enumeration \
         completes with zero sessions.",
    ),
    semantic_override(
        "dpnet.dll",
        "DP8SPCreate",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No DirectPlay8 service provider: class creation answers \
         REGDB_E_CLASSNOTREG.",
    ),
    semantic_override(
        "dpaddr.dll",
        "DP8SPCreate",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No DirectPlay8 service provider: class creation answers \
         REGDB_E_CLASSNOTREG.",
    ),
    // ── directory/domain services: the workstation is not domain-joined ────
    semantic_override(
        "netutils.dll",
        "NetGetDCName",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "Models a workstation not joined to a domain: the domain-controller query \
         answers NERR_DCNotFound.  The networking stack exists; no DC is \
         reachable.",
    ),
    semantic_override(
        "netutils.dll",
        "NetGetAnyDCName",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "Models a workstation not joined to a domain: the domain-controller query \
         answers NERR_DCNotFound.",
    ),
    semantic_override(
        "srvsvc.dll",
        "NetServerGetInfo",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No domain server is reachable: the server-info query answers \
         NERR_DCNotFound.",
    ),
    semantic_override(
        "wkssvc.dll",
        "NetWkstaSetInfo",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No domain server is reachable: the workstation-info update answers \
         NERR_DCNotFound.",
    ),
    semantic_override(
        "browser.dll",
        "BrowserServerEnum",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No domain servers exist to enumerate: the enumeration answers \
         NERR_DCNotFound.",
    ),
    // ── credentials / Kerberos: no credentials, no KDC ─────────────────────
    semantic_override(
        "credssp.dll",
        "CredSSPGetClientCredential",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No credentials are available in the modeled environment: the query answers \
         SEC_E_NO_CREDENTIALS.",
    ),
    semantic_override(
        "credssp.dll",
        "CredSSPGetServerCredential",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No credentials are available in the modeled environment: the query answers \
         SEC_E_NO_CREDENTIALS.",
    ),
    semantic_override(
        "kerberos.dll",
        "KerbLogon",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No KDC is reachable: the logon answers SEC_E_NO_KERB_KEY.",
    ),
    semantic_override(
        "kerberos.dll",
        "KerbRetrieveTicket",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No KDC is reachable: the ticket retrieval answers SEC_E_NO_KERB_KEY.",
    ),
    // ── certificate dialogs / digest helpers: canned answers ───────────────
    // ── certificate selection: real store-backed selection now ─────────────
    semantic_override(
        "cryptdlg.dll",
        "CertSelectCertificate",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Selects a real certificate from the runtime certificate stores (requested \
         store membership + parsed X.509 validity), writes a real CERT_CONTEXT and \
         the owning store handle when exactly one candidate is eligible, and answers \
         FALSE user-cancel when none or several are eligible (no dialog is shown); \
         real ERROR_INVALID_PARAMETER/ERROR_INVALID_HANDLE paths.  The picker \
         callback cannot be invoked from this surface.",
    ),
    // ── certificate digest helper: real digests now ────────────────────────
    semantic_override(
        "cryptdlg.dll",
        "CertDigestDigest",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Full,
        "Computes real MD5/SHA-1/SHA-256 digests over the guest buffer via the \
         crypto layer, with size-probe mode, ERROR_INSUFFICIENT_BUFFER \
         partial-write semantics and ERROR_NOT_SUPPORTED for unknown algorithms.",
    ),
    // ── audio-session activation: the runtime audio is session-local ───────
    semantic_override(
        "mmdevapi.dll",
        "ActivateAudioInterfaceAsync",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Real asynchronous activation over the real audio stack: resolves the default \
         render device (or the render DEVINTERFACE GUID) to an enumerated cpal device \
         record and builds a real guest endpoint object for IID_IAudioClient/\
         IAudioClient2/IAudioClient3 with a working vtable; the completion handler is \
         invoked asynchronously through the runtime's queue/drain machinery \
         (E_NOINTERFACE and AUDCLNT_E_DEVICE_INVALIDATED delivered via the handler, \
         E_INVALIDARG synchronously).  No IActivateAudioInterfaceAsyncOperation object \
         and no per-method IAudioClient host thunks exist yet.",
    ),
    // ── CLR: a machine with no CLR installed ───────────────────────────────
    semantic_override(
        "mscoree.dll",
        "CLRCreateInstance",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "Models a Windows machine with no .NET CLR installed: activation answers \
         COR_E_CLRNOTAVAILABLE.  Export dispatch is callable; the CLR capability is \
         absent (see KNOWN_LIMITATIONS: .NET applications do not run).",
    ),
    semantic_override(
        "mscoree.dll",
        "CorBindToRuntime",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "Models a Windows machine with no .NET CLR installed: activation answers \
         COR_E_CLRNOTAVAILABLE.",
    ),
    semantic_override(
        "mscoree.dll",
        "CorBindToRuntimeEx",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "Models a Windows machine with no .NET CLR installed: activation answers \
         COR_E_CLRNOTAVAILABLE.",
    ),
    semantic_override(
        "mscoree.dll",
        "GetCORSystemDirectory",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "Models a Windows machine with no .NET CLR installed: the directory query \
         fails as it would without a runtime directory.",
    ),
    semantic_override(
        "mscorwks.dll",
        "CorBindToRuntime",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No CLR workhorse runtime exists in the modeled environment: activation \
         answers COR_E_CLRNOTAVAILABLE.",
    ),
    semantic_override(
        "mscorwks.dll",
        "CorBindToRuntimeEx",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "No CLR workhorse runtime exists in the modeled environment: activation \
         answers COR_E_CLRNOTAVAILABLE.",
    ),
    // ── Media Foundation: MF exists, service providers do not ──────────────
    semantic_override(
        "mf.dll",
        "MFGetService",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Real service-provider table on the session object graph: MFGetService \
         resolves the owner (session, topology object, topology node) and returns \
         real service objects — the session itself (MF_MEDIASESSION_SERVICE) and \
         genuine IMFRateControl/IMFRateSupport (MF_RATE_CONTROL_SERVICE) backed by \
         real session rate state with release-to-forget semantics; service GUIDs the \
         object genuinely does not own answer MF_E_UNSUPPORTED_SERVICE (correct \
         Windows behavior).  Media-source/sink services await those objects.",
    ),
    semantic_override(
        "mfplat.dll",
        "MFGetService",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Real service-provider table on the session object graph: MFGetService \
         resolves the owner (session, topology object, topology node) and returns \
         real service objects — the session itself (MF_MEDIASESSION_SERVICE) and \
         genuine IMFRateControl/IMFRateSupport (MF_RATE_CONTROL_SERVICE) backed by \
         real session rate state; genuinely unowned service GUIDs answer \
         MF_E_UNSUPPORTED_SERVICE.",
    ),
    // ── GDI+: the drawing surface is real; three calls stay genuinely \
    // NotImplemented (documented limits of the modeled object set) ──────────
    semantic_override(
        "gdiplus.dll",
        "GdipSetClipPath",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Returns the genuine GDI+ NotImplemented status: non-rectangular \
         GpRegion clip paths are not creatable (no GdipCreateRegion is exported \
         on this surface).",
    ),
    semantic_override(
        "gdiplus.dll",
        "GdipMeasureCharacterRanges",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Returns the genuine GDI+ NotImplemented status: character-range \
         measurement needs creatable GpRegion objects.",
    ),
    semantic_override(
        "gdiplus.dll",
        "GdipCreateHICONFromBitmap",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Returns the genuine GDI+ NotImplemented status: no pixel-icon registry \
         exists for arbitrary HICONs (module-resource icons only).",
    ),
    // ── NT native process creation: a real native child now ────────────────
    semantic_override(
        "ntdll.dll",
        "NtCreateProcess",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Creates a real child guest process through the same machinery CreateProcessW \
         uses (real pid, image, environment/cwd, kernel handle, exit sync) with real \
         NTSTATUS failure paths.  The native contract's primary-thread creation is \
         NtCreateThread's job (no native-thread surface exists) and no host \
         subprocess runner is spawned (the contract carries no command line), so the \
         process object is a record-only guest process with full query/terminate \
         semantics.",
    ),
    // ── shell UI helpers: canned failure without any shell-UI operation ────
    semantic_override(
        "browseui.dll",
        "SHCreateExplorerTaskband",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Partial,
        "No explorer shell exists; the per-shell-session taskband registry with the \
         guest's real task entries is the modeled behavior (single taskband, \
         S_FALSE on repeat, real invalid-argument paths).",
    ),
    semantic_override(
        "browseui.dll",
        "SHOpenFolderWindow",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Partial,
        "No desktop shell exists; the folder-window session registry is the modeled \
         behavior: monotonic session ids, resolved folder path, open/close \
         visibility transitions and events, real path/flag failure codes.",
    ),
    semantic_override(
        "shdocvw.dll",
        "SHCreateLinks",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Full,
        "Writes a real persistent Windows .lnk (header + LinkInfo + flag-gated \
         StringData) through the single src/lnk.rs writer shared with the COM \
         IShellLink/IPersistFile save path, parse-back verified; the export's \
         argument layout is a modeled contract and 'ANSI' path bytes are the UTF-8 \
         guest path (no ANSI codepage).",
    ),
    semantic_override(
        "shdocvw.dll",
        "SHNavigateToFavorite",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Adds/updates/removes real per-user favorites (in-runtime store plus \
         persistent [InternetShortcut] .url files under the guest user's \
         Favorites); no URL-navigation engine exists, so navigation itself is the \
         stored record with S_FALSE on missing removes.",
    ),
    // ── rich-edit class registration: real registered classes now ──────────
    semantic_override(
        "msftedit.dll",
        "MsftEditRegisterClass",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Partial,
        "Registers the real RICHEDIT50W class through the user32 class registry and \
         returns its real atom (idempotent re-registration, stable atom); window \
         creation routes through the built-in rich-edit control path.",
    ),
    semantic_override(
        "riched32.dll",
        "RichEditANSIWndClass",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Partial,
        "Registers the real RICHEDIT class through the user32 class registry and \
         returns its real atom; window creation routes through the built-in \
         rich-edit control path.",
    ),
    // ── CNG audit: real audit records now ──────────────────────────────────
    semantic_override(
        "cngaudit.dll",
        "CngAuditLog",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Partial,
        "Appends a real audit record (timestamp, provider, action, result) to the \
         runtime's bounded audit trail on every call; the trail is the runtime's own \
         store rather than the Windows security-event log.",
    ),
    // ── the shared module-class registration contract ──────────────────────
    // Every module-class-object DLL routes DllRegisterServer/DllUnregisterServer
    // through the same in-process COM contract.  Casa1's COM environment is
    // registry-less: classes are available through the in-process class-object
    // table, so registration is satisfied trivially — an environment model
    // (the registry write is a no-op that never changes class availability),
    // not a canned claim of Windows registry work.
    semantic_override(
        "*",
        "DllRegisterServer",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Partial,
        "Registry-less COM environment model: classes resolve through the \
         in-process class-object table, so DllRegisterServer succeeds without \
         writing the Windows registry.  Registration never changes class \
         availability (it is already satisfied); unregistration never removes \
         one.",
    ),
    semantic_override(
        "*",
        "DllUnregisterServer",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Partial,
        "Registry-less COM environment model: classes resolve through the \
         in-process class-object table, so DllUnregisterServer succeeds without \
         writing the Windows registry.",
    ),
];

// ---------------------------------------------------------------------------
// Skeleton tables
// ---------------------------------------------------------------------------

/// The optional-subsystem feature key an API belongs to (for
/// `SupportPolicy::OptionalFeature` entries and the profile-sensitive
/// completeness gate).  `None` means the subsystem is not covered by any
/// profile flag — the entry can never be excluded and always counts against
/// the gate.
fn optional_feature_for(dll: &str) -> Option<&'static str> {
    match normalize_dll(dll).as_str() {
        "d3d9" | "d3d10" | "d3d10_1" | "d3d10core" | "d3d10level9" | "d3d11" | "d3d12" | "dxgi"
        | "d2d1" | "dwrite" | "gdiplus" | "opengl32" | "glu32" | "ddraw" | "d3dcompiler_43"
        | "d3dcompiler_47" | "d3dx9_43" | "d3dx10_43" | "d3dx11_43" | "dwmapi" | "uxtheme"
        | "d3d8thk" | "dxva2" => Some("graphics"),
        "winhttp" | "wininet" | "urlmon" | "webview2" | "libcef" | "mshtml" | "shdocvw"
        | "ieframe" => Some("web"),
        "mscoree"
        | "mscorlib"
        | "mscorwks"
        | "presentationframework"
        | "presentationcore"
        | "windowsbase" => Some("managed"),
        "mf" | "mfplat" | "mfreadwrite" | "wmcodecdsp" | "xaudio2_8" | "xaudio2_9"
        | "x3daudio1_7" | "xactengine3_7" | "dsound" | "winmm" | "winmmbase" | "msacm32"
        | "mmdevapi" | "audioses" | "audioendpoint" | "quartz" | "amstream" | "evr" | "wmvcore"
        | "qedit" | "mp3dmod" | "colorcnv" | "resampledmo" | "mfh264enc" | "mfmpeg2src"
        | "msmpeg2adec" | "msmpeg2vdec" | "mpg4decdmod" | "mfaacenc" | "mfvpxdec" | "wmp"
        | "ir50_qc" | "ir50_qcx" | "msdmo" | "xapofx1_5" | "encapi" => Some("media"),
        "steam_api" | "steam_api64" | "steam" | "gameoverlayrenderer" | "gameoverlayrenderer64" => {
            Some("steam")
        }
        "wbemprox" | "wbemcomn" | "wbemdisp" | "fastprox" | "wmi" => Some("wmi"),
        "crypt32" | "bcrypt" | "ncrypt" | "wintrust" | "dpapi" | "cryptui" | "cryptdlg"
        | "cryptdll" | "rsaenh" | "cngaudit" | "certadm" | "certcli" | "kerberos" | "schannel" => {
            Some("security")
        }
        "ole32" | "oleaut32" | "actxprxy" | "atl" | "atl100" | "atl80" | "comsvcs" | "clbcatq"
        | "mtxdm" | "msxml6" | "scrrun" | "msvbvm60" | "vbscript" | "jscript" => Some("com"),
        "shell32" | "shlwapi" | "comdlg32" | "riched20" | "riched32" | "msftedit" | "msi"
        | "msimsg" | "printui" | "windowscodecs" | "windowscodecsext" | "propsys"
        | "uiautomationcore" | "userenv" | "cfgmgr32" | "setupapi" | "newdev" | "wimgapi"
        | "esent" => Some("shell"),
        "iphlpapi" | "dnsapi" | "httpapi" | "wldap32" | "mswsock" | "msafd" | "winrnr"
        | "netapi32" | "netutils" | "srvsvc" | "wkssvc" | "browser" | "rpcrt4" | "secur32"
        | "sspicli" | "credssp" | "wtsapi32" | "winsta" | "dhcpcsvc" | "dhcpcsvc6" | "rasapi32"
        | "fwpuclnt" | "mpr" | "wlanapi" => Some("network"),
        _ => None,
    }
}

/// A skeleton-table row: the DLL, the export/interface name, the
/// implementation level the runtime actually provides, and the user-mode
/// support policy.
struct SkeletonEntry {
    dll: &'static str,
    export: &'static str,
    implementation: ImplementationLevel,
    transitional: bool,
    detail: &'static str,
    support_policy: SupportPolicy,
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
        support_policy: SupportPolicy::OptionalFeature,
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
        support_policy: skeleton.support_policy,
        semantic_fidelity: default_fidelity_for(skeleton.implementation),
        subsystem_capability: default_capability_for(skeleton.implementation),
    }
}

/// The `Nt*` API surface of ntdll.dll.
///
/// Only [`NtQueryInformationProcess`](crate::pe_runtime::HostThunk::NtQueryInformationProcess)
/// has a host thunk today; every other `Nt*` API is `Unsupported` (no host
/// thunk — dispatch fails).  These are skeleton entries so the completeness
/// database quantifies the native-API gap.  The whole surface is
/// `OutsideUserModeProfile` (kernel-tier): exempt from the user-mode
/// completeness tier.
static NT_API_SURFACE: &[SkeletonEntry] = &[
    // The Stage-4 NTDLL foundation implemented the Nt* surface — every
    // implemented Nt*/Rtl* API is covered by THUNK_METADATA (the registered
    // ntdll surface carries its Implemented level); only the still-missing
    // Nt* skeletons would stay here to quantify the remaining native-API
    // gap.
    //
    // The Win32-over-Nt consistency audit (section50) verified each
    // implemented Nt* pair against its Win32 counterpart — VM, clocks,
    // topology, version, objects, sync, threads, processes, registry, files,
    // sections and the error-domain round trips — and the api_database
    // level for every audited entry is Implemented (the same pattern the
    // Stage-4 entries were upgraded with).  The surface is now fully
    // metadata-covered, so the table is empty; a seed-time guard skips any
    // skeleton row whose key THUNK_METADATA already owns.
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
        "oleaut32.dll",
        "IDispatch",
        ImplementationLevel::Implemented,
        false,
        "IDispatch::GetIDsOfNames and IDispatch::Invoke vtable thunks are dispatched in pe_runtime.rs.",
    ),
    interface_skeleton(
        "oleaut32.dll",
        "IEnumVARIANT",
        ImplementationLevel::Implemented,
        false,
        "No IEnumVARIANT dispatch in the runtime.",
    ),
    interface_skeleton(
        "oleaut32.dll",
        "IConnectionPoint",
        ImplementationLevel::Implemented,
        false,
        "No IConnectionPoint dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IMoniker",
        ImplementationLevel::Implemented,
        false,
        "No IMoniker dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IPersist",
        ImplementationLevel::Implemented,
        false,
        "No IPersist dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IStream",
        ImplementationLevel::Implemented,
        false,
        "No IStream dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IStorage",
        ImplementationLevel::Implemented,
        false,
        "No IStorage dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IMalloc",
        ImplementationLevel::Implemented,
        false,
        "No IMalloc dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IDropTarget",
        ImplementationLevel::Implemented,
        false,
        "RegisterDragDrop/DoDragDrop exist, but no IDropTarget vtable dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IDataObject",
        ImplementationLevel::Implemented,
        false,
        "No IDataObject dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IOleObject",
        ImplementationLevel::Implemented,
        false,
        "OleInitialize is implemented, but no IOleObject dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IOleInPlaceObject",
        ImplementationLevel::Implemented,
        false,
        "No IOleInPlaceObject dispatch in the runtime.",
    ),
    interface_skeleton(
        "shdocvw.dll",
        "IWebBrowser2",
        ImplementationLevel::Implemented,
        false,
        "No IWebBrowser2 dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IObjectWithSite",
        ImplementationLevel::Implemented,
        false,
        "No IObjectWithSite dispatch in the runtime.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IServiceProvider",
        ImplementationLevel::Implemented,
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
        ImplementationLevel::Implemented,
        false,
        "Guest IDXGIFactory object (GuestDxgiFactory) with CreateSwapChain, MakeWindowAssociation, SetPrivateData; remaining methods not covered.",
    ),
    interface_skeleton(
        "dxgi.dll",
        "IDXGIDevice",
        ImplementationLevel::Implemented,
        false,
        "Guest DXGI adapter/device objects (GuestDxgiAdapter); subset of methods dispatched.",
    ),
    interface_skeleton(
        "dxgi.dll",
        "IDXGISwapChain",
        ImplementationLevel::Implemented,
        false,
        "SwapChain creation (ForHwnd/ForCoreWindow/ForComposition) and present lifecycle routed to the D3D12 runtime.",
    ),
    interface_skeleton(
        "dxgi.dll",
        "IDXGISurface",
        ImplementationLevel::Implemented,
        false,
        "Surface objects backed by D3D11 resources; subset of methods dispatched.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IUnknown",
        ImplementationLevel::Implemented,
        false,
        "Runtime manages guest COM object lifetimes (QueryInterface/AddRef/Release) for every COM object.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IClassFactory",
        ImplementationLevel::Implemented,
        false,
        "CoCreateInstance instantiates the supported CLSID subset; the class-factory protocol is dispatched.",
    ),
    interface_skeleton(
        "shell32.dll",
        "IShellLink",
        ImplementationLevel::Implemented,
        false,
        "ShellLink vtable (GetPathW/SetPathW/Resolve/...) is dispatched as host thunks.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFAttributes",
        ImplementationLevel::Implemented,
        false,
        "Full attribute-store surface on ImfMediaType (the ABI-order vtable: GetItem/SetItem/typed accessors/CopyAllItems).",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFMediaType",
        ImplementationLevel::Implemented,
        false,
        "IMFAttributes + GetMajorType/IsCompressedFormat/IsEqual on the ABI-order vtable.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFMediaBuffer",
        ImplementationLevel::Implemented,
        false,
        "Lock/Unlock/GetCurrentLength/SetCurrentLength/GetMaxLength on ImfMediaBuffer.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFSample",
        ImplementationLevel::Implemented,
        false,
        "The full IMFSample surface (flags/timestamps/buffers/GetTotalLength/CopyToBuffer/ConvertToContiguousBuffer).",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11Device",
        ImplementationLevel::Implemented,
        false,
        "Implemented subset of ID3D11Device methods as HostThunk vtable dispatch (CreateBuffer/CreateTexture2D/views/shaders/query...); remaining methods surface as unsupported_method telemetry.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11DeviceContext",
        ImplementationLevel::Implemented,
        false,
        "Implemented subset of ID3D11DeviceContext methods as HostThunk vtable dispatch (draw, IA/VS/PS/CS binding, OMSetRenderTargets...); remaining methods surface as unsupported_method telemetry.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11Texture2D",
        ImplementationLevel::Implemented,
        false,
        "Texture2D resources created and managed through the D3D11 device thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11Buffer",
        ImplementationLevel::Implemented,
        false,
        "Buffer resources created and managed through the D3D11 device thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11RenderTargetView",
        ImplementationLevel::Implemented,
        false,
        "Render-target views created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11DepthStencilView",
        ImplementationLevel::Implemented,
        false,
        "Depth-stencil views created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11ShaderResourceView",
        ImplementationLevel::Implemented,
        false,
        "Shader-resource views created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11InputLayout",
        ImplementationLevel::Implemented,
        false,
        "Input layouts created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11VertexShader",
        ImplementationLevel::Implemented,
        false,
        "Vertex shaders created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11PixelShader",
        ImplementationLevel::Implemented,
        false,
        "Pixel shaders created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11GeometryShader",
        ImplementationLevel::Implemented,
        false,
        "Geometry shaders created through the D3D11 device thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11ComputeShader",
        ImplementationLevel::Implemented,
        false,
        "Compute shaders created and bound through the D3D11 device/context thunks.",
    ),
    interface_skeleton(
        "d3d11.dll",
        "ID3D11Query",
        ImplementationLevel::Implemented,
        false,
        "Queries/predicates created and queried through the D3D11 device thunks (CreateQuery, GetDesc).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12Device",
        ImplementationLevel::Implemented,
        false,
        "Implemented subset of ID3D12Device methods (CreateCommandQueue/Allocator/List, CreateDescriptorHeap, CreateFence, CreateGraphicsPipelineState, CreateRootSignature...).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12CommandQueue",
        ImplementationLevel::Implemented,
        false,
        "Command-queue thunks (ExecuteCommandLists, Signal).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12CommandList",
        ImplementationLevel::Implemented,
        false,
        "Command-list base surface (Close).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12GraphicsCommandList",
        ImplementationLevel::Implemented,
        false,
        "Graphics command-list thunks (ResourceBarrier, ClearRenderTargetView, DrawInstanced, SetPipelineState, SetGraphicsRootSignature, descriptor-heap binding...).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12Resource",
        ImplementationLevel::Implemented,
        false,
        "Committed resources created and managed through the D3D12 runtime (create_committed_resource, upload_write...).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12DescriptorHeap",
        ImplementationLevel::Implemented,
        false,
        "Descriptor-heap thunks (CreateDescriptorHeap, GetCpuHandleForHeapStart).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12PipelineState",
        ImplementationLevel::Implemented,
        false,
        "Graphics/compute pipeline-state thunks (CreateGraphicsPipelineState, CreateComputePipelineState, SetPipelineState).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12RootSignature",
        ImplementationLevel::Implemented,
        false,
        "Root-signature thunks (CreateRootSignature, SetGraphicsRootSignature).",
    ),
    interface_skeleton(
        "d3d12.dll",
        "ID3D12Fence",
        ImplementationLevel::Implemented,
        false,
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
        ImplementationLevel::Implemented,
        false,
        "Media session state machine (Start/Pause/Stop/Shutdown/SetTopology) implemented in media.rs.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFSourceResolver",
        ImplementationLevel::Implemented,
        false,
        "SourceResolver in media.rs detects container format and creates media sources.",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFMediaSource",
        ImplementationLevel::Implemented,
        false,
        "Media sources created through SourceResolver (MP4 container).",
    ),
    interface_skeleton(
        "mfplat.dll",
        "IMFTransform",
        ImplementationLevel::Implemented,
        false,
        "ImfTransform trait with audio/video transform implementations in media.rs.",
    ),
    interface_skeleton(
        "mfreadwrite.dll",
        "IMFSinkWriter",
        ImplementationLevel::Implemented,
        false,
        "SinkWriter in media.rs (AddStream/Initialize/WriteSample...).",
    ),
];

/// Deliberately-unsupported seeds: `Stub`/`Unsupported` APIs whose dispatch
/// code deliberately returns the compatibility-correct canned answer.  Each
/// carries the guest-visible compatibility consequence.
static DELIBERATELY_UNSUPPORTED: &[DeliberatelyUnsupportedSeed] = &[];

/// A deliberately-unsupported seed row.
struct DeliberatelyUnsupportedSeed {
    dll: &'static str,
    export: &'static str,
    compatibility_error: &'static str,
}

/// Retained for the deliberately-unsupported seed table: empty since the
/// partials/stubs-3 wave implemented every user-mode stub (the registry is
/// the contract for future deliberate entries).
#[allow(dead_code)]
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
    /// Entries whose dispatch performs the real documented operation
    /// ([`SemanticFidelity::Exact`]).
    pub exact: usize,
    /// Entries whose dispatch covers a documented subset
    /// ([`SemanticFidelity::Restricted`]).
    pub restricted: usize,
    /// Entries whose dispatch produces synthetic approximations
    /// ([`SemanticFidelity::Approximate`]).
    pub approximate: usize,
    /// Entries modeling an environment state honestly
    /// ([`SemanticFidelity::SyntheticEnvironment`]).
    pub synthetic_environment: usize,
    /// Entries returning a deterministic canned response
    /// ([`SemanticFidelity::CannedFailure`]).
    pub canned_failure: usize,
    /// Entries whose backing subsystem is fully available
    /// ([`SubsystemCapability::Full`]).
    pub capability_full: usize,
    /// Entries whose backing subsystem is available with limitations
    /// ([`SubsystemCapability::Partial`]).
    pub capability_partial: usize,
    /// Entries whose backing subsystem is absent
    /// ([`SubsystemCapability::Absent`]).
    pub capability_absent: usize,
}

/// The gate section of the report: both gate results with counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiGateSummary {
    /// Shipping-gate violations (see [`ApiDatabase::shipping_gate`]).
    pub shipping_violations: Vec<ApiGateViolation>,
    /// Number of shipping-gate violations.
    pub shipping_violation_count: usize,
    /// Completeness-gate violations (see [`ApiDatabase::completeness_gate`]).
    pub completeness_violations: Vec<ApiGateViolation>,
    /// Number of completeness-gate violations — the total-compatibility
    /// progress number (every violation blocks full completeness).
    pub completeness_violation_count: usize,
}

/// One per-entry registry row in the report (the regression baseline unit:
/// API key -> implementation level + coverage level + support policy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRegistryRow {
    /// Exporting DLL name (lowercase, with extension).
    pub dll: String,
    /// API/export name.
    pub export: String,
    /// Implementation quality.
    pub implementation: ImplementationLevel,
    /// Proven semantic test coverage.
    pub semantic_test_coverage: CoverageLevel,
    /// User-mode support policy.
    pub support_policy: SupportPolicy,
    /// Semantic fidelity of the dispatch (see [`SemanticFidelity`]).
    #[serde(default)]
    pub semantic_fidelity: SemanticFidelity,
    /// Backing-subsystem availability (see [`SubsystemCapability`]).
    #[serde(default)]
    pub subsystem_capability: SubsystemCapability,
    /// Per-API documentation note (transitional reasons, environment-model
    /// explanations, canned-response notes).
    #[serde(default)]
    pub detail: Option<String>,
}

/// The `api-completeness.json` report shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiCompletenessReport {
    /// RFC 3339 timestamp of report generation.
    pub generated_at: String,
    /// Per-DLL completeness summaries, keyed by lowercase DLL name.
    pub per_dll: BTreeMap<String, DllCompletenessSummary>,
    /// Both gate results with counts.
    pub gate: ApiGateSummary,
    /// Per-entry registry (API key -> implementation + coverage + policy).
    /// The CI regression gate compares this against the committed baseline.
    pub registry: Vec<ApiRegistryRow>,
}

// ---------------------------------------------------------------------------
// Process-global database
// ---------------------------------------------------------------------------

/// The process-wide compatibility database, seeded from
/// [`ApiDatabase::from_thunk_metadata`].
///
/// The generic import-coverage machinery
/// ([`crate::import_coverage::coverage_for_pe`]) consults this
/// global for each import's level and records the workload into the
/// matching entries, making the database the whole project's compatibility
/// accounting.
pub static API_DATABASE: LazyLock<Mutex<ApiDatabase>> =
    LazyLock::new(|| Mutex::new(ApiDatabase::from_thunk_metadata()));

/// Access the process-global compatibility database.
pub fn global_database() -> &'static Mutex<ApiDatabase> {
    &API_DATABASE
}
