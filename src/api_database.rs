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
//! - Method-level accounting for COM-style interfaces
//!   ([`InterfaceMethodEntry`]): every `(DLL, interface, method)` row carries
//!   its own implementation/fidelity/capability/coverage status, seeded from
//!   the object vtables the runtime actually allocates (D3D11, D3D12, DXGI,
//!   COM/OLE, Media Foundation, browser).  Aggregate interface rows are
//!   computed as the worst required child status — never inherited defaults —
//!   and [`ApiDatabase::interface_completeness_gate`] rejects an aggregate
//!   that overstates its children, a known interface with no method rows, or
//!   a method row for an unknown interface.
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

use crate::api_coverage::{COVERAGE_EVIDENCE, method_coverage_evidence_for};
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

/// A single `(DLL, interface, method)` compatibility-accounting record.
///
/// COM-style interfaces are not a single dispatch: an allocated vtable can
/// expose hundreds of method slots, some real and some unsupported
/// telemetry-only fallthroughs.  The aggregate interface row is only as good
/// as its worst required method, so every method carries its own
/// implementation/fidelity/capability/coverage status.  Methods without
/// method-level proof are seeded `Partial`/`Unsupported` with `Restricted`
/// fidelity and `Partial` capability — never `Exact`/`Full`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceMethodEntry {
    /// Exporting DLL name (lowercase, with extension).
    pub dll: String,
    /// COM/OLE interface name (e.g. `"ID3D11Device"`).
    pub interface: String,
    /// Method name within the interface vtable.
    pub method: String,
    /// Whether the method is part of the interface's required base surface
    /// (as opposed to a later interface-version extension).  Only required
    /// methods participate in the aggregate status.
    pub required: bool,
    /// Implementation quality of this method.
    pub implementation: ImplementationLevel,
    /// Semantic fidelity of this method (see [`SemanticFidelity`]).
    pub semantic_fidelity: SemanticFidelity,
    /// Backing-subsystem availability for this method (see
    /// [`SubsystemCapability`]).
    pub subsystem_capability: SubsystemCapability,
    /// Proven semantic test coverage for this method.
    pub semantic_test_coverage: CoverageLevel,
    /// Optional documentation note (what is missing or why the method is
    /// unsupported).
    #[serde(default)]
    pub detail: Option<String>,
    /// The compiled contract that proved this method, when one exists.
    #[serde(default)]
    pub evidence_id: Option<String>,
}

impl InterfaceMethodEntry {
    /// Create a method row.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dll: impl Into<String>,
        interface: impl Into<String>,
        method: impl Into<String>,
        required: bool,
        implementation: ImplementationLevel,
        semantic_fidelity: SemanticFidelity,
        subsystem_capability: SubsystemCapability,
        semantic_test_coverage: CoverageLevel,
    ) -> Self {
        Self {
            dll: dll.into(),
            interface: interface.into(),
            method: method.into(),
            required,
            implementation,
            semantic_fidelity,
            subsystem_capability,
            semantic_test_coverage,
            detail: None,
            evidence_id: None,
        }
    }

    /// Whether this method deviates from exact/full semantics.
    pub fn is_deviation(&self) -> bool {
        self.semantic_fidelity != SemanticFidelity::Exact
            || self.subsystem_capability != SubsystemCapability::Full
    }
}

/// The aggregate status computed from an interface's required method rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAggregateStatus {
    /// Number of method rows belonging to the interface.
    pub method_count: usize,
    /// Number of required method rows (the ones the aggregate is computed
    /// from; `0` means the aggregate fell back to every row).
    pub required_count: usize,
    /// Worst implementation status across the considered methods.
    pub implementation: ImplementationLevel,
    /// Worst semantic fidelity across the considered methods.
    pub semantic_fidelity: SemanticFidelity,
    /// Worst subsystem capability across the considered methods.
    pub subsystem_capability: SubsystemCapability,
    /// Weakest semantic test coverage across the considered methods.
    pub semantic_test_coverage: CoverageLevel,
    /// `true` only when every considered method is semantically proven
    /// (Differential or Conformance coverage).  This is the interface's
    /// method-level proof state, independent of its worst-child
    /// fidelity/capability.
    pub proven: bool,
    /// Required methods that still lack semantic proof, in vtable order.
    /// Empty when [`InterfaceAggregateStatus::proven`] is `true`.
    pub unproven_methods: Vec<String>,
}

/// Severity ordering for [`ImplementationLevel`] (higher is worse).
const fn implementation_severity(level: ImplementationLevel) -> u8 {
    match level {
        ImplementationLevel::Implemented => 0,
        ImplementationLevel::Partial => 1,
        ImplementationLevel::Stub => 2,
        ImplementationLevel::Unsupported => 3,
    }
}

/// Whether a method carries real semantic proof (not merely unit or
/// scenario coverage).
fn has_semantic_proof(method: &InterfaceMethodEntry) -> bool {
    matches!(
        method.semantic_test_coverage,
        CoverageLevel::Differential | CoverageLevel::Conformance
    )
}

/// Compute the worst child status over an interface's method rows.
///
/// Required methods define the aggregate when any exist; interfaces whose
/// rows are all optional fall back to every row.  Fidelity and capability are
/// the worst (highest-ordinal) child value, coverage the weakest
/// (lowest-ordinal) value, and implementation the most severe child level.
/// The aggregate is `proven` only when every considered method has
/// Differential/Conformance proof; otherwise the unproven method names are
/// reported.
fn aggregate_interface_status(
    methods: &[&InterfaceMethodEntry],
) -> Option<InterfaceAggregateStatus> {
    if methods.is_empty() {
        return None;
    }
    let required_count = methods.iter().filter(|method| method.required).count();
    let considered: Vec<&InterfaceMethodEntry> = if required_count == 0 {
        methods.to_vec()
    } else {
        methods
            .iter()
            .copied()
            .filter(|method| method.required)
            .collect()
    };
    let mut implementation = ImplementationLevel::Implemented;
    let mut semantic_fidelity = SemanticFidelity::Exact;
    let mut subsystem_capability = SubsystemCapability::Full;
    let mut semantic_test_coverage = CoverageLevel::Conformance;
    for method in &considered {
        if implementation_severity(method.implementation) > implementation_severity(implementation)
        {
            implementation = method.implementation;
        }
        if method.semantic_fidelity > semantic_fidelity {
            semantic_fidelity = method.semantic_fidelity;
        }
        if method.subsystem_capability > subsystem_capability {
            subsystem_capability = method.subsystem_capability;
        }
        if method.semantic_test_coverage < semantic_test_coverage {
            semantic_test_coverage = method.semantic_test_coverage;
        }
    }
    let unproven_methods: Vec<String> = considered
        .iter()
        .filter(|method| !has_semantic_proof(method))
        .map(|method| method.method.clone())
        .collect();
    Some(InterfaceAggregateStatus {
        method_count: methods.len(),
        required_count,
        implementation,
        semantic_fidelity,
        subsystem_capability,
        semantic_test_coverage,
        proven: unproven_methods.is_empty(),
        unproven_methods,
    })
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
    /// An aggregate interface row claims better fidelity/capability than its
    /// worst required method child.
    InterfaceAggregateOverstatesChildren,
    /// A known COM-style interface has no method-level rows, so its aggregate
    /// status cannot be derived from children.
    InterfaceMethodRowsMissing,
    /// A method row names an interface that has no seeded vtable method list.
    InterfaceUnknown,
    /// An interface still claims Exact fidelity and/or Full capability while
    /// at least one required method has no Differential/Conformance proof.
    InterfaceClaimsUnprovenMethods,
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
    /// Method-level accounting rows for COM-style interfaces.
    interface_methods: Vec<InterfaceMethodEntry>,
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

    /// Append a method-level row for a COM-style interface.
    pub fn add_interface_method(&mut self, method: InterfaceMethodEntry) {
        self.interface_methods.push(method);
    }

    /// All method-level rows, in insertion order.
    pub fn interface_methods(&self) -> &[InterfaceMethodEntry] {
        &self.interface_methods
    }

    /// Look up a single method row by `(DLL, interface, method)`.
    ///
    /// DLL/interface/method matching is case-insensitive and tolerates the
    /// `.dll` suffix on the DLL side.
    pub fn lookup_interface_method(
        &self,
        dll: &str,
        interface: &str,
        method: &str,
    ) -> Option<&InterfaceMethodEntry> {
        let dll_key = normalize_dll(dll);
        self.interface_methods.iter().find(|entry| {
            normalize_dll(&entry.dll) == dll_key
                && entry.interface.eq_ignore_ascii_case(interface)
                && entry.method.eq_ignore_ascii_case(method)
        })
    }

    /// Iterate over every method row of one interface.
    pub fn methods_for_interface(
        &self,
        dll: &str,
        interface: &str,
    ) -> impl Iterator<Item = &InterfaceMethodEntry> + '_ {
        let dll_key = normalize_dll(dll);
        let interface_key = interface.to_ascii_lowercase();
        self.interface_methods.iter().filter(move |entry| {
            normalize_dll(&entry.dll) == dll_key
                && entry.interface.eq_ignore_ascii_case(&interface_key)
        })
    }

    /// The aggregate status derived from an interface's method rows.
    ///
    /// Returns `None` when the interface has no rows at all.  Required
    /// methods define the aggregate; if every row is optional the aggregate
    /// falls back to all rows.
    pub fn interface_aggregate_status(
        &self,
        dll: &str,
        interface: &str,
    ) -> Option<InterfaceAggregateStatus> {
        let methods: Vec<&InterfaceMethodEntry> =
            self.methods_for_interface(dll, interface).collect();
        aggregate_interface_status(&methods)
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

    /// The interface-completeness gate for COM-style interfaces.
    ///
    /// Fails when:
    ///
    /// 1. An aggregate interface row's `semantic_fidelity` or
    ///    `subsystem_capability` is better than the worst status of its
    ///    required method rows (the aggregate overstates its children).
    ///    Understated aggregates are conservative and do not fail.
    /// 2. A known interface has no method-level rows, so its aggregate status
    ///    cannot be derived.
    /// 3. A method row names an interface that has no seeded vtable method
    ///    list (an unknown interface cannot be accounted for).
    pub fn interface_completeness_gate(&self) -> Vec<ApiGateViolation> {
        let mut violations = Vec::new();
        let known: std::collections::BTreeSet<(String, String)> = INTERFACE_METHOD_SURFACE
            .iter()
            .map(|interface| {
                (
                    normalize_dll(interface.dll),
                    interface.interface.to_ascii_lowercase(),
                )
            })
            .collect();

        let mut reported_unknown: std::collections::BTreeSet<(String, String)> =
            std::collections::BTreeSet::new();
        for method in &self.interface_methods {
            let key = (
                normalize_dll(&method.dll),
                method.interface.to_ascii_lowercase(),
            );
            if !known.contains(&key) && reported_unknown.insert(key) {
                violations.push(ApiGateViolation {
                    dll: method.dll.clone(),
                    export: method.interface.clone(),
                    kind: ApiGateViolationKind::InterfaceUnknown,
                    message: format!(
                        "{}!{} has method-level rows but no seeded vtable method list — \
                         add the interface to the dispatch metadata before accounting for \
                         its methods",
                        method.dll, method.interface
                    ),
                });
            }
        }

        for interface in INTERFACE_METHOD_SURFACE {
            let Some(entry) = self.entries.iter().find(|entry| {
                normalize_dll(&entry.dll) == normalize_dll(interface.dll)
                    && entry.export.eq_ignore_ascii_case(interface.interface)
            }) else {
                continue;
            };
            let methods: Vec<&InterfaceMethodEntry> = self
                .methods_for_interface(interface.dll, interface.interface)
                .collect();
            let Some(aggregate) = aggregate_interface_status(&methods) else {
                violations.push(ApiGateViolation {
                    dll: entry.dll.clone(),
                    export: entry.export.clone(),
                    kind: ApiGateViolationKind::InterfaceMethodRowsMissing,
                    message: format!(
                        "{}!{} is a known interfaced surface with no method-level rows — \
                         its aggregate status cannot be derived from children",
                        entry.dll, entry.export
                    ),
                });
                continue;
            };
            let fidelity_overstated = entry.semantic_fidelity < aggregate.semantic_fidelity;
            let capability_overstated = entry.subsystem_capability < aggregate.subsystem_capability;
            if fidelity_overstated {
                violations.push(ApiGateViolation {
                    dll: entry.dll.clone(),
                    export: entry.export.clone(),
                    kind: ApiGateViolationKind::InterfaceAggregateOverstatesChildren,
                    message: format!(
                        "{}!{} aggregate fidelity {:?} overstates its worst required method \
                         child {:?}",
                        entry.dll,
                        entry.export,
                        entry.semantic_fidelity,
                        aggregate.semantic_fidelity
                    ),
                });
            }
            if capability_overstated {
                violations.push(ApiGateViolation {
                    dll: entry.dll.clone(),
                    export: entry.export.clone(),
                    kind: ApiGateViolationKind::InterfaceAggregateOverstatesChildren,
                    message: format!(
                        "{}!{} aggregate capability {:?} overstates its worst required method \
                         child {:?}",
                        entry.dll,
                        entry.export,
                        entry.subsystem_capability,
                        aggregate.subsystem_capability
                    ),
                });
            }
            let claims_exact_or_full = entry.semantic_fidelity == SemanticFidelity::Exact
                || entry.subsystem_capability == SubsystemCapability::Full;
            if !fidelity_overstated
                && !capability_overstated
                && claims_exact_or_full
                && !aggregate.proven
            {
                violations.push(ApiGateViolation {
                    dll: entry.dll.clone(),
                    export: entry.export.clone(),
                    kind: ApiGateViolationKind::InterfaceClaimsUnprovenMethods,
                    message: format!(
                        "{}!{} claims exact/full semantics but {} required method(s) lack \
                         semantic proof: {}",
                        entry.dll,
                        entry.export,
                        aggregate.unproven_methods.len(),
                        aggregate.unproven_methods.join(", ")
                    ),
                });
            }
        }
        violations
    }

    /// Seed the method-level accounting rows from the runtime's actual
    /// vtable/dispatch metadata and re-derive every aggregate interface row
    /// from its required children.
    ///
    /// The aggregate interface row's fidelity and capability are replaced by
    /// the worst required method status — `Exact`/`Full` only when every
    /// required method is `Exact`/`Full`, otherwise `Restricted`/`Partial`.
    /// The aggregate's implementation level and coverage evidence stay the
    /// export-level values (dispatch callability and interface-level
    /// evidence); method rows carry their own status.
    /// Methods with a documented, tested restriction keep Restricted/Partial.
    /// Everything else that is dispatched and proven is Exact/Full.
    fn method_has_documented_restriction(interface: &str, method: &str) -> bool {
        // Only methods whose semantics the runtime genuinely cannot provide on
        // Metal stay restricted. Everything else is Exact/Full.
        matches!(
            (interface, method),
            // Reserved vtable slot with no runtime semantics.
            ("IMFTransform", "UnsupportedSlot19")
                // Metal has no foreign-address heaps, meta-commands, or tiled
                // resource queries; these map to no host primitive.
                | ("ID3D12Device", "OpenExistingHeapFromAddress")
                | ("ID3D12Device", "OpenExistingHeapFromFileMapping")
                | ("ID3D12Device", "CreateProtectedResourceSession")
                | ("ID3D12Device", "CreateMetaCommand")
                | ("ID3D12Device", "EnumerateMetaCommands")
                | ("ID3D12Device", "EnumerateMetaCommandParameters")
                | ("ID3D12Device", "GetResourceTiling")
        )
    }

    pub fn apply_interface_method_surface(&mut self) {
        for interface in INTERFACE_METHOD_SURFACE {
            for method in interface.methods {
                let evidence =
                    method_coverage_evidence_for(interface.dll, interface.interface, method.method);
                // A real dispatch plus a compiled proof is Implemented; fidelity
                // and capability stay conservative until a method-specific
                // exactness claim exists.  No dispatch is Unsupported.
                let implementation = match method.dispatch {
                    MethodDispatch::Dispatched if evidence.is_some() => {
                        ImplementationLevel::Implemented
                    }
                    MethodDispatch::Dispatched => ImplementationLevel::Partial,
                };
                let restricted =
                    Self::method_has_documented_restriction(interface.interface, method.method);
                let (fidelity, capability, coverage) = if evidence.is_some() && !restricted {
                    (
                        SemanticFidelity::Exact,
                        SubsystemCapability::Full,
                        CoverageLevel::Conformance,
                    )
                } else {
                    (
                        SemanticFidelity::Restricted,
                        SubsystemCapability::Partial,
                        CoverageLevel::None,
                    )
                };
                self.interface_methods.push(InterfaceMethodEntry {
                    dll: interface.dll.to_string(),
                    interface: interface.interface.to_string(),
                    method: method.method.to_string(),
                    required: method.required,
                    implementation,
                    semantic_fidelity: fidelity,
                    subsystem_capability: capability,
                    semantic_test_coverage: evidence.map(|row| row.level).unwrap_or(coverage),
                    detail: Some(method.detail.to_string()),
                    evidence_id: evidence.map(|row| row.evidence_id.to_string()),
                });
            }
            let methods: Vec<&InterfaceMethodEntry> = self
                .interface_methods
                .iter()
                .filter(|method| {
                    normalize_dll(&method.dll) == normalize_dll(interface.dll)
                        && method.interface.eq_ignore_ascii_case(interface.interface)
                })
                .collect();
            let aggregate = aggregate_interface_status(&methods)
                .expect("every seeded interface has at least one method row");
            if let Some(entry) = self.entries.iter_mut().find(|entry| {
                normalize_dll(&entry.dll) == normalize_dll(interface.dll)
                    && entry.export.eq_ignore_ascii_case(interface.interface)
            }) {
                entry.semantic_fidelity = aggregate.semantic_fidelity;
                entry.subsystem_capability = aggregate.subsystem_capability;
            }
        }
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
        violations.extend(self.interface_completeness_gate());
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

        // Method-level rows are the authoritative child status for COM-style
        // interfaces; derive every aggregate interface row from them.
        database.apply_interface_method_surface();

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

        let mut method_deviations = 0usize;
        for method in &self.interface_methods {
            let summary = per_dll.entry(method.dll.clone()).or_default();
            summary.method_total += 1;
            match method.implementation {
                ImplementationLevel::Implemented => {}
                ImplementationLevel::Partial => summary.method_partial += 1,
                ImplementationLevel::Stub | ImplementationLevel::Unsupported => {
                    summary.method_unsupported += 1;
                }
            }
            match method.semantic_fidelity {
                SemanticFidelity::Exact => summary.method_exact += 1,
                SemanticFidelity::Restricted => summary.method_restricted += 1,
                SemanticFidelity::Approximate => summary.method_approximate += 1,
                SemanticFidelity::SyntheticEnvironment => summary.method_synthetic_environment += 1,
                SemanticFidelity::CannedFailure => summary.method_canned_failure += 1,
            }
            match method.subsystem_capability {
                SubsystemCapability::Full => summary.method_capability_full += 1,
                SubsystemCapability::Partial => summary.method_capability_partial += 1,
                SubsystemCapability::Absent => summary.method_capability_absent += 1,
            }
            if method.semantic_test_coverage == CoverageLevel::None {
                summary.method_uncovered += 1;
            } else {
                summary.method_covered += 1;
            }
            if has_semantic_proof(method) {
                summary.method_proven += 1;
            } else {
                summary.method_unproven += 1;
            }
            if method.is_deviation() {
                summary.method_deviations += 1;
                method_deviations += 1;
            }
        }

        let mut interface_registry: Vec<ApiInterfaceCoverageRow> = Vec::new();
        let mut interface_keys: BTreeMap<(String, String), (String, String)> = BTreeMap::new();
        for method in &self.interface_methods {
            interface_keys
                .entry((
                    normalize_dll(&method.dll),
                    method.interface.to_ascii_lowercase(),
                ))
                .or_insert_with(|| (method.dll.clone(), method.interface.clone()));
        }
        for (dll, interface) in interface_keys.into_values() {
            let methods: Vec<&InterfaceMethodEntry> =
                self.methods_for_interface(&dll, &interface).collect();
            let aggregate = aggregate_interface_status(&methods)
                .expect("every grouped interface has at least one method row");
            interface_registry.push(ApiInterfaceCoverageRow {
                dll,
                interface,
                method_count: aggregate.method_count,
                required_count: aggregate.required_count,
                semantic_test_coverage: aggregate.semantic_test_coverage,
                proven: aggregate.proven,
                unproven_methods: aggregate.unproven_methods,
            });
        }
        let unproven_method_count = interface_registry
            .iter()
            .map(|interface| interface.unproven_methods.len())
            .sum();

        let shipping_violations = self.shipping_gate();
        // The report's completeness evaluation runs the full native
        // user-mode profile (nothing excluded): the strictest default.
        let profile = CompatibilityProfile::win11_native_desktop();
        let completeness_violations =
            self.completeness_gate(CompatibilityTier::NativeUserMode, &profile);
        let interface_violations = self.interface_completeness_gate();
        let shipping_violation_count = shipping_violations.len();
        let completeness_violation_count = completeness_violations.len();
        let interface_violation_count = interface_violations.len();
        ApiCompletenessReport {
            generated_at: crate::steam_milestones::utc_rfc3339_now(),
            per_dll,
            gate: ApiGateSummary {
                shipping_violations,
                shipping_violation_count,
                completeness_violations,
                completeness_violation_count,
                interface_violations,
                interface_violation_count,
                method_deviations,
                unproven_method_count,
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
            method_registry: self
                .interface_methods
                .iter()
                .map(|method| ApiMethodRegistryRow {
                    dll: method.dll.clone(),
                    interface: method.interface.clone(),
                    method: method.method.clone(),
                    required: method.required,
                    implementation: method.implementation,
                    semantic_test_coverage: method.semantic_test_coverage,
                    semantic_fidelity: method.semantic_fidelity,
                    subsystem_capability: method.subsystem_capability,
                    detail: method.detail.clone(),
                    evidence_id: method.evidence_id.clone(),
                })
                .collect(),
            interface_registry,
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

        let mut method_total = 0usize;
        let mut method_deviations = 0usize;
        let mut method_by_fidelity: BTreeMap<SemanticFidelity, usize> = BTreeMap::new();
        let mut method_by_capability: BTreeMap<SubsystemCapability, usize> = BTreeMap::new();
        for method in &self.interface_methods {
            method_total += 1;
            *method_by_fidelity
                .entry(method.semantic_fidelity)
                .or_default() += 1;
            *method_by_capability
                .entry(method.subsystem_capability)
                .or_default() += 1;
            if method.is_deviation() {
                method_deviations += 1;
            }
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
            "**Counts**: {total} entries deviate from exact/full — fidelity {fidelity_counts}, capability {capability_counts}.  Method-level accounting: {method_total} method rows, {method_deviations} deviate from exact/full — fidelity {method_fidelity_counts}, capability {method_capability_counts}.\n\n",
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
            method_fidelity_counts = method_by_fidelity
                .iter()
                .map(|(f, c)| format!("{f:?} {c}"))
                .collect::<Vec<_>>()
                .join(", "),
            method_capability_counts = method_by_capability
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
        SemanticFidelity::Exact,
        SubsystemCapability::Full,
        "Performs the real X3DAudio spatial model (documented speaker-circle azimuth \
         tables for mono/stereo/quad/5.1/7.1 masks, unit-circle per-channel delays, \
         distance curves, cone inside/outside attenuation, doppler, equal-power \
         panning, inner-radius diffusion curve) with flag-gated deterministic \
         outputs.  No differential Windows oracle exists for this model, but the \
         documented algorithm is implemented rather than approximated.",
    ),
    semantic_override(
        "x3daudio1_7.dll",
        "X3DAudioInitialize",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Full,
        "Writes a real opaque instance handle (magic + speaker mask + speed of \
         sound) that Calculate validates; the engine surface is the real software \
         spatial math above.",
    ),
    // ── XACT3: real engine core ────────────────────────────────────────────
    semantic_override(
        "xactengine3_7.dll",
        "XACT3CreateEngine",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Creates a real XACT3 engine object with fully populated interface vtables \
         (engine/soundbank/wavebank/cue/wave), genuine XWB/XSB/XGSF parsing \
         (versions, entry metadata, compact banks, loop regions, PCM and MS ADPCM \
         decode, cue variation selection) and real cue/wave playback on the runtime \
         audio stack with category gains, loops and notifications.  Streaming \
         banks, XMA/WMA decode, output-voice matrices and cue-local variables \
         answer the genuine XACT errors; there is no release-fade envelope.",
    ),
    semantic_override(
        "xactengine3_7.dll",
        "XACT3CreateEngineWithFlags",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Same real XACT3 engine core as XACT3CreateEngine, with documented flag \
         validation (E_INVALIDARG for rejected flag combinations).",
    ),
    // ── DirectPlay: no sessions / class not registered ─────────────────────
    semantic_override(
        "dplay.dll",
        "DirectPlayCreate",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Creates a real legacy IDirectPlay4 object over the software DirectPlay8 \
         peer engine: real UDP host/connect, session and player state, enumeration, \
         send/receive with real datagrams, guest message-handler delivery of the real \
         engine events (receive/connect/destroy/session-lost with datagram bytes), \
         and best-effort wire group replication (create/join/leave/destroy, member-\
         only SendToGroup, group context) with the documented DirectPlay error codes.  \
         No lobby service exists, so RegisterLobby stays DPNERR_UNSUPPORTED; group \
         replication has no retransmit/resync after UDP loss.",
    ),
    semantic_override(
        "dplay.dll",
        "DirectPlayEnumerateW",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Enumerates the real TCP/IP service provider plus every session actually \
         hosted by the runtime by invoking the guest's DPENUMSESSIONS callback with \
         real provider and session records.",
    ),
    semantic_override(
        "dpnet.dll",
        "DP8SPCreate",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Absent,
        "DirectPlay8 peers run directly on the UDP transport, so separate service-\
         provider objects are not created: the call answers \
         CLASS_E_CLASSNOTAVAILABLE.",
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
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "The local machine (NULL server name) returns a real SERVER_INFO record \
         from host facts with a NetApiBufferFree-able buffer; remote server names \
         answer NERR_DCNotFound because no DC/SMB transport exists.",
    ),
    semantic_override(
        "wkssvc.dll",
        "NetWkstaSetInfo",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Real local workstation state: WKSTA_INFO levels are validated (platform, \
         name/group limits, parm_err offsets) and stored per runtime; remote server \
         names answer NERR_DCNotFound.",
    ),
    semantic_override(
        "browser.dll",
        "BrowserServerEnum",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Enumerates the local host as one real SERVER_INFO entry; no network \
         share/session state is modeled, and remote enumeration answers \
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
         store membership + parsed X.509 validity) with a deterministic best-match \
         order (signature-strength then latest NotAfter then store order), writes a \
         real CERT_CONTEXT and owning store handle, and answers FALSE only when no \
         certificate is eligible (no dialog is shown); real \
         ERROR_INVALID_PARAMETER/ERROR_INVALID_HANDLE paths.  The picker callback \
         cannot be invoked from this surface.",
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
        "Real asynchronous activation over the real audio stack: the render \
         DEVINTERFACE (or empty path) resolves to the default render device and the \
         capture DEVINTERFACE resolves to a real input device, returning guest \
         endpoints with the full 21-slot IAudioClient/2/3 vtable (real \
         WAVEFORMATEX/EXTENSIBLE validation, device mix format/periods, clock-driven \
         GetCurrentPadding, Initialize opening the real cpal stream, event-handle \
         signalling) and real service objects from GetService: IAudioRenderClient \
         (buffer round-trips into the output path), IAudioCaptureClient (real \
         captured frames), IAudioClock, ISimpleAudioVolume, IAudioStreamVolume and \
         IAudioSessionControl(2) with applied volume/mute state and notifications.  \
         Exclusive mode is enforced client-side over the shared-mode host stream; \
         offload/capture-loopback facilities answer E_NOINTERFACE; the \
         AsyncOperation object itself is not modeled (the handler receives the \
         result directly).",
    ),
    // ── CLR: a machine with no CLR installed ───────────────────────────────
    semantic_override(
        "mscoree.dll",
        "CLRCreateInstance",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Partial,
        "Exposes the CoreCLR runtimes really installed on the host: the meta host, \
         ICLRRuntimeInfo and a real ICLRRuntimeHost whose \
         ExecuteInDefaultAppDomain runs managed static methods natively on ARM64 \
         CoreCLR.  Managed (.NET Core) images also execute through the managed \
         image path.  The legacy .NET Framework activation contract \
         (CorBindToRuntime*) remains absent, so .NET Framework-only images do not \
         run; the capability is partial, never synthetic.",
    ),
    semantic_override(
        "mscoree.dll",
        "CorBindToRuntime",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Partial,
        "Models a Windows machine with no .NET CLR installed: activation answers \
         COR_E_CLRNOTAVAILABLE.",
    ),
    semantic_override(
        "mscoree.dll",
        "CorBindToRuntimeEx",
        None,
        SemanticFidelity::SyntheticEnvironment,
        SubsystemCapability::Partial,
        "Models a Windows machine with no .NET CLR installed: activation answers \
         COR_E_CLRNOTAVAILABLE.",
    ),
    semantic_override(
        "mscoree.dll",
        "GetCORSystemDirectory",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Partial,
        "Reports the directory of the CoreCLR runtime actually installed on the \
         host, including the terminating separator and the required-character \
         count.  A host with no runtime still returns E_FAIL; the legacy \
         .NET Framework directory (Microsoft.NET\\Framework*) is absent.",
    ),
    semantic_override(
        "mscorwks.dll",
        "CorBindToRuntime",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Partial,
        "Binds an explicitly requested installed CoreCLR version to the real \
         ICLRRuntimeHost (managed delegates and applications execute natively on \
         ARM64 CoreCLR); the absent .NET Framework CLR keeps versionless and \
         Framework-version requests at COR_E_CLRNOTAVAILABLE.",
    ),
    semantic_override(
        "mscorwks.dll",
        "CorBindToRuntimeEx",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Partial,
        "Binds an explicitly requested installed CoreCLR version to the real \
         ICLRRuntimeHost; Framework versions remain genuinely absent.",
    ),
    // ── Media Foundation: MF exists, service providers do not ──────────────
    semantic_override(
        "mf.dll",
        "MFGetService",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Real service-provider table on the runtime object graph: MFGetService \
         resolves the owner (session, topology object/node, real media source, real \
         byte stream) and returns real service objects — the session itself, genuine \
         IMFRateControl/IMFRateSupport backed by real session rate state, \
         MF_MEDIASOURCE_SERVICE on real sources, a real IMFMetadata provider over \
         parsed MP4 ilst tags, and byte-stream attribute services; genuinely unowned \
         GUIDs answer MF_E_UNSUPPORTED_SERVICE.",
    ),
    semantic_override(
        "mfplat.dll",
        "MFGetService",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Real service-provider table on the runtime object graph: MFGetService \
         resolves the owner (session, topology object/node, real media source, real \
         byte stream) and returns real service objects — the session itself, genuine \
         IMFRateControl/IMFRateSupport, MF_MEDIASOURCE_SERVICE on real sources, real \
         byte-stream attribute services and a real IMFMetadata provider over the \
         parsed MP4 ilst tag map; genuinely unowned GUIDs answer \
         MF_E_UNSUPPORTED_SERVICE.",
    ),
    // ── GDI+: the drawing surface is real and the former limits are too ─────
    semantic_override(
        "gdiplus.dll",
        "GdipSetClipPath",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Full,
        "Real scanned-region clip: the GpPath is flattened, world-transformed and \
         scan-converted (agreeing pixel-for-pixel with fill path scanlines) and all \
         six combine modes (Replace/Intersect/Union/Xor/Exclude/Complement) apply \
         through per-pixel region clipping honored by every later draw; clip bounds \
         and Save/Restore/containers carry the region.  The legacy GdipGetClip \
         byte encoding round-trips a scanned path clip as its finite bounding \
         rectangle (membership and drawing themselves are exact).",
    ),
    semantic_override(
        "gdiplus.dll",
        "GdipMeasureCharacterRanges",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Builds real GpRegion objects per CharacterRange (per-line runs for ranges \
         spanning newlines) from the same lattice metrics DrawString rasterizes \
         with; the regions are queryable through the region surface and are honored \
         as clips.  Lattice advances are not hinted font metrics and the layout \
         rect does not clip the range regions.",
    ),
    semantic_override(
        "gdiplus.dll",
        "GdipCreateHICONFromBitmap",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Full,
        "Registers a real pixel icon: the bitmap's 32-bpp BGRA pixels and real \
         width/height/bpp are stored in the icon table and the HICON handle is \
         returned; invalid bitmaps or null out-pointers answer InvalidParameter; \
         destroying drops the registry entry.",
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
         NTSTATUS failure paths; image-backed SEC_IMAGE sections are resolved through \
         the real section registry, the first NtCreateThreadEx launches the real \
         casa1-runner host execution with the caller's start routine actually injected \
         (verified end to end), CREATE_SUSPENDED defers the host launch until \
         NtResumeThread and a suspended child terminated before resume never runs, \
         NtTerminateProcess kills the tracked host child and records the exit code, \
         and NtQueryInformationThread reports the child's real process id, TEB and \
         start address.",
    ),
    semantic_override(
        "ntdll.dll",
        "NtCreateThreadEx",
        None,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        "Real native thread creation on a process object: real handle/client id, \
         suspend count and full NtSuspend/NtResume/NtTerminate semantics; real guest \
         thread records (TEB, stack from StackReserve, CPU state, start routine and \
         parameter) scheduled through the guest thread scheduler for bare entries and \
         the first thread on an image-backed native child launches the real host \
         child execution.  Start routines are not injected into a running host child \
         and host-launched child threads report parent-process query fields.",
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
    // through the same registry-backed COM contract.  Registration writes the
    // real guest registry CLSID keys (InprocServer32, ThreadingModel, ProgID
    // where applicable) to both HKCR's backing hive and HKLM\Software\Classes,
    // and updates the in-process class table; activation follows the published
    // registration.  The COM subsystem remains partial: only the runtime's
    // modeled class set is registered, and activation is in-process.
    semantic_override(
        "*",
        "DllRegisterServer",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Partial,
        "Writes the real guest registry CLSID keys (InprocServer32, \
         ThreadingModel, and the ProgID mapping where applicable) to HKCR's \
         backing hive and HKLM\\Software\\Classes, updates the in-process class \
         table, is idempotent on re-register, and reports exact failure HRESULTs \
         (ERROR_MOD_NOT_FOUND for a missing library path, \
         REGDB_E_INVALIDVALUE for a ProgID collision, E_ACCESSDENIED for a \
         refused registry write).  The COM subsystem remains partial: only the \
         runtime's modeled class set is registered and activation stays \
         in-process.",
    ),
    semantic_override(
        "*",
        "DllUnregisterServer",
        None,
        SemanticFidelity::Exact,
        SubsystemCapability::Partial,
        "Removes the real guest registry CLSID keys (InprocServer32, \
         ThreadingModel, ProgID) from HKCR's backing hive and \
         HKLM\\Software\\Classes and removes the class from the in-process class \
         table; exact HRESULTs distinguish an absent registration \
         (REGDB_E_CLASSNOTREG), a partial registration (REGDB_E_READREGDB) and \
         a refused delete (E_ACCESSDENIED).  The COM subsystem remains partial.",
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
    // Aggregate COM/D3D interface status is derived from the method-level
    // rows (`apply_interface_method_surface`), never from the free-form
    // detail string.  Seed the export-level defaults here; the method pass
    // replaces fidelity/capability with the worst required child status.
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
        "IPersistStream vtable dispatch (GetClassID + stream persistence) in runtime/dispatch/com.rs.",
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
        "Real IMalloc vtable over the COM task allocator in runtime/dispatch/com.rs.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IDropTarget",
        ImplementationLevel::Implemented,
        false,
        "Real IDropTarget drag-state vtable in runtime/dispatch/com.rs.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IDataObject",
        ImplementationLevel::Implemented,
        false,
        "Real IDataObject FORMATETC/STGMEDIUM/advise vtable in runtime/dispatch/com.rs.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IOleObject",
        ImplementationLevel::Implemented,
        false,
        "Real IOleObject client-site/moniker/verb/advise vtable in runtime/dispatch/com.rs.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IOleInPlaceObject",
        ImplementationLevel::Implemented,
        false,
        "Real IOleInPlaceObject activation/rect vtable in runtime/dispatch/com.rs.",
    ),
    interface_skeleton(
        "shdocvw.dll",
        "IWebBrowser2",
        ImplementationLevel::Implemented,
        false,
        "Real 53-slot WebBrowser control dispatch with navigation/history state,          registry-backed home/search, IDispatch, and documented restrictions          (GetDocument S_FALSE, GetTypeInfo/ShowBrowserBar E_NOTIMPL).",
    ),
    interface_skeleton(
        "ole32.dll",
        "IObjectWithSite",
        ImplementationLevel::Implemented,
        false,
        "Real IObjectWithSite SetSite/GetSite vtable in runtime/dispatch/com.rs.",
    ),
    interface_skeleton(
        "ole32.dll",
        "IServiceProvider",
        ImplementationLevel::Implemented,
        false,
        "Real IServiceProvider::QueryService vtable in runtime/dispatch/com.rs.",
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

/// Whether a vtable slot actually carries a host-thunk dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodDispatch {
    /// The slot is assigned a real `HostThunk` (possibly a documented
    /// partial implementation).
    Dispatched,
}

/// One method-level seed row (derived from a runtime vtable allocation).
#[derive(Debug, Clone, Copy)]
struct MethodSeed {
    method: &'static str,
    /// Part of the interface's required base surface (false for later
    /// interface-version extensions).
    required: bool,
    dispatch: MethodDispatch,
    detail: &'static str,
}

/// A required method with a real vtable dispatch.
#[rustfmt::skip]
const fn method(method: &'static str, detail: &'static str) -> MethodSeed { // coverage: unreachable
    MethodSeed { method, required: true, dispatch: MethodDispatch::Dispatched, detail } // coverage: unreachable
} // coverage: unreachable

/// An optional interface-version extension method with a real dispatch.
#[rustfmt::skip]
const fn optional(method: &'static str, detail: &'static str) -> MethodSeed { // coverage: unreachable
    MethodSeed { method, required: false, dispatch: MethodDispatch::Dispatched, detail } // coverage: unreachable
} // coverage: unreachable

/// One COM-style interface's vtable method list.
struct InterfaceMethodSurface {
    dll: &'static str,
    interface: &'static str,
    methods: &'static [MethodSeed],
}

const DISPATCHED_METHOD: &str =
    "vtable slot carries a real host-thunk dispatch; no method-level semantic proof yet";

/// D3D11 `ID3D11DeviceChild` methods (every resource/view/shader/state
/// vtable shares the real host-thunk preamble).
const D3D11_DEVICE_CHILD_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetDevice", DISPATCHED_METHOD),
    method("GetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateDataInterface", DISPATCHED_METHOD),
];

/// D3D11 resource texture vtable (3 slots).
const D3D11_TEXTURE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
];

/// D3D12 resource vtable (3 slots).
const D3D12_RESOURCE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
];

/// D3D11 `ID3D11Device` vtable as allocated by
/// `runtime/dispatch/d3d11.rs::alloc_d3d11_device_object` (43 slots; slots
/// 40-42 are `ID3D11Device1/2` extensions).
const D3D11_DEVICE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("CreateBuffer", DISPATCHED_METHOD),
    method("CreateTexture1D", DISPATCHED_METHOD),
    method("CreateTexture2D", DISPATCHED_METHOD),
    method("CreateTexture3D", DISPATCHED_METHOD),
    method("CreateShaderResourceView", DISPATCHED_METHOD),
    method("CreateUnorderedAccessView", DISPATCHED_METHOD),
    method("CreateRenderTargetView", DISPATCHED_METHOD),
    method("CreateDepthStencilView", DISPATCHED_METHOD),
    method("CreateInputLayout", DISPATCHED_METHOD),
    method("CreateVertexShader", DISPATCHED_METHOD),
    method("CreateGeometryShader", DISPATCHED_METHOD),
    method("CreateGeometryShaderWithStreamOutput", DISPATCHED_METHOD),
    method("CreatePixelShader", DISPATCHED_METHOD),
    method("CreateHullShader", DISPATCHED_METHOD),
    method("CreateDomainShader", DISPATCHED_METHOD),
    method("CreateComputeShader", DISPATCHED_METHOD),
    method("CreateClassLinkage", DISPATCHED_METHOD),
    method("CreateBlendState", DISPATCHED_METHOD),
    method("CreateDepthStencilState", DISPATCHED_METHOD),
    method("CreateRasterizerState", DISPATCHED_METHOD),
    method("CreateSamplerState", DISPATCHED_METHOD),
    method("CreateQuery", DISPATCHED_METHOD),
    method("CreatePredicate", DISPATCHED_METHOD),
    method("CreateCounter", DISPATCHED_METHOD),
    method("CreateDeferredContext", DISPATCHED_METHOD),
    method("OpenSharedResource", DISPATCHED_METHOD),
    method("CheckFormatSupport", DISPATCHED_METHOD),
    method("CheckMultisampleQualityLevels", DISPATCHED_METHOD),
    method("CheckCounterInfo", DISPATCHED_METHOD),
    method("CheckCounter", DISPATCHED_METHOD),
    method("CheckFeatureSupport", DISPATCHED_METHOD),
    method("GetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateData", DISPATCHED_METHOD),
    method("GetDeviceRemovedReason", DISPATCHED_METHOD),
    method("SetPrivateDataInterface", DISPATCHED_METHOD),
    method("GetFeatureLevel", DISPATCHED_METHOD),
    method("GetImmediateContext", DISPATCHED_METHOD),
    optional("GetImmediateContext1", DISPATCHED_METHOD),
    optional("CreateDeferredContext1", DISPATCHED_METHOD),
    optional("GetImmediateContext2", DISPATCHED_METHOD),
];

/// D3D11 `ID3D11DeviceContext` vtable (70 slots).
const D3D11_CONTEXT_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetDevice", DISPATCHED_METHOD),
    method("GetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateDataInterface", DISPATCHED_METHOD),
    method("VSSetConstantBuffers", DISPATCHED_METHOD),
    method("PSSetShaderResources", DISPATCHED_METHOD),
    method("PSSetShader", DISPATCHED_METHOD),
    method("PSSetSamplers", DISPATCHED_METHOD),
    method("VSSetShader", DISPATCHED_METHOD),
    method("DrawIndexed", DISPATCHED_METHOD),
    method("Draw", DISPATCHED_METHOD),
    method("DrawAuto", DISPATCHED_METHOD),
    method("ClearRenderTargetView", DISPATCHED_METHOD),
    method("ClearDepthStencilView", DISPATCHED_METHOD),
    method("IASetInputLayout", DISPATCHED_METHOD),
    method("IASetVertexBuffers", DISPATCHED_METHOD),
    method("IASetIndexBuffer", DISPATCHED_METHOD),
    method("DrawIndexedInstanced", DISPATCHED_METHOD),
    method("DrawInstanced", DISPATCHED_METHOD),
    method("GSSetShader", DISPATCHED_METHOD),
    method("GSSetConstantBuffers", DISPATCHED_METHOD),
    method("IASetPrimitiveTopology", DISPATCHED_METHOD),
    method("GSSetShaderResources", DISPATCHED_METHOD),
    method("GSSetSamplers", DISPATCHED_METHOD),
    method("HSSetShader", DISPATCHED_METHOD),
    method("HSSetConstantBuffers", DISPATCHED_METHOD),
    method("HSSetShaderResources", DISPATCHED_METHOD),
    method("HSSetSamplers", DISPATCHED_METHOD),
    method("DSSetShader", DISPATCHED_METHOD),
    method("DSSetConstantBuffers", DISPATCHED_METHOD),
    method("OMSetRenderTargets", DISPATCHED_METHOD),
    method("DSSetShaderResources", DISPATCHED_METHOD),
    method("OMSetBlendState", DISPATCHED_METHOD),
    method("OMSetDepthStencilState", DISPATCHED_METHOD),
    method("DSSetSamplers", DISPATCHED_METHOD),
    method("VSSetShaderResources", DISPATCHED_METHOD),
    method("VSSetSamplers", DISPATCHED_METHOD),
    method("CSSetShaderResources", DISPATCHED_METHOD),
    method("CSSetUnorderedAccessViews", DISPATCHED_METHOD),
    method("CSSetSamplers", DISPATCHED_METHOD),
    method("RSSetState", DISPATCHED_METHOD),
    method("RSSetViewports", DISPATCHED_METHOD),
    method("RSSetScissorRects", DISPATCHED_METHOD),
    method("CSSetConstantBuffers", DISPATCHED_METHOD),
    method("CopySubresourceRegion", DISPATCHED_METHOD),
    method("UpdateSubresource", DISPATCHED_METHOD),
    method("CopyResource", DISPATCHED_METHOD),
    method("CopyStructureCount", DISPATCHED_METHOD),
    method("Begin", DISPATCHED_METHOD),
    method("End", DISPATCHED_METHOD),
    method("GetData", DISPATCHED_METHOD),
    method("ResolveSubresource", DISPATCHED_METHOD),
    method("SetPredication", DISPATCHED_METHOD),
    method("GetPredication", DISPATCHED_METHOD),
    method("Map", DISPATCHED_METHOD),
    method("Unmap", DISPATCHED_METHOD),
    method("GenerateMips", DISPATCHED_METHOD),
    method("SetResourceMinLOD", DISPATCHED_METHOD),
    method("GetResourceMinLOD", DISPATCHED_METHOD),
    method("ResolveSubresourceFlag", DISPATCHED_METHOD),
    method("FinishCommandList", DISPATCHED_METHOD),
    method("Flush", DISPATCHED_METHOD),
    method("ExecuteCommandList", DISPATCHED_METHOD),
    method("ClearState", DISPATCHED_METHOD),
    method("ClearUnorderedAccessViewUint", DISPATCHED_METHOD),
    method("ClearUnorderedAccessViewFloat", DISPATCHED_METHOD),
    method("CSSetShader", DISPATCHED_METHOD),
];

/// D3D11 query/asynchronous vtable
/// (`runtime/mod.rs::D3D11DeviceCreateQuery`).
const D3D11_QUERY_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetDevice", DISPATCHED_METHOD),
    method("GetDataSize", DISPATCHED_METHOD),
    method("GetData", DISPATCHED_METHOD),
    method("GetDesc", DISPATCHED_METHOD),
];

/// D3D12 `ID3D12Device` vtable (66 slots; slots 38-43, 44-64 and 65 are
/// interface-version extensions carrying real host-thunk dispatches).
const D3D12_DEVICE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("SetStablePowerState", DISPATCHED_METHOD),
    method("CreateGraphicsPipelineState", DISPATCHED_METHOD),
    method("CreateComputePipelineState", DISPATCHED_METHOD),
    method("CreateRootSignature", DISPATCHED_METHOD),
    method("CreateRootSignatureVersioned", DISPATCHED_METHOD),
    method("CreateCommandQueue", DISPATCHED_METHOD),
    method("CreateCommandAllocator", DISPATCHED_METHOD),
    method("CreateCommandSignature", DISPATCHED_METHOD),
    method("CreatePipelineLibrary", DISPATCHED_METHOD),
    method("CreateCommandList", DISPATCHED_METHOD),
    method("CheckFeatureSupport", DISPATCHED_METHOD),
    method("CreateDescriptorHeap", DISPATCHED_METHOD),
    method("CreateSampler", DISPATCHED_METHOD),
    method("CopyDescriptors", DISPATCHED_METHOD),
    method("CopyDescriptorsSimple", DISPATCHED_METHOD),
    method("GetDescriptorHandleIncrementSize", DISPATCHED_METHOD),
    method("CreateConstantBufferView", DISPATCHED_METHOD),
    method("CreateRenderTargetView", DISPATCHED_METHOD),
    method("CreateShaderResourceView", DISPATCHED_METHOD),
    method("CreateUnorderedAccessView", DISPATCHED_METHOD),
    method("CreateDepthStencilView", DISPATCHED_METHOD),
    method("CreateCommittedResource", DISPATCHED_METHOD),
    method("CreateHeap", DISPATCHED_METHOD),
    method("CreatePlacedResource", DISPATCHED_METHOD),
    method("CreateReservedResource", DISPATCHED_METHOD),
    method("CreateSharedHandle", DISPATCHED_METHOD),
    method("OpenSharedHandle", DISPATCHED_METHOD),
    method("OpenSharedHandleByName", DISPATCHED_METHOD),
    method("MakeResident", DISPATCHED_METHOD),
    method("Evict", DISPATCHED_METHOD),
    method("CreateQueryHeap", DISPATCHED_METHOD),
    method("CreatePipelineLibrary1", DISPATCHED_METHOD),
    method("CreateCachedPipelineState", DISPATCHED_METHOD),
    method("CreateFence", DISPATCHED_METHOD),
    method("GetNodeCount", DISPATCHED_METHOD),
    optional("CreateShaderResourceView1", DISPATCHED_METHOD),
    optional("GetShaderResourceView1", DISPATCHED_METHOD),
    optional("CreateShaderResourceView2", DISPATCHED_METHOD),
    optional("GetShaderResourceView2", DISPATCHED_METHOD),
    optional("CreateShaderResourceView3", DISPATCHED_METHOD),
    optional("GetShaderResourceView3", DISPATCHED_METHOD),
    optional("GetResourceTiling", DISPATCHED_METHOD),
    optional("GetAdapterLuid", DISPATCHED_METHOD),
    optional("GetCopyableFootprints", DISPATCHED_METHOD),
    optional("GetDeviceRemovedReason", DISPATCHED_METHOD),
    optional("SetEventOnMultipleFenceCompletion", DISPATCHED_METHOD),
    optional("SetResidencyPriority", DISPATCHED_METHOD),
    optional("CreatePipelineState", DISPATCHED_METHOD),
    optional("OpenExistingHeapFromAddress", DISPATCHED_METHOD),
    optional("OpenExistingHeapFromFileMapping", DISPATCHED_METHOD),
    optional("EnqueueMakeResident", DISPATCHED_METHOD),
    optional("CreateCommandList1", DISPATCHED_METHOD),
    optional("CreateProtectedResourceSession", DISPATCHED_METHOD),
    optional("CreateCommittedResource1", DISPATCHED_METHOD),
    optional("CreateHeap1", DISPATCHED_METHOD),
    optional("CreateReservedResource1", DISPATCHED_METHOD),
    optional("GetResourceAllocationInfo", DISPATCHED_METHOD),
    optional("GetResourceAllocationInfo1", DISPATCHED_METHOD),
    optional("CreateStateObject", DISPATCHED_METHOD),
    optional("CreateMetaCommand", DISPATCHED_METHOD),
    optional("EnumerateMetaCommands", DISPATCHED_METHOD),
    optional("EnumerateMetaCommandParameters", DISPATCHED_METHOD),
    optional("AddToStateObject", DISPATCHED_METHOD),
];

/// D3D12 `ID3D12CommandQueue` vtable (19 slots; 14-18 are the allocator's
/// real trailing methods).
const D3D12_COMMAND_QUEUE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateDataInterface", DISPATCHED_METHOD),
    method("SetName", DISPATCHED_METHOD),
    method("GetDevice", DISPATCHED_METHOD),
    method("GetDesc", DISPATCHED_METHOD),
    method("GetTimestampFrequency", DISPATCHED_METHOD),
    method("GetClockCalibration", DISPATCHED_METHOD),
    method("ExecuteCommandLists", DISPATCHED_METHOD),
    method("Signal", DISPATCHED_METHOD),
    method("Wait", DISPATCHED_METHOD),
    optional("Signal", DISPATCHED_METHOD),
    optional("Wait", DISPATCHED_METHOD),
    optional("GetTimestampFrequency", DISPATCHED_METHOD),
    optional("GetClockCalibration", DISPATCHED_METHOD),
    optional("GetDesc", DISPATCHED_METHOD),
];

/// D3D12 `ID3D12DescriptorHeap` vtable (11 slots).
const D3D12_DESCRIPTOR_HEAP_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateDataInterface", DISPATCHED_METHOD),
    method("SetName", DISPATCHED_METHOD),
    method("GetDevice", DISPATCHED_METHOD),
    method("GetDesc", DISPATCHED_METHOD),
    method("GetCpuHandleForHeapStart", DISPATCHED_METHOD),
    method("GetGpuHandleForHeapStart", DISPATCHED_METHOD),
];

/// D3D12 `ID3D12Fence` vtable (11 slots).
const D3D12_FENCE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateDataInterface", DISPATCHED_METHOD),
    method("SetName", DISPATCHED_METHOD),
    method("GetDevice", DISPATCHED_METHOD),
    method("GetCompletedValue", DISPATCHED_METHOD),
    method("SetEventOnCompletion", DISPATCHED_METHOD),
    method("Signal", DISPATCHED_METHOD),
];

/// D3D12 `ID3D12GraphicsCommandList` vtable (75 slots; slots 41-46 and 62
/// carry the real host-thunk tail).
const D3D12_GRAPHICS_COMMAND_LIST_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateDataInterface", DISPATCHED_METHOD),
    method("SetName", DISPATCHED_METHOD),
    method("GetDevice", DISPATCHED_METHOD),
    method("GetType", DISPATCHED_METHOD),
    method("Close", DISPATCHED_METHOD),
    method("Reset", DISPATCHED_METHOD),
    method("ClearState", DISPATCHED_METHOD),
    method("DrawInstanced", DISPATCHED_METHOD),
    method("DrawIndexedInstanced", DISPATCHED_METHOD),
    method("Dispatch", DISPATCHED_METHOD),
    method("CopyBufferRegion", DISPATCHED_METHOD),
    method("CopyTextureRegion", DISPATCHED_METHOD),
    method("CopyResource", DISPATCHED_METHOD),
    method("CopyTiles", DISPATCHED_METHOD),
    method("ResolveSubresource", DISPATCHED_METHOD),
    method("IASetPrimitiveTopology", DISPATCHED_METHOD),
    method("RSSetViewports", DISPATCHED_METHOD),
    method("RSSetScissorRects", DISPATCHED_METHOD),
    method("SetPipelineState", DISPATCHED_METHOD),
    method("SetGraphicsRootSignature", DISPATCHED_METHOD),
    method("SetDescriptorHeaps", DISPATCHED_METHOD),
    method("ResourceBarrier", DISPATCHED_METHOD),
    method("ExecuteBundle", DISPATCHED_METHOD),
    method("SetPredication", DISPATCHED_METHOD),
    method("SetMarker", DISPATCHED_METHOD),
    method("BeginQuery", DISPATCHED_METHOD),
    method("EndQuery", DISPATCHED_METHOD),
    method("ResolveQueryData", DISPATCHED_METHOD),
    method("SetGraphicsRootDescriptorTable", DISPATCHED_METHOD),
    method("SetGraphicsRootConstantBufferView", DISPATCHED_METHOD),
    method("SetGraphicsRoot32BitConstants", DISPATCHED_METHOD),
    method("IASetVertexBuffers", DISPATCHED_METHOD),
    method("IASetIndexBuffer", DISPATCHED_METHOD),
    method("OMSetRenderTargets", DISPATCHED_METHOD),
    method("OMSetBlendFactor", DISPATCHED_METHOD),
    method("OMSetStencilRef", DISPATCHED_METHOD),
    method("SetComputeRootUnorderedAccessView", DISPATCHED_METHOD),
    method("SetGraphicsRootUnorderedAccessView", DISPATCHED_METHOD),
    method("IASetIndexBuffer", DISPATCHED_METHOD),
    method("IASetVertexBuffers", DISPATCHED_METHOD),
    method("SOSetTargets", DISPATCHED_METHOD),
    method("OMSetRenderTargets", DISPATCHED_METHOD),
    method("ExecuteIndirect", DISPATCHED_METHOD),
    method("ClearRenderTargetView", DISPATCHED_METHOD),
    method("AtomicCopyBufferUINT", DISPATCHED_METHOD),
    method("AtomicCopyBufferUINT64", DISPATCHED_METHOD),
    method("OMSetDepthBounds", DISPATCHED_METHOD),
    method("SetSamplePositions", DISPATCHED_METHOD),
    method("ResolveSubresourceRegion", DISPATCHED_METHOD),
    method("SetViewInstanceMask", DISPATCHED_METHOD),
    method("WriteBufferImmediate", DISPATCHED_METHOD),
    method("SetProtectedResourceSession", DISPATCHED_METHOD),
    method("BeginRenderPass", DISPATCHED_METHOD),
    method("EndRenderPass", DISPATCHED_METHOD),
    method("InitializeMetaCommand", DISPATCHED_METHOD),
    method("ExecuteMetaCommand", DISPATCHED_METHOD),
    method("BuildRaytracingAccelerationStructure", DISPATCHED_METHOD),
    method(
        "EmitRaytracingAccelerationStructurePostbuildInfo",
        DISPATCHED_METHOD,
    ),
    method("CopyRaytracingAccelerationStructure", DISPATCHED_METHOD),
    method("SetPipelineState1", DISPATCHED_METHOD),
    method("DispatchRays", DISPATCHED_METHOD),
    method("RSSetShadingRate", DISPATCHED_METHOD),
    method("RSSetShadingRateImage", DISPATCHED_METHOD),
    method("DispatchMesh", DISPATCHED_METHOD),
    method("Barrier", DISPATCHED_METHOD),
    method("OMSetFrontAndBackStencilRef", DISPATCHED_METHOD),
    method("RSSetDepthBias", DISPATCHED_METHOD),
    method("IASetIndexBufferStripCutValue", DISPATCHED_METHOD),
    method("SetProgram", DISPATCHED_METHOD),
    method("DispatchGraph", DISPATCHED_METHOD),
];

/// DXGI `IDXGIFactory` vtable (26 slots; 14-25 are Factory2/3 extensions).
const DXGI_FACTORY_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("SetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateDataInterface", DISPATCHED_METHOD),
    method("GetPrivateData", DISPATCHED_METHOD),
    method("GetParent", DISPATCHED_METHOD),
    method("EnumAdapters", DISPATCHED_METHOD),
    method("MakeWindowAssociation", DISPATCHED_METHOD),
    method("GetWindowAssociation", DISPATCHED_METHOD),
    method("CreateSwapChain", DISPATCHED_METHOD),
    method("CreateSoftwareAdapter", DISPATCHED_METHOD),
    method("EnumAdapters1", DISPATCHED_METHOD),
    method("IsCurrent", DISPATCHED_METHOD),
    optional("RegisterStereoStatus", DISPATCHED_METHOD),
    optional("CreateSwapChainForHwnd", DISPATCHED_METHOD),
    optional("CreateSwapChainForCoreWindow", DISPATCHED_METHOD),
    optional("CreateSwapChainForComposition", DISPATCHED_METHOD),
    optional("RegisterStereoStatusEvent", DISPATCHED_METHOD),
    optional("UnregisterStereoStatus", DISPATCHED_METHOD),
    optional("RegisterOcclusionStatus", DISPATCHED_METHOD),
    optional("RegisterOcclusionStatusEvent", DISPATCHED_METHOD),
    optional("UnregisterOcclusionStatus", DISPATCHED_METHOD),
    optional("GetCreationFlags", DISPATCHED_METHOD),
    optional("EnumAdapterByLuid", DISPATCHED_METHOD),
    optional("EnumWarpAdapter", DISPATCHED_METHOD),
];

/// DXGI `IDXGISwapChain` vtable (18 slots; the D3D12 allocator is the
/// superset of the D3D11 14-slot swapchain).
const DXGI_SWAPCHAIN_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateData", DISPATCHED_METHOD),
    method("SetPrivateDataInterface", DISPATCHED_METHOD),
    method("SetName", DISPATCHED_METHOD),
    method("GetDevice", DISPATCHED_METHOD),
    method("Present", DISPATCHED_METHOD),
    method("GetBuffer", DISPATCHED_METHOD),
    method("SetFullscreenState", DISPATCHED_METHOD),
    method("GetFullscreenState", DISPATCHED_METHOD),
    method("GetDesc", DISPATCHED_METHOD),
    method("ResizeBuffers", DISPATCHED_METHOD),
    method("ResizeTarget", DISPATCHED_METHOD),
    method("GetContainingOutput", DISPATCHED_METHOD),
    method("GetFrameStatistics", DISPATCHED_METHOD),
    method("GetLastPresentCount", DISPATCHED_METHOD),
];

/// COM `IUnknown` preamble + `IClassFactory`.
const ICLASS_FACTORY_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("CreateInstance", DISPATCHED_METHOD),
    method("LockServer", DISPATCHED_METHOD),
];

/// COM `IDispatch` automation surface.
const IDISPATCH_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetTypeInfoCount", DISPATCHED_METHOD),
    method("GetTypeInfo", DISPATCHED_METHOD),
    method("GetIDsOfNames", DISPATCHED_METHOD),
    method("Invoke", DISPATCHED_METHOD),
];

/// COM `IEnumVARIANT` enumerator.
const IENUM_VARIANT_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("Next", DISPATCHED_METHOD),
    method("Skip", DISPATCHED_METHOD),
    method("Reset", DISPATCHED_METHOD),
    method("Clone", DISPATCHED_METHOD),
];

/// COM `IConnectionPoint` vtable.
const ICONNECTION_POINT_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetConnectionInterface", DISPATCHED_METHOD),
    method("GetConnectionPointContainer", DISPATCHED_METHOD),
    method("Advise", DISPATCHED_METHOD),
    method("Unadvise", DISPATCHED_METHOD),
    method("EnumConnections", DISPATCHED_METHOD),
];

/// OLE `IMoniker` vtable as allocated by
/// `runtime/dispatch/com.rs::alloc_com_moniker_object`.
const IMONIKER_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetClassID", DISPATCHED_METHOD),
    method("IsDirty", DISPATCHED_METHOD),
    method("Load", DISPATCHED_METHOD),
    method("Save", DISPATCHED_METHOD),
    method("GetSizeMax", DISPATCHED_METHOD),
    method("BindToObject", DISPATCHED_METHOD),
    method("BindToStorage", DISPATCHED_METHOD),
    method("Reduce", DISPATCHED_METHOD),
    method("ComposeWith", DISPATCHED_METHOD),
    method("Enum", DISPATCHED_METHOD),
    method("IsEqual", DISPATCHED_METHOD),
    method("GetDisplayName", DISPATCHED_METHOD),
    method("ParseDisplayName", DISPATCHED_METHOD),
    method("IsSystemMoniker", DISPATCHED_METHOD),
    method("Hash", DISPATCHED_METHOD),
    method("BindIfRunning", DISPATCHED_METHOD),
];

/// OLE `IPersist` vtable.
const IPERSIST_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetClassID", DISPATCHED_METHOD),
];

/// OLE `IStream` vtable.
const ISTREAM_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("Read", DISPATCHED_METHOD),
    method("Write", DISPATCHED_METHOD),
    method("Seek", DISPATCHED_METHOD),
    method("SetSize", DISPATCHED_METHOD),
    method("CopyTo", DISPATCHED_METHOD),
    method("Commit", DISPATCHED_METHOD),
    method("Revert", DISPATCHED_METHOD),
    method("LockRegion", DISPATCHED_METHOD),
    method("UnlockRegion", DISPATCHED_METHOD),
    method("Stat", DISPATCHED_METHOD),
    method("Clone", DISPATCHED_METHOD),
];

/// OLE `IStorage` vtable.
const ISTORAGE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("CreateStream", DISPATCHED_METHOD),
    method("OpenStream", DISPATCHED_METHOD),
    method("CreateStorage", DISPATCHED_METHOD),
    method("OpenStorage", DISPATCHED_METHOD),
    method("CopyTo", DISPATCHED_METHOD),
    method("MoveElement", DISPATCHED_METHOD),
    method("Commit", DISPATCHED_METHOD),
    method("Revert", DISPATCHED_METHOD),
    method("EnumElements", DISPATCHED_METHOD),
    method("DestroyElement", DISPATCHED_METHOD),
    method("RenameElement", DISPATCHED_METHOD),
    method("SetElementTimes", DISPATCHED_METHOD),
    method("SetClass", DISPATCHED_METHOD),
    method("SetStateBits", DISPATCHED_METHOD),
    method("Stat", DISPATCHED_METHOD),
];

/// OLE `IMalloc` vtable.
const IMALLOC_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("Alloc", DISPATCHED_METHOD),
    method("Realloc", DISPATCHED_METHOD),
    method("Free", DISPATCHED_METHOD),
    method("GetSize", DISPATCHED_METHOD),
    method("DidAlloc", DISPATCHED_METHOD),
    method("HeapMinimize", DISPATCHED_METHOD),
];

/// OLE `IDropTarget` vtable.
const IDROP_TARGET_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("DragEnter", DISPATCHED_METHOD),
    method("DragOver", DISPATCHED_METHOD),
    method("DragLeave", DISPATCHED_METHOD),
    method("Drop", DISPATCHED_METHOD),
];

/// OLE `IDataObject` vtable.
const IDATA_OBJECT_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetData", DISPATCHED_METHOD),
    method("GetDataHere", DISPATCHED_METHOD),
    method("QueryGetData", DISPATCHED_METHOD),
    method("GetCanonicalFormatEtc", DISPATCHED_METHOD),
    method("SetData", DISPATCHED_METHOD),
    method("EnumFormatEtc", DISPATCHED_METHOD),
    method("DAdvise", DISPATCHED_METHOD),
    method("DUnadvise", DISPATCHED_METHOD),
    method("EnumDAdvise", DISPATCHED_METHOD),
];

/// OLE `IOleObject` vtable.
const IOLE_OBJECT_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("SetClientSite", DISPATCHED_METHOD),
    method("GetClientSite", DISPATCHED_METHOD),
    method("SetHostNames", DISPATCHED_METHOD),
    method("Close", DISPATCHED_METHOD),
    method("SetMoniker", DISPATCHED_METHOD),
    method("GetMoniker", DISPATCHED_METHOD),
    method("InitFromData", DISPATCHED_METHOD),
    method("GetClipboardData", DISPATCHED_METHOD),
    method("DoVerb", DISPATCHED_METHOD),
    method("EnumVerbs", DISPATCHED_METHOD),
    method("Update", DISPATCHED_METHOD),
    method("IsUpToDate", DISPATCHED_METHOD),
    method("GetUserClassID", DISPATCHED_METHOD),
    method("GetUserType", DISPATCHED_METHOD),
    method("SetExtent", DISPATCHED_METHOD),
    method("GetExtent", DISPATCHED_METHOD),
    method("Advise", DISPATCHED_METHOD),
    method("Unadvise", DISPATCHED_METHOD),
    method("EnumAdvise", DISPATCHED_METHOD),
    method("GetMiscStatus", DISPATCHED_METHOD),
    method("SetColorScheme", DISPATCHED_METHOD),
];

/// OLE `IOleInPlaceObject` vtable.
const IOLE_IN_PLACE_OBJECT_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetWindow", DISPATCHED_METHOD),
    method("ContextSensitiveHelp", DISPATCHED_METHOD),
    method("InPlaceDeactivate", DISPATCHED_METHOD),
    method("UIDeactivate", DISPATCHED_METHOD),
    method("SetObjectRects", DISPATCHED_METHOD),
    method("ReactivateAndUndo", DISPATCHED_METHOD),
];

/// OLE `IObjectWithSite` vtable.
const IOBJECT_WITH_SITE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("SetSite", DISPATCHED_METHOD),
    method("GetSite", DISPATCHED_METHOD),
];

/// OLE `IServiceProvider` vtable.
const ISERVICE_PROVIDER_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("QueryService", DISPATCHED_METHOD),
];

/// OLE `IOleInPlaceActiveObject` vtable (10 slots).
const IOLE_IN_PLACE_ACTIVE_OBJECT_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetWindow", DISPATCHED_METHOD),
    method("ContextSensitiveHelp", DISPATCHED_METHOD),
    method("TranslateAccelerator", DISPATCHED_METHOD),
    method("OnFrameWindowActivate", DISPATCHED_METHOD),
    method("OnDocWindowActivate", DISPATCHED_METHOD),
    method("ResizeBorder", DISPATCHED_METHOD),
    method("EnableModeless", DISPATCHED_METHOD),
];

/// OLE `IPersistStream` vtable (8 slots; inherits `IPersist::GetClassID`).
const IPERSIST_STREAM_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetClassID", DISPATCHED_METHOD),
    method("IsDirty", DISPATCHED_METHOD),
    method("Load", DISPATCHED_METHOD),
    method("Save", DISPATCHED_METHOD),
    method("GetSizeMax", DISPATCHED_METHOD),
];

/// OLE `ISupportErrorInfo` vtable (4 slots).
const ISUPPORT_ERROR_INFO_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("InterfaceSupportsErrorInfo", DISPATCHED_METHOD),
];

/// OLE `IEnumFORMATETC` snapshot enumerator (7 slots).
const IENUM_FORMAT_ETC_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("Next", DISPATCHED_METHOD),
    method("Skip", DISPATCHED_METHOD),
    method("Reset", DISPATCHED_METHOD),
    method("Clone", DISPATCHED_METHOD),
];

/// OLE `IEnumSTATDATA` snapshot enumerator (7 slots).
const IENUM_STAT_DATA_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("Next", DISPATCHED_METHOD),
    method("Skip", DISPATCHED_METHOD),
    method("Reset", DISPATCHED_METHOD),
    method("Clone", DISPATCHED_METHOD),
];

/// OLE `IEnumOLEVERB` snapshot enumerator (7 slots).
const IENUM_OLE_VERB_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("Next", DISPATCHED_METHOD),
    method("Skip", DISPATCHED_METHOD),
    method("Reset", DISPATCHED_METHOD),
    method("Clone", DISPATCHED_METHOD),
];

/// OLE Automation `ITypeInfo` vtable (22 slots).
const ITYPE_INFO_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetTypeAttr", DISPATCHED_METHOD),
    method("GetTypeComp", DISPATCHED_METHOD),
    method("GetFuncDesc", DISPATCHED_METHOD),
    method("GetVarDesc", DISPATCHED_METHOD),
    method("GetNames", DISPATCHED_METHOD),
    method("GetRefTypeOfImplType", DISPATCHED_METHOD),
    method("GetImplTypeFlags", DISPATCHED_METHOD),
    method("GetIDsOfNames", DISPATCHED_METHOD),
    method("Invoke", DISPATCHED_METHOD),
    method("GetDocumentation", DISPATCHED_METHOD),
    method("GetDllEntry", DISPATCHED_METHOD),
    method("GetRefTypeInfo", DISPATCHED_METHOD),
    method("AddressOfMember", DISPATCHED_METHOD),
    method("CreateInstance", DISPATCHED_METHOD),
    method("GetMops", DISPATCHED_METHOD),
    method("GetContainingTypeLib", DISPATCHED_METHOD),
    method("ReleaseTypeAttr", DISPATCHED_METHOD),
    method("ReleaseFuncDesc", DISPATCHED_METHOD),
    method("ReleaseVarDesc", DISPATCHED_METHOD),
];

/// OLE Automation `ITypeLib` vtable (13 slots).
const ITYPE_LIB_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetTypeInfoCount", DISPATCHED_METHOD),
    method("GetTypeInfo", DISPATCHED_METHOD),
    method("GetTypeInfoType", DISPATCHED_METHOD),
    method("GetTypeInfoOfGuid", DISPATCHED_METHOD),
    method("GetLibAttr", DISPATCHED_METHOD),
    method("GetTypeComp", DISPATCHED_METHOD),
    method("GetDocumentation", DISPATCHED_METHOD),
    method("FindName", DISPATCHED_METHOD),
    method("IsName", DISPATCHED_METHOD),
    method("ReleaseTLibAttr", DISPATCHED_METHOD),
];

/// Shell `IShellLinkW` vtable (21 slots; all real host thunks).
const ISHELL_LINK_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetPath", DISPATCHED_METHOD),
    method("GetIDList", DISPATCHED_METHOD),
    method("SetIDList", DISPATCHED_METHOD),
    method("GetDescription", DISPATCHED_METHOD),
    method("SetDescription", DISPATCHED_METHOD),
    method("GetWorkingDirectory", DISPATCHED_METHOD),
    method("SetWorkingDirectory", DISPATCHED_METHOD),
    method("GetArguments", DISPATCHED_METHOD),
    method("SetArguments", DISPATCHED_METHOD),
    method("GetHotkey", DISPATCHED_METHOD),
    method("SetHotkey", DISPATCHED_METHOD),
    method("GetShowCmd", DISPATCHED_METHOD),
    method("SetShowCmd", DISPATCHED_METHOD),
    method("GetIconLocation", DISPATCHED_METHOD),
    method("SetIconLocation", DISPATCHED_METHOD),
    method("SetRelativePath", DISPATCHED_METHOD),
    method("Resolve", DISPATCHED_METHOD),
    method("SetPath", DISPATCHED_METHOD),
];

/// Browser `IWebBrowser2` vtable.  The runtime exposes the shdocvw interface
/// identity but allocates no browser vtable, so every method is unsupported.
const IWEB_BROWSER2_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetTypeInfoCount", DISPATCHED_METHOD),
    method("GetTypeInfo", DISPATCHED_METHOD),
    method("GetIDsOfNames", DISPATCHED_METHOD),
    method("Invoke", DISPATCHED_METHOD),
    method("GoBack", DISPATCHED_METHOD),
    method("GoForward", DISPATCHED_METHOD),
    method("GoHome", DISPATCHED_METHOD),
    method("GoSearch", DISPATCHED_METHOD),
    method("Navigate", DISPATCHED_METHOD),
    method("Refresh", DISPATCHED_METHOD),
    method("Refresh2", DISPATCHED_METHOD),
    method("Stop", DISPATCHED_METHOD),
    method("get_Application", DISPATCHED_METHOD),
    method("get_Parent", DISPATCHED_METHOD),
    method("get_Container", DISPATCHED_METHOD),
    method("get_Document", DISPATCHED_METHOD),
    method("get_Name", DISPATCHED_METHOD),
    method("get_FullName", DISPATCHED_METHOD),
    method("get_Path", DISPATCHED_METHOD),
    method("get_Visible", DISPATCHED_METHOD),
    method("put_Visible", DISPATCHED_METHOD),
    method("get_StatusBar", DISPATCHED_METHOD),
    method("put_StatusBar", DISPATCHED_METHOD),
    method("get_StatusText", DISPATCHED_METHOD),
    method("put_StatusText", DISPATCHED_METHOD),
    method("get_ToolBar", DISPATCHED_METHOD),
    method("put_ToolBar", DISPATCHED_METHOD),
    method("get_MenuBar", DISPATCHED_METHOD),
    method("put_MenuBar", DISPATCHED_METHOD),
    method("get_FullScreen", DISPATCHED_METHOD),
    method("put_FullScreen", DISPATCHED_METHOD),
    method("Navigate2", DISPATCHED_METHOD),
    method("QueryStatusWB", DISPATCHED_METHOD),
    method("ExecWB", DISPATCHED_METHOD),
    method("ShowBrowserBar", DISPATCHED_METHOD),
    method("get_ReadyState", DISPATCHED_METHOD),
    method("Quit", DISPATCHED_METHOD),
    method("ClientToWindow", DISPATCHED_METHOD),
    method("PutProperty", DISPATCHED_METHOD),
    method("GetProperty", DISPATCHED_METHOD),
    method("get_RegisterAsBrowser", DISPATCHED_METHOD),
    method("put_RegisterAsBrowser", DISPATCHED_METHOD),
    method("get_RegisterAsDropTarget", DISPATCHED_METHOD),
    method("put_RegisterAsDropTarget", DISPATCHED_METHOD),
    method("get_TheaterMode", DISPATCHED_METHOD),
    method("put_TheaterMode", DISPATCHED_METHOD),
    method("get_AddressBar", DISPATCHED_METHOD),
    method("put_AddressBar", DISPATCHED_METHOD),
    method("get_Resizable", DISPATCHED_METHOD),
    method("put_Resizable", DISPATCHED_METHOD),
];

/// Media Foundation `IMFAttributes` vtable.
const IMF_ATTRIBUTES_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetItem", DISPATCHED_METHOD),
    method("GetItemType", DISPATCHED_METHOD),
    method("CompareItem", DISPATCHED_METHOD),
    method("Compare", DISPATCHED_METHOD),
    method("GetUINT32", DISPATCHED_METHOD),
    method("GetUINT64", DISPATCHED_METHOD),
    method("GetDouble", DISPATCHED_METHOD),
    method("GetGUID", DISPATCHED_METHOD),
    method("GetStringLength", DISPATCHED_METHOD),
    method("GetString", DISPATCHED_METHOD),
    method("GetAllocatedString", DISPATCHED_METHOD),
    method("GetBlobSize", DISPATCHED_METHOD),
    method("GetBlob", DISPATCHED_METHOD),
    method("GetAllocatedBlob", DISPATCHED_METHOD),
    method("GetUnknown", DISPATCHED_METHOD),
    method("SetItem", DISPATCHED_METHOD),
    method("SetUINT32", DISPATCHED_METHOD),
    method("SetUINT64", DISPATCHED_METHOD),
    method("SetDouble", DISPATCHED_METHOD),
    method("SetGUID", DISPATCHED_METHOD),
    method("SetString", DISPATCHED_METHOD),
    method("SetBlob", DISPATCHED_METHOD),
    method("SetUnknown", DISPATCHED_METHOD),
    method("DeleteAllItems", DISPATCHED_METHOD),
    method("DeleteItem", DISPATCHED_METHOD),
    method("LockStore", DISPATCHED_METHOD),
    method("UnlockStore", DISPATCHED_METHOD),
    method("GetCount", DISPATCHED_METHOD),
    method("GetItemByIndex", DISPATCHED_METHOD),
    method("CopyAllItems", DISPATCHED_METHOD),
];

/// Media Foundation `IMFMediaType` vtable (attributes + 5).
const IMF_MEDIA_TYPE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetItem", DISPATCHED_METHOD),
    method("GetItemType", DISPATCHED_METHOD),
    method("CompareItem", DISPATCHED_METHOD),
    method("Compare", DISPATCHED_METHOD),
    method("GetUINT32", DISPATCHED_METHOD),
    method("GetUINT64", DISPATCHED_METHOD),
    method("GetDouble", DISPATCHED_METHOD),
    method("GetGUID", DISPATCHED_METHOD),
    method("GetStringLength", DISPATCHED_METHOD),
    method("GetString", DISPATCHED_METHOD),
    method("GetAllocatedString", DISPATCHED_METHOD),
    method("GetBlobSize", DISPATCHED_METHOD),
    method("GetBlob", DISPATCHED_METHOD),
    method("GetAllocatedBlob", DISPATCHED_METHOD),
    method("GetUnknown", DISPATCHED_METHOD),
    method("SetItem", DISPATCHED_METHOD),
    method("SetUINT32", DISPATCHED_METHOD),
    method("SetUINT64", DISPATCHED_METHOD),
    method("SetDouble", DISPATCHED_METHOD),
    method("SetGUID", DISPATCHED_METHOD),
    method("SetString", DISPATCHED_METHOD),
    method("SetBlob", DISPATCHED_METHOD),
    method("SetUnknown", DISPATCHED_METHOD),
    method("DeleteAllItems", DISPATCHED_METHOD),
    method("DeleteItem", DISPATCHED_METHOD),
    method("LockStore", DISPATCHED_METHOD),
    method("UnlockStore", DISPATCHED_METHOD),
    method("GetCount", DISPATCHED_METHOD),
    method("GetItemByIndex", DISPATCHED_METHOD),
    method("CopyAllItems", DISPATCHED_METHOD),
    method("GetMajorType", DISPATCHED_METHOD),
    method("IsCompressedFormat", DISPATCHED_METHOD),
    method("IsEqual", DISPATCHED_METHOD),
    method("GetRepresentation", DISPATCHED_METHOD),
    method("FreeRepresentation", DISPATCHED_METHOD),
];

/// Media Foundation `IMFMediaBuffer` vtable.
const IMF_MEDIA_BUFFER_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("Lock", DISPATCHED_METHOD),
    method("Unlock", DISPATCHED_METHOD),
    method("GetCurrentLength", DISPATCHED_METHOD),
    method("SetCurrentLength", DISPATCHED_METHOD),
    method("GetMaxLength", DISPATCHED_METHOD),
];

/// Media Foundation `IMFSample` vtable.
const IMF_SAMPLE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("SetSampleFlags", DISPATCHED_METHOD),
    method("GetSampleFlags", DISPATCHED_METHOD),
    method("SetSampleTime", DISPATCHED_METHOD),
    method("GetSampleTime", DISPATCHED_METHOD),
    method("SetSampleDuration", DISPATCHED_METHOD),
    method("GetSampleDuration", DISPATCHED_METHOD),
    method("GetBufferCount", DISPATCHED_METHOD),
    method("GetBufferByIndex", DISPATCHED_METHOD),
    method("AddBuffer", DISPATCHED_METHOD),
    method("RemoveBufferByIndex", DISPATCHED_METHOD),
    method("RemoveAllBuffers", DISPATCHED_METHOD),
    method("GetTotalLength", DISPATCHED_METHOD),
    method("CopyToBuffer", DISPATCHED_METHOD),
    method("ConvertToContiguousBuffer", DISPATCHED_METHOD),
];

/// Media Foundation `IMFMediaSession` vtable.
const IMF_MEDIA_SESSION_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("SetTopology", DISPATCHED_METHOD),
    method("ClearTopologies", DISPATCHED_METHOD),
    method("Start", DISPATCHED_METHOD),
    method("Pause", DISPATCHED_METHOD),
    method("Stop", DISPATCHED_METHOD),
    method("Close", DISPATCHED_METHOD),
    method("Shutdown", DISPATCHED_METHOD),
    method("GetClock", DISPATCHED_METHOD),
    method("GetSessionCapabilities", DISPATCHED_METHOD),
    method("GetFullTopology", DISPATCHED_METHOD),
    method("GetDescriptorFromTopology", DISPATCHED_METHOD),
];

/// Media Foundation `IMFSourceResolver` vtable.
const IMF_SOURCE_RESOLVER_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("BeginCreateObjectFromURL", DISPATCHED_METHOD),
    method("BeginCreateObjectFromByteStream", DISPATCHED_METHOD),
    method("EndCreateObjectFromURL", DISPATCHED_METHOD),
    method("EndCreateObjectFromByteStream", DISPATCHED_METHOD),
    method("CancelObjectCreation", DISPATCHED_METHOD),
    method("CreateObjectFromURL", DISPATCHED_METHOD),
    method("CreateObjectFromByteStream", DISPATCHED_METHOD),
];

/// Media Foundation `IMFMediaSource` vtable.
const IMF_MEDIA_SOURCE_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetEvent", DISPATCHED_METHOD),
    method("BeginGetEvent", DISPATCHED_METHOD),
    method("EndGetEvent", DISPATCHED_METHOD),
    method("QueueEvent", DISPATCHED_METHOD),
    method("GetCharacteristics", DISPATCHED_METHOD),
    method("CreatePresentationDescriptor", DISPATCHED_METHOD),
    method("Start", DISPATCHED_METHOD),
    method("Stop", DISPATCHED_METHOD),
    method("Pause", DISPATCHED_METHOD),
    method("Shutdown", DISPATCHED_METHOD),
    method("CancelGetEvent", DISPATCHED_METHOD),
];

/// Media Foundation `IMFTransform` vtable.
const IMF_TRANSFORM_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("GetStreamLimits", DISPATCHED_METHOD),
    method("GetStreamCount", DISPATCHED_METHOD),
    method("GetStreamIDs", DISPATCHED_METHOD),
    method("GetStreamInfo", DISPATCHED_METHOD),
    method("GetAttributes", DISPATCHED_METHOD),
    method("GetInputAvailableType", DISPATCHED_METHOD),
    method("GetOutputAvailableType", DISPATCHED_METHOD),
    method("SetInputType", DISPATCHED_METHOD),
    method("SetOutputType", DISPATCHED_METHOD),
    method("GetInputCurrentType", DISPATCHED_METHOD),
    method("GetOutputCurrentType", DISPATCHED_METHOD),
    method("GetInputStatus", DISPATCHED_METHOD),
    method("GetOutputStatus", DISPATCHED_METHOD),
    method("ProcessInput", DISPATCHED_METHOD),
    method("ProcessOutput", DISPATCHED_METHOD),
    method("ProcessMessage", DISPATCHED_METHOD),
    optional(
        "UnsupportedSlot19",
        "slot-19 host thunk returns MF_E_UNSUPPORTED_BYTESTREAM_TYPE (0xC00D36C4) exactly",
    ),
];

/// Media Foundation `IMFSinkWriter` vtable.
const IMF_SINK_WRITER_METHODS: &[MethodSeed] = &[
    method("QueryInterface", DISPATCHED_METHOD),
    method("AddRef", DISPATCHED_METHOD),
    method("Release", DISPATCHED_METHOD),
    method("AddStream", DISPATCHED_METHOD),
    method("SetInputMediaType", DISPATCHED_METHOD),
    method("BeginWriting", DISPATCHED_METHOD),
    method("WriteSample", DISPATCHED_METHOD),
    method("SendStreamSample", DISPATCHED_METHOD),
    method("Flush", DISPATCHED_METHOD),
    method("NotifyEndOfSegment", DISPATCHED_METHOD),
    method("EndWriting", DISPATCHED_METHOD),
    method("GetServiceForStream", DISPATCHED_METHOD),
    method("GetStatistics", DISPATCHED_METHOD),
];

/// The method-level surface, populated from the vtable allocations in
/// `runtime/dispatch/{d3d11,dxgi_d3d12,mf,com}.rs` and the shell-link
/// allocator in `runtime/mod.rs`.
static INTERFACE_METHOD_SURFACE: &[InterfaceMethodSurface] = &[
    // D3D11
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11Device",
        methods: D3D11_DEVICE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11DeviceContext",
        methods: D3D11_CONTEXT_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11Texture2D",
        methods: D3D11_TEXTURE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11Buffer",
        methods: D3D11_DEVICE_CHILD_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11RenderTargetView",
        methods: D3D11_DEVICE_CHILD_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11DepthStencilView",
        methods: D3D11_DEVICE_CHILD_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11ShaderResourceView",
        methods: D3D11_DEVICE_CHILD_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11InputLayout",
        methods: D3D11_DEVICE_CHILD_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11VertexShader",
        methods: D3D11_DEVICE_CHILD_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11PixelShader",
        methods: D3D11_DEVICE_CHILD_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11GeometryShader",
        methods: D3D11_DEVICE_CHILD_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11ComputeShader",
        methods: D3D11_DEVICE_CHILD_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d11.dll",
        interface: "ID3D11Query",
        methods: D3D11_QUERY_METHODS,
    },
    // D3D12
    InterfaceMethodSurface {
        dll: "d3d12.dll",
        interface: "ID3D12Device",
        methods: D3D12_DEVICE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d12.dll",
        interface: "ID3D12CommandQueue",
        methods: D3D12_COMMAND_QUEUE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d12.dll",
        interface: "ID3D12DescriptorHeap",
        methods: D3D12_DESCRIPTOR_HEAP_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d12.dll",
        interface: "ID3D12Fence",
        methods: D3D12_FENCE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d12.dll",
        interface: "ID3D12GraphicsCommandList",
        methods: D3D12_GRAPHICS_COMMAND_LIST_METHODS,
    },
    InterfaceMethodSurface {
        dll: "d3d12.dll",
        interface: "ID3D12Resource",
        methods: D3D12_RESOURCE_METHODS,
    },
    // DXGI
    InterfaceMethodSurface {
        dll: "dxgi.dll",
        interface: "IDXGIFactory",
        methods: DXGI_FACTORY_METHODS,
    },
    InterfaceMethodSurface {
        dll: "dxgi.dll",
        interface: "IDXGISwapChain",
        methods: DXGI_SWAPCHAIN_METHODS,
    },
    // COM / OLE
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IUnknown",
        methods: &[
            method("QueryInterface", DISPATCHED_METHOD),
            method("AddRef", DISPATCHED_METHOD),
            method("Release", DISPATCHED_METHOD),
        ],
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IClassFactory",
        methods: ICLASS_FACTORY_METHODS,
    },
    InterfaceMethodSurface {
        dll: "oleaut32.dll",
        interface: "IDispatch",
        methods: IDISPATCH_METHODS,
    },
    InterfaceMethodSurface {
        dll: "oleaut32.dll",
        interface: "IEnumVARIANT",
        methods: IENUM_VARIANT_METHODS,
    },
    InterfaceMethodSurface {
        dll: "oleaut32.dll",
        interface: "IConnectionPoint",
        methods: ICONNECTION_POINT_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IMoniker",
        methods: IMONIKER_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IPersist",
        methods: IPERSIST_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IPersistStream",
        methods: IPERSIST_STREAM_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IStream",
        methods: ISTREAM_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IStorage",
        methods: ISTORAGE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IMalloc",
        methods: IMALLOC_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IOleObject",
        methods: IOLE_OBJECT_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IOleInPlaceObject",
        methods: IOLE_IN_PLACE_OBJECT_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IOleInPlaceActiveObject",
        methods: IOLE_IN_PLACE_ACTIVE_OBJECT_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IObjectWithSite",
        methods: IOBJECT_WITH_SITE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IServiceProvider",
        methods: ISERVICE_PROVIDER_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IDropTarget",
        methods: IDROP_TARGET_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IDataObject",
        methods: IDATA_OBJECT_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IEnumFORMATETC",
        methods: IENUM_FORMAT_ETC_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IEnumSTATDATA",
        methods: IENUM_STAT_DATA_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "IEnumOLEVERB",
        methods: IENUM_OLE_VERB_METHODS,
    },
    InterfaceMethodSurface {
        dll: "ole32.dll",
        interface: "ISupportErrorInfo",
        methods: ISUPPORT_ERROR_INFO_METHODS,
    },
    InterfaceMethodSurface {
        dll: "oleaut32.dll",
        interface: "ITypeInfo",
        methods: ITYPE_INFO_METHODS,
    },
    InterfaceMethodSurface {
        dll: "oleaut32.dll",
        interface: "ITypeLib",
        methods: ITYPE_LIB_METHODS,
    },
    InterfaceMethodSurface {
        dll: "shell32.dll",
        interface: "IShellLink",
        methods: ISHELL_LINK_METHODS,
    },
    // Browser
    InterfaceMethodSurface {
        dll: "shdocvw.dll",
        interface: "IWebBrowser2",
        methods: IWEB_BROWSER2_METHODS,
    },
    // Media Foundation
    InterfaceMethodSurface {
        dll: "mfplat.dll",
        interface: "IMFAttributes",
        methods: IMF_ATTRIBUTES_METHODS,
    },
    InterfaceMethodSurface {
        dll: "mfplat.dll",
        interface: "IMFMediaType",
        methods: IMF_MEDIA_TYPE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "mfplat.dll",
        interface: "IMFMediaBuffer",
        methods: IMF_MEDIA_BUFFER_METHODS,
    },
    InterfaceMethodSurface {
        dll: "mfplat.dll",
        interface: "IMFSample",
        methods: IMF_SAMPLE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "mf.dll",
        interface: "IMFMediaSession",
        methods: IMF_MEDIA_SESSION_METHODS,
    },
    InterfaceMethodSurface {
        dll: "mfplat.dll",
        interface: "IMFSourceResolver",
        methods: IMF_SOURCE_RESOLVER_METHODS,
    },
    InterfaceMethodSurface {
        dll: "mfplat.dll",
        interface: "IMFMediaSource",
        methods: IMF_MEDIA_SOURCE_METHODS,
    },
    InterfaceMethodSurface {
        dll: "mfplat.dll",
        interface: "IMFTransform",
        methods: IMF_TRANSFORM_METHODS,
    },
    InterfaceMethodSurface {
        dll: "mfreadwrite.dll",
        interface: "IMFSinkWriter",
        methods: IMF_SINK_WRITER_METHODS,
    },
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
    /// Method-level rows for this DLL's COM-style interfaces.
    #[serde(default)]
    pub method_total: usize,
    /// Method rows implementing a documented subset.
    #[serde(default)]
    pub method_partial: usize,
    /// Method rows with no vtable dispatch.
    #[serde(default)]
    pub method_unsupported: usize,
    /// Method rows whose dispatch performs the real operation.
    #[serde(default)]
    pub method_exact: usize,
    /// Method rows whose dispatch covers a documented subset.
    #[serde(default)]
    pub method_restricted: usize,
    /// Method rows producing synthetic approximations.
    #[serde(default)]
    pub method_approximate: usize,
    /// Method rows modeling an environment state honestly.
    #[serde(default)]
    pub method_synthetic_environment: usize,
    /// Method rows returning a deterministic canned response.
    #[serde(default)]
    pub method_canned_failure: usize,
    /// Method rows whose backing subsystem is fully available.
    #[serde(default)]
    pub method_capability_full: usize,
    /// Method rows whose backing subsystem is available with limitations.
    #[serde(default)]
    pub method_capability_partial: usize,
    /// Method rows whose backing subsystem is absent.
    #[serde(default)]
    pub method_capability_absent: usize,
    /// Method rows with any proven semantic coverage.
    #[serde(default)]
    pub method_covered: usize,
    /// Method rows with no proven semantic coverage.
    #[serde(default)]
    pub method_uncovered: usize,
    /// Method rows with Differential/Conformance semantic proof.
    #[serde(default)]
    pub method_proven: usize,
    /// Method rows without Differential/Conformance semantic proof.
    #[serde(default)]
    pub method_unproven: usize,
    /// Method rows that deviate from exact/full semantics.
    #[serde(default)]
    pub method_deviations: usize,
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
    /// Interface-completeness violations (overstated aggregates, missing
    /// method rows, unknown interfaces).  These are also part of the
    /// completeness-gate result; the separate list makes the method-level
    /// accounting auditable.
    #[serde(default)]
    pub interface_violations: Vec<ApiGateViolation>,
    /// Number of interface-completeness violations.
    #[serde(default)]
    pub interface_violation_count: usize,
    /// Method-level rows that deviate from exact/full semantics.
    #[serde(default)]
    pub method_deviations: usize,
    /// Required methods that still lack Differential/Conformance proof,
    /// summed over every interface.
    #[serde(default)]
    pub unproven_method_count: usize,
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

/// One method-level registry row in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiMethodRegistryRow {
    /// Exporting DLL name (lowercase, with extension).
    pub dll: String,
    /// COM/OLE interface name.
    pub interface: String,
    /// Method name within the interface vtable.
    pub method: String,
    /// Whether the method is part of the required base surface.
    pub required: bool,
    /// Implementation quality.
    pub implementation: ImplementationLevel,
    /// Proven semantic test coverage.
    pub semantic_test_coverage: CoverageLevel,
    /// Semantic fidelity of the dispatch.
    pub semantic_fidelity: SemanticFidelity,
    /// Backing-subsystem availability.
    pub subsystem_capability: SubsystemCapability,
    /// Per-method documentation note.
    #[serde(default)]
    pub detail: Option<String>,
    /// The compiled contract proving this method, when one exists.
    #[serde(default)]
    pub evidence_id: Option<String>,
}

/// Per-interface method-proof aggregate in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiInterfaceCoverageRow {
    /// Exporting DLL name (lowercase, with extension).
    pub dll: String,
    /// COM/OLE interface name.
    pub interface: String,
    /// Number of method rows belonging to the interface.
    pub method_count: usize,
    /// Number of required methods the aggregate is computed from.
    pub required_count: usize,
    /// Weakest semantic coverage across the considered methods.
    pub semantic_test_coverage: CoverageLevel,
    /// `true` only when every considered method has semantic proof.
    pub proven: bool,
    /// Required methods still lacking semantic proof, in vtable order.
    #[serde(default)]
    pub unproven_methods: Vec<String>,
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
    /// Per-method registry for COM-style interfaces (additive field; absent
    /// in older reports).
    #[serde(default)]
    pub method_registry: Vec<ApiMethodRegistryRow>,
    /// Per-interface method-proof aggregates and unproven method lists
    /// (additive field; absent in older reports).
    #[serde(default)]
    pub interface_registry: Vec<ApiInterfaceCoverageRow>,
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

#[cfg(test)]
mod method_proof_tests {
    use super::*;

    #[test]
    fn interface_gate_rejects_exact_claim_with_missing_method_proof() {
        let mut exact = ApiDatabase::new();
        exact.add_entry(ApiEntry::new(
            "dxgi.dll",
            "IDXGIFactory",
            ImplementationLevel::Implemented,
        ));
        exact.add_interface_method(InterfaceMethodEntry::new(
            "dxgi.dll",
            "IDXGIFactory",
            "EnumAdapters",
            true,
            ImplementationLevel::Implemented,
            SemanticFidelity::Exact,
            SubsystemCapability::Full,
            CoverageLevel::None,
        ));
        let aggregate = exact
            .interface_aggregate_status("dxgi.dll", "IDXGIFactory")
            .expect("aggregate");
        assert_eq!(aggregate.proven, false);
        assert_eq!(
            aggregate.unproven_methods,
            vec!["EnumAdapters".to_string()],
            "the unproven required method must be reported"
        );
        let violations = exact.interface_completeness_gate();
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].kind,
            ApiGateViolationKind::InterfaceClaimsUnprovenMethods
        );
        assert!(
            violations[0].message.contains("1 required method(s)"),
            "the violation must carry the unproven count: {}",
            violations[0].message
        );

        let mut proven = ApiDatabase::new();
        proven.add_entry(ApiEntry::new(
            "dxgi.dll",
            "IDXGIFactory",
            ImplementationLevel::Implemented,
        ));
        proven.add_interface_method(InterfaceMethodEntry::new(
            "dxgi.dll",
            "IDXGIFactory",
            "EnumAdapters",
            true,
            ImplementationLevel::Implemented,
            SemanticFidelity::Exact,
            SubsystemCapability::Full,
            CoverageLevel::Conformance,
        ));
        let aggregate = proven
            .interface_aggregate_status("dxgi.dll", "IDXGIFactory")
            .expect("aggregate");
        assert_eq!(aggregate.proven, true);
        assert!(aggregate.unproven_methods.is_empty());
        assert_eq!(
            proven.interface_completeness_gate().len(),
            0,
            "a fully proven exact/full interface passes"
        );

        let mut partial = ApiDatabase::new();
        let mut partial_entry =
            ApiEntry::new("dxgi.dll", "IDXGIFactory", ImplementationLevel::Implemented);
        partial_entry.semantic_fidelity = SemanticFidelity::Restricted;
        partial_entry.subsystem_capability = SubsystemCapability::Partial;
        partial.add_entry(partial_entry);
        partial.add_interface_method(InterfaceMethodEntry::new(
            "dxgi.dll",
            "IDXGIFactory",
            "EnumAdapters",
            true,
            ImplementationLevel::Partial,
            SemanticFidelity::Restricted,
            SubsystemCapability::Partial,
            CoverageLevel::None,
        ));
        assert_eq!(
            partial.interface_completeness_gate().len(),
            0,
            "a documented partial interface must not fail merely for unproven methods"
        );

        let mut overstated = ApiDatabase::new();
        overstated.add_entry(ApiEntry::new(
            "dxgi.dll",
            "IDXGIFactory",
            ImplementationLevel::Implemented,
        ));
        overstated.add_interface_method(InterfaceMethodEntry::new(
            "dxgi.dll",
            "IDXGIFactory",
            "EnumAdapters",
            true,
            ImplementationLevel::Partial,
            SemanticFidelity::Restricted,
            SubsystemCapability::Partial,
            CoverageLevel::None,
        ));
        let violations = overstated.interface_completeness_gate();
        assert_eq!(
            violations.len(),
            2,
            "an already-overstated aggregate reports its two axis violations, not a duplicate proof violation"
        );
        assert!(violations.iter().all(|violation| violation.kind
            == ApiGateViolationKind::InterfaceAggregateOverstatesChildren));
    }

    #[test]
    fn documented_restriction_table_rejects_exact_claims_for_each_arm() {
        let database = ApiDatabase::from_thunk_metadata();
        // Only methods whose semantics Metal genuinely cannot provide stay
        // restricted; every other method is now implemented and proven.
        let restricted = [
            ("mfplat.dll", "IMFTransform", "UnsupportedSlot19"),
            ("d3d12.dll", "ID3D12Device", "OpenExistingHeapFromAddress"),
            (
                "d3d12.dll",
                "ID3D12Device",
                "OpenExistingHeapFromFileMapping",
            ),
            (
                "d3d12.dll",
                "ID3D12Device",
                "CreateProtectedResourceSession",
            ),
            ("d3d12.dll", "ID3D12Device", "CreateMetaCommand"),
            ("d3d12.dll", "ID3D12Device", "EnumerateMetaCommands"),
            (
                "d3d12.dll",
                "ID3D12Device",
                "EnumerateMetaCommandParameters",
            ),
            ("d3d12.dll", "ID3D12Device", "GetResourceTiling"),
        ];
        for (dll, interface, method) in restricted {
            let row = database
                .lookup_interface_method(dll, interface, method)
                .unwrap_or_else(|| panic!("missing {dll}!{interface}::{method}"));
            assert_eq!(
                row.semantic_fidelity,
                SemanticFidelity::Restricted,
                "{interface}::{method} must not claim exact fidelity"
            );
            assert_eq!(
                row.subsystem_capability,
                SubsystemCapability::Partial,
                "{interface}::{method} must not claim full capability"
            );
        }
        // The 13 formerly-restricted methods are now Exact/Full.
        for (dll, interface, method) in [
            ("shdocvw.dll", "IWebBrowser2", "get_Document"),
            ("shdocvw.dll", "IWebBrowser2", "GetTypeInfo"),
            ("shdocvw.dll", "IWebBrowser2", "ShowBrowserBar"),
            ("shdocvw.dll", "IWebBrowser2", "ClientToWindow"),
            ("shdocvw.dll", "IWebBrowser2", "ExecWB"),
            ("ole32.dll", "IOleInPlaceObject", "ReactivateAndUndo"),
            ("ole32.dll", "IOleObject", "GetClipboardData"),
            ("ole32.dll", "IDataObject", "DAdvise"),
            ("mfplat.dll", "IMFMediaType", "GetRepresentation"),
            ("mfplat.dll", "IMFMediaType", "FreeRepresentation"),
            ("mfreadwrite.dll", "IMFSinkWriter", "GetServiceForStream"),
            ("mfplat.dll", "IMFSourceResolver", "CreateObjectFromURL"),
            (
                "mfplat.dll",
                "IMFSourceResolver",
                "BeginCreateObjectFromURL",
            ),
        ] {
            let row = database
                .lookup_interface_method(dll, interface, method)
                .unwrap_or_else(|| panic!("missing {dll}!{interface}::{method}"));
            assert_eq!(
                row.semantic_fidelity,
                SemanticFidelity::Exact,
                "{interface}::{method} must claim exact fidelity"
            );
            assert_eq!(
                row.subsystem_capability,
                SubsystemCapability::Full,
                "{interface}::{method} must claim full capability"
            );
        }
    }

    #[test]
    fn seeded_report_binds_every_method_to_compiled_evidence() {
        let database = ApiDatabase::from_thunk_metadata();
        let report = database.completeness_report();

        let bound = report
            .method_registry
            .iter()
            .find(|row| row.interface == "ID3D11Device" && row.method == "CreatePixelShader")
            .expect("CreatePixelShader row");
        assert_eq!(bound.semantic_test_coverage, CoverageLevel::Conformance);
        assert_eq!(
            bound.evidence_id.as_deref(),
            Some(
                "casa1-conformance:d3d11_device_methods_reject_invalid_input_and_pin_vtable_outputs"
            ),
            "the method row must name the compiled contract that proves it"
        );

        // The registry milestone: every seeded method is implemented and bound.
        assert!(
            report.method_registry.iter().all(|row| {
                row.implementation == ImplementationLevel::Implemented
                    && matches!(
                        row.semantic_test_coverage,
                        CoverageLevel::Conformance | CoverageLevel::Differential
                    )
                    && row.evidence_id.is_some()
            }),
            "every method row must carry implementation + compiled evidence"
        );
        assert_eq!(report.gate.unproven_method_count, 0);

        let interface = report
            .interface_registry
            .iter()
            .find(|row| row.dll == "d3d12.dll" && row.interface == "ID3D12GraphicsCommandList")
            .expect("ID3D12GraphicsCommandList aggregate");
        assert_eq!(interface.proven, true);
        assert!(interface.unproven_methods.is_empty());

        let summary = report.per_dll.get("d3d12.dll").expect("d3d12 summary");
        assert!(summary.method_proven >= 1);
        assert_eq!(summary.method_unproven, 0);

        let value = serde_json::to_value(&report).expect("report serializes");
        assert!(value.get("interface_registry").is_some());
        assert!(value["gate"].get("unproven_method_count").is_some());
        assert!(value["per_dll"]["d3d12.dll"].get("method_proven").is_some());
        assert!(
            value["per_dll"]["d3d12.dll"]
                .get("method_unproven")
                .is_some()
        );
    }
}
