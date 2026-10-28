#![allow(dead_code, unused_imports)]
//! Phase 43 — quantitative Windows API completeness database.
//!
//! Unit-style tests of the `api_database` module: seeding from the canonical
//! thunk metadata (Partial entries transitional ONLY with a specific reason),
//! the two gates (shipping allows explicitly documented Partial entries;
//! completeness never does), the semantic-coverage requirement, full-key
//! lookup, workload recording from the Steam fixture scan, the
//! api-completeness.json report shape, and the `casa1-oracle api-report
//! --gate` enforcement.

use casa1::api_coverage::{
    METHOD_COVERAGE_EVIDENCE, MethodCoverageEvidence, method_coverage_evidence_for,
    unresolved_method_evidence,
};
use casa1::api_database::{
    ApiCompletenessReport, ApiDatabase, ApiEntry, ApiGateViolationKind, CompatibilityTier,
    CoverageLevel, InterfaceMethodEntry, SemanticFidelity, SubsystemCapability, WindowsVersion,
};
use casa1::compatibility_profile::CompatibilityProfile;
use casa1::host_thunks::{ImplementationLevel, SupportPolicy};
use casa1::import_coverage::{WorkloadId, coverage_for_pe};
use serde_json::Value;
use std::path::Path;

fn native_user_mode_gate() -> (CompatibilityTier, CompatibilityProfile) {
    (
        CompatibilityTier::NativeUserMode,
        CompatibilityProfile::win11_native_desktop(),
    )
}

fn tracked_steam_fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("ges")
        .join("steam")
        .join("drive_c")
        .join("Steam")
        .join("Steam.exe")
}

// ---------------------------------------------------------------------------
// (a) Seeding from the thunk metadata
// ---------------------------------------------------------------------------

#[test]
fn database_seeds_from_thunk_metadata_with_levels() {
    let database = ApiDatabase::from_thunk_metadata();
    assert!(!database.is_empty());

    // A known fully-implemented thunk exists with its level.
    let create_file = database
        .lookup("kernel32.dll", "CreateFileW")
        .expect("CreateFileW must be seeded from THUNK_METADATA");
    assert_eq!(create_file.dll, "kernel32.dll");
    assert_eq!(create_file.export, "CreateFileW");
    assert_eq!(create_file.implementation, ImplementationLevel::Implemented);
    assert!(!create_file.transitional);

    // CompareStringW was completed in the partial-completion wave (the
    // NORM_IGNORECASE flag semantics are honored) and is now Implemented.
    let compare_string = database
        .lookup("kernel32.dll", "CompareStringW")
        .expect("CompareStringW must be seeded");
    assert_eq!(
        compare_string.implementation,
        ImplementationLevel::Implemented
    );
    assert!(!compare_string.transitional);

    // Stub entries are seeded with their metadata levels; the kernel32 core
    // surface (GetVersionExA and the interlocked/environment/INI/search
    // family) is Implemented with evidence_core_* conformance suites, and
    // the partials/stubs-3 wave implemented the resource table (FindResourceA
    // serves the module's .rsrc directory) with conformance evidence.
    let find_resource = database
        .lookup("kernel32.dll", "FindResourceA")
        .expect("FindResourceA must be seeded");
    assert_eq!(
        find_resource.implementation,
        ImplementationLevel::Implemented
    );
    assert_eq!(
        find_resource.semantic_test_coverage,
        CoverageLevel::Conformance,
        "FindResourceA is bound to the section11 NT surface evidence"
    );
    let version_ex_a = database
        .lookup("kernel32.dll", "GetVersionExA")
        .expect("GetVersionExA must be seeded");
    assert_eq!(
        version_ex_a.implementation,
        ImplementationLevel::Implemented
    );
    assert_eq!(
        version_ex_a.semantic_test_coverage,
        CoverageLevel::Conformance,
        "GetVersionExA is proven by the file-info/version/move/search suite"
    );
    // GetTickCount64 is implemented and oracle-covered (windows-oracle:time_clock).
    let tick_count_64 = database
        .lookup("kernel32.dll", "GetTickCount64")
        .expect("GetTickCount64 must be seeded");
    assert_eq!(
        tick_count_64.implementation,
        ImplementationLevel::Implemented
    );
    assert_eq!(
        tick_count_64.semantic_test_coverage,
        CoverageLevel::Differential,
        "GetTickCount64 is proven by the time_clock differential"
    );
}

#[test]
fn seed_classification_never_emits_the_generic_partial_reason() {
    let database = ApiDatabase::from_thunk_metadata();
    for entry in database.entries() {
        if entry.implementation == ImplementationLevel::Partial && entry.transitional {
            let reason = entry
                .detail
                .as_deref()
                .expect("transitional must carry a reason");
            assert!(
                !reason.contains("Partial per THUNK_METADATA"),
                "{}!{} carries the generic auto-transitional reason: {reason}",
                entry.dll,
                entry.export
            );
        }
    }
}

#[test]
fn database_seeds_interface_tables_at_runtime_levels() {
    let database = ApiDatabase::from_thunk_metadata();
    // COM: IDispatch is genuinely dispatched (GetIDsOfNames/Invoke thunks)
    // with the completed GetTypeInfoCount/GetTypeInfo answers.
    let dispatch = database
        .lookup("oleaut32.dll", "IDispatch")
        .expect("IDispatch entry");
    assert_eq!(dispatch.implementation, ImplementationLevel::Implemented);
    assert!(!dispatch.transitional);
    // DXGI/D3D: the device vtables are fully slotted (the graphics-ABI
    // wave completed the object/private-data/QI surfaces).
    let device = database
        .lookup("d3d11.dll", "ID3D11Device")
        .expect("ID3D11Device entry");
    assert_eq!(device.implementation, ImplementationLevel::Implemented);
    assert!(!device.transitional);
    assert_eq!(
        device.semantic_fidelity,
        SemanticFidelity::Restricted,
        "an aggregate interface admitting unsupported methods is never exact"
    );
    assert_eq!(
        device.subsystem_capability,
        SubsystemCapability::Partial,
        "the D3D11 device surface is partial until every method is proven"
    );
    let dxgi_factory = database
        .lookup("dxgi.dll", "IDXGIFactory")
        .expect("IDXGIFactory entry");
    assert_eq!(
        dxgi_factory.implementation,
        ImplementationLevel::Implemented
    );
    assert!(!dxgi_factory.transitional);
    // D3D12 heaps: the IID data export is implemented (the final-scraps
    // wave); the heap object surface remains the documented partial.
    let heap = database
        .lookup("d3d12.dll", "ID3D12Heap")
        .expect("ID3D12Heap entry");
    assert_eq!(heap.implementation, ImplementationLevel::Implemented);
    // Media Foundation: the session state machine exists in media.rs.
    let session = database
        .lookup("mf.dll", "IMFMediaSession")
        .expect("IMFMediaSession entry");
    assert_eq!(session.implementation, ImplementationLevel::Implemented);
    assert!(!session.transitional);
}

#[test]
fn method_level_rows_missing_proof_seed_restricted_not_exact() {
    let database = ApiDatabase::from_thunk_metadata();
    let unproven = database
        .lookup_interface_method("d3d12.dll", "ID3D12GraphicsCommandList", "ClearState")
        .expect("ClearState must be seeded from the D3D12 vtable metadata");
    assert_eq!(unproven.method, "ClearState");
    assert_eq!(
        unproven.implementation,
        ImplementationLevel::Partial,
        "a dispatched method without method-level proof is not Implemented-exact"
    );
    assert_eq!(
        unproven.semantic_fidelity,
        SemanticFidelity::Restricted,
        "methods without proof never seed Exact"
    );
    assert_eq!(
        unproven.subsystem_capability,
        SubsystemCapability::Partial,
        "methods without proof never seed Full"
    );
    assert_eq!(
        unproven.semantic_test_coverage,
        CoverageLevel::None,
        "no method-level evidence exists yet"
    );
    assert!(unproven.required);

    let aggregate = database
        .interface_aggregate_status("d3d11.dll", "ID3D11Device")
        .expect("ID3D11Device aggregate");
    assert_eq!(aggregate.method_count, 43);
    assert_eq!(aggregate.required_count, 40);
    assert_eq!(aggregate.semantic_fidelity, SemanticFidelity::Restricted);
    assert_eq!(aggregate.subsystem_capability, SubsystemCapability::Partial);

    assert_eq!(
        database
            .lookup_interface_method("d3d11.dll", "ID3D11Device", "NoSuchMethod")
            .map(|method| method.method.as_str()),
        None,
        "unknown methods must not resolve"
    );
}

#[test]
fn interface_gate_rejects_overstated_aggregate_status() {
    let mut database = ApiDatabase::new();
    let mut entry = ApiEntry::new(
        "d3d11.dll",
        "ID3D11Device",
        ImplementationLevel::Implemented,
    );
    entry.semantic_fidelity = SemanticFidelity::Exact;
    entry.subsystem_capability = SubsystemCapability::Full;
    database.add_entry(entry);
    database.add_interface_method(InterfaceMethodEntry::new(
        "d3d11.dll",
        "ID3D11Device",
        "CreateBuffer",
        true,
        ImplementationLevel::Partial,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        CoverageLevel::None,
    ));
    database.add_interface_method(InterfaceMethodEntry::new(
        "d3d11.dll",
        "ID3D11Device",
        "CreateQuery",
        true,
        ImplementationLevel::Stub,
        SemanticFidelity::CannedFailure,
        SubsystemCapability::Absent,
        CoverageLevel::None,
    ));

    let aggregate = database
        .interface_aggregate_status("d3d11.dll", "ID3D11Device")
        .expect("aggregate");
    assert_eq!(aggregate.implementation, ImplementationLevel::Stub);
    assert_eq!(aggregate.semantic_fidelity, SemanticFidelity::CannedFailure);
    assert_eq!(aggregate.subsystem_capability, SubsystemCapability::Absent);

    let violations = database.interface_completeness_gate();
    assert_eq!(
        violations.len(),
        2,
        "both fidelity and capability overstatement must be reported"
    );
    assert!(
        violations.iter().all(|violation| violation.kind
            == ApiGateViolationKind::InterfaceAggregateOverstatesChildren),
        "unexpected violation kinds: {violations:?}"
    );
}

#[test]
fn understated_interface_aggregate_is_not_flagged_as_an_error() {
    let mut database = ApiDatabase::new();
    let mut entry = ApiEntry::new("dxgi.dll", "IDXGIFactory", ImplementationLevel::Implemented);
    entry.semantic_fidelity = SemanticFidelity::Restricted;
    entry.subsystem_capability = SubsystemCapability::Partial;
    database.add_entry(entry);
    database.add_interface_method(InterfaceMethodEntry::new(
        "dxgi.dll",
        "IDXGIFactory",
        "EnumAdapters",
        false,
        ImplementationLevel::Implemented,
        SemanticFidelity::Exact,
        SubsystemCapability::Full,
        CoverageLevel::Conformance,
    ));

    let aggregate = database
        .interface_aggregate_status("dxgi.dll", "IDXGIFactory")
        .expect("aggregate");
    assert_eq!(aggregate.required_count, 0);
    assert_eq!(aggregate.semantic_fidelity, SemanticFidelity::Exact);
    assert_eq!(aggregate.subsystem_capability, SubsystemCapability::Full);
    assert_eq!(
        database.interface_completeness_gate().len(),
        0,
        "a conservative (understated) aggregate must not fail the interface gate"
    );
}

#[test]
fn interface_gate_rejects_missing_method_rows() {
    let mut database = ApiDatabase::new();
    let mut entry = ApiEntry::new("dxgi.dll", "IDXGIFactory", ImplementationLevel::Implemented);
    entry.semantic_fidelity = SemanticFidelity::Restricted;
    entry.subsystem_capability = SubsystemCapability::Partial;
    database.add_entry(entry);

    let violations = database.interface_completeness_gate();
    assert_eq!(
        violations.len(),
        1,
        "a known interface without method rows must fail once"
    );
    assert_eq!(
        violations[0].kind,
        ApiGateViolationKind::InterfaceMethodRowsMissing
    );
}

#[test]
fn interface_gate_rejects_unknown_interface_method_rows() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry::new(
        "gpu.dll",
        "IUnknownFake",
        ImplementationLevel::Implemented,
    ));
    database.add_interface_method(InterfaceMethodEntry::new(
        "gpu.dll",
        "IUnknownFake",
        "DoThing",
        true,
        ImplementationLevel::Partial,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        CoverageLevel::None,
    ));

    let violations = database.interface_completeness_gate();
    assert_eq!(violations.len(), 1, "an unknown interface must fail once");
    assert_eq!(violations[0].kind, ApiGateViolationKind::InterfaceUnknown);
}

#[test]
fn seeded_interface_aggregates_missing_method_proof_never_overstate() {
    let database = ApiDatabase::from_thunk_metadata();
    for (dll, interface) in [
        ("d3d11.dll", "ID3D11Device"),
        ("d3d12.dll", "ID3D12Device"),
        ("dxgi.dll", "IDXGIFactory"),
    ] {
        let entry = database
            .lookup(dll, interface)
            .unwrap_or_else(|| panic!("{dll}!{interface} entry"));
        let aggregate = database
            .interface_aggregate_status(dll, interface)
            .unwrap_or_else(|| panic!("{dll}!{interface} aggregate"));
        assert_eq!(
            entry.semantic_fidelity, aggregate.semantic_fidelity,
            "{dll}!{interface} aggregate fidelity must equal the worst child"
        );
        assert_eq!(
            entry.subsystem_capability, aggregate.subsystem_capability,
            "{dll}!{interface} aggregate capability must equal the worst child"
        );
        assert_eq!(aggregate.semantic_fidelity, SemanticFidelity::Restricted);
        assert_eq!(aggregate.subsystem_capability, SubsystemCapability::Partial);
    }
    assert_eq!(
        database.interface_completeness_gate().len(),
        0,
        "seeded aggregates must never overstate their method children"
    );
}

#[test]
fn method_level_deviations_are_counted_without_report_errors() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry::new(
        "d3d11.dll",
        "ID3D11Device",
        ImplementationLevel::Implemented,
    ));
    let rows = [
        (
            "ExactMethod",
            ImplementationLevel::Implemented,
            SemanticFidelity::Exact,
            SubsystemCapability::Full,
            CoverageLevel::Conformance,
        ),
        (
            "RestrictedMethod",
            ImplementationLevel::Partial,
            SemanticFidelity::Restricted,
            SubsystemCapability::Partial,
            CoverageLevel::None,
        ),
        (
            "ApproximateMethod",
            ImplementationLevel::Partial,
            SemanticFidelity::Approximate,
            SubsystemCapability::Partial,
            CoverageLevel::None,
        ),
        (
            "SyntheticMethod",
            ImplementationLevel::Partial,
            SemanticFidelity::SyntheticEnvironment,
            SubsystemCapability::Absent,
            CoverageLevel::Unit,
        ),
        (
            "CannedMethod",
            ImplementationLevel::Unsupported,
            SemanticFidelity::CannedFailure,
            SubsystemCapability::Absent,
            CoverageLevel::None,
        ),
    ];
    for (method, implementation, fidelity, capability, coverage) in rows {
        database.add_interface_method(InterfaceMethodEntry::new(
            "d3d11.dll",
            "ID3D11Device",
            method,
            true,
            implementation,
            fidelity,
            capability,
            coverage,
        ));
    }

    let report = database.completeness_report();
    let summary = report
        .per_dll
        .get("d3d11.dll")
        .expect("d3d11 method summary");
    assert_eq!(summary.method_total, 5);
    assert_eq!(summary.method_exact, 1);
    assert_eq!(summary.method_restricted, 1);
    assert_eq!(summary.method_approximate, 1);
    assert_eq!(summary.method_synthetic_environment, 1);
    assert_eq!(summary.method_canned_failure, 1);
    assert_eq!(summary.method_capability_full, 1);
    assert_eq!(summary.method_capability_partial, 2);
    assert_eq!(summary.method_capability_absent, 2);
    assert_eq!(summary.method_covered, 2);
    assert_eq!(summary.method_uncovered, 3);
    assert_eq!(summary.method_deviations, 4);
    assert_eq!(report.gate.method_deviations, 4);
    assert_eq!(report.method_registry.len(), 5);
    assert_eq!(
        report.gate.interface_violation_count, 2,
        "the default Exact/Full aggregate overstates both axes"
    );
    assert_eq!(
        report.gate.interface_violations.len(),
        report.gate.interface_violation_count
    );
}

#[test]
fn semantic_axes_keep_callable_separate_from_exact() {
    // The audit's "meaning of Implemented" regression: an export can be
    // callable without being exact, and the registry must never claim real
    // semantics its dispatch does not perform.  X3DAudioCalculate once
    // claimed "real sound-cone math" while writing a zeroed DSP response;
    // the real documented speaker model was implemented, so the row is
    // Implemented + Exact (the documented algorithm, not an approximation)
    // with a full software engine behind it.
    let database = ApiDatabase::from_thunk_metadata();
    let x3daudio_calculate = database
        .lookup("x3daudio1_7.dll", "X3DAudioCalculate")
        .expect("X3DAudioCalculate entry");
    assert_eq!(
        x3daudio_calculate.implementation,
        ImplementationLevel::Implemented,
        "the real spatial-math dispatch is Implemented"
    );
    assert!(
        !x3daudio_calculate.transitional,
        "no transitional partial reason applies to an implemented row"
    );
    assert_eq!(
        x3daudio_calculate.semantic_fidelity,
        SemanticFidelity::Exact,
        "the documented speaker model is implemented for real"
    );
    assert_eq!(
        x3daudio_calculate.subsystem_capability,
        SubsystemCapability::Full,
        "the software X3DAudio engine is complete"
    );
    assert!(
        database
            .deliberately_unsupported_error("x3daudio1_7.dll", "X3DAudioCalculate")
            .is_none(),
        "an implemented export is no longer deliberately unsupported"
    );
    assert!(
        x3daudio_calculate
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("spatial")),
        "the implemented row documents what the math covers"
    );

    // mscoree exposes the CoreCLR runtimes really installed on the host;
    // the legacy .NET Framework activation contract remains absent.
    let clr = database
        .lookup("mscoree.dll", "CLRCreateInstance")
        .expect("CLRCreateInstance entry");
    assert_eq!(clr.implementation, ImplementationLevel::Implemented);
    assert_eq!(
        clr.semantic_fidelity,
        SemanticFidelity::Exact,
        "the meta host and runtime host are the real installed CoreCLR objects"
    );
    assert_eq!(
        clr.subsystem_capability,
        SubsystemCapability::Partial,
        "managed execution works; the .NET Framework activation contract is absent"
    );
    let mf_service = database
        .lookup("mfplat.dll", "MFGetService")
        .expect("MFGetService entry");
    assert_eq!(
        mf_service.semantic_fidelity,
        SemanticFidelity::Restricted,
        "MF exists but no service provider is registered"
    );
    assert_eq!(
        mf_service.subsystem_capability,
        SubsystemCapability::Partial
    );
    let direct_play = database
        .lookup("dplay.dll", "DirectPlayCreate")
        .expect("DirectPlayCreate entry");
    assert_eq!(
        direct_play.semantic_fidelity,
        SemanticFidelity::Restricted,
        "the software DirectPlay8 peer engine now backs the legacy object"
    );
    assert_eq!(
        direct_play.subsystem_capability,
        SubsystemCapability::Partial
    );
    let dc_query = database
        .lookup("netutils.dll", "NetGetDCName")
        .expect("NetGetDCName entry");
    assert_eq!(
        dc_query.semantic_fidelity,
        SemanticFidelity::SyntheticEnvironment
    );
    assert_eq!(dc_query.subsystem_capability, SubsystemCapability::Absent);

    // Ordinary implemented APIs default to exact/full: the axes only downgrade
    // where the dispatch is actually restricted.
    let create_file = database
        .lookup("kernel32.dll", "CreateFileW")
        .expect("CreateFileW entry");
    assert_eq!(create_file.semantic_fidelity, SemanticFidelity::Exact);
    assert_eq!(create_file.subsystem_capability, SubsystemCapability::Full);
}

// ---------------------------------------------------------------------------
// (b) Gates: Partial must carry a specific reason to ship; never for release
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// (c) Semantic-coverage requirement
// ---------------------------------------------------------------------------

#[test]
fn implemented_without_coverage_fails_both_gates() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry::new(
        "c.dll",
        "NoCoverage",
        ImplementationLevel::Implemented,
    ));
    let shipping = database.shipping_gate();
    assert_eq!(shipping.len(), 1);
    assert_eq!(
        shipping[0].kind,
        ApiGateViolationKind::ImplementedWithoutCoverage
    );
    let completeness =
        database.completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1);
    assert_eq!(completeness.len(), 1);
    assert_eq!(
        completeness[0].kind,
        ApiGateViolationKind::ImplementedWithoutSemanticCoverage
    );
}

// ---------------------------------------------------------------------------
// (d) Deliberately-unsupported entries
// ---------------------------------------------------------------------------

#[test]
fn deliberately_unsupported_clears_shipping_but_not_user_mode_completeness() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry::new(
        "b.dll",
        "CannedApi",
        ImplementationLevel::Stub,
    ));
    database.add_entry(ApiEntry::new(
        "b.dll",
        "MissingApi",
        ImplementationLevel::Unsupported,
    ));

    // Without registration both fail both gates.
    let shipping = database.shipping_gate();
    let completeness =
        database.completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1);
    assert_eq!(shipping.len(), 2);
    assert_eq!(completeness.len(), 2);
    for violations in [&shipping, &completeness] {
        assert!(
            violations
                .iter()
                .any(|v| v.kind == ApiGateViolationKind::StubNotDeliberatelyUnsupported)
        );
        assert!(
            violations
                .iter()
                .any(|v| v.kind == ApiGateViolationKind::UnsupportedNotDeliberatelyUnsupported)
        );
    }

    // Registering the stub as deliberately unsupported with a guest-visible
    // compatibility error clears it through the SHIPPING gate...
    database.deliberately_unsupported(
        "b.dll",
        "CannedApi",
        "Returns the canned compatible value; no guest-visible error is raised",
    );
    assert_eq!(
        database
            .deliberately_unsupported_error("b.dll", "CannedApi")
            .expect("registered error"),
        "Returns the canned compatible value; no guest-visible error is raised"
    );
    assert!(
        database
            .shipping_gate()
            .iter()
            .all(|v| v.export == "MissingApi"),
        "only the unregistered Unsupported entry may violate shipping"
    );
    // ... but the NativeUserMode COMPLETENESS gate still rejects the
    // deliberately-unsupported user-mode stub: completeness requires a
    // working, semantically proven implementation.
    assert!(
        database
            .completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1)
            .iter()
            .any(|v| v.dll == "b.dll"
                && v.export == "CannedApi"
                && v.kind == ApiGateViolationKind::StubNotDeliberatelyUnsupported),
        "a deliberately-unsupported user-mode Stub still fails NativeUserMode completeness"
    );
    database.deliberately_unsupported(
        "b.dll",
        "MissingApi",
        "No host thunk exists; guest dispatch fails closed",
    );
    assert!(database.shipping_gate().is_empty());
    assert_eq!(
        database
            .completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1)
            .len(),
        2,
        "both user-mode stubs still fail the NativeUserMode completeness gate"
    );
}

#[test]
fn seeded_deliberately_unsupported_entries_carry_compatibility_errors() {
    let database = ApiDatabase::from_thunk_metadata();
    // The partials/stubs-3 wave implemented the anti-debug stub: the
    // debugger flag is a real runtime state, IsDebuggerPresent reads it, and
    // the debugger/affinity/switch-and-suspend suite proves the behavior.
    let is_debugger = database
        .lookup("kernel32.dll", "IsDebuggerPresent")
        .expect("IsDebuggerPresent must be seeded");
    assert_eq!(is_debugger.implementation, ImplementationLevel::Implemented);
    assert_eq!(
        is_debugger.semantic_test_coverage,
        CoverageLevel::Conformance,
        "IsDebuggerPresent is bound to the section11 NT surface evidence"
    );
    // IsDebuggerPresent is now covered by the section11 evidence binding;
    // it is no longer a shipping violation.
    assert!(
        !database
            .shipping_gate()
            .iter()
            .any(|v| { v.dll == "kernel32.dll" && v.export == "IsDebuggerPresent" }),
        "IsDebuggerPresent's coverage closed its shipping violation"
    );
    assert!(
        !database
            .completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1)
            .iter()
            .any(|v| v.dll == "kernel32.dll" && v.export == "IsDebuggerPresent"),
        "IsDebuggerPresent's coverage closed its completeness violation too"
    );
}

// ---------------------------------------------------------------------------
// (e) Lookup semantics: full-key lookup, ambiguity
// ---------------------------------------------------------------------------

#[test]
fn shipping_gate_flags_duplicate_full_keys_as_lookup_ambiguity() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry::new(
        "dup.dll",
        "Twice",
        ImplementationLevel::Implemented,
    ));
    database.add_entry(ApiEntry::new(
        "dup.dll",
        "Twice",
        ImplementationLevel::Implemented,
    ));
    let violations = database.shipping_gate();
    assert!(
        violations
            .iter()
            .any(|v| v.kind == ApiGateViolationKind::LookupAmbiguity),
        "duplicate full keys must be a shipping violation"
    );
}

#[test]
fn for_dll_lists_entries_for_a_single_dll() {
    let database = ApiDatabase::from_thunk_metadata();
    let kernel32: Vec<&ApiEntry> = database.for_dll("KERNEL32").collect();
    assert!(!kernel32.is_empty());
    assert!(
        kernel32.iter().all(|entry| entry.dll == "kernel32.dll"),
        "every entry must belong to kernel32.dll"
    );
    let ntdll: Vec<&ApiEntry> = database.for_dll("ntdll.dll").collect();
    assert!(!ntdll.is_empty(), "ntdll skeleton entries must be listed");
    assert!(ntdll.iter().all(|entry| entry.dll == "ntdll.dll"));
}

#[test]
fn record_workload_dedups_and_reports_found() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry::new(
        "x.dll",
        "Reached",
        ImplementationLevel::Implemented,
    ));
    assert!(database.record_workload("x.dll", "Reached", "fixture-a"));
    assert!(database.record_workload("X.DLL", "reached", "fixture-a"));
    assert!(database.record_workload("x.dll", "Reached", "fixture-b"));
    assert!(!database.record_workload("x.dll", "Unreached", "fixture-a"));

    let entry = database.lookup("x.dll", "Reached").expect("entry");
    assert_eq!(entry.workloads_reaching, vec!["fixture-a", "fixture-b"]);
}

// ---------------------------------------------------------------------------
// Steam fixture workload integration
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// (f) Report generator
// ---------------------------------------------------------------------------

#[test]
fn ledger_counts_include_method_level_deviations_without_error() {
    let database = ApiDatabase::from_thunk_metadata();
    let method_count = database.interface_methods().len();
    assert_eq!(method_count, 810);
    let ledger = database.compatibility_limitations_markdown();
    assert_eq!(ledger.contains("Method-level accounting:"), true);
    assert_eq!(
        ledger.contains(&format!(
            "{method_count} method rows, {method_count} deviate from exact/full"
        )),
        true,
        "the generated ledger must count every method-level deviation"
    );
    let report = database.completeness_report();
    assert_eq!(report.gate.method_deviations, method_count);
}

#[test]
fn old_report_json_missing_method_fields_still_deserializes() {
    let old = serde_json::json!({
        "generated_at": "2026-01-01T00:00:00Z",
        "per_dll": {
            "kernel32.dll": {
                "total": 1,
                "implemented": 1,
                "partial": 0,
                "stub": 0,
                "unsupported": 0,
                "differential_tested": 0,
                "conformance_tested": 0,
                "transitional_partial": 0,
                "exact": 1,
                "restricted": 0,
                "approximate": 0,
                "synthetic_environment": 0,
                "canned_failure": 0,
                "capability_full": 1,
                "capability_partial": 0,
                "capability_absent": 0
            }
        },
        "gate": {
            "shipping_violations": [],
            "shipping_violation_count": 0,
            "completeness_violations": [],
            "completeness_violation_count": 0
        },
        "registry": []
    });
    let report: ApiCompletenessReport =
        serde_json::from_value(old).expect("old report JSON must still deserialize");
    assert_eq!(report.method_registry.len(), 0);
    assert_eq!(report.gate.interface_violation_count, 0);
    assert_eq!(report.gate.method_deviations, 0);
    assert_eq!(
        report
            .per_dll
            .get("kernel32.dll")
            .expect("per-DLL summary")
            .method_total,
        0
    );
    assert_eq!(
        report.interface_registry.len(),
        0,
        "the additive interface registry defaults to empty"
    );
    assert_eq!(
        report.gate.unproven_method_count, 0,
        "the additive unproven method count defaults to zero"
    );
    let old_summary = report.per_dll.get("kernel32.dll").expect("per-DLL summary");
    assert_eq!(old_summary.method_proven, 0);
    assert_eq!(old_summary.method_unproven, 0);
}

#[test]
fn report_generator_emits_expected_json_shape() {
    let database = ApiDatabase::from_thunk_metadata();
    let report = database.completeness_report();
    let value: Value = serde_json::to_value(&report).expect("report serializes");

    let object = value.as_object().expect("report must be a JSON object");
    for key in ["generated_at", "per_dll", "gate"] {
        assert!(object.contains_key(key), "missing report field {key}");
    }
    assert!(
        object["generated_at"]
            .as_str()
            .is_some_and(|timestamp| !timestamp.is_empty()),
        "generated_at must be a non-empty timestamp"
    );

    let per_dll = object["per_dll"].as_object().expect("per_dll object");
    let kernel32 = per_dll
        .get("kernel32.dll")
        .expect("per_dll must include kernel32.dll");
    let summary = kernel32.as_object().expect("per-DLL summary object");
    for key in [
        "total",
        "implemented",
        "partial",
        "stub",
        "unsupported",
        "differential_tested",
        "conformance_tested",
        "transitional_partial",
    ] {
        assert!(summary.contains_key(key), "missing summary field {key}");
    }
    let total = summary["total"].as_u64().expect("total is a number");
    let implemented = summary["implemented"].as_u64().expect("implemented");
    let partial = summary["partial"].as_u64().expect("partial");
    let stub = summary["stub"].as_u64().expect("stub");
    let unsupported = summary["unsupported"].as_u64().expect("unsupported");
    assert_eq!(
        total,
        implemented + partial + stub + unsupported,
        "level counts must sum to the DLL total"
    );
    // The coverage registry seeds Differential coverage for the kernel32
    // oracle contracts (CreateFileW, VirtualAlloc, ...) and Conformance
    // coverage for the suite-evidenced APIs: the seeded database must carry
    // both.
    assert!(
        summary["differential_tested"]
            .as_u64()
            .expect("differential_tested")
            > 0,
        "the coverage registry must promote oracle-covered kernel32 APIs to Differential"
    );
    assert!(
        summary["conformance_tested"]
            .as_u64()
            .expect("conformance_tested")
            > 0,
        "the coverage registry must promote suite-evidenced kernel32 APIs to Conformance"
    );

    // The gate section carries both gate results with counts.
    let gate = object["gate"].as_object().expect("gate object");
    for key in [
        "shipping_violations",
        "shipping_violation_count",
        "completeness_violations",
        "completeness_violation_count",
    ] {
        assert!(gate.contains_key(key), "missing gate field {key}");
    }
    assert_eq!(
        gate["shipping_violation_count"]
            .as_u64()
            .expect("shipping_violation_count"),
        gate["shipping_violations"]
            .as_array()
            .expect("shipping_violations")
            .len() as u64
    );
    let completeness_count = gate["completeness_violation_count"]
        .as_u64()
        .expect("completeness_violation_count");
    assert_eq!(
        completeness_count,
        gate["completeness_violations"]
            .as_array()
            .expect("completeness_violations")
            .len() as u64
    );
    // The completeness-gate violation count is the total-compatibility
    // progress number.  The real-implementation campaign completed every
    // audited no-op: the canned six (X3DAudio math, digests, audit records,
    // rich-edit registration, native child creation) plus the certificate
    // selection and the four shell-UI helpers — nothing canned is left, no
    // Stub row remains, and the honest complete-accounting report carries
    // zero completeness violations.
    assert_eq!(
        completeness_count, 0,
        "no stub, partial or uncovered-implemented row may remain"
    );
    let violations = gate["completeness_violations"]
        .as_array()
        .expect("completeness_violations");
    assert!(
        violations.is_empty(),
        "the completeness violation list must be empty, got {violations:?}"
    );
    for violation in violations {
        let entry = violation.as_object().expect("violation object");
        for key in ["dll", "export", "kind", "message"] {
            assert!(entry.contains_key(key), "missing violation field {key}");
        }
    }

    // The report type itself matches the expected shape as well.
    let typed: ApiCompletenessReport =
        serde_json::from_value(value).expect("report round-trips through the typed shape");
    // wsock32 WSAStartup was implemented in the final-scraps wave; the
    // unregistered-Unsupported surface is now empty, so the report carries
    // no shipping violations for it (the honest post-implementation state).
    assert!(
        !typed
            .gate
            .shipping_violations
            .iter()
            .any(|v| { v.dll == "wsock32.dll" && v.export == "WSAStartup" }),
        "wsock32 WSAStartup is implemented (no shipping violation)"
    );
    assert!(
        !typed.gate.completeness_violations.iter().any(|v| {
            v.dll == "kernel32.dll"
                && v.export == "CompareStringW"
                && v.kind == ApiGateViolationKind::PartialNotCompletenessReady
        }),
        "CompareStringW's completion closed its completeness violation"
    );
    assert_eq!(
        typed.gate.completeness_violation_count,
        typed.gate.completeness_violations.len()
    );
}

// ---------------------------------------------------------------------------
// (g) api-report --gate exits non-zero on violations
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// (h) Oracle-backed coverage evidence registry
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// (i) Import-coverage generalization
// ---------------------------------------------------------------------------

#[test]
fn coverage_for_pe_produces_generic_binary_import_entries() {
    use casa1::cpu::GuestArch;
    use casa1::import_coverage::ImportSource;

    let path = tracked_steam_fixture();
    let workload = WorkloadId::new("section43");
    let target = CompatibilityProfile::win10_legacy_desktop();
    let report = coverage_for_pe(&path, &workload, target.clone()).expect("coverage report");

    // The report is generic: it carries the binary identity and the profile.
    assert_eq!(report.image_arch, GuestArch::X86);
    assert_eq!(report.target, target);
    assert!(!report.image_sha256.is_empty());
    assert!(report.total_imports > 300);

    // Entries carry the new generic fields.
    let create_file = report
        .entries
        .iter()
        .find(|entry| entry.import.lookup_name() == "CreateFileW")
        .expect("CreateFileW import");
    assert_eq!(create_file.dll, "kernel32.dll");
    assert_eq!(create_file.source, ImportSource::Static);
    assert_eq!(create_file.implementation, ImplementationLevel::Implemented);
    assert_eq!(
        create_file.semantic_coverage,
        CoverageLevel::Differential,
        "oracle-covered APIs report their proven coverage"
    );
    assert!(!create_file.runtime_reached);
    assert_eq!(create_file.support_policy(), Some(SupportPolicy::Required));
    // The profile the report was computed for is recorded.
    assert_eq!(report.target.windows_version, WindowsVersion::Win10);

    // Delay-loaded imports are attributed separately.
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.source == ImportSource::DelayLoad)
            || report
                .entries
                .iter()
                .all(|entry| entry.source == ImportSource::Static),
        "delay-load imports must be attributed as DelayLoad when present"
    );
}

// ---------------------------------------------------------------------------
// (j) Method-level compatibility evidence
// ---------------------------------------------------------------------------

#[test]
fn method_evidence_resolves_real_test_and_rejects_uncompiled_binding() {
    let bound = method_coverage_evidence_for("D3D11.DLL", "id3d11device", "createpixelshader")
        .expect("the seeded D3D11 method evidence must resolve");
    assert_eq!(
        bound.evidence_id,
        "casa1-conformance:d3d11_device_methods_reject_invalid_input_and_pin_vtable_outputs"
    );
    assert_eq!(bound.level, CoverageLevel::Conformance);
    assert_eq!(
        method_coverage_evidence_for("d3d11.dll", "ID3D11Device", "NoSuchMethod"),
        None,
        "an unbound method must not resolve"
    );

    let fabricated = MethodCoverageEvidence {
        dll: "d3d11.dll",
        interface: "ID3D11Device",
        method: "Fabricated",
        level: CoverageLevel::Conformance,
        evidence_id: "casa1-conformance:this_method_suite_is_not_compiled",
    };
    let unresolved = unresolved_method_evidence(&[fabricated]);
    assert_eq!(
        unresolved,
        vec!["casa1-conformance:this_method_suite_is_not_compiled".to_string()],
        "an uncompiled evidence id must fail validation"
    );
    assert_eq!(
        unresolved_method_evidence(METHOD_COVERAGE_EVIDENCE),
        Vec::<String>::new(),
        "every shipped method evidence row must bind to a compiled test"
    );
}

#[test]
fn aggregate_coverage_recomputes_and_reports_missing_method_proof() {
    let mut unproven = ApiDatabase::new();
    unproven.add_entry(ApiEntry::new(
        "d3d11.dll",
        "ID3D11Device",
        ImplementationLevel::Implemented,
    ));
    unproven.add_interface_method(InterfaceMethodEntry::new(
        "d3d11.dll",
        "ID3D11Device",
        "CreateBuffer",
        true,
        ImplementationLevel::Partial,
        SemanticFidelity::Restricted,
        SubsystemCapability::Partial,
        CoverageLevel::None,
    ));
    let aggregate = unproven
        .interface_aggregate_status("d3d11.dll", "ID3D11Device")
        .expect("unproven aggregate");
    assert_eq!(aggregate.proven, false);
    assert_eq!(
        aggregate.unproven_methods,
        vec!["CreateBuffer".to_string()],
        "the aggregate must report the method that lacks proof"
    );

    let mut proven = ApiDatabase::new();
    proven.add_entry(ApiEntry::new(
        "d3d11.dll",
        "ID3D11Device",
        ImplementationLevel::Implemented,
    ));
    proven.add_interface_method(InterfaceMethodEntry::new(
        "d3d11.dll",
        "ID3D11Device",
        "CreateBuffer",
        true,
        ImplementationLevel::Implemented,
        SemanticFidelity::Exact,
        SubsystemCapability::Full,
        CoverageLevel::Conformance,
    ));
    let aggregate = proven
        .interface_aggregate_status("d3d11.dll", "ID3D11Device")
        .expect("proven aggregate");
    assert_eq!(aggregate.proven, true);
    assert_eq!(aggregate.semantic_test_coverage, CoverageLevel::Conformance);
    assert!(aggregate.unproven_methods.is_empty());
}

#[test]
fn interface_gate_rejects_exact_or_full_claim_with_missing_method_proof() {
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
    let violations = exact.interface_completeness_gate();
    assert_eq!(violations.len(), 1);
    assert_eq!(
        violations[0].kind,
        ApiGateViolationKind::InterfaceClaimsUnprovenMethods
    );
    assert!(
        violations[0].message.contains("EnumAdapters"),
        "the violation must name the unproven method"
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
}
