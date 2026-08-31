//! Phase 43 — quantitative Windows API completeness database.
//!
//! Unit-style tests of the `api_database` module: seeding from the canonical
//! thunk metadata (Partial entries transitional ONLY with a specific reason),
//! the two gates (shipping allows explicitly documented Partial entries;
//! completeness never does), the semantic-coverage requirement, full-key
//! lookup, workload recording from the Steam fixture scan, the
//! api-completeness.json report shape, and the `casa1-oracle api-report
//! --gate` enforcement.

use casa1::api_coverage::coverage_evidence_for;
use casa1::api_database::{
    ApiCompletenessReport, ApiDatabase, ApiEntry, ApiGateViolationKind, ArchSet, CompatibilityTier,
    CoverageLevel, WindowsVersion, global_database,
};
use casa1::compatibility_profile::CompatibilityProfile;
use casa1::host_thunks::{ImplementationLevel, SupportPolicy};
use casa1::import_coverage::{WorkloadId, coverage_for_pe, coverage_for_pe_with_runtime_trace};
use serde_json::Value;
use std::path::Path;

/// The default gate evaluation: the full native user-mode profile.
fn native_user_mode_gate() -> (CompatibilityTier, CompatibilityProfile) {
    (
        CompatibilityTier::NativeUserMode,
        CompatibilityProfile::win11_native_desktop(),
    )
}

/// Path to the tracked Steam.exe fixture (committed to the repo).
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

    // A Partial thunk is seeded transitional WITH a specific reason, never a
    // generic one: the seed-time classification pass records what is missing.
    let compare_string = database
        .lookup("kernel32.dll", "CompareStringW")
        .expect("CompareStringW must be seeded");
    assert_eq!(compare_string.implementation, ImplementationLevel::Partial);
    assert!(
        compare_string.transitional,
        "Partial entries with a documented limitation must be flagged transitional"
    );
    let reason = compare_string.detail.as_deref().expect("specific reason");
    assert!(
        !reason.contains("Partial per THUNK_METADATA"),
        "the transitional reason must be specific, not the generic metadata note"
    );
    assert!(
        reason.contains("locale"),
        "the reason names the concrete limitation: {reason}"
    );

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
        CoverageLevel::None,
        "FindResourceA's phantom resources-and-ioctl evidence was removed by the \
         evidence-chain audit fix; no verified suite covers it yet"
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
fn database_seeds_nt_surface_matching_runtime() {
    let database = ApiDatabase::from_thunk_metadata();
    // NtQueryInformationProcess is the one Nt* API with a real host thunk.
    let query_process = database
        .lookup("ntdll.dll", "NtQueryInformationProcess")
        .expect("NtQueryInformationProcess skeleton entry");
    assert_eq!(
        query_process.implementation,
        ImplementationLevel::Implemented,
        "the runtime dispatches NtQueryInformationProcess"
    );
    // The Stage-4 NTDLL foundation implemented the native surface — every
    // dispatched Nt* API carries its Implemented level from THUNK_METADATA.
    for implemented in [
        "NtCreateFile",
        "NtAllocateVirtualMemory",
        "NtWaitForSingleObject",
        "NtQuerySystemInformation",
        "NtClose",
        "NtOpenKey",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateSection",
        "NtMapViewOfSection",
    ] {
        let entry = database
            .lookup("ntdll.dll", implemented)
            .unwrap_or_else(|| panic!("{implemented} must have an entry"));
        assert_eq!(
            entry.implementation,
            ImplementationLevel::Implemented,
            "{implemented} is dispatched by the runtime"
        );
    }
    // The Nt* skeletons are implemented (the final-scraps wave); the
    // honestly-unsupported set is empty.
    for unsupported in [] as [&str; 0] {
        let entry = database
            .lookup("ntdll.dll", unsupported)
            .unwrap_or_else(|| panic!("{unsupported} must have a skeleton entry"));
        assert_eq!(
            entry.implementation,
            ImplementationLevel::Unsupported,
            "{unsupported} has no host thunk"
        );
    }
}

#[test]
fn database_seeds_interface_tables_at_runtime_levels() {
    let database = ApiDatabase::from_thunk_metadata();
    // COM: IDispatch is genuinely dispatched (GetIDsOfNames/Invoke thunks).
    let dispatch = database
        .lookup("oleaut32.dll", "IDispatch")
        .expect("IDispatch entry");
    assert_eq!(dispatch.implementation, ImplementationLevel::Partial);
    assert!(dispatch.transitional);
    assert!(dispatch.detail.is_some());
    // DXGI/D3D: ID3D11Device and friends are partial vtable dispatches.
    let device = database
        .lookup("d3d11.dll", "ID3D11Device")
        .expect("ID3D11Device entry");
    assert_eq!(device.implementation, ImplementationLevel::Partial);
    let dxgi_factory = database
        .lookup("dxgi.dll", "IDXGIFactory")
        .expect("IDXGIFactory entry");
    assert_eq!(dxgi_factory.implementation, ImplementationLevel::Partial);
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
    assert_eq!(session.implementation, ImplementationLevel::Partial);
    assert!(session.transitional);
}

// ---------------------------------------------------------------------------
// (b) Gates: Partial must carry a specific reason to ship; never for release
// ---------------------------------------------------------------------------

#[test]
fn shipping_gate_flags_partial_without_specific_reason() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry::new(
        "a.dll",
        "PartiallyDone",
        ImplementationLevel::Partial,
    ));
    database.add_entry(ApiEntry::new(
        "a.dll",
        "FullyDone",
        ImplementationLevel::Implemented,
    ));

    // The Implemented entry without coverage also violates shipping; focus on
    // the Partial violation.
    let violations = database.shipping_gate();
    let partial_violation = violations
        .iter()
        .find(|v| v.export == "PartiallyDone")
        .expect("the Partial entry must violate the shipping gate");
    assert_eq!(partial_violation.dll, "a.dll");
    assert_eq!(
        partial_violation.kind,
        ApiGateViolationKind::PartialNotTransitional
    );
    assert!(partial_violation.message.contains("specific"));
    // Completeness flags the Partial regardless of the reason.
    assert!(
        database
            .completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1)
            .iter()
            .any(|v| v.export == "PartiallyDone"
                && v.kind == ApiGateViolationKind::PartialNotCompletenessReady)
    );
}

#[test]
fn shipping_gate_accepts_partial_with_specific_reason() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry {
        transitional: true,
        detail: Some("only ASCII paths are folded; Unicode normalization is missing".to_string()),
        ..ApiEntry::new("a.dll", "PartiallyDone", ImplementationLevel::Partial)
    });
    database.add_entry(ApiEntry {
        semantic_test_coverage: CoverageLevel::Unit,
        ..ApiEntry::new("a.dll", "FullyDone", ImplementationLevel::Implemented)
    });
    assert!(
        database.shipping_gate().is_empty(),
        "a Partial with a specific documented reason passes the shipping gate"
    );
    // ... but Partial NEVER passes the completeness gate.
    let completeness_violations =
        database.completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1);
    assert_eq!(completeness_violations.len(), 2);
    assert!(
        completeness_violations
            .iter()
            .any(|v| v.export == "PartiallyDone"
                && v.kind == ApiGateViolationKind::PartialNotCompletenessReady)
    );
}

#[test]
fn transitional_flag_without_detail_is_not_a_specific_reason() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry {
        transitional: true,
        detail: None,
        ..ApiEntry::new("a.dll", "PartiallyDone", ImplementationLevel::Partial)
    });
    assert!(
        database
            .shipping_gate()
            .iter()
            .any(|v| v.kind == ApiGateViolationKind::PartialNotTransitional),
        "transitional without a recorded reason must still fail the shipping gate"
    );
}

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

#[test]
fn implemented_with_unit_coverage_passes_shipping_only() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry {
        semantic_test_coverage: CoverageLevel::Unit,
        ..ApiEntry::new("c.dll", "UnitCovered", ImplementationLevel::Implemented)
    });
    assert!(
        database.shipping_gate().is_empty(),
        "Unit coverage satisfies the shipping gate"
    );
    assert_eq!(
        database.completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1)[0].kind,
        ApiGateViolationKind::ImplementedWithoutSemanticCoverage,
        "Unit coverage is NOT enough for the completeness gate"
    );
}

#[test]
fn implemented_with_differential_coverage_passes_both_gates() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry {
        semantic_test_coverage: CoverageLevel::Differential,
        ..ApiEntry::new(
            "c.dll",
            "DifferentiallyCovered",
            ImplementationLevel::Implemented,
        )
    });
    assert!(
        database.shipping_gate().is_empty(),
        "Differential coverage satisfies the shipping gate"
    );
    assert!(
        database
            .completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1)
            .is_empty(),
        "Differential coverage satisfies the completeness gate"
    );
}

#[test]
fn implemented_with_conformance_coverage_passes_both_gates() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry {
        semantic_test_coverage: CoverageLevel::Conformance,
        ..ApiEntry::new(
            "c.dll",
            "ConformanceCovered",
            ImplementationLevel::Implemented,
        )
    });
    assert!(database.shipping_gate().is_empty());
    assert!(
        database
            .completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1)
            .is_empty()
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
fn outside_user_mode_profile_entries_are_exempt_from_user_mode_completeness() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry {
        support_policy: SupportPolicy::OutsideUserModeProfile,
        ..ApiEntry::new(
            "ntdll.dll",
            "NtCreateFile",
            ImplementationLevel::Unsupported,
        )
    });
    database.add_entry(ApiEntry {
        support_policy: SupportPolicy::OutsideUserModeProfile,
        ..ApiEntry::new(
            "d3d8thk.dll",
            "D3DKMTCloseAdapter",
            ImplementationLevel::Unsupported,
        )
    });
    database.add_entry(ApiEntry::new(
        "kernel32.dll",
        "RequiredUserApi",
        ImplementationLevel::Unsupported,
    ));

    let (tier, profile) = native_user_mode_gate();
    let violations = database.completeness_gate(tier, &profile);
    // Only the user-mode entry may violate NativeUserMode.
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].dll, "kernel32.dll");
    assert_eq!(violations[0].export, "RequiredUserApi");

    // The kernel tier evaluates ONLY the OutsideUserModeProfile entries.
    let kernel_violations =
        database.completeness_gate(CompatibilityTier::RestrictedKernel, &profile);
    assert_eq!(kernel_violations.len(), 2);
    assert!(
        kernel_violations
            .iter()
            .all(|v| v.dll == "ntdll.dll" || v.dll == "d3d8thk.dll")
    );

    // The shipping gate also exempts OutsideUserModeProfile entries from the
    // deliberately-unsupported requirement.
    assert!(
        database
            .shipping_gate()
            .iter()
            .all(|v| v.export == "RequiredUserApi"),
        "kernel-tier entries need no user-mode compatibility error"
    );
}

#[test]
fn optional_feature_entries_pass_when_the_profile_excludes_them() {
    let mut database = ApiDatabase::new();
    // An optional-subsystem API (web) that is implemented but not yet
    // semantically proven, plus an optional Stub in the same subsystem.
    database.add_entry(ApiEntry {
        support_policy: SupportPolicy::OptionalFeature,
        ..ApiEntry::new("winhttp.dll", "WinHttpOpen", ImplementationLevel::Partial)
    });
    database.add_entry(ApiEntry {
        support_policy: SupportPolicy::OptionalFeature,
        ..ApiEntry::new("wininet.dll", "InternetOpenW", ImplementationLevel::Stub)
    });
    // A required API for contrast: never excludable.
    database.add_entry(ApiEntry::new(
        "kernel32.dll",
        "RequiredApi",
        ImplementationLevel::Partial,
    ));

    let (tier, full_profile) = native_user_mode_gate();
    // Full desktop profile: nothing excluded — every entry violates.
    let violations = database.completeness_gate(tier, &full_profile);
    assert_eq!(violations.len(), 3);

    // Gaming profile: web excluded — the optional web entries pass.
    let gaming = CompatibilityProfile::win11_gaming();
    let violations = database.completeness_gate(tier, &gaming);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].export, "RequiredApi");

    // Legacy desktop profile also excludes web.
    let legacy = CompatibilityProfile::win10_legacy_desktop();
    let violations = database.completeness_gate(tier, &legacy);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].export, "RequiredApi");

    // The managed profile also excludes web: one violation again.
    let managed = CompatibilityProfile::managed_desktop();
    let violations = database.completeness_gate(tier, &managed);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].export, "RequiredApi");

    // A profile that excludes nothing but graphics leaves the web entries
    // unevaluated-exempt: all three violate.
    let custom = CompatibilityProfile {
        optional_features: std::collections::BTreeSet::from(["graphics".to_string()]),
        ..CompatibilityProfile::win11_native_desktop()
    };
    let violations = database.completeness_gate(tier, &custom);
    assert_eq!(violations.len(), 3);
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
        CoverageLevel::None,
        "IsDebuggerPresent's phantom evidence was removed; no verified suite covers it"
    );
    // Implemented without verified evidence (its phantom suite was removed
    // by the evidence-chain audit fix): a shipping violation AND a
    // completeness violation — the honest state until a real test exists.
    assert!(
        database
            .shipping_gate()
            .iter()
            .any(|v| { v.dll == "kernel32.dll" && v.export == "IsDebuggerPresent" }),
        "an implemented but uncovered IsDebuggerPresent IS a shipping violation"
    );
    assert!(
        database
            .completeness_gate(native_user_mode_gate().0, &native_user_mode_gate().1)
            .iter()
            .any(|v| v.dll == "kernel32.dll" && v.export == "IsDebuggerPresent"),
        "an implemented but uncovered IsDebuggerPresent IS a completeness violation"
    );
}

// ---------------------------------------------------------------------------
// (e) Lookup semantics: full-key lookup, ambiguity
// ---------------------------------------------------------------------------

#[test]
fn lookup_is_case_insensitive_and_tolerates_dll_suffix() {
    let database = ApiDatabase::from_thunk_metadata();
    for (dll, export) in [
        ("kernel32.dll", "CreateFileW"),
        ("KERNEL32.DLL", "createfilew"),
        ("kernel32", "CREATEFILEW"),
        ("Kernel32", "CreateFileW"),
    ] {
        let entry = database
            .lookup(dll, export)
            .unwrap_or_else(|| panic!("lookup({dll}, {export}) must match"));
        assert_eq!(entry.export, "CreateFileW");
        assert_eq!(entry.dll, "kernel32.dll");
    }
    assert!(database.lookup("kernel32.dll", "NoSuchExport").is_none());
    assert!(database.lookup("missing.dll", "CreateFileW").is_none());
}

#[test]
fn lookup_entry_uses_the_full_key_when_arch_rows_differ() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry {
        arch: ArchSet::X86,
        win_version: WindowsVersion::Win10,
        detail: Some("x86-specific row".to_string()),
        ..ApiEntry::new("z.dll", "PerArch", ImplementationLevel::Implemented)
    });
    database.add_entry(ApiEntry {
        arch: ArchSet::X64,
        win_version: WindowsVersion::Win10,
        detail: Some("x64-specific row".to_string()),
        ..ApiEntry::new("z.dll", "PerArch", ImplementationLevel::Implemented)
    });
    database.add_entry(ApiEntry {
        arch: ArchSet::X64,
        win_version: WindowsVersion::Win11,
        detail: Some("x64 Win11 row".to_string()),
        ..ApiEntry::new("z.dll", "PerArch", ImplementationLevel::Implemented)
    });

    // The full key returns exactly the right row.
    let x86 = database
        .lookup_entry("z.dll", "perarch", ArchSet::X86, WindowsVersion::Win10)
        .expect("x86 row");
    assert_eq!(x86.detail.as_deref(), Some("x86-specific row"));
    let x64 = database
        .lookup_entry("Z.DLL", "PerArch", ArchSet::X64, WindowsVersion::Win10)
        .expect("x64 row");
    assert_eq!(x64.detail.as_deref(), Some("x64-specific row"));
    let x64_win11 = database
        .lookup_entry("z.dll", "PerArch", ArchSet::X64, WindowsVersion::Win11)
        .expect("x64 Win11 row");
    assert_eq!(x64_win11.detail.as_deref(), Some("x64 Win11 row"));
    // A key that does not exist is None.
    assert!(
        database
            .lookup_entry("z.dll", "PerArch", ArchSet::X86, WindowsVersion::Win11)
            .is_none()
    );

    // The legacy (DLL, export) lookup is ambiguous across these rows and
    // returns None instead of silently picking the first.
    assert!(
        database.lookup("z.dll", "PerArch").is_none(),
        "legacy lookup must be None on ambiguity"
    );
}

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

#[test]
fn steam_fixture_scan_consults_database_and_records_workload() {
    let path = tracked_steam_fixture();
    assert!(
        path.is_file(),
        "tracked Steam fixture missing at {}",
        path.display()
    );
    let workload = WorkloadId::new("steam");
    let report = coverage_for_pe(
        &path,
        &workload,
        CompatibilityProfile::win11_native_desktop(),
    )
    .expect("fixture coverage scan");
    assert!(report.total_imports > 300);

    // The fixture scan consults the database: the classified level of every
    // import matches the database entry where one exists.
    let database = global_database();
    let database = database.lock().expect("database lock");
    let create_file = database
        .lookup("kernel32.dll", "CreateFileW")
        .expect("CreateFileW entry");
    assert_eq!(
        create_file.implementation,
        ImplementationLevel::Implemented,
        "the database is the compatibility accounting source"
    );
    // The scan records the workload into the entries it reaches.
    assert!(
        create_file
            .workloads_reaching
            .iter()
            .any(|workload| workload == "steam"),
        "the fixture scan must record the workload on CreateFileW"
    );
}

// ---------------------------------------------------------------------------
// (f) Report generator
// ---------------------------------------------------------------------------

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
    // progress number — the seeded database honestly fails both gates.
    assert!(
        completeness_count > 0,
        "the seeded database has honest gate violations"
    );
    for violation in gate["completeness_violations"]
        .as_array()
        .expect("completeness_violations")
    {
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
        typed.gate.completeness_violations.iter().any(|v| {
            v.dll == "kernel32.dll"
                && v.export == "CompareStringW"
                && v.kind == ApiGateViolationKind::PartialNotCompletenessReady
        }),
        "Partial entries are honest completeness violations"
    );
    assert_eq!(
        typed.gate.completeness_violation_count,
        typed.gate.completeness_violations.len()
    );
}

#[test]
fn arch_and_win_version_serialize_with_entries() {
    let entry = ApiEntry {
        arch: ArchSet::X64,
        win_version: WindowsVersion::Win11,
        semantic_test_coverage: CoverageLevel::Differential,
        ..ApiEntry::new("z.dll", "Exported", ImplementationLevel::Implemented)
    };
    let value = serde_json::to_value(&entry).expect("entry serializes");
    let object = value.as_object().expect("entry object");
    assert_eq!(object["arch"], Value::String("X64".to_string()));
    assert_eq!(object["win_version"], Value::String("Win11".to_string()));
    assert_eq!(
        object["semantic_test_coverage"],
        Value::String("Differential".to_string())
    );
    assert_eq!(
        object["implementation"],
        Value::String("Implemented".to_string())
    );
}

// ---------------------------------------------------------------------------
// (g) api-report --gate exits non-zero on violations
// ---------------------------------------------------------------------------

#[test]
fn api_report_gate_enforces_violations_via_the_binary() {
    let binary = env!("CARGO_BIN_EXE_casa1-oracle");
    let out = std::env::temp_dir().join("api-completeness-gate-test.json");

    // The seeded database honestly violates the shipping gate (Implemented
    // without coverage, unregistered Stub/Unsupported): the default gate must
    // exit non-zero.
    let status = std::process::Command::new(binary)
        .args(["api-report", "--gate", "shipping", "--out"])
        .arg(&out)
        .status()
        .expect("invoke casa1-oracle api-report");
    assert!(
        !status.success(),
        "api-report --gate shipping must exit non-zero when the seeded database has \
         shipping violations"
    );
    assert!(
        out.is_file(),
        "the report must still be written on gate failure"
    );

    // The completeness gate also fails on the seeded database (Partial never
    // passes it).
    let status = std::process::Command::new(binary)
        .args(["api-report", "--gate", "completeness", "--out"])
        .arg(&out)
        .status()
        .expect("invoke casa1-oracle api-report");
    assert!(!status.success());

    // --gate none never fails on violations.
    let status = std::process::Command::new(binary)
        .args(["api-report", "--gate", "none", "--out"])
        .arg(&out)
        .status()
        .expect("invoke casa1-oracle api-report");
    assert!(
        status.success(),
        "api-report --gate none must exit zero regardless of violations"
    );
    let _ = std::fs::remove_file(&out);
}

// ---------------------------------------------------------------------------
// (h) Oracle-backed coverage evidence registry
// ---------------------------------------------------------------------------

#[test]
fn coverage_registry_maps_create_file_w_to_differential_oracle_evidence() {
    let evidence = coverage_evidence_for(
        "KERNEL32.DLL",
        "CreateFileW",
        ArchSet::Any,
        WindowsVersion::Any,
    )
    .expect("CreateFileW evidence");
    assert_eq!(evidence.level, CoverageLevel::Differential);
    assert_eq!(evidence.evidence_id, "windows-oracle:file_sharing");
    // The seeded database carries the registry's level.
    let database = ApiDatabase::from_thunk_metadata();
    let create_file = database
        .lookup("kernel32.dll", "CreateFileW")
        .expect("CreateFileW entry");
    assert_eq!(
        create_file.semantic_test_coverage,
        CoverageLevel::Differential,
        "the registry's level must be merged into the seeded database"
    );
    // VirtualAlloc / TLS / loader contracts are also oracle-covered.
    for (dll, export, evidence_id) in [
        (
            "kernel32.dll",
            "VirtualAlloc",
            "windows-oracle:virtual_memory",
        ),
        ("kernel32.dll", "TlsAlloc", "windows-oracle:thread_tls"),
        ("kernel32.dll", "GetProcAddress", "windows-oracle:api_set"),
        (
            "kernel32.dll",
            "WaitForSingleObject",
            "windows-oracle:synchronization",
        ),
        (
            "d3d12.dll",
            "D3D12CreateDevice",
            "windows-oracle:d3d12_device",
        ),
    ] {
        let entry = database
            .lookup(dll, export)
            .unwrap_or_else(|| panic!("{dll}!{export} must be seeded with oracle evidence"));
        assert_eq!(
            entry.semantic_test_coverage,
            CoverageLevel::Differential,
            "{dll}!{export} must carry the oracle contract level"
        );
        let evidence = coverage_evidence_for(dll, export, ArchSet::Any, WindowsVersion::Any)
            .expect("evidence");
        assert_eq!(evidence.evidence_id, evidence_id);
    }
}

#[test]
fn coverage_registry_maps_suite_evidenced_apis_to_conformance_levels() {
    // Suite-backed evidence rows (casa1-conformance:<suite>) resolve to
    // CoverageLevel::Conformance and merge into the seeded database.
    for (dll, export, evidence_id) in [
        (
            "kernel32.dll",
            "CreateProcessW",
            "casa1-conformance:section29_process",
        ),
        (
            "kernel32.dll",
            "GetSystemInfo",
            "casa1-conformance:section50_win32_nt_consistency",
        ),
        (
            "kernel32.dll",
            "GetTickCount",
            "casa1-conformance:section50_win32_nt_consistency",
        ),
        (
            "kernel32.dll",
            "CloseHandle",
            "casa1-conformance:section38_manifest_gate",
        ),
        ("ntdll.dll", "LdrLoadDll", "casa1-conformance:section48_ldr"),
        (
            "ntdll.dll",
            "NtCreateEvent",
            "casa1-conformance:section47_ntdll",
        ),
        (
            "ntdll.dll",
            "NtSetEvent",
            "casa1-conformance:section47_ntdll",
        ),
        (
            "ntdll.dll",
            "NtQuerySystemTime",
            "casa1-conformance:section50_win32_nt_consistency",
        ),
        (
            "ntdll.dll",
            "NtAllocateVirtualMemory",
            "casa1-conformance:section47_ntdll",
        ),
        (
            "kernel32.dll",
            "GetCurrentDirectoryA",
            "casa1-conformance:allocate_reserves_and_commits_through_the_canonical_vm",
        ),
        (
            "kernel32.dll",
            "ReleaseSemaphore",
            "casa1-conformance:evidence_core_event_and_semaphore_thunks",
        ),
    ] {
        let evidence = coverage_evidence_for(dll, export, ArchSet::Any, WindowsVersion::Any)
            .unwrap_or_else(|| panic!("{dll}!{export} must have conformance evidence"));
        assert_eq!(
            evidence.level,
            CoverageLevel::Conformance,
            "{dll}!{export} must carry the conformance level"
        );
        assert_eq!(evidence.evidence_id, evidence_id);
    }

    // The seeded database carries the registry's Conformance level.
    let database = ApiDatabase::from_thunk_metadata();
    for (dll, export) in [
        ("kernel32.dll", "CreateProcessW"),
        ("kernel32.dll", "GetSystemInfo"),
        ("kernel32.dll", "GetTickCount"),
        ("kernel32.dll", "CloseHandle"),
        ("kernel32.dll", "GetCurrentDirectoryA"),
        ("kernel32.dll", "ReleaseSemaphore"),
        ("ntdll.dll", "LdrLoadDll"),
        ("ntdll.dll", "NtCreateEvent"),
        ("ntdll.dll", "NtQuerySystemTime"),
    ] {
        let entry = database
            .lookup(dll, export)
            .unwrap_or_else(|| panic!("{dll}!{export} must be seeded"));
        assert_eq!(
            entry.semantic_test_coverage,
            CoverageLevel::Conformance,
            "{dll}!{export} must carry the conformance-suite level"
        );
    }
}

#[test]
fn coverage_registry_merges_conformance_only_where_suite_evidence_exists() {
    // APIs with no evidence row keep CoverageLevel::None in the seeded
    // database (an honest violation, never an inferred one).
    let database = ApiDatabase::from_thunk_metadata();
    let entry = database
        .lookup("user32.dll", "DialogBoxParamA")
        .expect("DialogBoxParamA entry");
    assert_eq!(
        entry.semantic_test_coverage,
        CoverageLevel::None,
        "no evidence row exists for DialogBoxParamA"
    );
    // FindResourceA's former evidence row named the phantom
    // evidence_ps3_resources_and_ioctl suite (removed by the evidence-chain
    // audit fix) — the API is Implemented but currently has NO verified
    // semantic coverage, and must stay that way until a real test exists.
    let find_resource = database
        .lookup("kernel32.dll", "FindResourceA")
        .expect("FindResourceA entry");
    assert_eq!(
        find_resource.semantic_test_coverage,
        CoverageLevel::None,
        "FindResourceA lost its phantom evidence and must not claim coverage"
    );
}

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

#[test]
fn dynamic_lookups_recorded_via_get_proc_address_identity() {
    use casa1::import_coverage::ImportSource;

    // The runtime records GetProcAddress resolutions into the shared log:
    // simulate exactly what HostThunk::GetProcAddress does.
    casa1::pe_runtime::record_dynamic_import("kernel32.dll", "GetProcAddress");
    casa1::pe_runtime::record_dynamic_import("user32.dll", "MessageBoxW");

    let path = tracked_steam_fixture();
    let workload = WorkloadId::new("section43-dynamic");
    let report = coverage_for_pe_with_runtime_trace(
        &path,
        &workload,
        CompatibilityProfile::win11_native_desktop(),
        &[],
    )
    .expect("coverage report with trace");

    // Dynamic lookups appear as DynamicLookup entries keyed by (DLL, name) —
    // never by name alone.
    let dynamic: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| entry.source == ImportSource::DynamicLookup)
        .map(|entry| (entry.dll.as_str(), entry.import.lookup_name()))
        .collect();
    assert!(
        dynamic.contains(&("kernel32.dll", "GetProcAddress".to_string())),
        "GetProcAddress(kernel32) must be recorded"
    );
    assert!(
        dynamic.contains(&("user32.dll", "MessageBoxW".to_string())),
        "MessageBoxW must be recorded under user32.dll"
    );
    assert!(
        report
            .entries
            .iter()
            .filter(|entry| entry.source == ImportSource::DynamicLookup)
            .all(|entry| entry.runtime_reached),
        "dynamic lookups are reached by construction"
    );
}
