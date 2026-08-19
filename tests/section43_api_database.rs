//! Phase 43 — quantitative Windows API completeness database.
//!
//! Unit-style tests of the `api_database` module: seeding from the canonical
//! thunk metadata (Partial entries transitional ONLY with a specific reason),
//! the two gates (shipping allows explicitly documented Partial entries;
//! completeness never does), the semantic-coverage requirement, full-key
//! lookup, workload recording from the Steam fixture scan, the
//! api-completeness.json report shape, and the `casa1-oracle api-report
//! --gate` enforcement.

use casa1::api_database::{
    ApiCompletenessReport, ApiDatabase, ApiEntry, ApiGateViolationKind, ArchSet, CoverageLevel,
    WindowsVersion, global_database,
};
use casa1::host_thunks::ImplementationLevel;
use serde_json::Value;
use std::path::Path;

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

    // Stub and Unsupported entries are seeded with their metadata levels.
    let find_resource = database
        .lookup("kernel32.dll", "FindResourceA")
        .expect("FindResourceA must be seeded");
    assert_eq!(find_resource.implementation, ImplementationLevel::Stub);
    let tick_count_64 = database
        .lookup("kernel32.dll", "GetTickCount64")
        .expect("GetTickCount64 must be seeded");
    assert_eq!(
        tick_count_64.implementation,
        ImplementationLevel::Unsupported
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
    // Everything else in the Nt* skeleton is honestly unsupported.
    for unsupported in [
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
    // D3D12 heaps have no dispatch at all.
    let heap = database
        .lookup("d3d12.dll", "ID3D12Heap")
        .expect("ID3D12Heap entry");
    assert_eq!(heap.implementation, ImplementationLevel::Unsupported);
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
            .completeness_gate()
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
    let completeness_violations = database.completeness_gate();
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
    let completeness = database.completeness_gate();
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
        database.completeness_gate()[0].kind,
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
        database.completeness_gate().is_empty(),
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
    assert!(database.completeness_gate().is_empty());
}

// ---------------------------------------------------------------------------
// (d) Deliberately-unsupported entries
// ---------------------------------------------------------------------------

#[test]
fn deliberately_unsupported_passes_both_gates_with_compatibility_error() {
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
    let completeness = database.completeness_gate();
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
    // compatibility error clears it through BOTH gates.
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
    assert!(
        database
            .completeness_gate()
            .iter()
            .all(|v| v.export == "MissingApi"),
        "only the unregistered Unsupported entry may violate completeness"
    );
    database.deliberately_unsupported(
        "b.dll",
        "MissingApi",
        "No host thunk exists; guest dispatch fails closed",
    );
    assert!(database.shipping_gate().is_empty());
    assert!(
        database.completeness_gate().is_empty(),
        "DeliberatelyUnsupported with a precise compatibility consequence passes both gates"
    );
}

#[test]
fn seeded_deliberately_unsupported_entries_carry_compatibility_errors() {
    let database = ApiDatabase::from_thunk_metadata();
    // IsDebuggerPresent's FALSE answer is the deliberate anti-debug answer.
    let error = database
        .deliberately_unsupported_error("kernel32.dll", "IsDebuggerPresent")
        .expect("IsDebuggerPresent must be seeded as deliberately unsupported");
    assert!(error.contains("FALSE"));
    // The stub is therefore not a gate violation.
    for violations in [&database.shipping_gate(), &database.completeness_gate()] {
        assert!(
            !violations
                .iter()
                .any(|v| { v.dll == "kernel32.dll" && v.export == "IsDebuggerPresent" }),
            "deliberately-unsupported stubs must not be flagged"
        );
    }
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
    let report =
        casa1::import_coverage::coverage_for_steam_fixture(&path).expect("fixture coverage scan");
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
    // The scan records the "steam" workload into the entries it reaches.
    assert!(
        create_file
            .workloads_reaching
            .iter()
            .any(|workload| workload == "steam"),
        "the fixture scan must record the steam workload on CreateFileW"
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
    assert_eq!(
        summary["differential_tested"]
            .as_u64()
            .expect("differential_tested"),
        0
    );
    assert_eq!(
        summary["conformance_tested"]
            .as_u64()
            .expect("conformance_tested"),
        0
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
    assert!(
        typed
            .gate
            .shipping_violations
            .iter()
            .any(|v| { v.dll == "kernel32.dll" && v.export == "GetTickCount64" }),
        "unregistered Unsupported entries are honest shipping violations"
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
