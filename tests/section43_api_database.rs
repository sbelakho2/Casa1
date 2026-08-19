//! Phase 43 — quantitative Windows API completeness database.
//!
//! Unit-style tests of the `api_database` module: seeding from the canonical
//! thunk metadata, the production gate (Partial-must-be-transitional,
//! Stub/Unsupported-must-be-deliberately-unsupported-with-compat-error),
//! lookup semantics, workload recording from the Steam fixture scan, and the
//! api-completeness.json report shape emitted by the `casa1-oracle
//! api-report` command.

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

    // A Partial thunk is seeded transitional with a documented reason.
    let compare_string = database
        .lookup("kernel32.dll", "CompareStringW")
        .expect("CompareStringW must be seeded");
    assert_eq!(compare_string.implementation, ImplementationLevel::Partial);
    assert!(
        compare_string.transitional,
        "Partial entries must be flagged transitional"
    );
    assert!(
        compare_string.detail.is_some(),
        "transitional entries must carry a documented reason"
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
// (b) Production gate: Partial must be transitional
// ---------------------------------------------------------------------------

#[test]
fn production_gate_flags_partial_without_transitional_flag() {
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

    let violations = database.production_gate();
    assert_eq!(violations.len(), 1, "only the Partial entry may violate");
    assert_eq!(violations[0].dll, "a.dll");
    assert_eq!(violations[0].export, "PartiallyDone");
    assert_eq!(
        violations[0].kind,
        ApiGateViolationKind::PartialNotTransitional
    );
    assert!(violations[0].message.contains("transitional"));
}

#[test]
fn production_gate_accepts_transitional_partial() {
    let mut database = ApiDatabase::new();
    database.add_entry(ApiEntry {
        transitional: true,
        detail: Some("documented limitation: only ASCII paths are folded".to_string()),
        ..ApiEntry::new("a.dll", "PartiallyDone", ImplementationLevel::Partial)
    });
    assert!(
        database.production_gate().is_empty(),
        "a transitional Partial with a documented reason passes the gate"
    );
}

// ---------------------------------------------------------------------------
// (c) Deliberately-unsupported entries
// ---------------------------------------------------------------------------

#[test]
fn deliberately_unsupported_passes_gate_with_compatibility_error() {
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

    // Without registration both fail the gate.
    let violations = database.production_gate();
    assert_eq!(violations.len(), 2);
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

    // Registering the stub as deliberately unsupported with a
    // guest-visible compatibility error clears it.
    database.deliberately_unsupported(
        "b.dll",
        "CannedApi",
        "Returns the canned compatible value; no guest-visible error is raised",
    );
    let violations = database.production_gate();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].export, "MissingApi");
    assert_eq!(
        database
            .deliberately_unsupported_error("b.dll", "CannedApi")
            .expect("registered error"),
        "Returns the canned compatible value; no guest-visible error is raised"
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
    assert!(
        !database
            .production_gate()
            .iter()
            .any(|v| { v.dll == "kernel32.dll" && v.export == "IsDebuggerPresent" }),
        "deliberately-unsupported stubs must not be flagged"
    );
}

// ---------------------------------------------------------------------------
// (d) Lookup semantics
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
// (e) Report generator
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
        summary["transitional_partial"]
            .as_u64()
            .expect("transitional_partial"),
        partial,
        "every seeded Partial is transitional with a documented reason"
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

    let gate = object["gate"].as_object().expect("gate object");
    let violations = gate["violations"].as_array().expect("violations array");
    assert!(
        !violations.is_empty(),
        "the seeded database has honest gate violations"
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
    assert!(
        typed
            .gate
            .violations
            .iter()
            .any(|v| { v.dll == "kernel32.dll" && v.export == "GetTickCount64" })
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
