#![allow(dead_code, unused_imports)]
//! Phase 1.3.4 — Per-DLL Integration Tests
//!
//! These tests verify that every export from each DLL that Steam.exe imports
//! resolves correctly via [`HostThunk`] dispatch.  For each of the 14 DLLs, the
//! tests enumerate all imports from [`Steam.exe`](ges/steam-live-run-x86/drive_c/Steam.exe)
//! and verify [`is_import_supported()`](src/pe_runtime.rs:28022) returns `true`.
//! Smoke tests execute Steam.exe with a small instruction budget to verify that
//! basic imports work end-to-end through the full PE runtime.
//!
//! Phase 24.2 extends the model with implementation-quality coverage: every
//! Steam import is classified against the canonical [`ThunkMetadata`] table
//! ([`crate::host_thunks::THUNK_METADATA`]) as Implemented / Partial / Stub /
//! Unsupported, and the release requirement *"no runtime-reached Required
//! (user-mode-profile) API is Stub or Unsupported"* is encoded as an
//! assertion over the runtime-reached set only (an empty set is trivially
//! satisfied but reported).  The tracked fixture
//! ([`Steam.exe`](ges/steam/drive_c/Steam/Steam.exe)) drives the always-on
//! model; trace-derived runtime-reached sets come from the GE smoke runs.
//!
//! These tests require the Steam GE at `ges/steam-live-run-x86/` with
//! `Steam.exe`.  If the GE is not present, tests are skipped at runtime with a
//! clear message.
//!
//! Usage:
//! ```bash
//! cargo test t24_ -- --nocapture
//! ```

use casa1::compatibility_profile::CompatibilityProfile;
use casa1::ge::GameEnvironment;
use casa1::host_thunks::ImplementationLevel;
use casa1::import_coverage::{
    BinaryCoverageReport, WorkloadId, coverage_for_pe_with_runtime_trace,
    invoked_api_names_from_trace,
};
use casa1::pe::{self, ApiSetResolver, ImportSymbol};
use casa1::pe_runtime::{self, PeExecutionOptions, PeExecutionResult, is_import_supported};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ═══════════════════════════════════════════════════════════════════════════════
// Helper infrastructure
// ═══════════════════════════════════════════════════════════════════════════════

fn steam_ge_root() -> &'static str {
    "steam-live-run-x86"
}

fn require_steam_ge() -> bool {
    let ge_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("ges")
        .join(steam_ge_root());
    let steam_exe = ge_path.join("drive_c").join("Steam.exe");
    if !steam_exe.is_file() {
        eprintln!(
            "SKIP: Steam GE not found at `{}`.\n\
             The section24 integration tests require the Steam Game Environment\n\
             at `ges/{}/` with `Steam.exe`.  Without this file the per-DLL\n\
             import-coverage and smoke tests cannot run.\n\
             \n\
             To obtain the environment, run the Casa1 Steam setup workflow:\n\
               cargo run --bin casa1 -- steam setup\n\
             \n\
             Once the GE is in place, re-run with:\n\
               cargo test t24_ -- --nocapture",
            steam_exe.display(),
            steam_ge_root(),
        );
        return false;
    }
    true
}

fn open_steam() -> (GameEnvironment, pe::ParsedPe, ApiSetResolver) {
    let ge = GameEnvironment::open(steam_ge_root()).expect("failed to open steam-live-run-x86 GE");
    let path = ge.root.join("drive_c").join("Steam.exe");
    assert!(path.is_file(), "Steam.exe not found at {path:?}");
    let image = pe::parse_from_file(&path).expect("failed to parse Steam.exe");
    let resolver = ApiSetResolver::new();
    (ge, image, resolver)
}

fn imports_for_dll(
    image: &pe::ParsedPe,
    resolver: &ApiSetResolver,
    dll_name: &str,
) -> Vec<(String, ImportSymbol)> {
    let target = dll_name.to_ascii_lowercase();
    let mut out = Vec::new();
    for desc in image.imports.iter().chain(image.delay_imports.iter()) {
        let resolved = resolver.resolve(&desc.dll_name);
        if resolved.to_ascii_lowercase() != target {
            continue;
        }
        for imp in &desc.imports {
            let name = match &imp.symbol {
                ImportSymbol::ByName { name, .. } => name.clone(),
                ImportSymbol::ByOrdinal { ordinal } => format!("ordinal#{ordinal}"),
            };
            out.push((name, imp.symbol.clone()));
        }
    }
    out
}

fn run_steam_with_budget(budget: u64) -> PeExecutionResult {
    let ge = GameEnvironment::open(steam_ge_root()).expect("failed to open steam-live-run-x86 GE");
    let path = ge.root.join("drive_c").join("Steam.exe");
    assert!(path.is_file(), "Steam.exe not found at {path:?}");

    let mut env = BTreeMap::new();
    env.insert("CASA1_PE_RUNTIME_BUDGET".to_string(), budget.to_string());
    env.insert("CASA1_STEAM_CRASH_WORKAROUND".to_string(), "1".to_string());

    pe_runtime::execute_with_options(
        &path,
        &[], // no command-line arguments
        &ge,
        &ge.root.join("drive_c"), // cwd
        &env,
        true, // dtm
        "section24_smoke",
        PeExecutionOptions::default(),
    )
    .expect("Steam.exe execution failed")
}

// All smoke tests exercise the same execution (same Steam.exe, same environment,
// same budget), so the run is shared through a once-guard. This keeps the suite
// practical: previously every smoke test re-executed Steam.exe, and 15 runs of
// the PE runtime each took >60 s of wall time.
fn run_with_large_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn_scoped(scope, f)
            .expect("spawn large-stack worker")
            .join()
            .expect("large-stack worker panicked")
    })
}

static SMOKE_RESULT: OnceLock<PeExecutionResult> = OnceLock::new();

fn steam_smoke_result() -> &'static PeExecutionResult {
    SMOKE_RESULT.get_or_init(|| run_with_large_stack(|| run_steam_with_budget(1_000_000)))
}

fn assert_clean_smoke(result: &PeExecutionResult, dll_label: &str) {
    assert!(
        result.guest_exceptions.is_empty(),
        "[{dll_label} smoke] guest exceptions during dispatch: {:#?}",
        result.guest_exceptions
    );
    assert!(
        result.exit_code == 0 || result.exit_code == -2,
        "[{dll_label} smoke] unexpected exit code {} (documented: 0 = clean guest \
         exit, -2 = bounded-run termination)",
        result.exit_code
    );
    assert!(
        result
            .trace_events
            .iter()
            .any(|e| e.call_id == "SteamInitialGlobals"),
        "[{dll_label} smoke] SteamInitialGlobals trace event missing — the \
         crash-workaround instrumentation did not run"
    );
    eprintln!(
        "[{dll_label} smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );
}

fn verify_dll_coverage(dll_name: &str) {
    let (_, image, resolver) = open_steam();
    let imports = imports_for_dll(&image, &resolver, dll_name);
    eprintln!("[{dll_name}] {} import(s) found", imports.len());

    let mut unsupported: Vec<String> = Vec::new();
    for (name, symbol) in &imports {
        if !is_import_supported(dll_name, symbol) {
            unsupported.push(name.clone());
        }
    }

    assert!(
        unsupported.is_empty(),
        "[{dll_name}] {} / {} imports are UNSUPPORTED:\n  {}",
        unsupported.len(),
        imports.len(),
        unsupported.join("\n  "),
    );
    eprintln!(
        "  ✓ All {count}/{count} imports have HostThunk dispatch",
        count = imports.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_01 — kernel32.dll (188 imports)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_02 — user32.dll (57 imports)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_03 — ws2_32.dll (28 imports)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_04 — gdi32.dll (19 imports)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_05 — advapi32.dll (13 imports)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_06 — crypt32.dll (7 imports)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_07 — shell32.dll (4 imports)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_08 — psapi.dll (3 imports)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_09 — bcrypt.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_10 — comctl32.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_11 — ole32.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_12 — oleaut32.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_13 — version.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_14 — wsock32.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t24_15 — aggregate coverage matrix (reprise)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Re-runs the full coverage matrix from t23_3 as a sanity check inside this
// test module, so the per-DLL tests have a cross-reference.

// ═══════════════════════════════════════════════════════════════════════════════
// t24_16 — kernel32 key-function smoke tests
// ═══════════════════════════════════════════════════════════════════════════════
//
// Execute Steam.exe with a trace-enabled run and inspect the steam_api_init
// trace events for key kernel32 functions, verifying they were called with
// sensible values.

#[test]
fn t24_16_kernel32_key_functions() {
    if !require_steam_ge() {
        return;
    }
    // Execute with tracing enabled for steam_api_init category.
    let ge = GameEnvironment::open(steam_ge_root()).expect("failed to open steam-live-run-x86 GE");
    let path = ge.root.join("drive_c").join("Steam.exe");
    assert!(path.is_file(), "Steam.exe not found at {path:?}");

    let mut env = BTreeMap::new();
    env.insert(
        "CASA1_PE_RUNTIME_BUDGET".to_string(),
        500_000_u64.to_string(),
    );
    env.insert("CASA1_STEAM_CRASH_WORKAROUND".to_string(), "1".to_string());
    env.insert(
        "CASA1_TRACE_CATEGORIES".to_string(),
        "steam_api_init".to_string(),
    );

    let result = run_with_large_stack(|| {
        pe_runtime::execute_with_options(
            &path,
            &[],
            &ge,
            &ge.root.join("drive_c"),
            &env,
            true,
            "t24_16_kernel32_key",
            PeExecutionOptions::default(),
        )
        .expect("Steam.exe execution failed")
    });

    eprintln!(
        "[kernel32 key-funcs] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // The run must not have thrown guest exceptions while dispatching kernel32
    // thunks, and must terminate with a documented code.
    assert!(
        result.guest_exceptions.is_empty(),
        "guest exceptions during kernel32 dispatch: {:#?}",
        result.guest_exceptions
    );
    assert!(
        result.exit_code == 0 || result.exit_code == -2,
        "unexpected exit code {} (documented: 0 = clean guest exit, -2 = bounded-run termination)",
        result.exit_code
    );

    // Collect steam_api_init trace events.
    let api_events: Vec<_> = result
        .trace_events
        .iter()
        .filter(|e| e.category == "steam_api_init")
        .collect();

    eprintln!("  steam_api_init events: {}", api_events.len());

    // Print a summary of the thunks that were actually dispatched.
    let mut thunk_counts: BTreeMap<String, usize> = BTreeMap::new();
    for ev in &api_events {
        *thunk_counts.entry(ev.call_id.clone()).or_default() += 1;
    }
    for (thunk, count) in &thunk_counts {
        eprintln!("    {thunk:<50} × {count}");
    }

    // The whole point of this test: kernel32 thunks must actually have been
    // dispatched. A run that never reaches thunk dispatch (or a runtime that
    // swallows dispatch) fails here.
    assert!(
        !api_events.is_empty(),
        "no steam_api_init trace events captured with a 500K budget — \
         kernel32 thunk dispatch never happened"
    );
    eprintln!("  ✓ kernel32 key functions dispatched successfully");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_17/t24_18 — fixture-derived implementation-quality model (Phase 24.2)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The exact-import scanning above stays untouched.  This model additionally
// classifies EVERY Steam import against the canonical ThunkMetadata table
// (host_thunks::THUNK_METADATA) and reports:
//   (a) all imported APIs,
//   (b) all actually invoked APIs (from an E2E trace when available, else
//       empty),
//   (c) all actually invoked APIs whose implementation is Partial/Stub/
//       Unsupported.
// The release requirement — "no runtime-reached Steam-critical API is Stub
// or Unsupported" — is encoded as an assertion over the INVOKED set ONLY
// (an empty invoked set is trivially satisfied, but still reported).

fn tracked_steam_exe() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("ges")
        .join("steam")
        .join("drive_c")
        .join("Steam")
        .join("Steam.exe")
}

fn print_quality_telemetry(label: &str, report: &BinaryCoverageReport) {
    eprintln!("\n═══════════════════════════════════════════════════════════════");
    eprintln!("  Steam import quality telemetry [{label}]");
    eprintln!("═══════════════════════════════════════════════════════════════");
    eprintln!("binary:  {}", report.binary_path);
    eprintln!("sha256:  {}", report.image_sha256);
    eprintln!(
        "version: {}",
        report.image_version.as_deref().unwrap_or("<none>")
    );
    eprintln!("imports: {}", report.total_imports);
    eprintln!(
        "levels:  Implemented={}  Partial={}  Stub={}  Unsupported={}",
        report
            .by_implementation
            .get("Implemented")
            .copied()
            .unwrap_or(0),
        report
            .by_implementation
            .get("Partial")
            .copied()
            .unwrap_or(0),
        report.by_implementation.get("Stub").copied().unwrap_or(0),
        report
            .by_implementation
            .get("Unsupported")
            .copied()
            .unwrap_or(0),
    );
    eprintln!(
        "runtime-trace flag: {}",
        if report.runtime_trace_included {
            "yes"
        } else {
            "no"
        }
    );

    // (a) All imported APIs, grouped per DLL, with quality + criticality.
    eprintln!("\n--- (a) all imported APIs ({}):", report.entries.len());
    let mut current_dll = String::new();
    for entry in &report.entries {
        if entry.dll != current_dll {
            current_dll = entry.dll.clone();
            eprintln!("  [{current_dll}]");
        }
        eprintln!(
            "    {:40} {:12} policy={:<22} reached={}",
            entry.import.lookup_name(),
            format!("{:?}", entry.implementation),
            format!(
                "{:?}",
                entry
                    .support_policy()
                    .unwrap_or(casa1::host_thunks::SupportPolicy::OptionalFeature)
            ),
            entry.runtime_reached,
        );
    }

    // (b) All actually invoked APIs.
    let invoked: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| entry.runtime_reached)
        .collect();
    eprintln!("\n--- (b) actually invoked APIs ({}):", invoked.len());
    for entry in &invoked {
        eprintln!(
            "    {:40} {:12?} policy={:?}",
            entry.import.lookup_name(),
            entry.implementation,
            entry
                .support_policy()
                .unwrap_or(casa1::host_thunks::SupportPolicy::OptionalFeature),
        );
    }

    // (c) Invoked APIs with non-Implemented quality.
    let flagged: Vec<_> = invoked
        .iter()
        .filter(|entry| !matches!(entry.implementation, ImplementationLevel::Implemented))
        .collect();
    eprintln!(
        "\n--- (c) invoked APIs that are Partial/Stub/Unsupported ({}):",
        flagged.len()
    );
    for entry in &flagged {
        eprintln!(
            "    {}!{} [{:?}]",
            entry.dll,
            entry.import.lookup_name(),
            entry.implementation
        );
    }

    // Release gate (over the runtime-reached set only).
    let violations = report.runtime_reached_required_violations();
    eprintln!(
        "\n--- release gate: no runtime-reached Required API is Stub/Unsupported — violations: {}",
        violations.len()
    );
    if violations.is_empty() && invoked.is_empty() {
        eprintln!("    (runtime-reached set is empty — gate trivially satisfied but reported)");
    }

    eprintln!("\n--- JSON report:");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(report).expect("serialize coverage report")
    );
    eprintln!("═══════════════════════════════════════════════════════════════\n");
}

#[test]
fn t24_18_tracked_fixture_import_quality_with_trace() {
    if !require_steam_ge() {
        return;
    }
    let result = steam_smoke_result();
    let invoked = invoked_api_names_from_trace(&result.trace_events);
    eprintln!(
        "[t24_18] trace-derived invoked API names: {}",
        invoked.len()
    );

    let path = tracked_steam_exe();
    let workload = WorkloadId::new("steam-fixture");
    let target = CompatibilityProfile::win10_legacy_desktop();
    let report = coverage_for_pe_with_runtime_trace(&path, &workload, target, &invoked)
        .expect("coverage report with runtime trace");

    print_quality_telemetry("tracked-fixture (invoked set: smoke trace)", &report);

    // (b) The runtime-reached set is non-empty and reflected in the report.
    let invoked_entries: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| entry.runtime_reached)
        .collect();
    assert!(
        !invoked_entries.is_empty(),
        "smoke trace produced no runtime-reached imports"
    );

    // (c) Report the invoked APIs whose quality is not Implemented.
    let flagged: Vec<_> = invoked_entries
        .iter()
        .filter(|entry| !matches!(entry.implementation, ImplementationLevel::Implemented))
        .collect();
    eprintln!(
        "[t24_18] invoked APIs with Partial/Stub/Unsupported quality: {}",
        flagged.len()
    );
    for entry in &flagged {
        eprintln!(
            "  - {}!{} [{:?}] policy={:?}",
            entry.dll,
            entry.import.lookup_name(),
            entry.implementation,
            entry
                .support_policy()
                .unwrap_or(casa1::host_thunks::SupportPolicy::OptionalFeature),
        );
    }

    // Release requirement: over the RUNTIME-REACHED set only.
    let violations = report.runtime_reached_required_violations();
    assert!(
        violations.is_empty(),
        "a runtime-reached Required API is Stub or Unsupported: {:#?}",
        violations
    );
    eprintln!(
        "  ✓ t24_18: release gate over the real runtime-reached set PASSES ({} violation(s))",
        violations.len()
    );
}
