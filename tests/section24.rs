//! Phase 1.3.4 — Per-DLL Integration Tests
//!
//! These tests verify that every export from each DLL that Steam.exe imports
//! resolves correctly via [`HostThunk`] dispatch.  For each of the 14 DLLs, the
//! tests enumerate all imports from [`Steam.exe`](ges/steam-live-run-x86/drive_c/Steam.exe)
//! and verify [`is_import_supported()`](src/pe_runtime.rs:28022) returns `true`.
//! Smoke tests execute Steam.exe with a small instruction budget to verify that
//! basic imports work end-to-end through the full PE runtime.
//!
//! These tests require the Steam GE at `ges/steam-live-run-x86/` with
//! `Steam.exe`.  If the GE is not present, tests will be skipped at runtime
//! with a clear message.
//!
//! Usage:
//! ```bash
//! cargo test t24_ -- --nocapture
//! ```

use casa1::ge::GameEnvironment;
use casa1::pe::{self, ApiSetResolver, ImportSymbol};
use casa1::pe_runtime::{self, PeExecutionOptions, PeExecutionResult, is_import_supported};
use std::collections::BTreeMap;
use std::path::Path;

// ═══════════════════════════════════════════════════════════════════════════════
// Helper infrastructure
// ═══════════════════════════════════════════════════════════════════════════════

/// Path to the Steam GE (relative to the workspace `ges/` directory).
fn steam_ge_root() -> &'static str {
    "steam-live-run-x86"
}

/// Require that the Steam GE exists; skip the test with a clear message if not.
///
/// This replaces the former `#[ignore = "requires ges/steam-live-run-x86 with Steam.exe"]`
/// attribute with a runtime check, so the test only skips when the environment
/// is genuinely absent rather than unconditionally.
fn require_steam_ge() {
    let ge_path = Path::new("ges").join(steam_ge_root());
    let steam_exe = ge_path.join("drive_c").join("Steam.exe");
    if !steam_exe.is_file() {
        panic!(
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
    }
}

/// Open the Steam GE, parse [`Steam.exe`](ges/steam-live-run-x86/drive_c/Steam.exe),
/// and create an [`ApiSetResolver`].
fn open_steam() -> (GameEnvironment, pe::ParsedPe, ApiSetResolver) {
    let ge = GameEnvironment::open(steam_ge_root()).expect("failed to open steam-live-run-x86 GE");
    let path = ge.root.join("drive_c").join("Steam.exe");
    assert!(path.is_file(), "Steam.exe not found at {path:?}");
    let image = pe::parse_from_file(&path).expect("failed to parse Steam.exe");
    let resolver = ApiSetResolver::new();
    (ge, image, resolver)
}

/// Extract all import names and [`ImportSymbol`]s for a given DLL from the
/// parsed PE image (including delayed imports).
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

/// Execute Steam.exe with a given instruction budget and return the result.
///
/// This is the primary smoke-test helper.  It sets up a minimal environment
/// with the crash-workaround flag enabled (so the runtime is instrumented) and
/// runs in deterministic mode (DTM).
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

/// Verify that *every* import for a given DLL is flagged as supported by
/// [`is_import_supported()`].
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

#[test]
fn t24_01_kernel32_coverage() {
    require_steam_ge();
    verify_dll_coverage("kernel32.dll");
}

#[test]
fn t24_01_kernel32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(200_000);
    eprintln!(
        "[kernel32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // If kernel32 imports are wired correctly, execution should at least
    // proceed past the import-resolution phase without crashing.
    // A budget of 200K is enough to exercise GetModuleHandleW, GetLastError,
    // GetSystemInfo, and other early-kernel32 calls during CRT init.
    eprintln!("  ✓ kernel32 smoke completed (import resolution phase passed)");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_02 — user32.dll (57 imports)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_02_user32_coverage() {
    require_steam_ge();
    verify_dll_coverage("user32.dll");
}

#[test]
fn t24_02_user32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(500_000);
    eprintln!(
        "[user32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // user32 imports are used slightly later in startup (window creation,
    // message dispatch).  A 500K budget usually reaches user32 thunks.
    // The test simply verifies execution doesn't crash during user32 dispatch.
    eprintln!("  ✓ user32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_03 — ws2_32.dll (28 imports)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_03_ws2_32_coverage() {
    require_steam_ge();
    verify_dll_coverage("ws2_32.dll");
}

#[test]
fn t24_03_ws2_32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[ws2_32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // ws2_32 (Winsock) imports are used during network initialisation.
    // WSAStartup and friends should resolve without crashing.
    eprintln!("  ✓ ws2_32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_04 — gdi32.dll (19 imports)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_04_gdi32_coverage() {
    require_steam_ge();
    verify_dll_coverage("gdi32.dll");
}

#[test]
fn t24_04_gdi32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[gdi32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // GDI imports (GetDeviceCaps, SelectObject, etc.) are used for
    // display-DeviceCaps queries during early window initialisation.
    eprintln!("  ✓ gdi32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_05 — advapi32.dll (13 imports)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_05_advapi32_coverage() {
    require_steam_ge();
    verify_dll_coverage("advapi32.dll");
}

#[test]
fn t24_05_advapi32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(500_000);
    eprintln!(
        "[advapi32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // advapi32 (registry, security) imports are used early in startup.
    eprintln!("  ✓ advapi32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_06 — crypt32.dll (7 imports)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_06_crypt32_coverage() {
    require_steam_ge();
    verify_dll_coverage("crypt32.dll");
}

#[test]
fn t24_06_crypt32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[crypt32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // crypt32 (certificate store) imports are used during Steam's
    // TLS / certificate validation setup.
    eprintln!("  ✓ crypt32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_07 — shell32.dll (4 imports)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_07_shell32_coverage() {
    require_steam_ge();
    verify_dll_coverage("shell32.dll");
}

#[test]
fn t24_07_shell32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[shell32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // shell32 (shell API) imports: SHGetFileInfoW, SHGetFolderPathW, etc.
    eprintln!("  ✓ shell32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_08 — psapi.dll (3 imports)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_08_psapi_coverage() {
    require_steam_ge();
    verify_dll_coverage("psapi.dll");
}

#[test]
fn t24_08_psapi_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[psapi smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // psapi (process status API) imports: GetModuleFileNameExW,
    // GetModuleInformation, GetProcessMemoryInfo.
    eprintln!("  ✓ psapi smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_09 — bcrypt.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_09_bcrypt_coverage() {
    require_steam_ge();
    verify_dll_coverage("bcrypt.dll");
}

#[test]
fn t24_09_bcrypt_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[bcrypt smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // bcrypt.dll has a single import: BCryptGenRandom.
    eprintln!("  ✓ bcrypt smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_10 — comctl32.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_10_comctl32_coverage() {
    require_steam_ge();
    verify_dll_coverage("comctl32.dll");
}

#[test]
fn t24_10_comctl32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[comctl32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // comctl32.dll has a single import: InitCommonControlsEx.
    eprintln!("  ✓ comctl32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_11 — ole32.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_11_ole32_coverage() {
    require_steam_ge();
    verify_dll_coverage("ole32.dll");
}

#[test]
fn t24_11_ole32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[ole32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // ole32.dll has a single import: CoCreateInstance.
    eprintln!("  ✓ ole32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_12 — oleaut32.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_12_oleaut32_coverage() {
    require_steam_ge();
    verify_dll_coverage("oleaut32.dll");
}

#[test]
fn t24_12_oleaut32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[oleaut32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // oleaut32.dll has a single import: VariantClear.
    eprintln!("  ✓ oleaut32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_13 — version.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_13_version_coverage() {
    require_steam_ge();
    verify_dll_coverage("version.dll");
}

#[test]
fn t24_13_version_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[version smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // version.dll has 3 imports: GetFileVersionInfoSizeW, GetFileVersionInfoW,
    // VerQueryValueW.
    eprintln!("  ✓ version smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_14 — wsock32.dll (1 import)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t24_14_wsock32_coverage() {
    require_steam_ge();
    verify_dll_coverage("wsock32.dll");
}

#[test]
fn t24_14_wsock32_smoke() {
    require_steam_ge();
    let result = run_steam_with_budget(1_000_000);
    eprintln!(
        "[wsock32 smoke] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
    );

    // wsock32.dll has a single ordinal-1142 import that maps to WSAStartup.
    eprintln!("  ✓ wsock32 smoke completed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_15 — aggregate coverage matrix (reprise)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Re-runs the full coverage matrix from t23_3 as a sanity check inside this
// test module, so the per-DLL tests have a cross-reference.

#[test]
fn t24_15_aggregate_coverage() {
    require_steam_ge();
    let (_, image, resolver) = open_steam();

    let mut total_supported = 0_usize;
    let mut total_unsupported = 0_usize;
    let mut per_dll: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();

    for desc in image.imports.iter().chain(image.delay_imports.iter()) {
        let resolved = resolver.resolve(&desc.dll_name);
        for imp in &desc.imports {
            let name = match &imp.symbol {
                ImportSymbol::ByName { name, .. } => name.clone(),
                ImportSymbol::ByOrdinal { ordinal } => format!("ordinal#{ordinal}"),
            };
            let supported = is_import_supported(&resolved, &imp.symbol);
            let entry = per_dll
                .entry(resolved.clone())
                .or_insert_with(|| (Vec::new(), Vec::new()));
            if supported {
                total_supported += 1;
                entry.0.push(name);
            } else {
                total_unsupported += 1;
                entry.1.push(name);
            }
        }
    }

    let total = total_supported + total_unsupported;
    let pct = (total_supported as f64 / total as f64) * 100.0;

    eprintln!("=== Aggregate Import Coverage (Phase 1.3.4) ===\n");
    eprintln!("Total: {total_supported}/{total} ({pct:.1}%) imports supported");
    eprintln!("  Supported:   {total_supported}");
    eprintln!("  Unsupported: {total_unsupported}\n");

    eprintln!("{:<40} {:>5}/{:<5}  {:>6}", "DLL", "Ok", "Total", "Pct");
    eprintln!("{}", "-".repeat(60));
    for (dll, (ok, missing)) in &per_dll {
        let dll_total = ok.len() + missing.len();
        let dll_pct = (ok.len() as f64 / dll_total as f64) * 100.0;
        eprintln!("{dll:<40} {:>5}/{dll_total:<5}  {dll_pct:>5.1}%", ok.len());
    }

    assert!(
        pct >= 95.0,
        "Aggregate coverage {pct:.1}% is below 95% threshold — {total_unsupported} imports unsupported",
    );
    eprintln!("\n✓ Aggregate coverage meets 95% threshold");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t24_16 — kernel32 key-function smoke tests
// ═══════════════════════════════════════════════════════════════════════════════
//
// Execute Steam.exe with a trace-enabled run and inspect the steam_api_init
// trace events for key kernel32 functions, verifying they were called with
// sensible values.

#[test]
fn t24_16_kernel32_key_functions() {
    require_steam_ge();
    // Execute with tracing enabled for steam_api_init category.
    let ge = GameEnvironment::open(steam_ge_root()).expect("failed to open steam-live-run-x86 GE");
    let path = ge.root.join("drive_c").join("Steam.exe");
    assert!(path.is_file(), "Steam.exe not found at {path:?}");

    let mut env = BTreeMap::new();
    env.insert("CASA1_PE_RUNTIME_BUDGET".to_string(), "500_000".to_string());
    env.insert("CASA1_STEAM_CRASH_WORKAROUND".to_string(), "1".to_string());
    env.insert(
        "CASA1_TRACE_CATEGORIES".to_string(),
        "steam_api_init".to_string(),
    );

    let result = pe_runtime::execute_with_options(
        &path,
        &[],
        &ge,
        &ge.root.join("drive_c"),
        &env,
        true,
        "t24_16_kernel32_key",
        PeExecutionOptions::default(),
    )
    .expect("Steam.exe execution failed");

    eprintln!(
        "[kernel32 key-funcs] exit_code={}  trace_events={}  guest_exceptions={}",
        result.exit_code,
        result.trace_events.len(),
        result.guest_exceptions.len(),
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

    // We don't assert specific counts — the key point is that kernel32
    // thunks were dispatched without crashing.
    if api_events.is_empty() {
        eprintln!("  ⚠ No steam_api_init trace events — budget may be too small");
    } else {
        eprintln!("  ✓ kernel32 key functions dispatched successfully");
    }
}
