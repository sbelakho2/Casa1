//! Phase 1 — Steam Bootstrap Crash Diagnostic Test
//!
//! This test runs Steam.exe with comprehensive API call tracing enabled
//! (`CASA1_TRACE_CATEGORIES=steam_api_init,process`) and a generous
//! instruction budget so that we can capture the sequence of Win32 API
//! calls made during early startup.  The goal is to identify which
//! initialization API returns an unexpected value, causing the record
//! table at global 0x42a270 to remain empty and triggering the crash
//! at RVA 0x401390.
//!
//! Usage:
//!   cargo test t23_1_steam_bootstrap_diagnostic -- --ignored --nocapture
//!
//! The test will print a report of every API call made during startup,
//! with caller RVA, thunk name, arguments, and return value.  Look for
//! APIs that return 0 (failure) or another unexpected sentinel.
//!
//! NOTE: The initial run used `CASA1_PE_RUNTIME_BUDGET=25000`.  This was
//! far too tight — execution exhausted the budget (25 004 steps) before
//! reaching any thunk dispatch, and RIP jumped to 0x1d65097e (~493 MB,
//! far outside the Steam.exe mapped image at base ~0x400000).  The
//! instruction at that address was an SEH epilogue (`mov fs:[0], ecx` /
//! `ret`), suggesting an indirect call/jump to garbage or an SEH unwind
//! through uninitialised handlers.  The current budget is 2 000 000;
//! increase further or remove the override (default 25 000 000) if still
//! insufficient.

use casa1::ge::GameEnvironment;
use casa1::pe_runtime::{self, PeExecutionOptions};
use std::collections::BTreeMap;

/// Helper: find the host path for the Steam GE.
fn steam_ge_root() -> String {
    // The GE lives at <workspace>/ges/steam-live-run-x86/
    // GameEnvironment::open("steam-live-run-x86") resolves this via the
    // Cargo.toml workspace-root heuristic.
    "steam-live-run-x86".to_string()
}

/// Helper: build the environment map for Steam startup tracing.
///
/// Uses a 3,000,000 instruction budget — enough to get past the ~2M-step
/// CRT initialisation phase and capture the `ImageExit` process trace event
/// that fires when execution first leaves the mapped image.  Previous runs
/// showed execution exits the image at approximately step 2,000,000, jumping
/// to heap memory (0x1a419da0 or 0x1d65097e).  The default 25M budget would
/// take too long; 3M gives us the ImageExit event plus a small margin.
fn trace_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    // Enable our new API-initialisation trace category plus the process
    // category (for ImageExit, SteamCrashWorkaround, etc.).
    env.insert(
        "CASA1_TRACE_CATEGORIES".to_string(),
        "steam_api_init,process".to_string(),
    );
    env.insert(
        "CASA1_PE_RUNTIME_BUDGET".to_string(),
        "3_000_000".to_string(),
    );
    env
}

// ---------------------------------------------------------------------------
// t23_1_steam_bootstrap_diagnostic
// Phase 1.1.1 — Full diagnostic run with API tracing
// ---------------------------------------------------------------------------

#[test]
#[ignore = "manual diagnostic — requires ges/steam-live-run-x86 with Steam.exe"]
fn t23_1_steam_bootstrap_diagnostic() {
    // 1. Open the game environment.
    let ge = GameEnvironment::open(&steam_ge_root()).expect("failed to open steam-live-run-x86 GE");

    // 2. Locate the host Steam.exe.
    let steam_host_path = ge.root.join("drive_c").join("Steam.exe");
    assert!(
        steam_host_path.is_file(),
        "Steam.exe not found at {:?}",
        steam_host_path
    );

    // 3. Build execution options.
    let env = trace_env();
    let options = PeExecutionOptions { live_session: None };

    // 4. Execute Steam.exe with tracing.
    let result = pe_runtime::execute_with_options(
        &steam_host_path,
        &[], // no command-line arguments
        &ge,
        &ge.root.join("drive_c"), // cwd
        &env,
        false, // dtm (deterministic mode) — false for now
        "t23_1_steam_bootstrap_diagnostic",
        options,
    );

    // 5. Analyse the result.
    match result {
        Ok(exec_result) => {
            let trace_events = &exec_result.trace_events;
            let exit_code = exec_result.exit_code;
            let exceptions = &exec_result.guest_exceptions;

            eprintln!(
                "Execution completed.\n\
                 Exit code:  {exit_code}\n\
                 Trace events: {}\n\
                 Guest exceptions: {}\n",
                trace_events.len(),
                exceptions.len(),
            );

            // Dump all steam_api_init trace events.
            let api_events: Vec<_> = trace_events
                .iter()
                .filter(|e| e.category == "steam_api_init")
                .collect();

            eprintln!("=== Steam API Init Trace ({} events) ===", api_events.len());
            for event in &api_events {
                let caller_rva = event
                    .parameters
                    .get("caller_rva")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let thunk = &event.call_id;
                let arg0 = event
                    .parameters
                    .get("arg0")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let arg1 = event
                    .parameters
                    .get("arg1")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let arg2 = event
                    .parameters
                    .get("arg2")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let eax = event
                    .parameters
                    .get("eax")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                eprintln!(
                    "  [{:>4}] 0x{caller_rva:<8}  {thunk:<45}  arg0={arg0:<10}  arg1={arg1:<10}  arg2={arg2:<10}  eax={eax}",
                    event.event_index,
                );
            }

            // Dump "process" category events (crash workaround, etc.).
            let process_events: Vec<_> = trace_events
                .iter()
                .filter(|e| e.category == "process")
                .collect();

            if !process_events.is_empty() {
                eprintln!(
                    "\n=== Process Trace Events ({} events) ===",
                    process_events.len()
                );
                for event in &process_events {
                    let params_str: Vec<String> = event
                        .parameters
                        .iter()
                        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or(&v.to_string())))
                        .collect();
                    eprintln!(
                        "  [{:>4}] {}  {}",
                        event.event_index,
                        event.call_id,
                        params_str.join(", "),
                    );
                }
            }

            // Assert that we at least captured some API trace.
            assert!(
                !api_events.is_empty(),
                "No steam_api_init trace events captured — Steam may not have started, \
                 or the trace category was not enabled"
            );
            // The captured events must carry real dispatch data: every event names a
            // thunk, and the init sequence must have produced a caller-RVA trail.
            assert!(
                api_events.iter().all(|e| !e.call_id.is_empty()),
                "every steam_api_init event must name a thunk"
            );
            assert!(
                api_events
                    .iter()
                    .any(|e| e.parameters.contains_key("caller_rva")),
                "steam_api_init events must record caller RVAs"
            );
            assert!(
                !trace_events.is_empty(),
                "at least one trace event must be captured overall"
            );

            // If the crash workaround was triggered, we should see a SteamZeroRecord event.
            let zero_record = process_events
                .iter()
                .find(|e| e.call_id == "SteamZeroRecord");
            if let Some(zr) = zero_record {
                eprintln!(
                    "\n*** CRASH WORKAROUND TRIGGERED at RVA 0x401390 ***\n\
                     Zero-record details: {zr:#?}\n\
                     See above for the full API call trace.  Look for an API that\n\
                     returned an unexpected value (e.g. 0 instead of a valid handle,\n\
                     or an error code) in the calls immediately before the crash."
                );
            }

            if exit_code != 0 {
                eprintln!(
                    "\nNote: Steam.exe exited with code {exit_code} \
                     (non-zero). This is expected during diagnostic runs."
                );
            }
        }
        Err(error) => {
            // The execution itself failed (e.g. budget exceeded, unhandled opcode).
            let error_msg = format!("{error:?}");
            eprintln!(
                "Steam.exe execution FAILED with error:\n\n  {error_msg}\n\n\
                 This may indicate an unhandled instruction, missing import, \
                 or other runtime issue that prevents Steam from even reaching \
                 the crash workaround.\n"
            );

            // Extract the guest-crash-context hint which contains the mapped_base,
            // rip, and block_start_rva / block_end_rva.
            let crash_context = error_msg
                .lines()
                .find(|line| line.contains("guest-crash-context"))
                .map(|line| line.trim());

            if let Some(ctx) = crash_context {
                eprintln!("[GUEST CRASH CONTEXT]\n  {ctx}\n");
                // Parse mapped_base=0x... etc.
                let mapped_base = ctx
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != 'x')
                    .filter_map(|part| {
                        if part.starts_with("0x") || part.starts_with("0X") {
                            u64::from_str_radix(&part[2..], 16).ok()
                        } else {
                            None
                        }
                    })
                    .next();
                if let Some(base) = mapped_base {
                    eprintln!("  ==> mapped_image_base = {base:#x}");
                    if let Some((_, rip_str)) = ctx.split_once("rip=")
                        && let Some(rip_val) = rip_str.split_whitespace().next()
                        && let Ok(rip) = u64::from_str_radix(rip_val.trim_start_matches("0x"), 16)
                    {
                        let rva = rip.saturating_sub(base);
                        eprintln!("  ==> current RIP RVA = {rva:#x} (relative to base {base:#x})");
                        let in_image = rva < 0x800_000; // typical image < 8MB
                        eprintln!(
                            "  ==> RIP is {} the mapped image",
                            if in_image { "WITHIN" } else { "OUTSIDE" }
                        );
                    }
                }
            } else {
                eprintln!("[GUEST CRASH CONTEXT] (not found in error output)");
            }

            // Check for budget-exceeded — this is a soft failure we can learn from.
            if error_msg.contains("exceeded the instruction budget") {
                eprintln!(
                    "[ANALYSIS] The instruction budget (25,000,000 (default)) was exhausted.\n\
                     The error above may include a 'guest-crash-context' hint with the\n\
                     mapped base address, current RIP, and the decoded instructions of the\n\
                     block that exceeded the budget.\n\
                     If RIP is OUTSIDE the mapped image, the CPU engine followed an indirect\n\
                     call/jump to a non-image address (heap, data, etc.).  The 'ImageExit'\n\
                     process trace event (emitted on first exit from the image) would have\n\
                     logged the last in-image block RVAs — but this event is only accessible\n\
                     on the success path.  Re-run with lower budget or add stderr logging."
                );
            }

            panic!("Steam.exe diagnostic execution failed: {error:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// t23_2_steam_import_coverage
// Phase 1.3.1 — Enumerate all DLL imports required by Steam.exe
// ---------------------------------------------------------------------------

#[test]
#[ignore = "manual diagnostic — requires ges/steam-live-run-x86 with Steam.exe"]
fn t23_2_steam_import_coverage() {
    use casa1::ge::GameEnvironment;
    use casa1::pe::{self, ApiSetResolver, ImportSymbol};

    let ge = GameEnvironment::open(&steam_ge_root()).expect("failed to open steam-live-run-x86 GE");
    let steam_host_path = ge.root.join("drive_c").join("Steam.exe");
    assert!(steam_host_path.is_file(), "Steam.exe not found");

    let image = pe::parse_from_file(&steam_host_path).expect("failed to parse Steam.exe");
    let resolver = ApiSetResolver::new();

    eprintln!("=== Steam.exe Import Coverage Report ===\n");
    eprintln!(
        "Machine: {:#x} ({})",
        image.machine,
        if image.machine == 0x14c {
            "x86"
        } else if image.machine == 0x8664 {
            "x64"
        } else {
            "unknown"
        }
    );
    eprintln!("Image base: {:#x}", image.image_base);
    eprintln!("Entry point RVA: {:#x}", image.address_of_entry_point);
    eprintln!(
        "Size of image: {:#x} ({} bytes)",
        image.size_of_image, image.size_of_image
    );
    eprintln!();

    // Collect all imports (regular + delayed)
    let mut all_imports: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total_imports = 0;

    for descriptor in image.imports.iter().chain(image.delay_imports.iter()) {
        let resolved = resolver.resolve(&descriptor.dll_name);
        let dll_key = resolved.clone();
        for thunk in &descriptor.imports {
            let symbol_name = match &thunk.symbol {
                ImportSymbol::ByName { name, .. } => name.clone(),
                ImportSymbol::ByOrdinal { ordinal } => format!("ordinal #{ordinal}"),
            };
            all_imports
                .entry(dll_key.clone())
                .or_default()
                .push(symbol_name);
            total_imports += 1;
        }
    }

    eprintln!(
        "Total imports: {} from {} DLLs\n",
        total_imports,
        all_imports.len()
    );
    eprintln!("{:<40} {:>6}  Functions", "DLL", "Count");
    eprintln!("{}", "-".repeat(80));

    let mut sorted_dlls: Vec<_> = all_imports.iter().collect();
    sorted_dlls.sort_by_key(|entry| std::cmp::Reverse(entry.1.len()));

    for (dll, functions) in &sorted_dlls {
        eprintln!(
            "{:<40} {:>6}  {}",
            dll,
            functions.len(),
            functions.join(", ")
        );
    }

    eprintln!();
    eprintln!("=== Import Coverage Summary ===");
    eprintln!("Total DLLs: {}", all_imports.len());
    eprintln!("Total import functions: {}", total_imports);

    // Real assertions so the diagnostic cannot pass vacuously: Steam.exe imports a
    // large, well-known function set across many DLLs, and every DLL must contribute
    // at least one import.
    assert!(
        total_imports >= 100,
        "Steam.exe must import at least 100 functions, got {total_imports}"
    );
    assert!(
        all_imports.len() >= 10,
        "Steam.exe must import from at least 10 DLLs, got {}",
        all_imports.len()
    );
    assert!(
        all_imports.values().all(|functions| !functions.is_empty()),
        "every imported DLL must contribute at least one function"
    );
}

// ---------------------------------------------------------------------------
// t23_3_import_coverage_matrix
// Phase 1.3.2 — Cross-reference Steam.exe imports against HostThunk dispatch
// ---------------------------------------------------------------------------

#[test]
#[ignore = "manual diagnostic — requires ges/steam-live-run-x86 with Steam.exe"]
fn t23_3_import_coverage_matrix() {
    use casa1::ge::GameEnvironment;
    use casa1::pe::{self, ApiSetResolver, ImportSymbol};
    use casa1::pe_runtime::is_import_supported;

    let ge = GameEnvironment::open(&steam_ge_root()).expect("failed to open steam-live-run-x86 GE");
    let steam_host_path = ge.root.join("drive_c").join("Steam.exe");
    assert!(steam_host_path.is_file(), "Steam.exe not found");

    let image = pe::parse_from_file(&steam_host_path).expect("failed to parse Steam.exe");
    let resolver = ApiSetResolver::new();

    eprintln!("=== Steam.exe Import Coverage Matrix ===\n");

    // Collect per-DLL coverage
    let mut dll_coverage: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    let mut total_supported = 0;
    let mut total_unsupported = 0;

    for descriptor in image.imports.iter().chain(image.delay_imports.iter()) {
        let resolved = resolver.resolve(&descriptor.dll_name);
        for thunk in &descriptor.imports {
            let symbol_name = match &thunk.symbol {
                ImportSymbol::ByName { name, .. } => name.clone(),
                ImportSymbol::ByOrdinal { ordinal } => format!("ordinal #{ordinal}"),
            };
            let supported = is_import_supported(&resolved, &thunk.symbol);
            let entry = dll_coverage
                .entry(resolved.clone())
                .or_insert_with(|| (Vec::new(), Vec::new()));
            if supported {
                total_supported += 1;
                entry.0.push(symbol_name);
            } else {
                total_unsupported += 1;
                entry.1.push(symbol_name);
            }
        }
    }

    let total = total_supported + total_unsupported;
    let coverage_pct = (total_supported as f64 / total as f64) * 100.0;

    // Summary
    eprintln!("Overall: {total_supported}/{total} ({coverage_pct:.1}%) imports supported");
    eprintln!("  Supported:   {total_supported}");
    eprintln!("  Unsupported: {total_unsupported}");
    eprintln!();

    // Per-DLL breakdown
    eprintln!(
        "{:<45} {:>5}/{:<5}  {:>6}  Missing",
        "DLL", "Ok", "Total", "Pct"
    );
    eprintln!("{}", "-".repeat(100));

    let mut sorted_dlls: Vec<_> = dll_coverage.iter().collect();
    sorted_dlls.sort_by_key(|entry| std::cmp::Reverse(entry.1.1.len()));

    for (dll, (supported, unsupported)) in &sorted_dlls {
        let total_dll = supported.len() + unsupported.len();
        let pct = (supported.len() as f64 / total_dll as f64) * 100.0;
        let missing_str = if unsupported.is_empty() {
            "✅".to_string()
        } else {
            unsupported.join(", ")
        };
        eprintln!(
            "{:<45} {:>5}/{:<5}  {:>5.1}%  {}",
            dll,
            supported.len(),
            total_dll,
            pct,
            missing_str
        );
    }

    eprintln!();

    // Detailed unsupported list
    if total_unsupported > 0 {
        eprintln!("=== Unsupported Imports (need implementation) ===");
        for (dll, (_, unsupported)) in &sorted_dlls {
            if !unsupported.is_empty() {
                eprintln!("\n  [{}]", dll);
                for func in unsupported {
                    eprintln!("    - {}", func);
                }
            }
        }
    }

    eprintln!();
    eprintln!("=== Coverage Matrix Complete ===");
    eprintln!(
        "Phase 1.3.2 result: {total_supported}/{total} ({coverage_pct:.1}%) imports have HostThunk dispatch coverage"
    );

    // Assert minimum coverage — 100% as of Phase 1.3.3.
    assert!(
        coverage_pct >= 95.0,
        "Import coverage {coverage_pct:.1}% is below the 95% minimum threshold. \
         {total_unsupported} imports need implementation.",
    );
}

// ---------------------------------------------------------------------------
// t23_4_steam_regression
// Phase 1.1.4 — Regression test: record table populated & no crash workaround
// ---------------------------------------------------------------------------
//
// Verifies that the Steam.exe record table at global 0x42a270 is populated
// with non-zero entries after execution under deterministic mode (DTM), and
// that no `SteamZeroRecord` trace event was emitted (i.e. the crash
// workaround at RVA 0x401390 did *not* trigger).
//
// A small instruction budget (100 000) is used so the test completes quickly.
// This is enough to exercise the early startup code path that populates the
// record table; if the table is still zero after this budget the regression
// has been exposed.  When the underlying cause (a missing/unexpected API
// return value) is eventually fixed, this test should pass without the
// CASA1_STEAM_CRASH_WORKAROUND env var being consulted at all.

#[test]
#[ignore = "requires ges/steam-live-run-x86 with Steam.exe"]
fn t23_4_steam_regression() {
    // 1. Execute Steam.exe with DTM enabled and a small budget.
    let result = pe_runtime::regression_test_steam_bootstrap(
        100_000,            // budget — enough for early startup
        true,               // dtm — deterministic mode
        Some(&["process"]), // trace categories for record-table events
    );

    let exit_code = result.exit_code;
    let trace_events = &result.trace_events;

    eprintln!(
        "=== Steam Regression Test ===\n\
         Exit code:  {exit_code}\n\
         Trace events: {}\n",
        trace_events.len(),
    );

    // 2. Verify that no SteamZeroRecord event was emitted.
    let zero_record: Vec<_> = trace_events
        .iter()
        .filter(|e| e.call_id == "SteamZeroRecord")
        .collect();
    assert!(
        zero_record.is_empty(),
        "SteamZeroRecord trace event(s) emitted — crash workaround triggered!\n\
         The record table at mapped_image_base + 0x2a270 was empty on first access.\n\
         Events: {zero_record:#?}",
    );
    eprintln!("✓ No SteamZeroRecord event emitted (workaround did not trigger)");

    // 3. Verify the post-execution record-table check. NOTE: the runtime emits a
    // `table_populated` bool, but that bool is self-verification — a buggy runtime
    // could report `true` without reading anything. Instead, recompute the verdict
    // from the RAW guest-memory values the runtime read (record_base is the u32 at
    // mapped_image_base + 0x2a270; first_opcode is the u32 stored at record_base):
    // the event must carry both, the table address must be non-zero, and the first
    // opcode must be non-zero. (A memory-exposing execution API would allow reading
    // 0x42a270 directly; until one exists, these raw parameters are the closest
    // independent observable.)
    let table_check: Vec<_> = trace_events
        .iter()
        .filter(|e| e.call_id == "SteamRecordTablePostExec")
        .collect();
    assert_eq!(
        table_check.len(),
        1,
        "Expected exactly one SteamRecordTablePostExec trace event, found {}",
        table_check.len(),
    );
    let record_base = table_check[0]
        .parameters
        .get("record_base")
        .and_then(|v: &serde_json::Value| v.as_str())
        .unwrap_or("0x0");
    let first_opcode = table_check[0]
        .parameters
        .get("first_opcode")
        .and_then(|v: &serde_json::Value| v.as_str())
        .unwrap_or("null");
    assert_ne!(
        record_base, "0x0",
        "record table global at mapped_image_base + 0x2a270 must be non-zero\n\
         Parameters: {:#?}",
        table_check[0].parameters,
    );
    assert!(
        first_opcode != "null" && first_opcode != "0x0",
        "first opcode of the record table must be non-zero\n\
         Parameters: {:#?}",
        table_check[0].parameters,
    );
    eprintln!(
        "✓ Record table is populated after execution (base {record_base}, first opcode {first_opcode})"
    );

    // 4. Also check the pre-execution SteamInitialGlobals event: it probes the
    // startup globals directly from guest memory before execution. The startup
    // state global must be non-zero once imports are bound (a zero value is the
    // documented indicator of the crash path).
    let initial_globals: Vec<_> = trace_events
        .iter()
        .filter(|e| e.call_id == "SteamInitialGlobals")
        .collect();
    if let Some(globals) = initial_globals.first() {
        let startup_state = globals
            .parameters
            .get("startup_state")
            .and_then(|v: &serde_json::Value| v.as_str())
            .unwrap_or("0x0");
        eprintln!("✓ SteamInitialGlobals: startup_state = {startup_state}");
        assert_ne!(
            startup_state, "0x0",
            "startup-state global (selected_base + 0x45715c) must be non-zero \
             after imports are bound"
        );
    } else {
        panic!("SteamInitialGlobals trace event missing — startup probe did not run");
    }

    eprintln!("\n=== Regression test PASSED ===");
}

// ---------------------------------------------------------------------------
// t23_5_x86_decode_coverage
// Phase 1.2.1 — Audit x86 instruction decode coverage against Steam.exe
// ---------------------------------------------------------------------------
//
// Loads Steam.exe via the PE parser, iterates over every executable section,
// decodes every instruction using `casa1::cpu::decode_block`, and reports:
//
//   - Total instructions decoded per section
//   - Unique `DecodedOpcode` variants encountered (by frequency)
//   - Any decode failures (unrecognised opcodes, parse errors, etc.)
//   - Overall coverage statistics
//
// Run with:
//   cargo test t23_5_x86_decode_coverage -- --ignored --nocapture
//
// NOTE: This is an *audit* test — it does not assert anything; it only
// prints a diagnostic report to stderr so you can identify holes in the
// x86 decoder.

#[test]
#[ignore = "manual diagnostic — requires ges/steam-live-run-x86 with Steam.exe"]
fn t23_5_x86_decode_coverage() {
    use casa1::cpu::{GuestArch, decode_block};
    use casa1::ge::GameEnvironment;
    use casa1::pe;
    use std::collections::HashMap;

    // ── 1. Load the PE image ──────────────────────────────────────────
    let ge = GameEnvironment::open(&steam_ge_root()).expect("failed to open steam-live-run-x86 GE");
    let steam_host_path = ge.root.join("drive_c").join("Steam.exe");
    assert!(
        steam_host_path.is_file(),
        "Steam.exe not found at {:?}",
        steam_host_path
    );

    let pe_bytes = std::fs::read(&steam_host_path).expect("failed to read Steam.exe");
    let image = pe::parse(&pe_bytes).expect("failed to parse Steam.exe PE headers");

    eprintln!("=== t23_5: x86 Instruction Decode Coverage ===\n");
    eprintln!(
        "Machine: {:#x} ({})",
        image.machine,
        if image.machine == 0x14c {
            "x86"
        } else if image.machine == 0x8664 {
            "x64"
        } else {
            "unknown"
        }
    );
    eprintln!("Image base: {:#x}", image.image_base);
    eprintln!("Entry point RVA: {:#x}", image.address_of_entry_point);
    eprintln!(
        "Size of image: {:#x} ({} bytes)",
        image.size_of_image, image.size_of_image
    );
    eprintln!("Number of sections: {}", image.number_of_sections);

    // ── 2. Determine the guest architecture from the machine field ──
    let arch = if image.machine == 0x8664 {
        GuestArch::X64
    } else {
        // Default to X86 for 0x14c (i386) and anything else.
        GuestArch::X86
    };
    eprintln!("Guest architecture: {arch:?}\n");

    // Image section characteristics constants
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

    // ── 3. Decode each executable section ────────────────────────────
    // Use HashMap<String, usize> because DecodedOpcode does not implement Ord/Hash.
    // We convert opcodes to their debug string representation for map keys.
    #[allow(clippy::type_complexity)]
    let mut section_results: Vec<(
        String,
        usize,
        HashMap<String, usize>,
        Vec<(usize, String)>,
    )> = Vec::new();

    let mut total_instructions = 0usize;
    let mut total_decode_errors = 0usize;
    let mut all_opcodes: HashMap<String, usize> = HashMap::new();

    // Outline for the report table
    eprintln!("{:-<120}", "");
    eprintln!(
        "{:<20} {:>12} {:>12} {:>12}  Executable",
        "Section", "Offset", "Size", "Insns"
    );
    eprintln!("{:-<120}", "");

    for section in &image.sections {
        let is_exec = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let raw_start = section.raw_data_ptr as usize;
        let raw_len = section.raw_data_size as usize;

        eprintln!(
            "{:<20} {:#10x} {:>10} {:>12}  {}",
            section.name,
            section.virtual_address,
            raw_len,
            if is_exec { "?" } else { "(skip)" },
            if is_exec { "✅" } else { "❌" },
        );

        // Debug: show raw_data_ptr and first bytes for executable sections
        if is_exec && raw_len > 0 && raw_start < pe_bytes.len() {
            let preview_end = (raw_start + 16).min(pe_bytes.len());
            let preview = &pe_bytes[raw_start..preview_end];
            let hex: String = preview
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            eprintln!(
                "  raw_data_ptr={:#x} virtual_address={:#x} first_bytes: {}",
                section.raw_data_ptr, section.virtual_address, hex,
            );
        }

        if !is_exec || raw_len == 0 {
            continue;
        }

        // Clamp raw range to actual file bytes
        let end = pe_bytes.len().min(raw_start.saturating_add(raw_len));
        let section_bytes = if raw_start < pe_bytes.len() {
            &pe_bytes[raw_start..end]
        } else {
            &[]
        };

        if section_bytes.len() < 4 {
            // Too small to contain a valid instruction
            continue;
        }

        // Decode the entire section
        let base_address = image.image_base + section.virtual_address as u64;
        let mut opcodes: HashMap<String, usize> = HashMap::new();
        let mut errors: Vec<(usize, String)> = Vec::new();
        let mut cursor = 0usize;

        // ── Windowed decode ─────────────────────────────────────────
        // `decode_block` decodes ALL instructions in the provided byte
        // slice (it does NOT stop at branches like jmp/ret).  If any one
        // instruction is unrecognised, the entire call returns Err and
        // *all* previously decoded instructions are lost.
        //
        // To bound the loss, we never hand more than DECODE_WINDOW bytes
        // to decode_block at once.  When an error occurs within the
        // window, at most ~DECODE_WINDOW bytes of successfully pre-decoded
        // instructions are discarded.
        const DECODE_WINDOW: usize = 4096;

        while cursor < section_bytes.len() {
            // Limit the byte slice passed to decode_block
            let window_end = (cursor + DECODE_WINDOW).min(section_bytes.len());
            let chunk = &section_bytes[cursor..window_end];

            match decode_block(chunk, base_address + cursor as u64, arch) {
                Ok(instructions) => {
                    for inst in &instructions {
                        let key = format!("{:?}", inst.opcode);
                        *opcodes.entry(key).or_insert(0) += 1;
                    }
                    // Advance past all decoded instructions
                    let block_len: usize = instructions.iter().map(|i| i.size).sum();
                    cursor += block_len.max(1); // ensure forward progress
                }
                Err(err) => {
                    // Debug: dump the first error with actual bytes at this cursor position
                    if errors.is_empty() {
                        let debug_end = (cursor + 8).min(section_bytes.len());
                        let debug_bytes: String = section_bytes[cursor..debug_end]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        eprintln!(
                            "  [DEBUG] First error at offset +{:#x}: opcode_byte={:#04x} bytes=[{}]",
                            cursor, section_bytes[cursor], debug_bytes,
                        );
                    }
                    errors.push((cursor, format!("{err:?}")));
                    total_decode_errors += 1;
                    // Skip one byte and try again
                    cursor += 1;
                }
            }
        }

        let section_total: usize = opcodes.values().sum();
        total_instructions += section_total;

        // Merge into global opcode tally
        for (opcode_key, count) in &opcodes {
            *all_opcodes.entry(opcode_key.clone()).or_insert(0) += count;
        }

        section_results.push((section.name.clone(), section_total, opcodes, errors));
    }

    // ── 4. Print per-section breakdown ────────────────────────────────
    eprintln!("\n\n=== Per-Section Opcode Breakdown ===\n");
    for (section_name, total, opcodes, errors) in &section_results {
        eprintln!("\n── [{section_name}] — {total} instructions ──");

        // Sort by frequency descending
        let mut sorted: Vec<(&String, &usize)> = opcodes.iter().collect();
        sorted.sort_by_key(|entry| std::cmp::Reverse(*entry.1));

        for (opcode, count) in sorted.iter().take(30) {
            let pct = (**count as f64 / *total as f64) * 100.0;
            eprintln!("  {:>8}x  ({:>5.1}%)  {}", count, pct, opcode);
        }
        if sorted.len() > 30 {
            eprintln!("  ... and {} more opcodes", sorted.len() - 30);
        }

        if !errors.is_empty() {
            eprintln!("\n  ⚠  DECODE ERRORS ({})", errors.len());
            for (offset, msg) in errors.iter().take(20) {
                let bytes_hex: String =
                    section_bytes_for_error(section_name, *offset, &pe_bytes, &image);
                eprintln!("    @+{:#x}: {}  [bytes: {}]", offset, msg, bytes_hex);
            }
            if errors.len() > 20 {
                eprintln!("    ... and {} more errors", errors.len() - 20);
            }
        }
    }

    // ── 5. Print overall coverage summary ────────────────────────────
    eprintln!("\n\n=== Overall x86 Decode Coverage Summary ===\n");
    eprintln!("Total instructions decoded:  {}", total_instructions);
    eprintln!("Total decode errors:         {}", total_decode_errors);
    eprintln!("Unique opcodes encountered:  {}", all_opcodes.len());

    // Real assertions so this diagnostic cannot pass vacuously: the executable
    // sections of Steam.exe must decode to a substantial instruction stream with a
    // meaningful opcode set.
    assert!(
        total_instructions > 0,
        "no instructions decoded from Steam.exe executable sections"
    );
    assert!(
        all_opcodes.len() >= 10,
        "expected a substantial opcode set, got {} unique opcodes",
        all_opcodes.len()
    );

    // Count how many opcodes are currently unknown (would need new variants)
    // All DecodedOpcodes in the enum are "known" — unknown bytes cause decode_block
    // to return an error (AppError). So decode_errors == unknown opcodes.
    let error_rate = if total_instructions + total_decode_errors > 0 {
        (total_decode_errors as f64 / (total_instructions + total_decode_errors) as f64) * 100.0
    } else {
        0.0
    };
    eprintln!("Error rate:                   {:.4}%", error_rate);

    // Top 20 most common opcodes
    eprintln!("\nTop 20 most common opcodes:");
    let mut sorted_global: Vec<(&String, &usize)> = all_opcodes.iter().collect();
    sorted_global.sort_by_key(|entry| std::cmp::Reverse(*entry.1));
    eprintln!("{:<8}  {:<6}  {:<8}  Opcode", "Count", "Pct", "Cumul");
    eprintln!("{:-<60}", "");
    let mut cumul = 0usize;
    for (opcode, count) in sorted_global.iter().take(20) {
        let pct = (**count as f64 / total_instructions as f64) * 100.0;
        cumul += **count;
        let cumul_pct = (cumul as f64 / total_instructions as f64) * 100.0;
        eprintln!(
            "{:>8}  {:>5.1}%  {:>6.1}%  {}",
            count, pct, cumul_pct, opcode
        );
    }

    // Opcodes NEVER encountered (zero count)
    // We can't easily enumerate which DecodedOpcode variants are never seen
    // without procedural reflection, but we can note which ones we *did* see.

    // Quick sanity: try to decode a known byte sequence
    eprintln!("\n--- Sanity check: decode push esi (0x56) standalone ---");
    let sanity_bytes = [0x56, 0x57, 0x8b, 0x7c, 0x24, 0x0c];
    match decode_block(&sanity_bytes, 0x1000, arch) {
        Ok(insns) => {
            eprintln!("  Decoded {} instruction(s):", insns.len());
            for i in &insns {
                eprintln!("    @{:#x}: {:?} size={}", i.address, i.opcode, i.size);
            }
            // `push esi` (1 B), `push edi` (1 B), `mov edi, [esp+0xc]` (4 B) —
            // the decoder must produce exactly these three instructions.
            assert_eq!(
                insns.len(),
                3,
                "known byte sequence must decode to 3 instructions"
            );
            assert_eq!(
                insns.iter().map(|i| i.size).sum::<usize>(),
                sanity_bytes.len(),
                "decoded instructions must cover the whole sanity buffer"
            );
        }
        Err(e) => {
            panic!("sanity decode of known bytes failed: {e:?}");
        }
    }

    eprintln!("\n=== Decode coverage audit complete ===");
    eprintln!(
        "{} instructions across {} executable sections, {} unique opcodes.",
        total_instructions,
        section_results.len(),
        all_opcodes.len()
    );
    if total_decode_errors > 0 {
        eprintln!("\n⚠  {total_decode_errors} decode error(s) encountered — review the");
        eprintln!("   error details above.  Each error represents an unrecognised");
        eprintln!("   x86 opcode or instruction encoding in Steam.exe that needs");
        eprintln!("   a new `DecodedOpcode` variant and decode logic.");
    } else {
        eprintln!("\n✅  No decode errors — all instructions in Steam.exe's executable");
        eprintln!("   sections were recognised by the decoder.");
    }
}

/// Helper: extract a hex dump of bytes around a decode error location.
fn section_bytes_for_error(
    section_name: &str,
    offset: usize,
    pe_bytes: &[u8],
    image: &casa1::pe::ParsedPe,
) -> String {
    // Find the section by name and get its raw_data_ptr
    for section in &image.sections {
        if section.name == section_name {
            let raw_start = section.raw_data_ptr as usize;
            let start = raw_start.saturating_add(offset);
            let end = (start + 16).min(pe_bytes.len());
            if start < pe_bytes.len() {
                let slice = &pe_bytes[start..end];
                return slice
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
            }
        }
    }
    "?".to_string()
}
