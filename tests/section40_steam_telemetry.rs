#![allow(dead_code, unused_imports)]
//! Phase 40 — Steam run telemetry (deterministic, no emulation).
//!
//! Unit-style tests of the milestone mechanics from `steam_milestones.rs`:
//! manifest-path detection, steamwebhelper command-line detection,
//! first-failure recording (first-wins per category), provenance building
//! from the build-time env vars, and the pure frame-source counting helper.
//!
//! No Steam binary is executed.  All assertions run on pure `*_in`
//! functions over local values (parallel-safe, no shared static), except
//! one manifest-path smoke test against the shared `MILESTONES` static.

use std::sync::Mutex;

use casa1::canonical::{GfxFrame, PerfMetric};
use casa1::ge::{GameEnvironment, GeArch};
use casa1::pe_runtime::{ExecutionTermination, PeExecutionResult};
use casa1::runner::{
    RunIntent, RunnerJob, is_steam_executable, steam_artifact_stem, write_steam_bootstrap_artifacts,
};
use casa1::steam_milestones::{
    FailureCategory, MilestoneEvidence, RunProvenance, SteamMilestones, command_line_is_webhelper,
    is_manifest_path, is_package_writability_probe_path, note_package_writability_probe_in,
    note_webhelper_process_started_in, note_webhelper_spawn_request_in, record_first_failure_in,
    utc_rfc3339_now,
};
use casa1::trace::TraceEvent;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

const MANIFEST_PLAIN: &str = r"C:\package\steam_client_win32.installed";
const MANIFEST_VERBATIM: &str = r"\\?\C:\package\steam_client_win32.installed";

fn evidence_at(pc: u64) -> MilestoneEvidence {
    MilestoneEvidence {
        observed: true,
        guest_pc: pc,
        thread_id: 1,
        process_id: 42,
        guest_tick: 1000,
        api: Some("test".to_string()),
        path: None,
        detail: Some("test evidence".to_string()),
    }
}

#[test]
fn manifest_path_detection_matches_steam_manifest_only() {
    assert!(is_manifest_path(MANIFEST_PLAIN));
    assert!(is_manifest_path(MANIFEST_VERBATIM));
    assert!(is_manifest_path(r"c:\PACKAGE\Steam_Client_Win32.installed"));
    // Anything else — including sibling files in C:\package — is not a
    // manifest open.
    assert!(!is_manifest_path(r"C:\package\steam_client_win32.exe"));
    assert!(!is_manifest_path(
        r"C:\package\steam_client_win32.installed.bak"
    ));
    assert!(!is_manifest_path(r"C:\Steam\steam_client_win32.installed"));
    assert!(!is_manifest_path(r"C:\package"));
    assert!(!is_manifest_path(""));
}

#[test]
fn package_writability_probe_detection() {
    let mut milestones = SteamMilestones::default();
    note_package_writability_probe_in(&mut milestones, r"C:\package", true, evidence_at(0x4030));
    assert!(milestones.steam.package_writability_probe.is_some());
    let mut milestones = SteamMilestones::default();
    note_package_writability_probe_in(&mut milestones, r"\\?\C:\.crash", true, evidence_at(0x4030));
    assert!(milestones.steam.package_writability_probe.is_some());
    // Probe paths opened WITHOUT write access are not probes.
    let mut milestones = SteamMilestones::default();
    note_package_writability_probe_in(&mut milestones, r"C:\package", false, evidence_at(0x4030));
    assert!(milestones.steam.package_writability_probe.is_none());
    // Ordinary writable files are not probes.
    let mut milestones = SteamMilestones::default();
    note_package_writability_probe_in(
        &mut milestones,
        r"C:\package\steam_client_win32.installed",
        true,
        evidence_at(0x4030),
    );
    assert!(milestones.steam.package_writability_probe.is_none());
    assert!(is_package_writability_probe_path(r"\\?\C:\.crash"));
    assert!(!is_package_writability_probe_path(r"D:\.crash"));
}

#[test]
fn webhelper_detection_from_command_lines() {
    assert!(command_line_is_webhelper(
        r"C:\Steam\steamwebhelper.exe",
        r"-lang=en_US",
    ));
    assert!(command_line_is_webhelper(
        r"C:\Steam\Steam.exe",
        "-applaunch 570 C:\\Steam\\steamwebhelper.exe -lang=en_US",
    ));
    assert!(command_line_is_webhelper(
        "",
        "\"C:\\Program Files\\Steam\\steamwebhelper.exe\" -lang=en_US",
    ));
    assert!(!command_line_is_webhelper(
        r"C:\Steam\Steam.exe",
        r"-applaunch 570",
    ));
    assert!(!command_line_is_webhelper("", ""));

    let mut milestones = SteamMilestones::default();
    note_webhelper_spawn_request_in(&mut milestones, evidence_at(0x4040));
    assert_eq!(milestones.steam.webhelper_spawn_requests, 1);
    note_webhelper_spawn_request_in(&mut milestones, evidence_at(0x4050));
    assert_eq!(milestones.steam.webhelper_spawn_requests, 2);
}

#[test]
fn first_failure_records_only_first_per_category() {
    let _guard = MILESTONES_TEST_LOCK.lock().unwrap();
    let mut milestones = SteamMilestones::default();
    let recorded = record_first_failure_in(
        &mut milestones,
        FailureCategory::Fs,
        0x4010,
        1,
        Some("CreateFileW".to_string()),
        Some(2),
        "first fs failure".to_string(),
        None,
        None,
    );
    assert!(recorded);
    let first = milestones.first_failures.fs.clone().expect("recorded");
    assert_eq!(first.guest_pc, 0x4010);
    assert_eq!(first.thread_id, 1);
    assert_eq!(first.api.as_deref(), Some("CreateFileW"));
    assert_eq!(first.guest_error, Some(2));
    assert_eq!(first.detail, "first fs failure");

    // A second failure in the same category is NOT recorded.
    let recorded = record_first_failure_in(
        &mut milestones,
        FailureCategory::Fs,
        0x4020,
        2,
        Some("CreateFileA".to_string()),
        Some(3),
        "second fs failure".to_string(),
        None,
        None,
    );
    assert!(!recorded);
    let second = milestones.first_failures.fs.clone().expect("still first");
    assert_eq!(second.guest_pc, 0x4010);
    assert_eq!(second.detail, "first fs failure");

    // Different categories are independent.
    let recorded = record_first_failure_in(
        &mut milestones,
        FailureCategory::Network,
        0x4030,
        1,
        Some("connect".to_string()),
        Some(10061),
        "connection refused".to_string(),
        None,
        None,
    );
    assert!(recorded);
    assert_eq!(
        milestones
            .first_failures
            .network
            .as_ref()
            .unwrap()
            .guest_error,
        Some(10061),
    );
    assert!(milestones.first_failures.crt.is_none());
    assert!(milestones.first_failures.thread.is_none());
    assert!(milestones.first_failures.cef.is_none());
    assert!(milestones.first_failures.gfx.is_none());
}

#[test]
fn provenance_builds_from_env_vars() {
    let provenance = RunProvenance::from_env();
    // The build script emits these for every target, so the env vars are
    // visible in integration tests too.
    assert_eq!(provenance.commit_sha, env!("CASA1_COMMIT_SHA"));
    assert_eq!(provenance.dirty_tree, env!("CASA1_DIRTY") == "true");
    assert!(
        provenance.host_os == "macos"
            || provenance.host_os == "linux"
            || provenance.host_os == "windows"
    );
    assert!(!provenance.host_arch.is_empty());
    let timestamp = provenance.timestamp_utc_rfc3339;
    assert!(
        timestamp.ends_with('Z'),
        "RFC3339 UTC timestamp ends with Z: {timestamp}"
    );
    assert!(timestamp.starts_with("20"), "RFC3339 year: {timestamp}");
    // Hash fields are empty for the env-only builder (no IO).
    assert_eq!(provenance.fixture_hash, "");
    assert_eq!(provenance.ge_hash, "");
    assert_eq!(provenance.steam_executable_hash, "");

    // collect() fills the hash fields for an existing directory.
    let temp_dir =
        std::env::temp_dir().join(format!("casa1-telemetry-provenance-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");
    std::fs::write(temp_dir.join("a.txt"), b"alpha").expect("write a");
    std::fs::write(temp_dir.join("b.bin"), b"beta").expect("write b");
    std::fs::write(temp_dir.join("ge.json"), b"{}").expect("write ge.json");
    let steam = temp_dir.join("Steam.exe");
    std::fs::write(&steam, b"MZ...").expect("write steam");
    let full = RunProvenance::collect(&temp_dir, &steam);
    assert_eq!(full.fixture_hash.len(), 64, "sha256 hex length");
    assert_eq!(full.ge_hash.len(), 64);
    assert_eq!(full.steam_executable_hash.len(), 64);
    assert_ne!(full.fixture_hash, full.ge_hash);
    // Deterministic: collecting twice yields the same fixture hash.
    let again = RunProvenance::collect(&temp_dir, &steam);
    assert_eq!(full.fixture_hash, again.fixture_hash);
    // A missing file is reported honestly, never fabricated.
    let missing = RunProvenance::collect(&temp_dir, &temp_dir.join("missing.exe"));
    assert_eq!(missing.steam_executable_hash, "unavailable");
    std::fs::remove_dir_all(&temp_dir).expect("remove temp dir");

    assert_eq!(utc_rfc3339_now().len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
}

// ---------------------------------------------------------------------------
// Evidence-integrity additions
// ---------------------------------------------------------------------------

#[test]
fn steam_artifact_gating_accepts_only_steam_exe() {
    assert!(is_steam_executable(Path::new("Steam.exe")));
    assert!(is_steam_executable(Path::new("steam.exe")));
    assert!(is_steam_executable(Path::new("/games/Steam/Steam.exe")));
    assert!(!is_steam_executable(Path::new("Steam.exe.bak")));
    assert!(!is_steam_executable(Path::new("steam.exe.bak")));
    assert!(!is_steam_executable(Path::new("foo-Steam.exe.backup")));
    assert!(!is_steam_executable(Path::new("other.exe")));
    assert!(!is_steam_executable(Path::new("Steam")));
    assert!(!is_steam_executable(Path::new("")));
}

#[test]
fn manifest_path_exact_components_only() {
    // True positives: plain, verbatim/extended, case-insensitive.
    assert!(is_manifest_path(MANIFEST_PLAIN));
    assert!(is_manifest_path(MANIFEST_VERBATIM));
    assert!(is_manifest_path(r"c:\PACKAGE\Steam_Client_Win32.installed"));
    // False positives the old substring test would have accepted.
    assert!(!is_manifest_path(
        r"C:\notpackage\steam_client_win32.installed"
    ));
    assert!(!is_manifest_path(
        r"C:\package\steam_client_win32.installed.bak"
    ));
    assert!(!is_manifest_path(
        r"C:\package\sub\steam_client_win32.installed"
    ));
    assert!(!is_manifest_path(
        r"C:\package\steam_client_win32.installed\extra"
    ));
    // Wrong drive, UNC, relative, device and ADS forms.
    assert!(!is_manifest_path(
        r"D:\package\steam_client_win32.installed"
    ));
    assert!(!is_manifest_path(
        r"\\server\share\package\steam_client_win32.installed"
    ));
    assert!(!is_manifest_path(r"package\steam_client_win32.installed"));
    assert!(!is_manifest_path(r"\package\steam_client_win32.installed"));
    assert!(!is_manifest_path(
        r"\\.\package\steam_client_win32.installed"
    ));
    assert!(!is_manifest_path(
        r"C:\package\steam_client_win32.installed:Zone.Identifier"
    ));
    // Directory-only and empty paths.
    assert!(!is_manifest_path(r"C:\package"));
    assert!(!is_manifest_path(r"C:\"));
    assert!(!is_manifest_path(""));
}

#[test]
fn webhelper_spawn_request_vs_process_started_counters() {
    let mut milestones = SteamMilestones::default();
    note_webhelper_spawn_request_in(&mut milestones, evidence_at(0x6000));
    note_webhelper_spawn_request_in(&mut milestones, evidence_at(0x6010));
    assert_eq!(milestones.steam.webhelper_spawn_requests, 2);
    assert_eq!(
        milestones.steam.webhelper_processes_started, 0,
        "spawn requests must not count as started processes",
    );
    assert!(milestones.steam.webhelper_spawn_requested.is_some());
    assert!(milestones.steam.webhelper_process_started.is_none());
    assert_eq!(
        milestones
            .steam
            .webhelper_spawn_requested
            .clone()
            .unwrap()
            .guest_pc,
        0x6000,
        "first spawn request is first-wins",
    );

    note_webhelper_process_started_in(&mut milestones, evidence_at(0x6020));
    assert_eq!(milestones.steam.webhelper_spawn_requests, 2);
    assert_eq!(milestones.steam.webhelper_processes_started, 1);
    assert!(milestones.steam.webhelper_process_started.is_some());
    assert_eq!(
        milestones
            .steam
            .webhelper_process_started
            .clone()
            .unwrap()
            .guest_pc,
        0x6020,
    );

    // The command-line gate still applies to spawn requests only.
    assert!(command_line_is_webhelper(
        r"C:\Steam\steamwebhelper.exe",
        "-lang=en_US",
    ));
    assert!(!command_line_is_webhelper(
        r"C:\Steam\Steam.exe",
        "-applaunch 570",
    ));
}

#[test]
fn deadline_terminated_run_artifact_retains_perf_trace_frames() {
    let temp_dir = tempfile::tempdir().expect("temp dir for artifact test");
    let ge = GameEnvironment::create_in(temp_dir.path(), "gate", GeArch::X86, "win11-23h2")
        .expect("create ge");
    let steam = temp_dir.path().join("Steam.exe");
    std::fs::write(&steam, b"MZ fake steam payload").expect("write steam.exe");
    let job = RunnerJob {
        jit_mode: Default::default(),
        steam_ipc: false,
        window_width: None,
        window_height: None,
        thread_start: None,
        ge_name: "gate".to_string(),
        ge_root: ge.root.clone(),
        program: steam.clone(),
        args: vec![],
        cwd: ge.root.clone(),
        env: BTreeMap::new(),
        dtm: true,
        intent: RunIntent::Run,
        trace_categories: vec![],
        test_id: "deadline-artifact-test".to_string(),
    };
    let mut metadata = BTreeMap::new();
    metadata.insert("source".to_string(), "gdi".to_string());
    let pe_output = PeExecutionResult {
        jit_telemetry: casa1::pe_runtime::JitTelemetry::default(),
        synthetic_pid: 42,
        stdout: "guest stdout".to_string(),
        stderr: "guest stderr".to_string(),
        exit_code: -2,
        guest_exceptions: Vec::new(),
        gfx_frames: vec![GfxFrame {
            scene_id: "scene-1".to_string(),
            frame_index: 7,
            hash: "frame-hash".to_string(),
            ssim: None,
            metadata,
        }],
        perf: vec![PerfMetric {
            metric_id: "pe_runtime_steps".to_string(),
            value: 123_456.0,
            unit: "instructions".to_string(),
        }],
        trace_events: vec![TraceEvent {
            event_index: 3,
            category: "network".to_string(),
            call_id: "connect".to_string(),
            parameters: BTreeMap::from([
                ("socket".to_string(), json!(7)),
                ("host".to_string(), json!("store.steampowered.com")),
                ("port".to_string(), json!(443)),
            ]),
            return_value: json!(0),
            get_last_error: None,
            side_effect_hashes: vec![],
        }],
        milestones: SteamMilestones::default(),
        provenance: RunProvenance::default(),
        termination: ExecutionTermination::HarnessDeadline,
        termination_detail: Some("wall-clock deadline".to_string()),
    };

    let paths = write_steam_bootstrap_artifacts(&ge, &pe_output, &job, "run-deadline-1")
        .expect("artifact write");
    let json = std::fs::read_to_string(&paths.json_path).expect("read artifact json");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse artifact json");
    assert_eq!(
        parsed["termination"],
        serde_json::json!("HarnessDeadline"),
        "structured termination must be authoritative in the artifact",
    );
    assert_eq!(parsed["run_id"], "run-deadline-1");
    assert_eq!(parsed["test_id"], "deadline-artifact-test");
    assert!(parsed["program_sha256"].as_str().unwrap().len() == 64);
    // Perf / trace / frame data survive the deadline termination.
    assert_eq!(parsed["instruction_count"], 123_456);
    // The network summary is now STRUCTURED: the connect trace contributes
    // an endpoint entry (a connect-only entry carries no status/bytes/TLS
    // evidence — S4 fails honestly on it, see steam_acceptance).
    assert_eq!(
        parsed["network_summary"][0]["host"],
        "store.steampowered.com"
    );
    assert_eq!(parsed["network_summary"][0]["port"], 443);
    assert_eq!(parsed["network_summary"][0]["proto"], "tcp");
    assert_eq!(parsed["network_summary"][0]["method"], "connect");
    assert_eq!(parsed["network_summary"][0]["status"], 0);
    let frames = parsed["milestones"].as_object().unwrap();
    assert!(frames.contains_key("graphics"));
    assert_eq!(parsed["exit_code"], -2);
    // The log artifact names the same run.
    let log = std::fs::read_to_string(&paths.log_path).expect("read artifact log");
    assert!(log.contains("run_id: run-deadline-1"));
    assert!(log.contains("termination: HarnessDeadline"));
    assert!(log.contains("test_id: deadline-artifact-test"));
    // Filenames carry the full run identity: `<short-sha>-<test-id>-<run-id>`.
    let short_sha = &env!("CASA1_COMMIT_SHA")[..8];
    let expected_stem = steam_artifact_stem(short_sha, "deadline-artifact-test", "run-deadline-1");
    assert_eq!(
        paths.json_path.file_name().unwrap().to_string_lossy(),
        format!("{expected_stem}.json"),
    );
    // A second run at the same commit with a different run-id writes a
    // DIFFERENT file (no overwrite).
    let paths_2 = write_steam_bootstrap_artifacts(&ge, &pe_output, &job, "run-deadline-2")
        .expect("artifact write 2");
    assert_ne!(paths.json_path, paths_2.json_path);
    assert!(paths_2.json_path.exists());
}

#[test]
fn first_failure_remains_first_wins() {
    let mut milestones = SteamMilestones::default();
    let recorded = record_first_failure_in(
        &mut milestones,
        FailureCategory::Cef,
        0x1111,
        1,
        Some("CefInitialize".to_string()),
        Some(87),
        "first cef failure".to_string(),
        None,
        None,
    );
    assert!(recorded);
    let recorded = record_first_failure_in(
        &mut milestones,
        FailureCategory::Cef,
        0x2222,
        2,
        Some("CefRunMessageLoop".to_string()),
        Some(88),
        "second cef failure".to_string(),
        None,
        None,
    );
    assert!(!recorded, "second failure in the category must be dropped");
    let first = milestones
        .first_failures
        .cef
        .as_ref()
        .expect("first failure kept");
    assert_eq!(first.guest_pc, 0x1111, "first failure's guest_pc kept");
    assert_eq!(first.detail, "first cef failure");
    assert_eq!(first.api.as_deref(), Some("CefInitialize"));
}

static MILESTONES_TEST_LOCK: Mutex<()> = Mutex::new(());

fn pe_output_for() -> PeExecutionResult {
    PeExecutionResult {
        jit_telemetry: casa1::pe_runtime::JitTelemetry::default(),
        synthetic_pid: 42,
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
        guest_exceptions: Vec::new(),
        gfx_frames: Vec::new(),
        perf: Vec::new(),
        trace_events: Vec::new(),
        milestones: SteamMilestones::default(),
        provenance: RunProvenance::default(),
        termination: ExecutionTermination::GuestExit { code: 0 },
        termination_detail: None,
    }
}

fn job_for(
    temp_dir: &tempfile::TempDir,
    ge: &GameEnvironment,
    program_name: &str,
    test_id: &str,
) -> RunnerJob {
    let program = temp_dir.path().join(program_name);
    RunnerJob {
        jit_mode: Default::default(),
        steam_ipc: false,
        window_width: None,
        window_height: None,
        thread_start: None,
        ge_name: ge.config.name.clone(),
        ge_root: ge.root.clone(),
        program,
        args: vec![],
        cwd: ge.root.clone(),
        env: BTreeMap::new(),
        dtm: true,
        intent: RunIntent::Run,
        trace_categories: vec![],
        test_id: test_id.to_string(),
    }
}
