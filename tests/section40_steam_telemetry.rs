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
    RunIntent, RunnerJob, SteamBootstrapArtifact, deterministic_run_id, is_steam_executable,
    steam_artifact_stem, write_steam_bootstrap_artifacts,
};
use casa1::steam_milestones::{
    FailureCategory, FrameCategory, MILESTONES, MilestoneEvidence, RunProvenance,
    SteamMilestoneGroup, SteamMilestones, command_line_is_webhelper, frame_category_for_metadata,
    frame_category_for_source, is_manifest_path, is_package_writability_probe_path,
    note_gfx_frame_in, note_manifest_path_in, note_manifest_read_in,
    note_package_writability_probe_in, note_thread_created_in, note_thread_normal_exit_in,
    note_thread_terminated_in, note_webhelper_process_started_in, note_webhelper_spawn_request_in,
    record_first_failure_in, reset_milestones, utc_rfc3339_now,
};
use casa1::trace::TraceEvent;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

/// Steam's real manifest path (plain and `\\?\` verbatim forms).
const MANIFEST_PLAIN: &str = r"C:\package\steam_client_win32.installed";
const MANIFEST_VERBATIM: &str = r"\\?\C:\package\steam_client_win32.installed";

/// Evidence used by the pure transition tests.
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
fn manifest_static_records_open_then_read() {
    let _guard = MILESTONES_TEST_LOCK.lock().unwrap();
    reset_milestones();
    {
        let milestones = MILESTONES.lock().unwrap();
        assert!(milestones.steam.manifest_opened.is_none());
        assert!(milestones.steam.manifest_full_read.is_none());
    }
    // An open of the manifest sets manifest_opened only.
    note_manifest_path_in(
        &mut SteamMilestones::default(),
        MANIFEST_PLAIN,
        evidence_at(0x4010),
    );
    {
        let mut milestones = MILESTONES.lock().unwrap();
        note_manifest_path_in(&mut milestones, MANIFEST_PLAIN, evidence_at(0x4010));
        assert!(milestones.steam.manifest_opened.is_some());
        assert!(milestones.steam.manifest_full_read.is_none());
        // A read of a non-manifest path changes nothing.
        note_manifest_read_in(
            &mut milestones,
            r"C:\package\steam_client_win32.exe",
            evidence_at(0x4020),
        );
        assert!(milestones.steam.manifest_full_read.is_none());
        // A full read of the manifest sets full_read (and keeps opened).
        note_manifest_read_in(&mut milestones, MANIFEST_VERBATIM, evidence_at(0x4020));
        assert!(milestones.steam.manifest_full_read.is_some());
        assert!(milestones.steam.manifest_opened.is_some());
    }
    reset_milestones();
    {
        let milestones = MILESTONES.lock().unwrap();
        assert!(milestones.steam.manifest_opened.is_none());
        assert!(milestones.steam.manifest_full_read.is_none());
    }
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
fn thread_counters_and_live_at_exit_derivation() {
    let mut milestones = SteamMilestones::default();
    // bootstrap starts, then two threads are created from the main process.
    milestones.steam.bootstrap_started = Some(evidence_at(0x1000));
    note_thread_created_in(&mut milestones, true, evidence_at(0x1010));
    assert!(milestones.steam.client_main_started.is_some());
    note_thread_created_in(&mut milestones, true, evidence_at(0x1020));
    assert_eq!(milestones.threads.created, 2);
    // A thread created before bootstrap never marks client_main_started.
    let mut early = SteamMilestones::default();
    note_thread_created_in(&mut early, true, evidence_at(0x1030));
    assert!(early.steam.client_main_started.is_none());
    assert!(early.steam.bootstrap_started.is_none());

    note_thread_normal_exit_in(&mut milestones);
    note_thread_terminated_in(&mut milestones);
    assert_eq!(milestones.threads.created, 2);
    assert_eq!(milestones.threads.normal_exits, 1);
    assert_eq!(milestones.threads.terminated, 1);
    assert_eq!(
        milestones.threads.created
            - milestones.threads.normal_exits
            - milestones.threads.terminated,
        0,
    );
}

#[test]
fn bootstrap_milestone_group_flags() {
    let mut milestones = SteamMilestones::default();
    milestones.steam.bootstrap_started = Some(evidence_at(0x2000));
    milestones.steam.manifest_opened = Some(evidence_at(0x2010));
    milestones.steam.manifest_full_read = Some(evidence_at(0x2020));
    milestones.steam.package_writability_probe = Some(evidence_at(0x2030));
    milestones.steam.cef_browser_created = Some(evidence_at(0x2040));
    milestones.steam.cef_first_paint = Some(evidence_at(0x2050));
    let group: SteamMilestoneGroup = milestones.steam;
    assert!(group.bootstrap_started.is_some());
    assert!(group.manifest_opened.is_some());
    assert!(group.manifest_full_read.is_some());
    assert!(group.package_writability_probe.is_some());
    assert!(group.cef_browser_created.is_some());
    assert!(group.cef_first_paint.is_some());
    let serialized = serde_json::to_string(&group).expect("serialize group");
    assert!(serialized.contains("bootstrap_started"));
    assert!(serialized.contains("manifest_full_read"));
    assert!(serialized.contains("guest_pc"));
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

#[test]
fn frame_source_counting_helper() {
    // Pure source-string mapping.
    assert_eq!(
        frame_category_for_source("host_placeholder"),
        FrameCategory::HostPlaceholder
    );
    assert_eq!(
        frame_category_for_source("placeholder"),
        FrameCategory::HostPlaceholder
    );
    assert_eq!(frame_category_for_source("gdi"), FrameCategory::Gdi);
    assert_eq!(frame_category_for_source("gdi32"), FrameCategory::Gdi);
    assert_eq!(
        frame_category_for_source("cef_software"),
        FrameCategory::CefSoftware
    );
    assert_eq!(
        frame_category_for_source("cef-software"),
        FrameCategory::CefSoftware
    );
    assert_eq!(
        frame_category_for_source("cef_accelerated"),
        FrameCategory::CefAccelerated
    );
    assert_eq!(
        frame_category_for_source("cef_gpu"),
        FrameCategory::CefAccelerated
    );
    // DXGI sources are not category-counted (tracked by dxgi_presents).
    assert_eq!(
        frame_category_for_source("dxgi_d3d11"),
        FrameCategory::Other
    );
    assert_eq!(
        frame_category_for_source("dxgi_d3d12"),
        FrameCategory::Other
    );
    assert_eq!(frame_category_for_source(""), FrameCategory::Other);

    // Metadata maps carry the source key.
    let mut metadata = BTreeMap::new();
    assert_eq!(frame_category_for_metadata(&metadata), FrameCategory::Other);
    metadata.insert("source".to_string(), "gdi".to_string());
    assert_eq!(frame_category_for_metadata(&metadata), FrameCategory::Gdi);

    // The counter hook increments the matching slot.
    let mut milestones = SteamMilestones::default();
    note_gfx_frame_in(&mut milestones, &metadata);
    assert_eq!(milestones.graphics.gdi_frames, 1);
    note_gfx_frame_in(&mut milestones, &metadata);
    assert_eq!(milestones.graphics.gdi_frames, 2);
    metadata.insert("source".to_string(), "cef_software".to_string());
    note_gfx_frame_in(&mut milestones, &metadata);
    assert_eq!(milestones.graphics.cef_software_frames, 1);
    assert_eq!(milestones.graphics.gdi_frames, 2);
    metadata.insert("source".to_string(), "dxgi_d3d11".to_string());
    note_gfx_frame_in(&mut milestones, &metadata);
    assert_eq!(milestones.graphics.host_placeholder_frames, 0);
    assert_eq!(milestones.graphics.cef_accelerated_frames, 0);
}

#[test]
fn snapshot_folds_atomic_counters_and_live_threads() {
    let _guard = MILESTONES_TEST_LOCK.lock().unwrap();
    reset_milestones();
    // Simulate a run on a local struct, then push it through the static.
    let mut milestones = SteamMilestones::default();
    milestones.steam.bootstrap_started = Some(evidence_at(0x3000));
    note_thread_created_in(&mut milestones, true, evidence_at(0x3010));
    note_thread_created_in(&mut milestones, true, evidence_at(0x3020));
    note_thread_normal_exit_in(&mut milestones);
    {
        let mut guard = MILESTONES.lock().unwrap();
        *guard = milestones;
    }
    casa1::steam_milestones::note_dxgi_present();
    casa1::steam_milestones::note_cef_paint(false);
    let snapshot = casa1::steam_milestones::snapshot_milestones();
    assert_eq!(snapshot.graphics.dxgi_presents, 1);
    assert_eq!(snapshot.steam.cef_software_paints, 1);
    assert!(snapshot.steam.cef_first_paint.is_some());
    assert!(snapshot.steam.cef_browser_created.is_some());
    assert!(snapshot.steam.first_software_paint.is_some());
    assert!(snapshot.steam.first_dxgi_present.is_some());
    assert_eq!(snapshot.threads.live_at_process_exit, 1);
    reset_milestones();
    let snapshot = casa1::steam_milestones::snapshot_milestones();
    assert_eq!(snapshot.graphics.dxgi_presents, 0);
    assert_eq!(snapshot.steam.cef_software_paints, 0);
    assert!(snapshot.steam.first_dxgi_present.is_none());
}

// ---------------------------------------------------------------------------
// Evidence-integrity additions
// ---------------------------------------------------------------------------

/// (a) The steam-bootstrap artifact is gated on the exact `steam.exe`
/// basename: backups, renamed copies and unrelated executables never produce
/// a Steam artifact.
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

/// (b) Two runs with different run-ids produce different artifact filenames;
/// the same run-id reproduces the same filename.
#[test]
fn run_ids_produce_distinct_artifact_filenames() {
    let stem_a = steam_artifact_stem("4a1ae92a", "run-identity-test", "run-1");
    let stem_b = steam_artifact_stem("4a1ae92a", "run-identity-test", "run-2");
    assert_ne!(stem_a, stem_b, "different run-ids must not collide");
    assert_eq!(stem_a, "4a1ae92a-run-identity-test-run-1-steam-bootstrap",);
    // The same run-id is stable (reconstruction, never timestamp noise).
    assert_eq!(
        steam_artifact_stem("4a1ae92a", "run-identity-test", "run-1"),
        stem_a,
    );
    // DTM run ids are deterministic from (short-sha, test-id) and distinct
    // across test ids.
    let id_a = deterministic_run_id("4a1ae92a", "test-a");
    let id_b = deterministic_run_id("4a1ae92a", "test-a");
    assert_eq!(id_a, id_b, "DTM run id must be deterministic");
    assert_eq!(id_a.len(), 12, "sha256[..12] hex");
    assert_ne!(
        deterministic_run_id("4a1ae92a", "test-a"),
        deterministic_run_id("4a1ae92a", "test-b"),
        "different test ids must not collide",
    );
    assert_ne!(
        deterministic_run_id("4a1ae92a", "test-a"),
        deterministic_run_id("deadbeef", "test-a"),
        "different short-shas must not collide",
    );
}

/// (c) Milestone state resets between runs: the static, the last-thunk
/// recorder and the run-start marker all clear.
#[test]
fn milestone_state_resets_between_runs() {
    let _guard = MILESTONES_TEST_LOCK.lock().unwrap();
    reset_milestones();
    {
        let mut guard = MILESTONES.lock().unwrap();
        guard.steam.bootstrap_started = Some(evidence_at(0x5000));
        guard.steam.manifest_full_read = Some(evidence_at(0x5010));
        guard.steam.webhelper_spawn_requests = 3;
        guard.graphics.dxgi_presents = 4;
    }
    casa1::steam_milestones::record_last_thunk("CreateFileW", 0x5020);
    casa1::steam_milestones::note_dxgi_present();
    casa1::steam_milestones::note_cef_paint(false);
    assert!(casa1::steam_milestones::snapshot_last_thunk().is_some());

    reset_milestones();

    {
        let guard = MILESTONES.lock().unwrap();
        assert!(guard.steam.bootstrap_started.is_none());
        assert!(guard.steam.manifest_full_read.is_none());
        assert_eq!(guard.steam.webhelper_spawn_requests, 0);
        assert_eq!(guard.graphics.dxgi_presents, 0);
    }
    assert!(
        casa1::steam_milestones::snapshot_last_thunk().is_none(),
        "last-thunk recorder must clear between runs",
    );
    let snapshot = casa1::steam_milestones::snapshot_milestones();
    assert_eq!(snapshot.graphics.dxgi_presents, 0);
    assert_eq!(snapshot.steam.cef_software_paints, 0);
    assert!(snapshot.steam.first_dxgi_present.is_none());
    // The run-start marker is gone too: a record after the reset measures
    // from zero wall time, not from the previous run's start.
    casa1::steam_milestones::record_last_thunk("GetTickCount", 0x5030);
    let last = casa1::steam_milestones::snapshot_last_thunk().expect("recorded after reset");
    assert_eq!(last.wall_secs_since_start, 0);
}

/// (d) Exact manifest path recognition: only `C:\package\<manifest>` (plain
/// or verbatim, any case) matches; near-misses are rejected.
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

/// (e) Webhelper spawn REQUESTS and actually-started processes are distinct
/// counters with distinct first-evidence fields.
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

/// (f) MilestoneEvidence survives a serde_json round-trip losslessly.
#[test]
fn milestone_evidence_serialization_round_trip() {
    let evidence = MilestoneEvidence {
        observed: true,
        guest_pc: 0x401_234,
        thread_id: 7,
        process_id: 42,
        guest_tick: 123_456,
        api: Some("CreateFileW".to_string()),
        path: Some(MANIFEST_PLAIN.to_string()),
        detail: Some("manifest opened".to_string()),
    };
    let json = serde_json::to_string(&evidence).expect("serialize evidence");
    let back: MilestoneEvidence = serde_json::from_str(&json).expect("deserialize evidence");
    assert_eq!(evidence, back);

    // Default evidence (host-side markers) also round-trips.
    let default_json =
        serde_json::to_string(&MilestoneEvidence::default()).expect("serialize default evidence");
    let back: MilestoneEvidence =
        serde_json::from_str(&default_json).expect("deserialize default evidence");
    assert_eq!(MilestoneEvidence::default(), back);
}

/// (g) A deadline-terminated run's artifact retains the full perf, trace and
/// frame data — the structured termination never discards diagnostics.
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

/// (h) First-failure remains first-wins per category when recorded twice.
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

/// (i) ExecutionTermination serializes deterministically and round-trips.
#[test]
fn execution_termination_serializes_deterministically() {
    let termination = ExecutionTermination::GuestExit { code: 7 };
    let serialized = serde_json::to_string(&termination).expect("serialize termination");
    assert_eq!(
        serialized, "{\"GuestExit\":{\"code\":7}}",
        "exact deterministic serialization",
    );
    // Repeated serialization is byte-identical.
    assert_eq!(
        serde_json::to_string(&termination).expect("serialize again"),
        serialized,
    );
    let back: ExecutionTermination = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(termination, back);

    // Every variant round-trips.
    for termination in [
        ExecutionTermination::GuestExit { code: 0 },
        ExecutionTermination::HarnessDeadline,
        ExecutionTermination::InstructionBudget,
        ExecutionTermination::UnsupportedInstruction,
        ExecutionTermination::GuestException,
        ExecutionTermination::HostError,
    ] {
        let json = serde_json::to_string(&termination).expect("serialize variant");
        let back: ExecutionTermination = serde_json::from_str(&json).expect("deserialize variant");
        assert_eq!(termination, back);
    }
}

/// Serializes tests that touch the process-wide MILESTONES static (and the
/// atomic graphics/CEF counters): parallel tests in the same binary would
/// otherwise interleave resets with assertions and poison the mutex.
static MILESTONES_TEST_LOCK: Mutex<()> = Mutex::new(());

/// The artifact JSON carries the full identity fields declared by
/// SteamBootstrapArtifact (run_id, test_id, program_path, program_sha256,
/// termination).
#[test]
fn artifact_declares_explicit_identity_fields() {
    let artifact = SteamBootstrapArtifact {
        provenance: RunProvenance::default(),
        run_id: "run-x".to_string(),
        test_id: "test-y".to_string(),
        program_path: r"C:\Steam\Steam.exe".to_string(),
        program_sha256: "ab".repeat(32),
        milestones: SteamMilestones::default(),
        last_thunk: None,
        guest_pid: 1,
        jit: casa1::pe_runtime::JitTelemetry::default(),
        exit_code: 0,
        termination: ExecutionTermination::GuestExit { code: 0 },
        termination_detail: None,
        instruction_count: Some(1),
        guest_exceptions: vec![],
        network_summary: vec![],
        metal_encoders_created: 0,
        metal_encoders_ended: 0,
    };
    let json = serde_json::to_value(&artifact).expect("serialize artifact");
    assert_eq!(json["run_id"], "run-x");
    assert_eq!(json["test_id"], "test-y");
    assert_eq!(json["program_path"], r"C:\Steam\Steam.exe");
    assert_eq!(json["program_sha256"], "ab".repeat(32));
    assert_eq!(
        json["termination"],
        serde_json::json!({"GuestExit": {"code": 0}})
    );
    assert!(json["milestones"].is_object());
    let _: Value = json;
}
