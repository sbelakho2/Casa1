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

use casa1::steam_milestones::{
    FailureCategory, FrameCategory, MILESTONES, RunProvenance, SteamMilestoneGroup,
    SteamMilestones, command_line_is_webhelper, frame_category_for_metadata,
    frame_category_for_source, is_manifest_path, is_package_writability_probe_path,
    note_gfx_frame_in, note_manifest_path_in, note_manifest_read_in,
    note_package_writability_probe_in, note_thread_created_in, note_thread_normal_exit_in,
    note_thread_terminated_in, note_webhelper_process_in, record_first_failure_in,
    reset_milestones, utc_rfc3339_now,
};
use std::collections::BTreeMap;

/// Steam's real manifest path (plain and `\\?\` verbatim forms).
const MANIFEST_PLAIN: &str = r"C:\package\steam_client_win32.installed";
const MANIFEST_VERBATIM: &str = r"\\?\C:\package\steam_client_win32.installed";

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
    reset_milestones();
    {
        let milestones = MILESTONES.lock().unwrap();
        assert!(!milestones.steam.manifest_opened);
        assert!(!milestones.steam.manifest_verified);
    }
    // An open of the manifest sets manifest_opened only.
    note_manifest_path_in(&mut SteamMilestones::default(), MANIFEST_PLAIN);
    {
        let mut milestones = MILESTONES.lock().unwrap();
        note_manifest_path_in(&mut milestones, MANIFEST_PLAIN);
        assert!(milestones.steam.manifest_opened);
        assert!(!milestones.steam.manifest_verified);
        // A read of a non-manifest path changes nothing.
        note_manifest_read_in(&mut milestones, r"C:\package\steam_client_win32.exe");
        assert!(!milestones.steam.manifest_verified);
        // A full read of the manifest sets verified (and keeps opened).
        note_manifest_read_in(&mut milestones, MANIFEST_VERBATIM);
        assert!(milestones.steam.manifest_verified);
        assert!(milestones.steam.manifest_opened);
    }
    reset_milestones();
    {
        let milestones = MILESTONES.lock().unwrap();
        assert!(!milestones.steam.manifest_opened);
        assert!(!milestones.steam.manifest_verified);
    }
}

#[test]
fn package_writability_probe_detection() {
    let mut milestones = SteamMilestones::default();
    note_package_writability_probe_in(&mut milestones, r"C:\package", true);
    assert!(milestones.steam.package_writability_probe);
    let mut milestones = SteamMilestones::default();
    note_package_writability_probe_in(&mut milestones, r"\\?\C:\.crash", true);
    assert!(milestones.steam.package_writability_probe);
    // Probe paths opened WITHOUT write access are not probes.
    let mut milestones = SteamMilestones::default();
    note_package_writability_probe_in(&mut milestones, r"C:\package", false);
    assert!(!milestones.steam.package_writability_probe);
    // Ordinary writable files are not probes.
    let mut milestones = SteamMilestones::default();
    note_package_writability_probe_in(
        &mut milestones,
        r"C:\package\steam_client_win32.installed",
        true,
    );
    assert!(!milestones.steam.package_writability_probe);
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
    note_webhelper_process_in(&mut milestones);
    assert_eq!(milestones.steam.webhelper_processes, 1);
    note_webhelper_process_in(&mut milestones);
    assert_eq!(milestones.steam.webhelper_processes, 2);
}

#[test]
fn first_failure_records_only_first_per_category() {
    let mut milestones = SteamMilestones::default();
    let recorded = record_first_failure_in(
        &mut milestones,
        FailureCategory::Fs,
        0x4010,
        1,
        Some("CreateFileW".to_string()),
        Some(2),
        "first fs failure".to_string(),
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
    milestones.steam.bootstrap_started = true;
    note_thread_created_in(&mut milestones, true);
    assert!(milestones.steam.client_main_started);
    note_thread_created_in(&mut milestones, true);
    assert_eq!(milestones.threads.created, 2);
    // A thread created before bootstrap never marks client_main_started.
    let mut early = SteamMilestones::default();
    note_thread_created_in(&mut early, true);
    assert!(!early.steam.client_main_started);
    assert!(!early.steam.bootstrap_started);

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
    milestones.steam.bootstrap_started = true;
    milestones.steam.manifest_opened = true;
    milestones.steam.manifest_verified = true;
    milestones.steam.package_writability_probe = true;
    milestones.steam.cef_browser_created = true;
    milestones.steam.cef_first_paint = true;
    let group: SteamMilestoneGroup = milestones.steam;
    assert!(group.bootstrap_started);
    assert!(group.manifest_opened);
    assert!(group.manifest_verified);
    assert!(group.package_writability_probe);
    assert!(group.cef_browser_created);
    assert!(group.cef_first_paint);
    let serialized = serde_json::to_string(&group).expect("serialize group");
    assert!(serialized.contains("bootstrap_started"));
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
    reset_milestones();
    // Simulate a run on a local struct, then push it through the static.
    let mut milestones = SteamMilestones::default();
    milestones.steam.bootstrap_started = true;
    note_thread_created_in(&mut milestones, true);
    note_thread_created_in(&mut milestones, true);
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
    assert!(snapshot.steam.cef_first_paint);
    assert!(snapshot.steam.cef_browser_created);
    assert_eq!(snapshot.threads.live_at_process_exit, 1);
    reset_milestones();
    let snapshot = casa1::steam_milestones::snapshot_milestones();
    assert_eq!(snapshot.graphics.dxgi_presents, 0);
    assert_eq!(snapshot.steam.cef_software_paints, 0);
}
