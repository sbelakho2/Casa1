mod support;

use casa1::canonical::CanonicalTestOutput;
use casa1::ge::{
    DllOverride, DllOverrideMode, FileAccess, FsEntryKind, FsProfile, GameEnvironment, GfxProfile,
    InputProfile, NetworkPolicy, NetworkProfile, OverrideMatchRule, OverridePayload,
    OverrideProfile, RegistrySetOverride, RegistryView, ReparseKind, ShareMode,
};
use casa1::logging::LogEvent;
use casa1::oracle_suites::{
    CaseCollisionSuite, LockShareSuite, PathEdgeOutcome, PathEdgeSuite, RegistryNotifyOperation,
    RegistryNotifySuite,
};
use casa1::reason::ReasonCode;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn ge_layout_and_drive_mapping_table_match_section2_requirements() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "layout-x86", "x86");
    let mut ge = open_ge(&temp_dir, "layout-x86");

    let required_paths = vec![
        ge.root.join("drive_c/Windows/System32"),
        ge.root.join("drive_c/Windows/SysWOW64"),
        ge.root.join("drive_c/Program Files"),
        ge.root.join("drive_c/Program Files (x86)"),
        ge.root.join("drive_c/users/casa1/AppData/Roaming"),
        ge.root.join("drive_c/users/casa1/AppData/Local"),
        ge.root.join("drive_c/users/casa1/AppData/LocalLow"),
        ge.root.join("registry/HKLM.db"),
        ge.root.join("registry/HKCU.db"),
        ge.root.join("registry/HKCR.db"),
        ge.root.join("cache/dbt"),
        ge.root.join("cache/shader"),
        ge.root.join("cache/pso"),
        ge.root.join("cache/dxgi"),
        ge.root.join("cache/http"),
        ge.root.join("tmp"),
        ge.root.join("logs"),
    ];
    for path in required_paths {
        assert!(path.exists(), "missing GE path {}", path.display());
    }

    let c_drive = ge
        .config
        .drive_mappings
        .iter()
        .find(|mapping| mapping.drive == "C")
        .expect("C drive mapping");
    assert_eq!(c_drive.target, "<GE>/drive_c");
    assert!(!c_drive.read_only);
    assert!(c_drive.enabled);
    assert!(!c_drive.requires_permission);

    let z_drive = ge
        .config
        .drive_mappings
        .iter()
        .find(|mapping| mapping.drive == "Z")
        .expect("Z drive mapping");
    assert_eq!(z_drive.target, "/");
    assert!(z_drive.read_only);
    assert!(!z_drive.enabled);
    assert!(z_drive.requires_permission);

    let granted = temp_dir.path().join("granted-host-drive");
    fs::create_dir_all(&granted).expect("create granted host drive");
    ge.add_drive_mapping("D", &granted, true, true)
        .expect("add explicit drive mapping");
    let ge = open_ge(&temp_dir, "layout-x86");
    let d_drive = ge
        .config
        .drive_mappings
        .iter()
        .find(|mapping| mapping.drive == "D")
        .expect("D drive mapping");
    assert_eq!(d_drive.target, granted.display().to_string());
    assert!(d_drive.read_only);
    assert!(d_drive.enabled);
    assert!(d_drive.requires_permission);
}

// The hand-written path-parsing cases (normalization, verbatim, device
// namespace, reserved names, long paths with/without policy) are pure
// duplicates of the oracle-driven `t2_1_path_edge_suite_matches_independent_oracle`
// below — the oracle encodes the same six expectations, so the hand-written
// copy was deleted to keep a single source of truth.

#[test]
fn t2_1_path_edge_suite_matches_independent_oracle() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "t2-path", "x64");
    let ge = open_ge(&temp_dir, "t2-path");
    let Some(suites) = support::suites_from_reference() else {
        return;
    };
    let Some(suite) = suites.path else {
        eprintln!("skipped: reference results do not cover this category");
        return;
    };
    let suite: PathEdgeSuite = suite;

    for case in suite.cases {
        match case.outcome {
            PathEdgeOutcome::Success {
                normalized_path,
                verbatim,
                device_namespace,
            } => {
                let parsed = ge
                    .parse_windows_path(&case.input, Some(case.long_paths_enabled))
                    .expect("oracle path case should succeed");
                assert_eq!(parsed.normalized_path, normalized_path);
                assert_eq!(parsed.verbatim, verbatim);
                assert_eq!(parsed.device_namespace, device_namespace);
            }
            PathEdgeOutcome::Error { reason_code } => {
                let error = ge
                    .parse_windows_path(&case.input, Some(case.long_paths_enabled))
                    .expect_err("oracle path case should fail");
                assert_eq!(error.code.as_u32(), reason_code);
            }
        }
    }
}

#[test]
fn case_insensitive_creation_opening_enumeration_and_metadata_work() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "casefs", "x64");
    let mut ge = open_ge(&temp_dir, "casefs");

    ge.create_directory("C:\\Case", false)
        .expect("create base directory");
    let collision = ge
        .create_directory("C:\\case", false)
        .expect_err("case-collision create should fail");
    assert_eq!(collision.code, ReasonCode::RcFsAlreadyExists);

    ge.write_file("C:\\Case\\ReadMe.TXT", b"hello", false)
        .expect("write file with preserved case");
    assert_eq!(
        ge.resolve_sandboxed_path("C:\\case\\readme.txt")
            .expect("case-insensitive resolution"),
        "C:\\case\\readme.txt"
    );

    ge.write_file("C:\\Case\\Σ.txt", b"sigma", false)
        .expect("write unicode filename with preserved case");
    assert_eq!(
        ge.resolve_sandboxed_path("C:\\case\\ς.txt")
            .expect("Windows-style sigma/final-sigma casefold resolution"),
        "C:\\case\\σ.txt"
    );
    let unicode_collision = ge
        .write_file("C:\\Case\\ς.txt", b"duplicate", false)
        .expect_err("unicode casefold collision should fail");
    assert_eq!(unicode_collision.code, ReasonCode::RcFsAlreadyExists);

    let entries = ge
        .enumerate_directory("C:\\CASE")
        .expect("enumerate original case");
    assert_eq!(entries, vec!["ReadMe.TXT".to_string(), "Σ.txt".to_string()]);

    ge.set_file_attributes("C:\\case\\readme.txt", &["archive", "hidden"])
        .expect("set custom attributes");
    let metadata = ge
        .get_file_metadata("C:\\Case\\ReadMe.TXT")
        .expect("get metadata");
    assert_eq!(metadata.kind, FsEntryKind::File);
    assert_eq!(metadata.original_case, "ReadMe.TXT");
    assert_eq!(
        metadata.attributes,
        vec!["archive".to_string(), "hidden".to_string()]
    );
    assert!(metadata.creation_time_ticks > 0);
    assert!(metadata.last_access_time_ticks > 0);
    assert!(metadata.last_write_time_ticks > 0);

    let reopened = open_ge(&temp_dir, "casefs");
    let reopened_metadata = reopened
        .get_file_metadata("C:\\case\\readme.txt")
        .expect("reopen metadata");
    assert_eq!(reopened_metadata.original_case, "ReadMe.TXT");
    assert_eq!(
        reopened_metadata.attributes,
        vec!["archive".to_string(), "hidden".to_string()]
    );
    assert_eq!(
        reopened
            .enumerate_directory("C:\\CASE")
            .expect("reopen enumerate original case"),
        vec!["ReadMe.TXT".to_string(), "Σ.txt".to_string()]
    );
}

#[test]
fn t2_2_case_collision_suite_matches_independent_oracle() {
    let Some(suites) = support::suites_from_reference() else {
        return;
    };
    let Some(suite) = suites.case else {
        eprintln!("skipped: reference results do not cover this category");
        return;
    };
    let suite: CaseCollisionSuite = suite;
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "t2-case", "x64");
    let mut ge = open_ge(&temp_dir, "t2-case");

    ge.create_directory(&suite.create_directory, false)
        .expect("create oracle case directory");
    let directory_collision = ge
        .create_directory(&suite.collision_directory, false)
        .expect_err("oracle case collision should fail");
    assert_eq!(
        directory_collision.code.as_u32(),
        suite.directory_collision_code
    );

    ge.write_file(&suite.ascii_file, b"hello", false)
        .expect("write oracle ASCII file");
    ge.write_file(&suite.unicode_file, b"sigma", false)
        .expect("write oracle unicode file");
    assert_eq!(
        ge.resolve_sandboxed_path(&suite.unicode_lookup)
            .expect("oracle unicode lookup should resolve"),
        suite.resolved_unicode_path
    );
    let unicode_collision = ge
        .write_file(&suite.unicode_lookup, b"duplicate", false)
        .expect_err("oracle unicode collision should fail");
    assert_eq!(
        unicode_collision.code.as_u32(),
        suite.unicode_collision_code
    );
    assert_eq!(
        ge.enumerate_directory(&suite.enumeration_path)
            .expect("oracle enumeration should succeed"),
        suite.enumeration
    );
}

#[test]
fn sharing_modes_and_byte_range_locks_reject_conflicts() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "locks", "x64");
    let mut ge = open_ge(&temp_dir, "locks");

    ge.create_directory("C:\\Locks", false)
        .expect("create lock directory");
    ge.write_file("C:\\Locks\\data.bin", b"0123456789", false)
        .expect("write data.bin");

    let exclusive_handle = ge
        .open_file(
            "C:\\Locks\\DATA.BIN",
            FileAccess::read_write(),
            ShareMode::none(),
        )
        .expect("open exclusive handle");
    let sharing_violation = ge
        .open_file(
            "C:\\locks\\data.bin",
            FileAccess::read_only(),
            ShareMode::all(),
        )
        .expect_err("second open should conflict");
    assert_eq!(sharing_violation.code, ReasonCode::RcFsSharingViolation);
    ge.close_file_handle(&exclusive_handle)
        .expect("close exclusive handle");

    let lock_a = ge
        .open_file(
            "C:\\Locks\\data.bin",
            FileAccess::read_write(),
            ShareMode::all(),
        )
        .expect("open lock handle A");
    let lock_b = ge
        .open_file(
            "C:\\LOCKS\\DATA.BIN",
            FileAccess::read_write(),
            ShareMode::all(),
        )
        .expect("open lock handle B");
    ge.lock_file_range(&lock_a, 0, 8, true)
        .expect("lock first range");
    let lock_violation = ge
        .lock_file_range(&lock_b, 4, 4, true)
        .expect_err("overlapping lock should fail");
    assert_eq!(lock_violation.code, ReasonCode::RcFsLockViolation);
    ge.close_file_handle(&lock_a).expect("close handle A");
    ge.close_file_handle(&lock_b).expect("close handle B");
}

#[test]
fn sharing_modes_and_byte_range_locks_reject_conflicts_across_processes() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "locks-xproc", "x64");
    let mut ge = open_ge(&temp_dir, "locks-xproc");

    ge.create_directory("C:\\Locks", false)
        .expect("create lock directory");
    ge.write_file("C:\\Locks\\data.bin", b"0123456789", false)
        .expect("write data.bin");

    let (mut hold_child, mut hold_stdin) = spawn_hold_file(
        &temp_dir,
        "locks-xproc",
        "C:\\Locks\\data.bin",
        "none",
        None,
        None,
        false,
    );
    let sharing_violation = ge
        .open_file(
            "C:\\locks\\data.bin",
            FileAccess::read_only(),
            ShareMode::all(),
        )
        .expect_err("helper-held file should conflict across processes");
    assert_eq!(sharing_violation.code, ReasonCode::RcFsSharingViolation);
    release_hold_file(&mut hold_child, &mut hold_stdin);

    let lock_owner = ge
        .open_file(
            "C:\\Locks\\data.bin",
            FileAccess::read_write(),
            ShareMode::all(),
        )
        .expect("open lock owner after release");
    ge.close_file_handle(&lock_owner)
        .expect("close post-release handle");

    let (mut lock_child, mut lock_stdin) = spawn_hold_file(
        &temp_dir,
        "locks-xproc",
        "C:\\Locks\\data.bin",
        "all",
        Some(0),
        Some(8),
        true,
    );
    let lock_handle = ge
        .open_file(
            "C:\\LOCKS\\DATA.BIN",
            FileAccess::read_write(),
            ShareMode::all(),
        )
        .expect("open competing handle");
    let lock_violation = ge
        .lock_file_range(&lock_handle, 4, 4, true)
        .expect_err("helper-held byte lock should conflict across processes");
    assert_eq!(lock_violation.code, ReasonCode::RcFsLockViolation);
    ge.close_file_handle(&lock_handle)
        .expect("close competing handle");
    release_hold_file(&mut lock_child, &mut lock_stdin);
}

#[test]
fn t2_3_lock_share_suite_matches_independent_oracle() {
    let Some(suites) = support::suites_from_reference() else {
        return;
    };
    let Some(suite) = suites.lock_share else {
        eprintln!("skipped: reference results do not cover this category");
        return;
    };
    let suite: LockShareSuite = suite;
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "t2-lock", "x64");
    let mut ge = open_ge(&temp_dir, "t2-lock");

    ge.create_directory("C:\\Locks", false)
        .expect("create oracle lock directory");
    ge.write_file(&suite.path, b"0123456789", false)
        .expect("write oracle lock file");

    let (mut hold_child, mut hold_stdin) =
        spawn_hold_file(&temp_dir, "t2-lock", &suite.path, "none", None, None, false);
    let share_violation = ge
        .open_file(&suite.path, FileAccess::read_only(), ShareMode::all())
        .expect_err("oracle share conflict should fail");
    assert_eq!(share_violation.code.as_u32(), suite.share_violation_code);
    release_hold_file(&mut hold_child, &mut hold_stdin);

    let (mut lock_child, mut lock_stdin) = spawn_hold_file(
        &temp_dir,
        "t2-lock",
        &suite.path,
        "all",
        Some(suite.first_lock_offset),
        Some(suite.first_lock_length),
        true,
    );
    let handle = ge
        .open_file(&suite.path, FileAccess::read_write(), ShareMode::all())
        .expect("open oracle lock competitor");
    let lock_violation = ge
        .lock_file_range(&handle, suite.overlap_offset, suite.overlap_length, true)
        .expect_err("oracle byte-range conflict should fail");
    assert_eq!(lock_violation.code.as_u32(), suite.lock_violation_code);
    ge.close_file_handle(&handle)
        .expect("close oracle lock competitor");
    release_hold_file(&mut lock_child, &mut lock_stdin);
}

#[test]
fn reparse_points_resolve_inside_sandbox_and_block_escape_targets() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "reparse", "x64");
    let mut ge = open_ge(&temp_dir, "reparse");

    ge.create_directory("C:\\Allowed", false)
        .expect("create allowed directory");
    ge.write_file("C:\\Allowed\\ok.txt", b"ok", false)
        .expect("write ok.txt");
    ge.create_directory("C:\\Sandbox", false)
        .expect("create sandbox directory");

    ge.create_reparse_point(
        "C:\\Sandbox\\Inside",
        "C:\\Allowed",
        ReparseKind::Junction,
        false,
    )
    .expect("create in-sandbox junction");
    let reparse_db_path = ge_root(&temp_dir, "reparse").join("fs/reparse.db.json");
    let ge_json_path = ge_root(&temp_dir, "reparse").join("ge.json");
    let inside_sidecar = fs::read_to_string(&reparse_db_path).expect("read reparse sidecar db");
    let inside_sidecar_json = serde_json::from_str::<serde_json::Value>(&inside_sidecar)
        .expect("parse reparse sidecar db");
    assert!(inside_sidecar_json.get("C:\\sandbox\\inside").is_some());
    let ge_json = fs::read_to_string(&ge_json_path).expect("read ge.json without reparse payload");
    let ge_json_value = serde_json::from_str::<serde_json::Value>(&ge_json).expect("parse ge.json");
    assert!(
        ge_json_value
            .get("fs_state")
            .and_then(|value| value.get("reparse_points"))
            .is_none(),
        "reparse metadata should live in the sidecar DB, not ge.json"
    );
    assert_eq!(
        ge.resolve_sandboxed_path("C:\\Sandbox\\Inside\\ok.txt")
            .expect("follow in-sandbox junction"),
        "C:\\allowed\\ok.txt"
    );

    ge.create_reparse_point(
        "C:\\Sandbox\\Escape",
        "\\\\?\\Z:\\escape",
        ReparseKind::Junction,
        false,
    )
    .expect("create escape junction metadata");
    let escape = ge
        .resolve_sandboxed_path("C:\\Sandbox\\Escape\\evil.txt")
        .expect_err("escape target must be blocked");
    assert_eq!(escape.code, ReasonCode::RcFsSandboxEscape);

    let reopened = open_ge(&temp_dir, "reparse");
    assert_eq!(
        reopened
            .resolve_sandboxed_path("C:\\Sandbox\\Inside\\ok.txt")
            .expect("reopened GE should load reparse sidecar db"),
        "C:\\allowed\\ok.txt"
    );
}

#[test]
fn registry_engine_supports_types_crud_hkcr_merge_and_wow64_views() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "registry-x86", "x86");
    let ge = open_ge(&temp_dir, "registry-x86");

    ge.registry_set_value(
        "HKCU",
        "Software\\Casa1\\Types",
        "Text",
        "REG_SZ",
        json!("hello"),
        RegistryView::Native,
    )
    .expect("set REG_SZ");
    ge.registry_set_value(
        "HKCU",
        "Software\\Casa1\\Types",
        "Expand",
        "REG_EXPAND_SZ",
        json!("%TEMP%\\demo"),
        RegistryView::Native,
    )
    .expect("set REG_EXPAND_SZ");
    ge.registry_set_value(
        "HKCU",
        "Software\\Casa1\\Types",
        "Multi",
        "REG_MULTI_SZ",
        json!(["alpha", "beta"]),
        RegistryView::Native,
    )
    .expect("set REG_MULTI_SZ");
    ge.registry_set_value(
        "HKCU",
        "Software\\Casa1\\Types",
        "Dword",
        "REG_DWORD",
        json!(7),
        RegistryView::Native,
    )
    .expect("set REG_DWORD");
    ge.registry_set_value(
        "HKCU",
        "Software\\Casa1\\Types",
        "Qword",
        "REG_QWORD",
        json!(9),
        RegistryView::Native,
    )
    .expect("set REG_QWORD");
    ge.registry_set_value(
        "HKCU",
        "Software\\Casa1\\Types",
        "Binary",
        "REG_BINARY",
        json!([1, 2, 3, 4]),
        RegistryView::Native,
    )
    .expect("set REG_BINARY");

    let values = ge
        .registry_enum_values("HKCU", "Software\\Casa1\\Types", RegistryView::Native)
        .expect("enumerate values");
    assert_eq!(values.len(), 6);
    assert_eq!(
        ge.registry_get_value(
            "HKCU",
            "Software\\Casa1\\Types",
            "Binary",
            RegistryView::Native
        )
        .expect("get binary")
        .expect("binary exists")
        .value_type,
        "REG_BINARY"
    );

    ge.registry_set_value(
        "HKLM",
        "Software\\Classes\\.txt",
        "ProgId",
        "REG_SZ",
        json!("machine.txt"),
        RegistryView::Native64,
    )
    .expect("set machine HKCR backing value");
    ge.registry_set_value(
        "HKCU",
        "Software\\Classes\\.txt",
        "ProgId",
        "REG_SZ",
        json!("user.txt"),
        RegistryView::Native,
    )
    .expect("set user HKCR backing value");
    let merged = ge
        .registry_get_value("HKCR", ".txt", "ProgId", RegistryView::Native64)
        .expect("query HKCR merged view")
        .expect("HKCR merged value");
    assert_eq!(merged.data, json!("user.txt"));

    ge.registry_set_value(
        "HKLM",
        "Software\\Vendor",
        "Flag",
        "REG_DWORD",
        json!(1),
        RegistryView::Wow6432,
    )
    .expect("set WOW64 redirected value");
    assert!(
        ge.registry_get_value("HKLM", "Software\\Vendor", "Flag", RegistryView::Native64)
            .expect("query native view")
            .is_none()
    );
    assert_eq!(
        ge.registry_get_value("HKLM", "Software\\Vendor", "Flag", RegistryView::Wow6432)
            .expect("query wow64 view")
            .expect("redirected value exists")
            .data,
        json!(1)
    );

    ge.registry_delete_value(
        "HKCU",
        "Software\\Casa1\\Types",
        "Binary",
        RegistryView::Native,
    )
    .expect("delete value");
    let values_after_delete = ge
        .registry_enum_values("HKCU", "Software\\Casa1\\Types", RegistryView::Native)
        .expect("enumerate values after delete");
    assert_eq!(values_after_delete.len(), 5);
}

#[test]
fn registry_watchers_receive_change_notifications() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "notify", "x64");
    let ge = open_ge(&temp_dir, "notify");

    let mut watcher = ge
        .registry_watch("HKCU", "Software\\Casa1Watch", true, RegistryView::Native)
        .expect("create watcher");
    ge.registry_set_value(
        "HKCU",
        "Software\\Casa1Watch",
        "State",
        "REG_SZ",
        json!("alpha"),
        RegistryView::Native,
    )
    .expect("first change");
    // Wait for the notification with a generous deadline instead of a single
    // short timeout: the watcher is driven by a condvar, so a loaded CI
    // machine may deliver the wake long after the change was recorded.
    assert!(
        wait_for_change_with_budget(&mut watcher),
        "first watcher wake"
    );

    ge.registry_set_value(
        "HKCU",
        "Software\\Casa1Watch\\Child",
        "Flag",
        "REG_DWORD",
        json!(2),
        RegistryView::Native,
    )
    .expect("second change");
    assert!(
        wait_for_change_with_budget(&mut watcher),
        "second watcher wake"
    );
    // No further writes happen, so a short negative probe is deterministic.
    assert!(
        !watcher
            .wait_for_change(Duration::from_millis(100))
            .expect("no more changes")
    );
}

/// Poll `wait_for_change` with short timeouts until a change is observed or a
/// 5-second budget is exhausted. Converts timeout-gated flakiness into a
/// bounded deadline wait on the watcher's condvar.
fn wait_for_change_with_budget(watcher: &mut casa1::ge::RegistryWatcher) -> bool {
    let budget = Duration::from_secs(5);
    let poll = Duration::from_millis(25);
    let deadline = std::time::Instant::now() + budget;
    loop {
        if watcher
            .wait_for_change(poll)
            .expect("registry watcher wait")
        {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
    }
}

#[test]
fn t2_4_registry_notify_suite_matches_independent_oracle_counts() {
    let Some(suites) = support::suites_from_reference() else {
        return;
    };
    let Some(suite) = suites.registry_notify else {
        eprintln!("skipped: reference results do not cover this category");
        return;
    };
    let suite: RegistryNotifySuite = suite;
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "t2-registry", "x64");
    let ge = open_ge(&temp_dir, "t2-registry");

    let mut watcher = ge
        .registry_watch(
            &suite.hive,
            &suite.key,
            suite.recursive,
            RegistryView::Native,
        )
        .expect("create oracle registry watcher");
    let mut wake_count = 0_u64;
    for operation in suite.operations {
        match operation {
            RegistryNotifyOperation::Set {
                value,
                value_type,
                data,
            } => ge
                .registry_set_value(
                    &suite.hive,
                    &suite.key,
                    &value,
                    &value_type,
                    data,
                    RegistryView::Native,
                )
                .expect("oracle registry set"),
            RegistryNotifyOperation::Delete { value } => ge
                .registry_delete_value(&suite.hive, &suite.key, &value, RegistryView::Native)
                .expect("oracle registry delete"),
        }
        // Each operation must produce exactly one wake. Wait with a bounded
        // budget rather than a single 50 ms timeout so slow CI scheduling
        // cannot make a correct watcher look broken.
        if wait_for_change_with_budget(&mut watcher) {
            wake_count += 1;
        }
    }

    assert_eq!(wake_count, suite.expected_wake_count);
}

#[test]
fn override_matching_priority_and_application_are_logged_before_guest_execution() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "overrides", "x64");
    let mut ge = open_ge(&temp_dir, "overrides");
    let guest = guest_bin();
    let identity = ge.executable_identity(&guest).expect("guest identity");

    let profiles = vec![
        OverrideProfile {
            id: "default-profile".to_string(),
            match_rule: OverrideMatchRule::DefaultProfile,
            payload: OverridePayload {
                env_add: btreemap(vec![(
                    "CASA1_TEST_OVERRIDE_ENV".to_string(),
                    "default".to_string(),
                )]),
                ..OverridePayload::default()
            },
        },
        OverrideProfile {
            id: "path-profile".to_string(),
            match_rule: OverrideMatchRule::InstallPathWildcard {
                pattern: "Z:\\*casa1-test-guest*".to_string(),
            },
            payload: OverridePayload {
                env_add: btreemap(vec![(
                    "CASA1_TEST_OVERRIDE_ENV".to_string(),
                    "path".to_string(),
                )]),
                ..OverridePayload::default()
            },
        },
        OverrideProfile {
            id: "product-profile".to_string(),
            match_rule: OverrideMatchRule::ProductVersion {
                product_name: "Casa1 Sample".to_string(),
                file_version: "1.0.0".to_string(),
            },
            payload: OverridePayload {
                env_add: btreemap(vec![(
                    "CASA1_TEST_OVERRIDE_ENV".to_string(),
                    "product".to_string(),
                )]),
                ..OverridePayload::default()
            },
        },
        OverrideProfile {
            id: "sha-profile".to_string(),
            match_rule: OverrideMatchRule::ExeSha256 {
                sha256: identity.sha256.clone(),
            },
            payload: OverridePayload {
                env_add: btreemap(vec![(
                    "CASA1_TEST_OVERRIDE_ENV".to_string(),
                    "sha-won".to_string(),
                )]),
                reg_set: vec![RegistrySetOverride {
                    hive: "HKCU".to_string(),
                    key: "Software\\Casa1Overrides".to_string(),
                    value: "Selected".to_string(),
                    value_type: "REG_SZ".to_string(),
                    data: json!("sha-profile"),
                }],
                dll_override: vec![DllOverride {
                    name: "d3d12.dll".to_string(),
                    mode: DllOverrideMode::Builtin,
                }],
                cpu_profile: Some(casa1::ge::CpuProfile {
                    cpuid_mask: "mask-a".to_string(),
                    dbt_flags: vec!["fast-fp".to_string()],
                }),
                gfx_profile: Some(GfxProfile {
                    feature_masks: vec!["mesh-shaders-off".to_string()],
                    shader_flags: vec!["no-fast-math".to_string()],
                }),
                input_profile: Some(InputProfile {
                    layout_id: "us".to_string(),
                    deadzone: 250,
                    mappings: btreemap(vec![("A".to_string(), "Cross".to_string())]),
                }),
                network_profile: Some(NetworkProfile {
                    policy: NetworkPolicy::AllowOnlyWhitelist,
                    whitelist: vec!["cdn.casa1.local".to_string()],
                }),
                fs_profile: Some(FsProfile {
                    case_mode: "windows-fold".to_string(),
                    long_paths_enabled: true,
                }),
                ..OverridePayload::default()
            },
        },
    ];
    ge.set_override_profiles(profiles)
        .expect("save override profiles");

    let direct_match = ge
        .match_override_for_identity(&casa1::ge::ExecutableIdentity {
            sha256: identity.sha256.clone(),
            product_name: Some("Casa1 Sample".to_string()),
            file_version: Some("1.0.0".to_string()),
            normalized_install_path: identity.normalized_install_path.clone(),
        })
        .expect("matched profile");
    assert_eq!(direct_match.id, "sha-profile");

    let output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "overrides",
            "--exe",
            &guest.display().to_string(),
            "--dtm",
        ],
    );
    let canonical: CanonicalTestOutput = parse_stdout_json(&output);
    assert!(canonical.stdout.contains("override=sha-won"));
    assert!(canonical.registry_delta.iter().any(|delta| {
        delta.hive == "HKCU"
            && delta.key_norm == "Software\\Casa1Overrides"
            && delta.value == "Selected"
            && delta.data_norm == "sha-profile"
    }));
    assert!(canonical.registry_delta.iter().any(|delta| {
        delta.hive == "HKCU"
            && delta.key_norm == "Software\\Casa1Test"
            && delta.value == "OverrideEnv"
            && delta.data_norm == "sha-won"
    }));

    let log_files = collect_files(&ge_root(&temp_dir, "overrides").join("logs"), "jsonl");
    assert_eq!(log_files.len(), 1);
    let log_events = fs::read_to_string(&log_files[0])
        .expect("read override log")
        .lines()
        .map(|line| serde_json::from_str::<LogEvent>(line).expect("parse override log"))
        .collect::<Vec<_>>();
    let override_event = log_events
        .iter()
        .find(|event| event.module == "overrides")
        .expect("override log event");
    assert_eq!(
        override_event
            .kv
            .get("profile_id")
            .expect("profile id present"),
        &json!("sha-profile")
    );
    assert_eq!(
        override_event
            .kv
            .get("match_rule")
            .expect("match rule present"),
        &json!("exe_sha256")
    );
}

#[test]
fn override_matching_reads_product_and_file_version_from_pe_version_resources() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "version-match", "x64");
    let mut ge = open_ge(&temp_dir, "version-match");

    let install_dir = ge_root(&temp_dir, "version-match").join("drive_c/Program Files/Demo");
    fs::create_dir_all(&install_dir).expect("create install dir");
    let program = install_dir.join("game.exe");
    fs::write(&program, support::sample_pe_bytes()).expect("write synthetic PE program");
    fs::write(
        install_dir.join("game.exe.casa1-version.json"),
        json!({
            "product_name": "Wrong Product",
            "file_version": "9.9.9.9"
        })
        .to_string(),
    )
    .expect("write mismatched version sidecar");

    ge.config.override_profiles = vec![OverrideProfile {
        id: "version-profile".to_string(),
        match_rule: OverrideMatchRule::ProductVersion {
            product_name: "Casa1 Demo".to_string(),
            file_version: "1.2.3.4".to_string(),
        },
        payload: OverridePayload {
            env_add: btreemap(vec![("CASA1_VERSION_MATCH".to_string(), "hit".to_string())]),
            ..OverridePayload::default()
        },
    }];
    ge.save_config()
        .expect("persist version-match override profile");

    let identity = ge
        .executable_identity(&program)
        .expect("derive executable identity from PE version resources");
    assert_eq!(identity.product_name.as_deref(), Some("Casa1 Demo"));
    assert_eq!(identity.file_version.as_deref(), Some("1.2.3.4"));

    let matched = ge
        .match_override_for_identity(&identity)
        .expect("match override via PE version resources");
    assert_eq!(matched.id, "version-profile");

    let mut env = BTreeMap::new();
    let applied = ge
        .apply_overrides_for_program(&program, &mut env)
        .expect("apply version-resource override")
        .expect("applied override");
    assert_eq!(applied.profile_id, "version-profile");
    assert_eq!(applied.match_rule, "product_version");
    assert_eq!(env.get("CASA1_VERSION_MATCH"), Some(&"hit".to_string()));
}

fn create_ge(temp_dir: &TempDir, name: &str, arch: &str) {
    let output = run_macwin(
        temp_dir,
        &[
            "ge:create",
            "--name",
            name,
            "--arch",
            arch,
            "--winver",
            "win11-23h2",
        ],
    );
    assert!(
        output.status.success(),
        "ge:create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn open_ge(temp_dir: &TempDir, name: &str) -> GameEnvironment {
    GameEnvironment::from_root(ge_root(temp_dir, name)).expect("open GE from temp root")
}

fn run_macwin(temp_dir: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_macwin"))
        .args(args)
        .env("CASA1_GES_ROOT", temp_dir.path().join("ges"))
        .output()
        .expect("run macwin")
}

fn parse_stdout_json<T: DeserializeOwned>(output: &Output) -> T {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse stdout json")
}

fn collect_files(path: &Path, extension: &str) -> Vec<PathBuf> {
    let mut entries = fs::read_dir(path)
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|entry| entry.extension().and_then(|value| value.to_str()) == Some(extension))
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

fn ge_root(temp_dir: &TempDir, name: &str) -> PathBuf {
    temp_dir.path().join("ges").join(name)
}

fn guest_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_casa1-test-guest"))
}

fn spawn_hold_file(
    temp_dir: &TempDir,
    ge_name: &str,
    path: &str,
    share: &str,
    lock_offset: Option<u64>,
    lock_length: Option<u64>,
    exclusive: bool,
) -> (Child, ChildStdin) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_casa1-helper"));
    command
        .arg("hold-file")
        .arg("--ge-root")
        .arg(ge_root(temp_dir, ge_name))
        .arg("--path")
        .arg(path)
        .arg("--share")
        .arg(share)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(offset) = lock_offset {
        command.arg("--lock-offset").arg(offset.to_string());
    }
    if let Some(length) = lock_length {
        command.arg("--lock-length").arg(length.to_string());
    }
    if exclusive {
        command.arg("--exclusive");
    }
    let mut child = command.spawn().expect("spawn helper hold-file");
    wait_for_hold_file_ready(child.stdout.take().expect("helper stdout"));
    let stdin = child.stdin.take().expect("helper stdin");
    (child, stdin)
}

fn wait_for_hold_file_ready(stdout: ChildStdout) {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("read hold-file ready line");
    assert!(
        !line.trim().is_empty(),
        "helper hold-file did not emit a ready line"
    );
}

fn release_hold_file(child: &mut Child, stdin: &mut ChildStdin) {
    stdin.write_all(b"\n").expect("release helper-held file");
    let status = child.wait().expect("wait for helper hold-file");
    assert!(
        status.success(),
        "helper hold-file failed with status {status}"
    );
}

fn btreemap<K, V>(entries: Vec<(K, V)>) -> BTreeMap<K, V>
where
    K: Ord,
{
    entries.into_iter().collect()
}
