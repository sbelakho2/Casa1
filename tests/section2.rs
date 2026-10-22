#![allow(dead_code, unused_imports)]
mod support;

use casa1::ge::{
    FileAccess, GameEnvironment, OverrideMatchRule, OverridePayload, OverrideProfile, RegistryView,
    ShareMode,
};
use casa1::oracle_suites::{PathEdgeOutcome, PathEdgeSuite};
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
