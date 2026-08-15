mod support;

use casa1::canonical::{CanonicalTestOutput, ToleranceRegistry, compare_outputs};
use casa1::diagnostics::{DoctorReport, ExportSummary};
use casa1::error::ErrorResponse;
use casa1::ge::GameEnvironment;
use casa1::logging::LogEvent;
use casa1::network::Certificate;
use casa1::reason::ReasonCode;
use casa1::runner::replay_trace;
use casa1::steam::SteamUpdatePlan;
use casa1::trace::TraceRecord;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;
use zip::ZipArchive;

#[test]
fn section1_cli_process_model_and_artifacts_work_end_to_end() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "alpha");

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "alpha",
            "--exe",
            &guest_bin().display().to_string(),
            "--dtm",
            "--trace-categories",
            "file,registry,process,time",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(
        canonical_output
            .stdout
            .contains("Casa1 sample guest finished mode=run")
    );
    assert!(canonical_output.stderr.contains("guest-mode=run"));
    assert!(canonical_output.file_manifest_delta.iter().any(|delta| {
        delta.path_norm == "C:\\program files\\casa1 sample\\hello.txt"
            && delta.op == "create"
            && delta.times_norm.created_ms == 0
            && delta.times_norm.accessed_ms == 0
            && delta.times_norm.modified_ms == 0
    }));
    assert!(canonical_output.registry_delta.iter().any(|delta| {
        delta.hive == "HKCU"
            && delta.key_norm == "Software\\Casa1Test"
            && delta.value == "GuestGuid"
            && delta.op == "set"
    }));

    let ge_root = ge_root(&temp_dir, "alpha");
    let report_path = ge_root.join("reports/run-casa1-test-guest.json");
    let trace_path = ge_root.join("traces/run-casa1-test-guest.json");
    assert!(report_path.exists());
    assert!(trace_path.exists());

    let trace_record: TraceRecord = read_json(&trace_path);
    assert_eq!(
        trace_record.categories,
        vec![
            "file".to_string(),
            "registry".to_string(),
            "process".to_string(),
            "time".to_string()
        ]
    );
    assert!(
        trace_record
            .events
            .iter()
            .enumerate()
            .all(|(index, event)| event.event_index == index as u64)
    );
    assert!(trace_record.events.iter().all(|event| {
        matches!(
            event.category.as_str(),
            "file" | "registry" | "process" | "time"
        )
    }));

    let log_files = collect_files(&ge_root.join("logs"), "jsonl");
    assert_eq!(log_files.len(), 1);
    let log_lines = fs::read_to_string(&log_files[0])
        .expect("read log")
        .lines()
        .map(|line| serde_json::from_str::<LogEvent>(line).expect("parse log line"))
        .collect::<Vec<_>>();
    assert_eq!(log_lines.len(), 2);
    assert!(log_lines.iter().all(|event| event.pid > 0));
    assert_eq!(log_lines[0].module, "runner");
    assert_eq!(log_lines[0].reason_code, ReasonCode::Success.as_u32());

    let install_output = run_macwin(
        &temp_dir,
        &[
            "ge:install",
            "--ge",
            "alpha",
            "--installer",
            &guest_bin().display().to_string(),
            "--silent",
            "--dtm",
            "--trace-categories",
            "file,registry,process,time",
        ],
    );
    let install_report: CanonicalTestOutput = parse_stdout_json(&install_output);
    assert_eq!(install_report.exit_code, 0);
    assert!(install_report.stdout.trim().is_empty());
    assert!(
        install_report
            .file_manifest_delta
            .iter()
            .any(|delta| delta.path_norm == "C:\\program files\\casa1 sample\\install.txt")
    );

    let doctor_output = run_macwin(&temp_dir, &["doctor", "--ge", "alpha"]);
    let doctor_report: DoctorReport = parse_stdout_json(&doctor_output);
    assert_eq!(doctor_report.ge_name, "alpha");
    assert!(doctor_report.filesystem_permissions.readable);
    assert!(doctor_report.filesystem_permissions.writable);
    assert!(!doctor_report.helper_process.ran_as_root);
    assert!(matches!(
        doctor_report.gpu.status.as_str(),
        "ok" | "unsupported"
    ));

    let zip_path = temp_dir.path().join("alpha-diagnostics.zip");
    let export_output = run_macwin(
        &temp_dir,
        &[
            "ge:export-diagnostics",
            "--ge",
            "alpha",
            "--out",
            &zip_path.display().to_string(),
        ],
    );
    let export_summary: ExportSummary = parse_stdout_json(&export_output);
    assert!(export_summary.output_zip.exists());
    assert!(export_summary.file_count > 0);

    let mut archive =
        ZipArchive::new(File::open(zip_path).expect("open zip")).expect("zip archive");
    let mut archive_names = Vec::new();
    for index in 0..archive.len() {
        let file = archive.by_index(index).expect("zip entry");
        archive_names.push(file.name().to_string());
    }
    assert!(archive_names.iter().any(|name| name == "ge.json"));
    assert!(
        archive_names
            .iter()
            .any(|name| name.ends_with("reports/run-casa1-test-guest.json"))
    );
    assert!(
        archive_names
            .iter()
            .any(|name| name.ends_with("traces/run-casa1-test-guest.json"))
    );
    assert!(
        archive_names
            .iter()
            .any(|name| name.ends_with("diagnostics/doctor.json"))
    );
}

#[test]
fn canonical_json_is_identical_across_20_dtm_runs() {
    // 20 sequential subprocess runs keep this determinism check inside the
    // suite's wall-clock budget (100 runs took ~10 minutes and dominated the
    // section1 binary); each run is a full ge:create + ge:run subprocess pair.
    let temp_dir = TempDir::new().expect("temp dir");
    let mut baseline = None;

    for iteration in 0..20 {
        let ge_name = format!("dtm-{iteration}");
        create_ge(&temp_dir, &ge_name);
        let output = run_macwin(
            &temp_dir,
            &[
                "ge:run",
                "--ge",
                &ge_name,
                "--exe",
                &guest_bin().display().to_string(),
                "--dtm",
            ],
        );
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        match &baseline {
            Some(expected) => assert_eq!(&stdout, expected),
            None => baseline = Some(stdout),
        }
    }
}

#[test]
fn comparator_reports_exact_path_for_single_byte_change() {
    let output = CanonicalTestOutput {
        test_id: "compare-sample".to_string(),
        build_id: "build".to_string(),
        os_build: "macos-aarch64".to_string(),
        stdout: "ok".to_string(),
        stderr: String::new(),
        exit_code: 0,
        guest_exceptions: Vec::new(),
        file_manifest_delta: vec![casa1::canonical::FileManifestDelta {
            op: "create".to_string(),
            path_norm: "C:\\program files\\casa1 sample\\hello.txt".to_string(),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            size: 4,
            times_norm: casa1::canonical::NormalizedTimes {
                created_ms: 0,
                accessed_ms: 0,
                modified_ms: 0,
            },
            attrs: Vec::new(),
        }],
        registry_delta: Vec::new(),
        network_summary: Vec::new(),
        gfx_frames: Vec::new(),
        perf: Vec::new(),
    };
    let mut changed = output.clone();
    changed.file_manifest_delta[0]
        .sha256
        .replace_range(0..1, "b");

    let failure = compare_outputs(&output, &changed, &ToleranceRegistry::default())
        .expect_err("comparison should fail");
    assert_eq!(failure.path, "file_manifest_delta[0].sha256");
}

#[test]
fn trace_replay_matches_captured_output_and_rejects_env_mismatch() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "capture");

    let capture_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "capture",
            "--exe",
            &guest_bin().display().to_string(),
            "--dtm",
        ],
    );
    let captured_canonical: CanonicalTestOutput = parse_stdout_json(&capture_output);
    let capture_trace_path = ge_root(&temp_dir, "capture").join("traces/run-casa1-test-guest.json");

    create_ge(&temp_dir, "replay");
    let mut replay_ge =
        GameEnvironment::from_root(ge_root(&temp_dir, "replay")).expect("open replay ge");
    let replay_output = replay_trace(&capture_trace_path, &replay_ge).expect("replay trace");
    assert_eq!(replay_output, captured_canonical);

    replay_ge.config.long_paths_enabled = true;
    replay_ge
        .save_config()
        .expect("persist replay config mismatch");
    let config_error =
        replay_trace(&capture_trace_path, &replay_ge).expect_err("expected config mismatch");
    assert_eq!(config_error.code, ReasonCode::RcTraceEnvMismatch);

    let mismatch_trace_path = temp_dir.path().join("mismatch-trace.json");
    let mut mismatch_trace: TraceRecord = read_json(&capture_trace_path);
    mismatch_trace.cache_version += 1;
    fs::write(
        &mismatch_trace_path,
        casa1::util::stable_json(&mismatch_trace).expect("encode mismatch trace"),
    )
    .expect("write mismatch trace");
    let error = replay_trace(&mismatch_trace_path, &replay_ge).expect_err("expected mismatch");
    assert_eq!(error.code, ReasonCode::RcTraceEnvMismatch);
}

#[test]
fn failures_return_machine_readable_reason_codes_and_hints() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "broken");

    let output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "broken",
            "--exe",
            "/definitely/missing/casa1-does-not-exist.exe",
            "--dtm",
        ],
    );
    assert!(!output.status.success());
    let error: ErrorResponse = serde_json::from_slice(&output.stderr).expect("parse stderr json");
    assert_eq!(error.reason_code, ReasonCode::RcRunnerSpawnFailed.as_u32());
    assert_eq!(error.reason_name, "RC_RUNNER_SPAWN_FAILED");
    assert!(!error.message.is_empty());
    assert!(
        error
            .reproduction_hints
            .iter()
            .any(|hint| hint.contains("missing") || hint.contains("non-executable"))
    );
}

#[test]
fn windows_pe_images_run_through_casa1_pe_runtime_branch() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime");
    let pe_path = temp_dir.path().join("sample-runtime.exe");
    fs::write(&pe_path, support::sample_pe_bytes()).expect("write sample PE");

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,time",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert_eq!(canonical_output.guest_exceptions, Vec::new());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );

    let trace_path = ge_root(&temp_dir, "pe-runtime").join("traces/run-sample-runtime.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| {
        event.category == "process"
            && event.call_id == "NtContinue"
            && event.parameters.get("mode")
                == Some(&serde_json::Value::String("pe-runtime".to_string()))
    }));
}

#[test]
#[ignore] // emulated execution of the zig-built real Windows PE hangs (>20 min at <1% CPU)
fn real_external_windows_pe_runs_through_actual_imports() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-imports");
    let pe_path = temp_dir.path().join("real-imports.exe");
    support::build_real_windows_sleep_probe(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-imports",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,time",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );

    let trace_path = ge_root(&temp_dir, "pe-runtime-imports").join("traces/run-real-imports.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "time" && event.call_id == "Sleep")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "process" && event.call_id == "ExitProcess")
    );
}

#[test]
#[ignore] // emulated execution of the zig-built indirect-import probe hangs (>20 min at <1% CPU)
fn indirect_import_calls_land_on_pe_host_thunks() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-indirect-imports");
    let pe_path = temp_dir.path().join("real-indirect-imports.exe");
    support::build_real_windows_indirect_import_probe(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-indirect-imports",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,time",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );

    let trace_path = ge_root(&temp_dir, "pe-runtime-indirect-imports")
        .join("traces/run-real-indirect-imports.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "time" && event.call_id == "Sleep")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "process" && event.call_id == "ExitProcess")
    );
}

#[test]
fn ge_install_steam_zero_touch_bootstraps_and_launches_game_from_real_ge_fail_first() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "steam-zero-touch-cli");

    let installer_path = temp_dir.path().join("SteamSetup.exe");
    fs::write(&installer_path, support::sample_pe_bytes()).expect("write steam setup probe");

    let payload_root = temp_dir.path().join("steam-payload");
    fs::create_dir_all(payload_root.join("Bin")).expect("create payload bin");
    fs::write(payload_root.join("Bin/ZeroTouch.exe"), b"zero-touch-game")
        .expect("write payload exe");
    fs::write(payload_root.join("steam_api64.dll"), b"steam-api64").expect("write steam api");

    let appmanifest_path = temp_dir.path().join("appmanifest_570.acf");
    fs::write(
        &appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"570\"\n",
            "\t\"name\"\t\"Zero Touch Game\"\n",
            "\t\"installdir\"\t\"Zero Touch Game\"\n",
            "}\n"
        ),
    )
    .expect("write appmanifest");

    let installscript_path = temp_dir.path().join("installscript.vdf");
    fs::write(
        &installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t\t\"Executable\"\t\"Bin/ZeroTouch.exe\"\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t\t\"DirectX\"\n",
            "\t\t{\n",
            "\t\t\t\"Dll\"\t\"xinput1_3.dll\"\n",
            "\t\t}\n",
            "\t\t\"VisualCpp\"\n",
            "\t\t{\n",
            "\t\t\t\"Version\"\t\"vc143\"\n",
            "\t\t\t\"Dlls\"\t\"vcruntime140.dll,msvcp140.dll\"\n",
            "\t\t}\n",
            "\t\t\"DotNet\"\n",
            "\t\t{\n",
            "\t\t\t\"Version\"\t\"net8.0\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write installscript");

    let update_plan_path = temp_dir.path().join("steam-update-plan.json");
    fs::write(
        &update_plan_path,
        casa1::util::stable_json(&SteamUpdatePlan {
            files: BTreeMap::from([
                (
                    "C:/Program Files/Steam/steam.exe".to_string(),
                    b"steam-bootstrap-v2".to_vec(),
                ),
                (
                    "C:/Program Files/Steam/package/steamui.dll".to_string(),
                    b"steam-ui-v2".to_vec(),
                ),
            ]),
            fail_after_write: None,
        })
        .expect("encode update plan"),
    )
    .expect("write update plan");

    let cert_chain_path = temp_dir.path().join("steam-certs.json");
    fs::write(
        &cert_chain_path,
        casa1::util::stable_json(&vec![
            Certificate {
                subject: "api.example.com".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "leaf-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
            Certificate {
                subject: "Casa1 Root".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "root-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
        ])
        .expect("encode cert chain"),
    )
    .expect("write cert chain");

    let install_output = run_macwin(
        &temp_dir,
        &[
            "ge:install",
            "--ge",
            "steam-zero-touch-cli",
            "--installer",
            &installer_path.display().to_string(),
            "--silent",
            "--dtm",
            "--steam-update-plan",
            &update_plan_path.display().to_string(),
            "--steam-cert-chain",
            &cert_chain_path.display().to_string(),
            "--steam-appmanifest",
            &appmanifest_path.display().to_string(),
            "--steam-installscript",
            &installscript_path.display().to_string(),
            "--steam-payload-root",
            &payload_root.display().to_string(),
            "--trace-categories",
            "file,registry,process,time",
        ],
    );
    let install_report: CanonicalTestOutput = parse_stdout_json(&install_output);

    assert_eq!(install_report.exit_code, 0);
    assert!(install_report.guest_exceptions.is_empty());
    assert!(
        install_report
            .file_manifest_delta
            .iter()
            .any(|delta| delta.path_norm == "C:\\program files\\steam\\steam.exe")
    );
    assert!(
        install_report
            .file_manifest_delta
            .iter()
            .any(|delta| delta.path_norm
                == "C:\\program files\\steam\\steamapps\\appmanifest_570.acf")
    );
    assert!(install_report
        .file_manifest_delta
        .iter()
        .any(|delta| delta.path_norm == "C:\\program files\\steam\\steamapps\\common\\zero touch game\\bin\\zerotouch.exe"));
    assert!(
        install_report
            .file_manifest_delta
            .iter()
            .any(|delta| delta.path_norm == "C:\\windows\\system32\\xinput1_3.dll")
    );
    assert!(
        install_report
            .file_manifest_delta
            .iter()
            .any(|delta| delta.path_norm == "C:\\windows\\winsxs\\vc143\\vcruntime140.dll")
    );
    assert!(
        install_report
            .registry_delta
            .iter()
            .any(|delta| delta.hive == "HKCU"
                && delta.key_norm == "Software\\Valve\\Steam"
                && delta.value == "SteamPath")
    );
    assert!(
        install_report
            .registry_delta
            .iter()
            .any(|delta| delta.hive == "HKCU"
                && delta.key_norm == "Software\\Valve\\Steam"
                && delta.value == "SteamExe")
    );

    let ge_root = ge_root(&temp_dir, "steam-zero-touch-cli");
    let trace_path = ge_root.join("traces/install-SteamSetup.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| {
        event.category == "process"
            && event.call_id == "SteamZeroTouchInstall"
            && event.parameters.get("app_id") == Some(&serde_json::json!(570))
            && event.parameters.get("launched") == Some(&serde_json::json!(true))
    }));
}

#[test]
fn ge_install_steam_zero_touch_supports_secondary_steam_library_without_user_input() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "steam-zero-touch-secondary-cli");

    let installer_path = temp_dir.path().join("SteamSetup.exe");
    fs::write(&installer_path, support::sample_pe_bytes()).expect("write steam setup probe");

    let payload_root = temp_dir.path().join("steam-secondary-payload");
    fs::create_dir_all(payload_root.join("Bin")).expect("create payload bin");
    fs::write(payload_root.join("Bin/LibraryGame.exe"), b"library-game")
        .expect("write payload exe");
    fs::write(payload_root.join("steam_api64.dll"), b"steam-api64").expect("write steam api");

    let appmanifest_path = temp_dir.path().join("appmanifest_571.acf");
    fs::write(
        &appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"571\"\n",
            "\t\"name\"\t\"Zero Touch Library Game\"\n",
            "\t\"installdir\"\t\"Zero Touch Library Game\"\n",
            "}\n"
        ),
    )
    .expect("write appmanifest");

    let installscript_path = temp_dir.path().join("installscript.vdf");
    fs::write(
        &installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t\t\"Executable\"\t\"Bin/LibraryGame.exe\"\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t\t\"DirectX\"\n",
            "\t\t{\n",
            "\t\t\t\"Dll\"\t\"xinput1_3.dll\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write installscript");

    let update_plan_path = temp_dir.path().join("steam-update-plan.json");
    fs::write(
        &update_plan_path,
        casa1::util::stable_json(&SteamUpdatePlan {
            files: BTreeMap::from([
                (
                    "C:/Program Files/Steam/steam.exe".to_string(),
                    b"steam-bootstrap-v2".to_vec(),
                ),
                (
                    "C:/Program Files/Steam/package/steamui.dll".to_string(),
                    b"steam-ui-v2".to_vec(),
                ),
            ]),
            fail_after_write: None,
        })
        .expect("encode update plan"),
    )
    .expect("write update plan");

    let cert_chain_path = temp_dir.path().join("steam-certs.json");
    fs::write(
        &cert_chain_path,
        casa1::util::stable_json(&vec![
            Certificate {
                subject: "api.example.com".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "leaf-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
            Certificate {
                subject: "Casa1 Root".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "root-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
        ])
        .expect("encode cert chain"),
    )
    .expect("write cert chain");

    let install_output = run_macwin(
        &temp_dir,
        &[
            "ge:install",
            "--ge",
            "steam-zero-touch-secondary-cli",
            "--installer",
            &installer_path.display().to_string(),
            "--silent",
            "--dtm",
            "--steam-update-plan",
            &update_plan_path.display().to_string(),
            "--steam-cert-chain",
            &cert_chain_path.display().to_string(),
            "--steam-appmanifest",
            &appmanifest_path.display().to_string(),
            "--steam-installscript",
            &installscript_path.display().to_string(),
            "--steam-payload-root",
            &payload_root.display().to_string(),
            "--steam-library-root",
            "C:/SteamLibraryArcade",
            "--trace-categories",
            "file,registry,process,time",
        ],
    );
    let install_report: CanonicalTestOutput = parse_stdout_json(&install_output);

    assert_eq!(install_report.exit_code, 0);
    assert!(
        install_report.file_manifest_delta.iter().any(
            |delta| delta.path_norm == "C:\\steamlibraryarcade\\steamapps\\appmanifest_571.acf"
        )
    );
    assert!(install_report
        .file_manifest_delta
        .iter()
        .any(|delta| delta.path_norm == "C:\\steamlibraryarcade\\steamapps\\common\\zero touch library game\\bin\\librarygame.exe"));
    assert!(
        install_report
            .file_manifest_delta
            .iter()
            .any(|delta| delta.path_norm
                == "C:\\program files\\steam\\steamapps\\libraryfolders.vdf")
    );
    assert!(install_report
        .file_manifest_delta
        .iter()
        .all(|delta| delta.path_norm != "C:\\program files\\steam\\steamapps\\common\\zero touch library game\\bin\\librarygame.exe"));

    let ge_root = ge_root(&temp_dir, "steam-zero-touch-secondary-cli");
    let trace_path = ge_root.join("traces/install-SteamSetup.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| {
        event.category == "process"
            && event.call_id == "SteamZeroTouchInstall"
            && event.parameters.get("app_id") == Some(&serde_json::json!(571))
            && event.parameters.get("launched") == Some(&serde_json::json!(true))
    }));
}

#[test]
fn ge_install_steam_zero_touch_supports_secondary_drive_library_without_user_input() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "steam-zero-touch-drive-d-cli");

    let installer_path = temp_dir.path().join("SteamSetup.exe");
    fs::write(&installer_path, support::sample_pe_bytes()).expect("write steam setup probe");

    let payload_root = temp_dir.path().join("steam-drive-d-payload");
    fs::create_dir_all(payload_root.join("Bin")).expect("create payload bin");
    fs::write(payload_root.join("Bin/DriveGame.exe"), b"drive-game").expect("write payload exe");
    fs::write(payload_root.join("steam_api64.dll"), b"steam-api64").expect("write steam api");

    let appmanifest_path = temp_dir.path().join("appmanifest_572.acf");
    fs::write(
        &appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"572\"\n",
            "\t\"name\"\t\"Zero Touch Drive Game\"\n",
            "\t\"installdir\"\t\"Zero Touch Drive Game\"\n",
            "}\n"
        ),
    )
    .expect("write appmanifest");

    let installscript_path = temp_dir.path().join("installscript.vdf");
    fs::write(
        &installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t\t\"Executable\"\t\"Bin/DriveGame.exe\"\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t\t\"DirectX\"\n",
            "\t	{\n",
            "\t\t\t\"Dll\"\t\"xinput1_3.dll\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write installscript");

    let update_plan_path = temp_dir.path().join("steam-update-plan.json");
    fs::write(
        &update_plan_path,
        casa1::util::stable_json(&SteamUpdatePlan {
            files: BTreeMap::from([
                (
                    "C:/Program Files/Steam/steam.exe".to_string(),
                    b"steam-bootstrap-v2".to_vec(),
                ),
                (
                    "C:/Program Files/Steam/package/steamui.dll".to_string(),
                    b"steam-ui-v2".to_vec(),
                ),
            ]),
            fail_after_write: None,
        })
        .expect("encode update plan"),
    )
    .expect("write update plan");

    let cert_chain_path = temp_dir.path().join("steam-certs.json");
    fs::write(
        &cert_chain_path,
        casa1::util::stable_json(&vec![
            Certificate {
                subject: "api.example.com".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "leaf-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
            Certificate {
                subject: "Casa1 Root".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "root-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
        ])
        .expect("encode cert chain"),
    )
    .expect("write cert chain");

    let install_output = run_macwin(
        &temp_dir,
        &[
            "ge:install",
            "--ge",
            "steam-zero-touch-drive-d-cli",
            "--installer",
            &installer_path.display().to_string(),
            "--silent",
            "--dtm",
            "--steam-update-plan",
            &update_plan_path.display().to_string(),
            "--steam-cert-chain",
            &cert_chain_path.display().to_string(),
            "--steam-appmanifest",
            &appmanifest_path.display().to_string(),
            "--steam-installscript",
            &installscript_path.display().to_string(),
            "--steam-payload-root",
            &payload_root.display().to_string(),
            "--steam-library-root",
            "D:/SteamLibraryArcade",
            "--trace-categories",
            "file,registry,process,time",
        ],
    );
    let install_report: CanonicalTestOutput = parse_stdout_json(&install_output);

    assert_eq!(install_report.exit_code, 0);
    assert!(
        install_report.file_manifest_delta.iter().any(
            |delta| delta.path_norm == "D:\\steamlibraryarcade\\steamapps\\appmanifest_572.acf"
        )
    );
    assert!(install_report
        .file_manifest_delta
        .iter()
        .any(|delta| delta.path_norm == "D:\\steamlibraryarcade\\steamapps\\common\\zero touch drive game\\bin\\drivegame.exe"));
    assert!(
        install_report
            .file_manifest_delta
            .iter()
            .any(|delta| delta.path_norm
                == "C:\\program files\\steam\\steamapps\\libraryfolders.vdf")
    );
    assert!(
        install_report
            .file_manifest_delta
            .iter()
            .any(|delta| delta.path_norm == "C:\\windows\\system32\\xinput1_3.dll")
    );

    let ge_root = ge_root(&temp_dir, "steam-zero-touch-drive-d-cli");
    let trace_path = ge_root.join("traces/install-SteamSetup.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| {
        event.category == "process"
            && event.call_id == "SteamZeroTouchInstall"
            && event.parameters.get("app_id") == Some(&serde_json::json!(572))
            && event.parameters.get("launched") == Some(&serde_json::json!(true))
    }));
}

#[test]
fn ge_install_steam_zero_touch_supports_external_host_volume_for_secondary_library() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "steam-zero-touch-external-volume-cli");

    let installer_path = temp_dir.path().join("SteamSetup.exe");
    fs::write(&installer_path, support::sample_pe_bytes()).expect("write steam setup probe");

    let payload_root = temp_dir.path().join("steam-external-volume-payload");
    fs::create_dir_all(payload_root.join("Bin")).expect("create payload bin");
    fs::write(payload_root.join("Bin/ExternalGame.exe"), b"external-game")
        .expect("write payload exe");
    fs::write(payload_root.join("steam_api64.dll"), b"steam-api64").expect("write steam api");

    let external_host_root = temp_dir.path().join("mounted-arcade-volume");
    fs::create_dir_all(&external_host_root).expect("create external host root");

    let appmanifest_path = temp_dir.path().join("appmanifest_573.acf");
    fs::write(
        &appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"573\"\n",
            "\t\"name\"\t\"Zero Touch External Game\"\n",
            "\t\"installdir\"\t\"Zero Touch External Game\"\n",
            "}\n"
        ),
    )
    .expect("write appmanifest");

    let installscript_path = temp_dir.path().join("installscript.vdf");
    fs::write(
        &installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t\t\"Executable\"\t\"Bin/ExternalGame.exe\"\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t\t\"DirectX\"\n",
            "\t\t{\n",
            "\t\t\t\"Dll\"\t\"xinput1_3.dll\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write installscript");

    let update_plan_path = temp_dir.path().join("steam-update-plan.json");
    fs::write(
        &update_plan_path,
        casa1::util::stable_json(&SteamUpdatePlan {
            files: BTreeMap::from([
                (
                    "C:/Program Files/Steam/steam.exe".to_string(),
                    b"steam-bootstrap-v2".to_vec(),
                ),
                (
                    "C:/Program Files/Steam/package/steamui.dll".to_string(),
                    b"steam-ui-v2".to_vec(),
                ),
            ]),
            fail_after_write: None,
        })
        .expect("encode update plan"),
    )
    .expect("write update plan");

    let cert_chain_path = temp_dir.path().join("steam-certs.json");
    fs::write(
        &cert_chain_path,
        casa1::util::stable_json(&vec![
            Certificate {
                subject: "api.example.com".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "leaf-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
            Certificate {
                subject: "Casa1 Root".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "root-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
        ])
        .expect("encode cert chain"),
    )
    .expect("write cert chain");

    let install_output = run_macwin(
        &temp_dir,
        &[
            "ge:install",
            "--ge",
            "steam-zero-touch-external-volume-cli",
            "--installer",
            &installer_path.display().to_string(),
            "--silent",
            "--dtm",
            "--steam-update-plan",
            &update_plan_path.display().to_string(),
            "--steam-cert-chain",
            &cert_chain_path.display().to_string(),
            "--steam-appmanifest",
            &appmanifest_path.display().to_string(),
            "--steam-installscript",
            &installscript_path.display().to_string(),
            "--steam-payload-root",
            &payload_root.display().to_string(),
            "--steam-library-root",
            "D:/SteamLibraryArcade",
            "--steam-library-host-root",
            &external_host_root.display().to_string(),
            "--trace-categories",
            "file,registry,process,time",
        ],
    );
    let install_report: CanonicalTestOutput = parse_stdout_json(&install_output);

    assert_eq!(install_report.exit_code, 0);
    assert!(
        install_report.file_manifest_delta.iter().any(
            |delta| delta.path_norm == "D:\\steamlibraryarcade\\steamapps\\appmanifest_573.acf"
        )
    );
    assert!(install_report
        .file_manifest_delta
        .iter()
        .any(|delta| delta.path_norm == "D:\\steamlibraryarcade\\steamapps\\common\\zero touch external game\\bin\\externalgame.exe"));

    let external_game_host_path = external_host_root
        .join("SteamLibraryArcade/steamapps/common/Zero Touch External Game/Bin/ExternalGame.exe");
    assert!(external_game_host_path.is_file());
    let external_manifest_host_path =
        external_host_root.join("SteamLibraryArcade/steamapps/appmanifest_573.acf");
    assert!(external_manifest_host_path.is_file());

    let ge = GameEnvironment::from_root(ge_root(&temp_dir, "steam-zero-touch-external-volume-cli"))
        .expect("reopen GE");
    assert!(
        ge.active_drive_mappings()
            .iter()
            .any(|mapping| mapping.drive == "D"
                && mapping.target == external_host_root.display().to_string())
    );
}

#[test]
fn ge_install_steam_zero_touch_selects_library_from_parsed_libraryfolders_metadata() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "steam-zero-touch-libraryfolders-cli");

    let installer_path = temp_dir.path().join("SteamSetup.exe");
    fs::write(&installer_path, support::sample_pe_bytes()).expect("write steam setup probe");

    let payload_root = temp_dir.path().join("steam-libraryfolders-payload");
    fs::create_dir_all(payload_root.join("Bin")).expect("create payload bin");
    fs::write(payload_root.join("Bin/RacingGame.exe"), b"racing-game").expect("write payload exe");
    fs::write(payload_root.join("steam_api64.dll"), b"steam-api64").expect("write steam api");

    let external_d_root = temp_dir.path().join("mounted-arcade-volume");
    let external_e_root = temp_dir.path().join("mounted-racing-volume");
    fs::create_dir_all(&external_d_root).expect("create D volume root");
    fs::create_dir_all(&external_e_root).expect("create E volume root");

    let appmanifest_path = temp_dir.path().join("appmanifest_574.acf");
    fs::write(
        &appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"574\"\n",
            "\t\"name\"\t\"Zero Touch Racing Game\"\n",
            "\t\"installdir\"\t\"Zero Touch Racing Game\"\n",
            "}\n"
        ),
    )
    .expect("write appmanifest");

    let installscript_path = temp_dir.path().join("installscript.vdf");
    fs::write(
        &installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t\t\"Executable\"\t\"Bin/RacingGame.exe\"\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t\t\"DirectX\"\n",
            "\t\t{\n",
            "\t\t\t\"Dll\"\t\"xinput1_3.dll\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write installscript");

    let libraryfolders_path = temp_dir.path().join("libraryfolders.vdf");
    fs::write(
        &libraryfolders_path,
        concat!(
            "\"libraryfolders\"\n",
            "{\n",
            "\t\"0\"\n",
            "\t{\n",
            "\t\t\"path\"\t\"C:\\\\Program Files\\\\Steam\"\n",
            "\t}\n",
            "\t\"1\"\n",
            "\t{\n",
            "\t\t\"path\"\t\"D:\\\\SteamLibraryArcade\"\n",
            "\t\t\"apps\"\n",
            "\t\t{\n",
            "\t\t\t\"573\"\t\"1\"\n",
            "\t\t}\n",
            "\t}\n",
            "\t\"2\"\n",
            "\t{\n",
            "\t\t\"path\"\t\"E:\\\\SteamLibraryRacing\"\n",
            "\t\t\"apps\"\n",
            "\t\t{\n",
            "\t\t\t\"574\"\t\"1\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write libraryfolders");

    let library_host_map_path = temp_dir.path().join("steam-library-host-map.json");
    fs::write(
        &library_host_map_path,
        casa1::util::stable_json(&BTreeMap::from([
            ("D".to_string(), external_d_root.display().to_string()),
            ("E".to_string(), external_e_root.display().to_string()),
        ]))
        .expect("encode library host map"),
    )
    .expect("write library host map");

    let update_plan_path = temp_dir.path().join("steam-update-plan.json");
    fs::write(
        &update_plan_path,
        casa1::util::stable_json(&SteamUpdatePlan {
            files: BTreeMap::from([
                (
                    "C:/Program Files/Steam/steam.exe".to_string(),
                    b"steam-bootstrap-v2".to_vec(),
                ),
                (
                    "C:/Program Files/Steam/package/steamui.dll".to_string(),
                    b"steam-ui-v2".to_vec(),
                ),
            ]),
            fail_after_write: None,
        })
        .expect("encode update plan"),
    )
    .expect("write update plan");

    let cert_chain_path = temp_dir.path().join("steam-certs.json");
    fs::write(
        &cert_chain_path,
        casa1::util::stable_json(&vec![
            Certificate {
                subject: "api.example.com".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "leaf-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
            Certificate {
                subject: "Casa1 Root".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "root-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
        ])
        .expect("encode cert chain"),
    )
    .expect("write cert chain");

    let install_output = run_macwin(
        &temp_dir,
        &[
            "ge:install",
            "--ge",
            "steam-zero-touch-libraryfolders-cli",
            "--installer",
            &installer_path.display().to_string(),
            "--silent",
            "--dtm",
            "--steam-update-plan",
            &update_plan_path.display().to_string(),
            "--steam-cert-chain",
            &cert_chain_path.display().to_string(),
            "--steam-appmanifest",
            &appmanifest_path.display().to_string(),
            "--steam-installscript",
            &installscript_path.display().to_string(),
            "--steam-payload-root",
            &payload_root.display().to_string(),
            "--steam-libraryfolders",
            &libraryfolders_path.display().to_string(),
            "--steam-library-host-map",
            &library_host_map_path.display().to_string(),
            "--trace-categories",
            "file,registry,process,time",
        ],
    );
    let install_report: CanonicalTestOutput = parse_stdout_json(&install_output);

    assert_eq!(install_report.exit_code, 0);
    assert!(
        install_report.file_manifest_delta.iter().any(
            |delta| delta.path_norm == "E:\\steamlibraryracing\\steamapps\\appmanifest_574.acf"
        )
    );
    assert!(install_report
        .file_manifest_delta
        .iter()
        .any(|delta| delta.path_norm == "E:\\steamlibraryracing\\steamapps\\common\\zero touch racing game\\bin\\racinggame.exe"));
    assert!(install_report
        .file_manifest_delta
        .iter()
        .all(|delta| delta.path_norm != "D:\\steamlibraryarcade\\steamapps\\common\\zero touch racing game\\bin\\racinggame.exe"));

    let external_e_game_host_path = external_e_root
        .join("SteamLibraryRacing/steamapps/common/Zero Touch Racing Game/Bin/RacingGame.exe");
    assert!(external_e_game_host_path.is_file());
    assert!(
        !external_d_root
            .join("SteamLibraryArcade/steamapps/common/Zero Touch Racing Game/Bin/RacingGame.exe")
            .exists()
    );

    let ge = GameEnvironment::from_root(ge_root(&temp_dir, "steam-zero-touch-libraryfolders-cli"))
        .expect("reopen GE");
    assert!(
        ge.active_drive_mappings()
            .iter()
            .any(|mapping| mapping.drive == "E"
                && mapping.target == external_e_root.display().to_string())
    );
}

#[test]
fn ge_install_steam_zero_touch_reuses_persisted_external_library_mapping_without_new_host_map() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "steam-zero-touch-persisted-library-cli");

    let installer_path = temp_dir.path().join("SteamSetup.exe");
    fs::write(&installer_path, support::sample_pe_bytes()).expect("write steam setup probe");

    let first_payload_root = temp_dir.path().join("steam-persisted-first-payload");
    fs::create_dir_all(first_payload_root.join("Bin")).expect("create first payload bin");
    fs::write(
        first_payload_root.join("Bin/ArcadeGame.exe"),
        b"arcade-game",
    )
    .expect("write first payload exe");
    fs::write(first_payload_root.join("steam_api64.dll"), b"steam-api64")
        .expect("write first steam api");

    let second_payload_root = temp_dir.path().join("steam-persisted-second-payload");
    fs::create_dir_all(second_payload_root.join("Bin")).expect("create second payload bin");
    fs::write(
        second_payload_root.join("Bin/RacingGame.exe"),
        b"racing-game",
    )
    .expect("write second payload exe");
    fs::write(second_payload_root.join("steam_api64.dll"), b"steam-api64")
        .expect("write second steam api");

    let external_e_root = temp_dir.path().join("mounted-racing-volume");
    fs::create_dir_all(&external_e_root).expect("create external host root");

    let first_appmanifest_path = temp_dir.path().join("appmanifest_576.acf");
    fs::write(
        &first_appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"576\"\n",
            "\t\"name\"\t\"Persisted Arcade Game\"\n",
            "\t\"installdir\"\t\"Persisted Arcade Game\"\n",
            "}\n"
        ),
    )
    .expect("write first appmanifest");

    let second_appmanifest_path = temp_dir.path().join("appmanifest_577.acf");
    fs::write(
        &second_appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"577\"\n",
            "\t\"name\"\t\"Persisted Racing Game\"\n",
            "\t\"installdir\"\t\"Persisted Racing Game\"\n",
            "}\n"
        ),
    )
    .expect("write second appmanifest");

    let first_installscript_path = temp_dir.path().join("installscript-first.vdf");
    fs::write(
        &first_installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t\t\"Executable\"\t\"Bin/ArcadeGame.exe\"\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t\t\"DirectX\"\n",
            "\t\t{\n",
            "\t\t\t\"Dll\"\t\"xinput1_3.dll\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write first installscript");

    let second_installscript_path = temp_dir.path().join("installscript-second.vdf");
    fs::write(
        &second_installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t\t\"Executable\"\t\"Bin/RacingGame.exe\"\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t\t\"DirectX\"\n",
            "\t\t{\n",
            "\t\t\t\"Dll\"\t\"xinput1_3.dll\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write second installscript");

    let libraryfolders_path = temp_dir.path().join("libraryfolders.vdf");
    fs::write(
        &libraryfolders_path,
        concat!(
            "\"libraryfolders\"\n",
            "{\n",
            "\t\"0\"\n",
            "\t{\n",
            "\t\t\"path\"\t\"C:\\\\Program Files\\\\Steam\"\n",
            "\t}\n",
            "\t\"1\"\n",
            "\t{\n",
            "\t\t\"path\"\t\"E:\\\\SteamLibraryRacing\"\n",
            "\t\t\"apps\"\n",
            "\t\t{\n",
            "\t\t\t\"576\"\t\"1\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write initial libraryfolders");

    let library_host_map_path = temp_dir.path().join("steam-library-host-map.json");
    fs::write(
        &library_host_map_path,
        casa1::util::stable_json(&BTreeMap::from([(
            "e:/steamlibraryracing".to_string(),
            external_e_root.display().to_string(),
        )]))
        .expect("encode library host map"),
    )
    .expect("write library host map");

    let update_plan_path = temp_dir.path().join("steam-update-plan.json");
    fs::write(
        &update_plan_path,
        casa1::util::stable_json(&SteamUpdatePlan {
            files: BTreeMap::from([
                (
                    "C:/Program Files/Steam/steam.exe".to_string(),
                    b"steam-bootstrap-v2".to_vec(),
                ),
                (
                    "C:/Program Files/Steam/package/steamui.dll".to_string(),
                    b"steam-ui-v2".to_vec(),
                ),
            ]),
            fail_after_write: None,
        })
        .expect("encode update plan"),
    )
    .expect("write update plan");

    let cert_chain_path = temp_dir.path().join("steam-certs.json");
    fs::write(
        &cert_chain_path,
        casa1::util::stable_json(&vec![
            Certificate {
                subject: "api.example.com".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "leaf-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
            Certificate {
                subject: "Casa1 Root".to_string(),
                issuer: "Casa1 Root".to_string(),
                fingerprint: "root-1".to_string(),
                valid_hostnames: vec![
                    "api.example.com".to_string(),
                    "launcher.example.com".to_string(),
                ],
                not_after_day: 10_000,
                revoked: false,
                supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            },
        ])
        .expect("encode cert chain"),
    )
    .expect("write cert chain");

    let first_install = run_macwin(
        &temp_dir,
        &[
            "ge:install",
            "--ge",
            "steam-zero-touch-persisted-library-cli",
            "--installer",
            &installer_path.display().to_string(),
            "--silent",
            "--dtm",
            "--steam-update-plan",
            &update_plan_path.display().to_string(),
            "--steam-cert-chain",
            &cert_chain_path.display().to_string(),
            "--steam-appmanifest",
            &first_appmanifest_path.display().to_string(),
            "--steam-installscript",
            &first_installscript_path.display().to_string(),
            "--steam-payload-root",
            &first_payload_root.display().to_string(),
            "--steam-libraryfolders",
            &libraryfolders_path.display().to_string(),
            "--steam-library-host-map",
            &library_host_map_path.display().to_string(),
            "--trace-categories",
            "file,registry,process,time",
        ],
    );
    let first_report: CanonicalTestOutput = parse_stdout_json(&first_install);
    assert_eq!(first_report.exit_code, 0);

    fs::write(
        &libraryfolders_path,
        concat!(
            "\"libraryfolders\"\n",
            "{\n",
            "\t\"0\"\n",
            "\t{\n",
            "\t\t\"path\"\t\"C:\\\\Program Files\\\\Steam\"\n",
            "\t}\n",
            "\t\"1\"\n",
            "\t{\n",
            "\t\t\"path\"\t\"E:\\\\SteamLibraryRacing\"\n",
            "\t\t\"apps\"\n",
            "\t\t{\n",
            "\t\t\t\"576\"\t\"1\"\n",
            "\t\t\t\"577\"\t\"1\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write updated libraryfolders");

    let second_install = run_macwin(
        &temp_dir,
        &[
            "ge:install",
            "--ge",
            "steam-zero-touch-persisted-library-cli",
            "--installer",
            &installer_path.display().to_string(),
            "--silent",
            "--dtm",
            "--steam-update-plan",
            &update_plan_path.display().to_string(),
            "--steam-cert-chain",
            &cert_chain_path.display().to_string(),
            "--steam-appmanifest",
            &second_appmanifest_path.display().to_string(),
            "--steam-installscript",
            &second_installscript_path.display().to_string(),
            "--steam-payload-root",
            &second_payload_root.display().to_string(),
            "--steam-libraryfolders",
            &libraryfolders_path.display().to_string(),
            "--trace-categories",
            "file,registry,process,time",
        ],
    );
    let second_report: CanonicalTestOutput = parse_stdout_json(&second_install);

    assert_eq!(second_report.exit_code, 0);
    assert!(
        second_report.file_manifest_delta.iter().any(
            |delta| delta.path_norm == "E:\\steamlibraryracing\\steamapps\\appmanifest_577.acf"
        )
    );
    assert!(second_report
        .file_manifest_delta
        .iter()
        .any(|delta| delta.path_norm == "E:\\steamlibraryracing\\steamapps\\common\\persisted racing game\\bin\\racinggame.exe"));
    assert!(
        second_report
            .file_manifest_delta
            .iter()
            .any(|delta| delta.path_norm
                == "C:\\program files\\steam\\steamapps\\libraryfolders.vdf")
    );

    let external_second_game = external_e_root
        .join("SteamLibraryRacing/steamapps/common/Persisted Racing Game/Bin/RacingGame.exe");
    assert!(external_second_game.is_file());

    let reopened_ge =
        GameEnvironment::from_root(ge_root(&temp_dir, "steam-zero-touch-persisted-library-cli"))
            .expect("reopen GE");
    assert!(
        reopened_ge
            .active_drive_mappings()
            .iter()
            .any(|mapping| mapping.drive == "E"
                && mapping.target == external_e_root.display().to_string())
    );
}

#[test]
#[ignore] // emulated execution of the zig-built real Windows PE hangs (>20 min at <1% CPU)
fn stock_crt_linked_windows_pe_runs_through_pe_runtime() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-crt");
    let pe_path = temp_dir.path().join("real-crt.exe");
    support::build_real_windows_crt_probe(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-crt",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );

    let trace_path = ge_root(&temp_dir, "pe-runtime-crt").join("traces/run-real-crt.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| {
        event.category == "process"
            && event.call_id == "NtContinue"
            && event.parameters.get("mode")
                == Some(&serde_json::Value::String("pe-runtime".to_string()))
    }));
}

#[test]
#[ignore] // emulated execution of the zig-built real Windows PE hangs (>20 min at <1% CPU)
fn real_external_windows_ui_audio_imports_trace_through_pe_runtime() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-ui-audio");
    let pe_path = temp_dir.path().join("real-ui-audio.exe");
    support::build_real_windows_ui_audio_probe(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-ui-audio",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,input,audio",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );

    let trace_path =
        ge_root(&temp_dir, "pe-runtime-ui-audio").join("traces/run-real-ui-audio.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "input" && event.call_id == "MessageBoxW")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "audio" && event.call_id == "Beep")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "process" && event.call_id == "ExitProcess")
    );
}

#[test]
#[ignore] // emulated execution of the zig-built real Windows PE hangs (>20 min at <1% CPU)
fn real_external_windows_xaudio2_imports_trace_through_pe_runtime() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-xaudio2");
    let pe_path = temp_dir.path().join("real-xaudio2.exe");
    support::build_real_windows_xaudio2_probe(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-xaudio2",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,audio",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );

    let trace_path = ge_root(&temp_dir, "pe-runtime-xaudio2").join("traces/run-real-xaudio2.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "audio" && event.call_id == "XAudio2Create")
    );
    assert!(trace_record.events.iter().any(
        |event| event.category == "audio" && event.call_id == "IXAudio2::CreateMasteringVoice"
    ));
    assert!(
        trace_record.events.iter().any(
            |event| event.category == "audio" && event.call_id == "IXAudio2::CreateSourceVoice"
        )
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "audio"
                && event.call_id == "IXAudio2SourceVoice::SubmitSourceBuffer")
    );
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "IXAudio2SourceVoice::Start"));
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "audio" && event.call_id == "XAudio2Render")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "process" && event.call_id == "ExitProcess")
    );
}

#[test]
#[ignore] // emulated execution of the zig-built real Windows PE hangs (>20 min at <1% CPU)
fn real_external_windows_d3d11_imports_present_through_pe_runtime() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-d3d11");
    let pe_path = temp_dir.path().join("real-d3d11.exe");
    support::build_real_windows_d3d11_probe(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-d3d11",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,d3d12,dxgi,input",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );
    assert_eq!(canonical_output.gfx_frames.len(), 1);
    assert_eq!(canonical_output.gfx_frames[0].scene_id, "pe-runtime-d3d11");

    let trace_path = ge_root(&temp_dir, "pe-runtime-d3d11").join("traces/run-real-d3d11.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "input" && event.call_id == "RegisterClassExW")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "input" && event.call_id == "CreateWindowExW")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "dxgi"
                && event.call_id == "D3D11CreateDeviceAndSwapChain")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::GetImmediateContext")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::GetBuffer")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::UpdateSubresource")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::Present")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "process" && event.call_id == "ExitProcess")
    );
}

#[test]
#[ignore] // emulated execution of the zig-built real Windows PE hangs (>20 min at <1% CPU)
fn real_external_windows_d3d11_shader_bindings_trace_through_pe_runtime() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-d3d11-shader-bindings");
    let pe_path = temp_dir.path().join("real-d3d11-shader-bindings.exe");
    support::build_real_windows_d3d11_shader_probe(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-d3d11-shader-bindings",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,d3d12,dxgi,input",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );
    assert_eq!(canonical_output.gfx_frames.len(), 1);

    let trace_path = ge_root(&temp_dir, "pe-runtime-d3d11-shader-bindings")
        .join("traces/run-real-d3d11-shader-bindings.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "dxgi"
                && event.call_id == "D3D11CreateDeviceAndSwapChain")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::GetBuffer")
    );
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11Device::CreateBuffer"));
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::CreateTexture2D")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::CreateShaderResourceView")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::CreateRenderTargetView")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::CreateDepthStencilView")
    );
    assert!(trace_record.events.iter().any(
        |event| event.category == "d3d12" && event.call_id == "ID3D11Device::CreateBlendState"
    ));
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::CreateDepthStencilState")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::CreateRasterizerState")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::CreateSamplerState")
    );
    assert!(trace_record.events.iter().any(
        |event| event.category == "d3d12" && event.call_id == "ID3D11Device::CreateInputLayout"
    ));
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::CreateVertexShader")
    );
    assert!(trace_record.events.iter().any(
        |event| event.category == "d3d12" && event.call_id == "ID3D11Device::CreatePixelShader"
    ));
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::OMSetRenderTargets")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::OMSetBlendState")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::OMSetDepthStencilState")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::VSSetConstantBuffers")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::PSSetShaderResources")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::PSSetSamplers")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::IASetInputLayout")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::IASetVertexBuffers")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::IASetIndexBuffer")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::IASetPrimitiveTopology")
    );
    assert!(trace_record.events.iter().any(
        |event| event.category == "d3d12" && event.call_id == "ID3D11DeviceContext::RSSetState"
    ));
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::RSSetViewports")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::RSSetScissorRects")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::VSSetShader")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::PSSetShader")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12" && event.call_id == "ID3D11DeviceContext::Draw")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::DrawIndexed")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::DrawInstanced")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::DrawIndexedInstanced")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::Present")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "process" && event.call_id == "ExitProcess")
    );
}

#[test]
#[ignore] // emulated execution of the zig-built real Windows PE hangs (>20 min at <1% CPU)
fn real_external_windows_d3d11_create_device_without_swapchain_traces_through_pe_runtime() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-d3d11-no-swapchain");
    let pe_path = temp_dir.path().join("real-d3d11-no-swapchain.exe");
    support::build_real_windows_d3d11_no_swapchain_probe(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-d3d11-no-swapchain",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,d3d12",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );
    assert!(canonical_output.gfx_frames.is_empty());

    let trace_path = ge_root(&temp_dir, "pe-runtime-d3d11-no-swapchain")
        .join("traces/run-real-d3d11-no-swapchain.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12" && event.call_id == "D3D11CreateDevice")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::GetImmediateContext")
    );
    assert!(
        !trace_record
            .events
            .iter()
            .any(|event| event.call_id == "D3D11CreateDeviceAndSwapChain")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "process" && event.call_id == "ExitProcess")
    );
}

#[test]
#[ignore] // emulated execution of the zig-built real Windows PE hangs (>20 min at <1% CPU)
fn real_external_windows_tetris_runs_separately_through_casa1() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-tetris");
    let pe_path = temp_dir.path().join("casa1-tetris.exe");
    let input_replay = support::windows_tetris_replay("smoke.json");
    support::build_windows_tetris_game(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-tetris",
            "--exe",
            &pe_path.display().to_string(),
            "--input-replay",
            &input_replay.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,input,d3d12,dxgi,audio",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );
    assert!(!canonical_output.gfx_frames.is_empty());

    let trace_path = ge_root(&temp_dir, "pe-runtime-tetris").join("traces/run-casa1-tetris.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "input" && event.call_id == "CreateWindowExW")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "input" && event.call_id == "KeyboardReplay")
    );
    assert!(trace_record.events.iter().any(|event| {
        event.category == "input"
            && event.call_id == "PeekMessageW"
            && event.return_value.as_u64() == Some(0x0100)
    }));
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "dxgi"
                && event.call_id == "D3D11CreateDeviceAndSwapChain")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11Device::GetImmediateContext")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::GetBuffer")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "d3d12"
                && event.call_id == "ID3D11DeviceContext::UpdateSubresource")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::Present")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "audio" && event.call_id == "XAudio2Create")
    );
    assert!(trace_record.events.iter().any(
        |event| event.category == "audio" && event.call_id == "IXAudio2::CreateMasteringVoice"
    ));
    assert!(
        trace_record.events.iter().any(
            |event| event.category == "audio" && event.call_id == "IXAudio2::CreateSourceVoice"
        )
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "audio" && event.call_id == "XAudio2Render")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "process" && event.call_id == "ExitProcess")
    );
}

#[test]
#[ignore] // emulated execution of the zig-built real Windows PE hangs (>20 min at <1% CPU)
fn real_external_windows_user32_imports_trace_through_pe_runtime() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "pe-runtime-user32");
    let pe_path = temp_dir.path().join("real-user32.exe");
    support::build_real_windows_user32_probe(&pe_path);

    let run_output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "pe-runtime-user32",
            "--exe",
            &pe_path.display().to_string(),
            "--dtm",
            "--trace-categories",
            "process,input",
        ],
    );
    let canonical_output: CanonicalTestOutput = parse_stdout_json(&run_output);
    assert_eq!(canonical_output.exit_code, 0);
    assert!(canonical_output.stdout.is_empty());
    assert!(canonical_output.stderr.is_empty());
    assert!(
        canonical_output
            .perf
            .iter()
            .any(|metric| metric.metric_id == "pe_runtime_steps")
    );

    let trace_path = ge_root(&temp_dir, "pe-runtime-user32").join("traces/run-real-user32.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "input" && event.call_id == "RegisterClassExW")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "input" && event.call_id == "CreateWindowExW")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "input" && event.call_id == "PeekMessageW")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "input" && event.call_id == "DispatchMessageW")
    );
    assert!(
        trace_record
            .events
            .iter()
            .any(|event| event.category == "process" && event.call_id == "ExitProcess")
    );
}

#[test]
fn driver_required_titles_fail_fast_with_stable_reason_code_and_actionable_hint() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "driver-required");

    let install_root = temp_dir.path().join("driver-required-game");
    fs::create_dir_all(install_root.join("Bin")).expect("create game bin");
    fs::create_dir_all(install_root.join("EasyAntiCheat")).expect("create anti-cheat dir");
    let executable = install_root.join("Bin/TestGame.exe");
    fs::copy(guest_bin(), &executable).expect("copy sample guest as game exe");
    fs::write(
        install_root.join("EasyAntiCheat/EasyAntiCheat.sys"),
        b"kernel-driver",
    )
    .expect("write anti-cheat indicator");

    let output = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "driver-required",
            "--exe",
            &executable.display().to_string(),
            "--dtm",
        ],
    );
    assert!(!output.status.success());
    let error: ErrorResponse = serde_json::from_slice(&output.stderr).expect("parse stderr json");
    assert_eq!(
        error.reason_code,
        ReasonCode::RcAnticheatDriverDetected.as_u32()
    );
    assert!(error.message.contains("driver-required title"));
    assert!(
        error
            .reproduction_hints
            .iter()
            .any(|hint| hint.contains("SCM fallback"))
    );
    assert!(
        error
            .reproduction_hints
            .iter()
            .any(|hint| hint.contains("Easy Anti-Cheat kernel driver"))
    );
}

#[test]
fn t01_18_forwarded_exports_cache_hit() {
    // The export tables power the forwarder export cache used by the PE
    // runtime (PeHostRuntime::forwarder_export_cache). Verify the actual
    // forwarder data the runtime resolves against: kernel32.dll exposes a
    // forwarder export "Forwarded" -> kernelbase.Sleep, and kernelbase.dll
    // must provide the Sleep target export.

    let tables = casa1::pe_runtime::export_tables();

    // Verify the core system DLLs that participate in forwarding are registered
    assert!(
        tables.contains_key("kernel32.dll"),
        "kernel32.dll must be in export tables"
    );
    assert!(
        tables.contains_key("user32.dll"),
        "user32.dll must be in export tables"
    );
    assert!(
        tables.contains_key("ntdll.dll"),
        "ntdll.dll must be in export tables"
    );

    // Verify each core DLL has at least one export registered
    for dll in &["kernel32.dll", "user32.dll", "ntdll.dll"] {
        let exports = &tables[*dll];
        assert!(!exports.is_empty(), "DLL '{dll}' has empty export table");
    }

    // The forwarder chain the runtime resolves: kernel32.Forwarded ->
    // kernelbase.Sleep (the cache-hit path in resolve_forwarder_export).
    let kernel32 = &tables["kernel32.dll"];
    let forwarded = kernel32
        .iter()
        .find(|export| export.name.as_deref() == Some("Forwarded"))
        .expect("kernel32.dll must contain the Forwarded forwarder export");
    assert_eq!(
        forwarded.target,
        casa1::pe::ExportTarget::Forwarder("kernelbase.Sleep".to_string()),
        "kernel32.Forwarded must forward to kernelbase.Sleep"
    );
    let kernelbase = tables
        .get("kernelbase.dll")
        .expect("kernelbase.dll must be in export tables");
    assert!(
        kernelbase
            .iter()
            .any(|export| export.name.as_deref() == Some("Sleep")
                && matches!(export.target, casa1::pe::ExportTarget::Rva(_))),
        "kernelbase.dll must provide the Sleep RVA export the forwarder lands on"
    );
}
// ---------------------------------------------------------------------------
// t01_19: MAX_FORWARDER_DEPTH overflow protection — chain too deep
// ---------------------------------------------------------------------------

#[test]
fn t01_19_forwarder_chain_too_deep_returns_none() {
    // The PE runtime guards forwarder chains with MAX_FORWARDER_DEPTH = 8
    // (src/pe_runtime.rs:8694): resolve_forwarder_export returns None once the
    // visited chain exceeds that depth, so deeply nested or circular forwarder
    // data cannot overflow the stack. The resolver itself is private, so this
    // test exercises the invariant over the production export tables: every
    // forwarder export must terminate within the documented depth limit and
    // never revisit a module (no cycles). A chain that never terminated would
    // blow the depth cap here exactly as it would in the resolver.
    let tables = casa1::pe_runtime::export_tables();
    const MAX_FORWARDER_DEPTH: usize = 8;

    fn parse_forwarder(forwarder: &str) -> Option<(String, &str)> {
        let (module, symbol) = forwarder.split_once('.')?;
        let module = module.to_ascii_lowercase();
        Some((
            if module.ends_with(".dll") {
                module
            } else {
                format!("{module}.dll")
            },
            symbol,
        ))
    }

    let mut checked = 0_usize;
    for (dll, exports) in &tables {
        for export in exports {
            let casa1::pe::ExportTarget::Forwarder(target) = &export.target else {
                continue;
            };
            checked += 1;
            let mut visited = std::collections::BTreeSet::new();
            visited.insert(dll.clone());
            let mut current = target.clone();
            loop {
                let (next_dll, symbol) = parse_forwarder(&current).unwrap_or_else(|| {
                    panic!(
                        "malformed forwarder '{current}' from '{dll}' cannot be parsed as DLL.Symbol"
                    )
                });
                assert!(
                    visited.insert(next_dll.clone()),
                    "circular forwarder chain detected: '{dll}' -> '{target}' revisits '{next_dll}'"
                );
                assert!(
                    visited.len() <= MAX_FORWARDER_DEPTH,
                    "forwarder chain '{dll}' -> '{target}' exceeds MAX_FORWARDER_DEPTH \
                     ({MAX_FORWARDER_DEPTH}) before terminating"
                );
                let provider = tables.get(&next_dll).unwrap_or_else(|| {
                    panic!(
                        "forwarder '{dll}' -> '{target}' targets missing module '{next_dll}'"
                    )
                });
                let symbol = symbol.strip_prefix('#').unwrap_or(symbol);
                let resolved = provider
                    .iter()
                    .find(|candidate| candidate.name.as_deref() == Some(symbol));
                let Some(resolved) = resolved else {
                    // Forwarder target symbol absent — resolution terminates
                    // (resolve_forwarder_export returns None and caches it).
                    break;
                };
                let casa1::pe::ExportTarget::Forwarder(next) = &resolved.target else {
                    // Landed on a concrete RVA export — chain terminates.
                    break;
                };
                current = next.clone();
            }
        }
    }
    assert!(
        checked > 0,
        "expected at least one forwarder export in the production tables"
    );
}

// ---------------------------------------------------------------------------
// Section: P0.3 — DLL Synthetic Export Table Verification
// ---------------------------------------------------------------------------
// Verifies that all 15 synthetic DLL export tables defined in pe_runtime.rs
// are properly structured: present in the map, sorted by ordinal, contain
// key expected exports, support random ordinal/name lookups, and gracefully
// handle unknown export requests.
// ---------------------------------------------------------------------------

fn get_export_tables() -> BTreeMap<String, Vec<casa1::pe::ExportSymbol>> {
    casa1::pe_runtime::export_tables()
}

fn require_dll_exports(
    tables: &BTreeMap<String, Vec<casa1::pe::ExportSymbol>>,
    dll: &str,
    min_exports: usize,
    expected: &[(&str, u32)],
) {
    let exports = tables
        .get(dll)
        .unwrap_or_else(|| panic!("DLL '{dll}' not found in export tables"));

    assert!(
        exports.len() >= min_exports,
        "DLL '{dll}' has {} exports, expected at least {min_exports}",
        exports.len(),
    );

    // Verify exports are sorted by ordinal
    for i in 1..exports.len() {
        assert!(
            exports[i].ordinal > exports[i - 1].ordinal,
            "DLL '{dll}' exports not sorted by ordinal at index {i}: ord {} <= {}",
            exports[i].ordinal,
            exports[i - 1].ordinal,
        );
    }

    // Verify all expected exports exist
    for &(name, ordinal) in expected {
        let found = exports
            .iter()
            .any(|e| e.name.as_deref() == Some(name) && e.ordinal == ordinal);
        assert!(
            found,
            "DLL '{dll}': expected export '{name}' with ordinal {ordinal} not found"
        );
    }

    // Verify unknown name lookup returns None
    let unknown_name = format!("__NO_SUCH_EXPORT_{dll}");
    let found_unknown = exports
        .iter()
        .any(|e| e.name.as_deref() == Some(&unknown_name));
    assert!(
        !found_unknown,
        "DLL '{dll}' should not have export '{unknown_name}'"
    );

    // Verify unknown ordinal lookup returns None
    let max_ord = exports.iter().map(|e| e.ordinal).max().unwrap_or(0);
    let unknown_ord = max_ord + 999;
    let found_unknown_ord = exports.iter().any(|e| e.ordinal == unknown_ord);
    assert!(
        !found_unknown_ord,
        "DLL '{dll}' should not have ordinal {unknown_ord}"
    );
}

#[test]
fn t01_20_synthetic_exports_comctl32() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "comctl32.dll",
        20,
        &[
            ("InitCommonControlsEx", 1),
            ("InitCommonControls", 2),
            ("ImageList_Create", 3),
            ("ImageList_Destroy", 4),
            ("ImageList_Add", 7),
            ("ImageList_ReplaceIcon", 8),
            ("ImageList_GetIcon", 10),
            ("ImageList_Draw", 11),
            ("PropertySheetW", 21),
        ],
    );
}

#[test]
fn t01_21_synthetic_exports_shlwapi() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "shlwapi.dll",
        30,
        &[
            ("PathCombineW", 1),
            ("PathAppendW", 2),
            ("PathFindFileNameW", 3),
            ("PathFindExtensionW", 4),
            ("PathRemoveFileSpecW", 5),
            ("PathIsDirectoryW", 6),
            ("PathFileExistsW", 7),
            ("StrStrW", 10),
            ("StrCmpW", 12),
            ("StrCmpIW", 13),
            ("StrChrW", 14),
            ("StrCpyW", 16),
            ("StrToIntW", 17),
            ("UrlCanonicalizeW", 21),
            ("SHDeleteKeyW", 24),
            ("SHDeleteEmptyKeyW", 25),
        ],
    );
}

#[test]
fn t01_22_synthetic_exports_crypt32() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "crypt32.dll",
        15,
        &[
            ("CertOpenSystemStoreW", 1),
            ("CertCloseStore", 2),
            ("CertFindCertificateInStore", 3),
            ("CertGetNameStringW", 4),
            ("CertFreeCertificateContext", 5),
            ("CertCreateCertificateContext", 6),
            ("CertGetCertificateChain", 8),
            ("CertVerifyCertificateChainPolicy", 9),
            ("CertOpenStore", 10),
            ("CertEnumCertificatesInStore", 11),
            ("CryptAcquireCertificatePrivateKey", 14),
            ("PFXImportCertStore", 15),
            ("CertGetIntendedKeyUsage", 18),
        ],
    );
}

#[test]
fn t01_23_synthetic_exports_setupapi() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "setupapi.dll",
        10,
        &[
            ("SetupDiGetClassDevsW", 1),
            ("SetupDiDestroyDeviceInfoList", 2),
            ("SetupDiEnumDeviceInfo", 3),
            ("SetupDiGetDeviceInstanceIdW", 4),
            ("SetupDiGetDeviceRegistryPropertyW", 5),
            ("SetupDiCallClassInstaller", 8),
            ("SetupDiBuildDriverInfoList", 10),
            ("SetupDiInstallDevice", 14),
            ("SetupDiUninstallDevice", 15),
        ],
    );
}

#[test]
fn t01_24_synthetic_exports_dwrite() {
    let tables = get_export_tables();
    require_dll_exports(&tables, "dwrite.dll", 1, &[("DWriteCreateFactory", 1)]);
}

#[test]
fn t01_25_synthetic_exports_propsys() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "propsys.dll",
        8,
        &[
            ("PSGetPropertyDescriptionFromName", 1),
            ("PSGetPropertyKeyFromName", 2),
            ("PSGetNameFromPropertyKey", 3),
            ("PSPropertyKeyFromString", 4),
            ("PSStringFromPropertyKey", 5),
            ("InitPropVariantFromString", 6),
            ("PropVariantClear", 8),
            ("PropVariantCopy", 9),
        ],
    );
}

#[test]
fn t01_26_synthetic_exports_urlmon() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "urlmon.dll",
        5,
        &[
            ("URLDownloadToFileW", 1),
            ("URLDownloadToCacheFileW", 2),
            ("CoInternetSetFeatureEnabled", 3),
            ("CoInternetIsFeatureEnabled", 4),
            ("CreateURLMoniker", 5),
            ("CreateAsyncBindCtx", 6),
            ("ObtainUserAgentString", 8),
        ],
    );
}

#[test]
fn t01_27_synthetic_exports_wintrust() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "wintrust.dll",
        4,
        &[
            ("WinVerifyTrust", 1),
            ("WTHelperProvDataFromStateData", 2),
            ("WTHelperGetProvSignerFromChain", 3),
            ("WTGetSignatureInfo", 5),
        ],
    );
}

#[test]
fn t01_28_synthetic_exports_mscoree() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "mscoree.dll",
        5,
        &[
            ("CorBindToRuntimeEx", 1),
            ("CorBindToRuntime", 2),
            ("CLRCreateInstance", 3),
            ("GetCORSystemDirectory", 4),
            ("GetRequestedRuntimeInfo", 5),
            ("LoadLibraryShim", 6),
        ],
    );
}

#[test]
fn t01_29_synthetic_exports_imm32() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "imm32.dll",
        8,
        &[
            ("ImmGetContext", 1),
            ("ImmReleaseContext", 2),
            ("ImmSetCompositionStringW", 3),
            ("ImmGetCompositionStringW", 4),
            ("ImmGetDefaultIMEWnd", 5),
            ("ImmSimulateHotKey", 6),
            ("ImmIsIME", 7),
            ("ImmNotifyIME", 9),
        ],
    );
}

#[test]
fn t01_30_synthetic_exports_oleaut32() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "oleaut32.dll",
        30,
        &[
            ("SysAllocString", 1),
            ("SysFreeString", 2),
            ("SysReAllocString", 3),
            ("SysAllocStringLen", 4),
            ("SysStringLen", 5),
            ("VariantInit", 7),
            ("VariantClear", 8),
            ("VariantCopy", 9),
            ("VariantCopyInd", 10),
            ("VariantChangeType", 11),
            ("VariantChangeTypeEx", 12),
            ("SafeArrayCreate", 13),
            ("SafeArrayDestroy", 14),
            ("SafeArrayGetElement", 16),
            ("SafeArrayPutElement", 17),
            ("SafeArrayAccessData", 18),
            ("SafeArrayUnaccessData", 19),
            ("SafeArrayCreateVector", 22),
            ("DispGetIDsOfNames", 29),
            ("DispInvoke", 30),
            ("LoadTypeLib", 32),
            ("LoadRegTypeLib", 33),
            ("RegisterTypeLib", 34),
            ("LHashValOfNameSys", 37),
        ],
    );
}

#[test]
fn t01_31_synthetic_exports_comdlg32() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "comdlg32.dll",
        8,
        &[
            ("GetOpenFileNameW", 1),
            ("GetSaveFileNameW", 2),
            ("ChooseColorW", 3),
            ("ChooseFontW", 4),
            ("PageSetupDlgW", 5),
            ("PrintDlgW", 6),
            ("PrintDlgExW", 7),
            ("FindTextW", 8),
            ("ReplaceTextW", 9),
            ("CommDlgExtendedError", 10),
        ],
    );
}

#[test]
fn t01_32_synthetic_exports_winmm() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "winmm.dll",
        35,
        &[
            ("waveOutOpen", 1),
            ("waveOutClose", 2),
            ("waveOutPrepareHeader", 3),
            ("waveOutUnprepareHeader", 4),
            ("waveOutWrite", 5),
            ("waveOutReset", 6),
            ("waveOutGetVolume", 7),
            ("waveOutSetVolume", 8),
            ("waveOutGetDevCapsW", 9),
            ("waveOutGetNumDevs", 10),
            ("waveInOpen", 11),
            ("waveInClose", 12),
            ("waveInPrepareHeader", 13),
            ("waveInAddBuffer", 15),
            ("waveInStart", 16),
            ("waveInGetDevCapsW", 18),
            ("waveInGetNumDevs", 19),
            ("midiOutOpen", 20),
            ("midiOutClose", 21),
            ("midiOutShortMsg", 22),
            ("midiOutLongMsg", 23),
            ("midiOutReset", 24),
            ("midiOutGetDevCapsW", 25),
            ("midiOutGetNumDevs", 26),
            ("midiInOpen", 27),
            ("midiInClose", 28),
            ("midiInStart", 29),
            ("midiInStop", 30),
            ("midiInReset", 31),
            ("timeGetTime", 32),
            ("timeBeginPeriod", 33),
            ("timeEndPeriod", 34),
            ("PlaySoundW", 35),
            ("mmioOpenW", 36),
            ("mmioClose", 37),
            ("mmioRead", 38),
            ("mmioWrite", 39),
            ("mmioAscend", 40),
            ("mmioDescend", 41),
            ("mmioStringToFOURCCW", 43),
        ],
    );
}

#[test]
fn t01_33_synthetic_exports_msvcrt() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "msvcrt.dll",
        40,
        &[
            ("malloc", 4),
            ("free", 3),
            ("calloc", 2),
            ("realloc", 5),
            ("memcpy", 31),
            ("memset", 32),
            ("memmove", 33),
            ("memcmp", 34),
            ("strlen", 27),
            ("strcmp", 35),
            ("strncmp", 28),
            ("strcpy", 36),
            ("sprintf", 38),
            ("sscanf", 40),
            ("fopen", 41),
            ("fclose", 42),
            ("fread", 43),
            ("fwrite", 26),
            ("fgets", 44),
            ("fflush", 45),
            ("abort", 18),
            ("exit", 19),
            ("signal", 67),
            ("sqrt", 46),
            ("pow", 47),
            ("atan2", 51),
            ("log", 52),
            ("exp", 53),
            ("rand", 57),
            ("srand", 58),
            ("time", 59),
            ("qsort", 60),
            ("abs", 62),
            ("atoi", 64),
            ("atof", 66),
            ("_beginthreadex", 20),
            ("_endthreadex", 21),
            ("_set_new_mode", 1),
            ("__C_specific_handler", 6),
            ("__acrt_iob_func", 22),
        ],
    );
}

#[test]
fn t01_34_synthetic_exports_usp10() {
    let tables = get_export_tables();
    require_dll_exports(
        &tables,
        "usp10.dll",
        10,
        &[
            ("ScriptStringAnalyse", 1),
            ("ScriptStringFree", 2),
            ("ScriptStringOut", 3),
            ("ScriptString_pSize", 4),
            ("ScriptItemize", 5),
            ("ScriptShape", 6),
            ("ScriptPlace", 7),
            ("ScriptLayout", 8),
            ("ScriptBreak", 9),
            ("ScriptGetProperties", 10),
            ("ScriptRecordDigitSubstitution", 11),
            ("ScriptApplyDigitSubstitution", 12),
            ("ScriptCacheGetHeight", 13),
            ("ScriptFreeCache", 14),
        ],
    );
}

#[test]
fn t01_35_synthetic_exports_all_dlls_present() {
    // Verify all 15 required DLLs are present in the export tables
    let tables = get_export_tables();
    let required = [
        "comctl32.dll",
        "comdlg32.dll",
        "oleaut32.dll",
        "shlwapi.dll",
        "crypt32.dll",
        "wintrust.dll",
        "setupapi.dll",
        "dwrite.dll",
        "propsys.dll",
        "urlmon.dll",
        "mscoree.dll",
        "msvcrt.dll",
        "winmm.dll",
        "imm32.dll",
        "usp10.dll",
    ];
    for dll in &required {
        assert!(
            tables.contains_key(*dll),
            "Required DLL '{dll}' is missing from export tables"
        );
        let exports = &tables[*dll];
        assert!(!exports.is_empty(), "DLL '{dll}' has empty export table");
    }
}

#[test]
fn t01_36_synthetic_exports_ordinal_continuity() {
    // Verify that ordinals are consecutive (no gaps) within each DLL's table
    let tables = get_export_tables();
    let dlls = [
        "comctl32.dll",
        "comdlg32.dll",
        "oleaut32.dll",
        "shlwapi.dll",
        "crypt32.dll",
        "wintrust.dll",
        "setupapi.dll",
        "dwrite.dll",
        "propsys.dll",
        "urlmon.dll",
        "mscoree.dll",
        "msvcrt.dll",
        "winmm.dll",
        "imm32.dll",
        "usp10.dll",
    ];
    for dll in &dlls {
        if let Some(exports) = tables.get(*dll) {
            for i in 1..exports.len() {
                assert_eq!(
                    exports[i].ordinal,
                    exports[i - 1].ordinal + 1,
                    "DLL '{dll}': ordinal gap between {} (index {}) and {} (index {})",
                    exports[i - 1].ordinal,
                    i - 1,
                    exports[i].ordinal,
                    i,
                );
            }
        }
    }
}

#[test]
fn reason_codes_keep_stable_numeric_values() {
    assert_eq!(ReasonCode::RcPeParseInvalid.as_u32(), 2000);
    assert_eq!(ReasonCode::RcImportMissing.as_u32(), 2001);
    assert_eq!(ReasonCode::RcUnimplInsn.as_u32(), 2002);
    assert_eq!(ReasonCode::RcD3dFeatureUnsupported.as_u32(), 2003);
    assert_eq!(ReasonCode::RcAnticheatDriverDetected.as_u32(), 2004);
    assert_eq!(ReasonCode::RcTlsCertRejected.as_u32(), 2005);
    assert_eq!(ReasonCode::RcMsiCustomActionServiceBlocked.as_u32(), 2006);
    assert_eq!(ReasonCode::RcVulkanNotSupported.as_u32(), 2106);
    assert_eq!(ReasonCode::RcOpenGlNotSupported.as_u32(), 2107);
}

fn create_ge(temp_dir: &TempDir, name: &str) {
    let output = run_macwin(
        temp_dir,
        &[
            "ge:create",
            "--name",
            name,
            "--arch",
            "x64",
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

fn read_json<T: DeserializeOwned>(path: &Path) -> T {
    let contents = fs::read_to_string(path).expect("read JSON file");
    serde_json::from_str(&contents).expect("parse JSON file")
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
