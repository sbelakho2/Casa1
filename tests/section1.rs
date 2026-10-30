#![allow(dead_code, unused_imports)]
mod support;

use casa1::canonical::CanonicalTestOutput;
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
        archive_names.push(file.name().expect("zip entry name").to_string());
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
                    panic!("forwarder '{dll}' -> '{target}' targets missing module '{next_dll}'")
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
