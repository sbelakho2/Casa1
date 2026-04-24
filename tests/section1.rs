mod support;

use casa1::canonical::{compare_outputs, CanonicalTestOutput, ToleranceRegistry};
use casa1::diagnostics::{DoctorReport, ExportSummary};
use casa1::error::ErrorResponse;
use casa1::ge::GameEnvironment;
use casa1::logging::LogEvent;
use casa1::reason::ReasonCode;
use casa1::runner::replay_trace;
use casa1::trace::TraceRecord;
use serde::de::DeserializeOwned;
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
    assert!(canonical_output.stdout.contains("Casa1 sample guest finished mode=run"));
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
    assert!(trace_record
        .events
        .iter()
        .enumerate()
        .all(|(index, event)| event.event_index == index as u64));
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
    assert!(install_report
        .file_manifest_delta
        .iter()
        .any(|delta| delta.path_norm == "C:\\program files\\casa1 sample\\install.txt"));

    let doctor_output = run_macwin(&temp_dir, &["doctor", "--ge", "alpha"]);
    let doctor_report: DoctorReport = parse_stdout_json(&doctor_output);
    assert_eq!(doctor_report.ge_name, "alpha");
    assert!(doctor_report.filesystem_permissions.readable);
    assert!(doctor_report.filesystem_permissions.writable);
    assert!(!doctor_report.helper_process.ran_as_root);
    assert!(matches!(doctor_report.gpu.status.as_str(), "ok" | "unsupported"));

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

    let mut archive = ZipArchive::new(File::open(zip_path).expect("open zip")).expect("zip archive");
    let mut archive_names = Vec::new();
    for index in 0..archive.len() {
        let file = archive.by_index(index).expect("zip entry");
        archive_names.push(file.name().to_string());
    }
    assert!(archive_names.iter().any(|name| name == "ge.json"));
    assert!(archive_names
        .iter()
        .any(|name| name.ends_with("reports/run-casa1-test-guest.json")));
    assert!(archive_names
        .iter()
        .any(|name| name.ends_with("traces/run-casa1-test-guest.json")));
    assert!(archive_names
        .iter()
        .any(|name| name.ends_with("diagnostics/doctor.json")));
}

#[test]
fn canonical_json_is_identical_across_100_dtm_runs() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut baseline = None;

    for iteration in 0..100 {
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
    changed.file_manifest_delta[0].sha256.replace_range(0..1, "b");

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
    let mut replay_ge = GameEnvironment::from_root(ge_root(&temp_dir, "replay")).expect("open replay ge");
    let replay_output = replay_trace(&capture_trace_path, &replay_ge).expect("replay trace");
    assert_eq!(replay_output, captured_canonical);

    replay_ge.config.long_paths_enabled = true;
    replay_ge.save_config().expect("persist replay config mismatch");
    let config_error = replay_trace(&capture_trace_path, &replay_ge).expect_err("expected config mismatch");
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
    assert!(error
        .reproduction_hints
        .iter()
        .any(|hint| hint.contains("missing") || hint.contains("non-executable")));
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));

    let trace_path = ge_root(&temp_dir, "pe-runtime").join("traces/run-sample-runtime.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| {
        event.category == "process"
            && event.call_id == "NtContinue"
            && event.parameters.get("mode") == Some(&serde_json::Value::String("pe-runtime".to_string()))
    }));
}

#[test]
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));

    let trace_path = ge_root(&temp_dir, "pe-runtime-imports").join("traces/run-real-imports.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| event.category == "time" && event.call_id == "Sleep"));
    assert!(trace_record.events.iter().any(|event| event.category == "process" && event.call_id == "ExitProcess"));
}

#[test]
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));

    let trace_path = ge_root(&temp_dir, "pe-runtime-indirect-imports").join("traces/run-real-indirect-imports.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| event.category == "time" && event.call_id == "Sleep"));
    assert!(trace_record.events.iter().any(|event| event.category == "process" && event.call_id == "ExitProcess"));
}

#[test]
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));

    let trace_path = ge_root(&temp_dir, "pe-runtime-crt").join("traces/run-real-crt.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| {
        event.category == "process"
            && event.call_id == "NtContinue"
            && event.parameters.get("mode") == Some(&serde_json::Value::String("pe-runtime".to_string()))
    }));
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));

    let trace_path = ge_root(&temp_dir, "pe-runtime-ui-audio").join("traces/run-real-ui-audio.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| event.category == "input" && event.call_id == "MessageBoxW"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "Beep"));
    assert!(trace_record.events.iter().any(|event| event.category == "process" && event.call_id == "ExitProcess"));
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));

    let trace_path = ge_root(&temp_dir, "pe-runtime-xaudio2").join("traces/run-real-xaudio2.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "XAudio2Create"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "IXAudio2::CreateMasteringVoice"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "IXAudio2::CreateSourceVoice"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "IXAudio2SourceVoice::SubmitSourceBuffer"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "IXAudio2SourceVoice::Start"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "XAudio2Render"));
    assert!(trace_record.events.iter().any(|event| event.category == "process" && event.call_id == "ExitProcess"));
}

#[test]
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));
    assert_eq!(canonical_output.gfx_frames.len(), 1);
    assert_eq!(canonical_output.gfx_frames[0].scene_id, "pe-runtime-d3d11");

    let trace_path = ge_root(&temp_dir, "pe-runtime-d3d11").join("traces/run-real-d3d11.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| event.category == "input" && event.call_id == "RegisterClassExW"));
    assert!(trace_record.events.iter().any(|event| event.category == "input" && event.call_id == "CreateWindowExW"));
    assert!(trace_record.events.iter().any(|event| event.category == "dxgi" && event.call_id == "D3D11CreateDeviceAndSwapChain"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11Device::GetImmediateContext"));
    assert!(trace_record.events.iter().any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::GetBuffer"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11DeviceContext::UpdateSubresource"));
    assert!(trace_record.events.iter().any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::Present"));
    assert!(trace_record.events.iter().any(|event| event.category == "process" && event.call_id == "ExitProcess"));
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));
    assert_eq!(canonical_output.gfx_frames.len(), 1);

    let trace_path = ge_root(&temp_dir, "pe-runtime-d3d11-shader-bindings")
        .join("traces/run-real-d3d11-shader-bindings.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| event.category == "dxgi" && event.call_id == "D3D11CreateDeviceAndSwapChain"));
    assert!(trace_record.events.iter().any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::GetBuffer"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11Device::CreateBuffer"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11Device::CreateShaderResourceView"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11Device::CreateInputLayout"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11Device::CreateVertexShader"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11Device::CreatePixelShader"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11DeviceContext::VSSetConstantBuffers"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11DeviceContext::PSSetShaderResources"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11DeviceContext::IASetInputLayout"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11DeviceContext::VSSetShader"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11DeviceContext::PSSetShader"));
    assert!(trace_record.events.iter().any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::Present"));
    assert!(trace_record.events.iter().any(|event| event.category == "process" && event.call_id == "ExitProcess"));
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));
    assert!(canonical_output.gfx_frames.is_empty());

    let trace_path = ge_root(&temp_dir, "pe-runtime-d3d11-no-swapchain")
        .join("traces/run-real-d3d11-no-swapchain.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "D3D11CreateDevice"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11Device::GetImmediateContext"));
    assert!(!trace_record.events.iter().any(|event| event.call_id == "D3D11CreateDeviceAndSwapChain"));
    assert!(trace_record.events.iter().any(|event| event.category == "process" && event.call_id == "ExitProcess"));
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));
    assert!(!canonical_output.gfx_frames.is_empty());

    let trace_path = ge_root(&temp_dir, "pe-runtime-tetris").join("traces/run-casa1-tetris.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| event.category == "input" && event.call_id == "CreateWindowExW"));
    assert!(trace_record.events.iter().any(|event| event.category == "input" && event.call_id == "KeyboardReplay"));
    assert!(trace_record.events.iter().any(|event| {
        event.category == "input"
            && event.call_id == "PeekMessageW"
            && event.return_value.as_u64() == Some(0x0100)
    }));
    assert!(trace_record.events.iter().any(|event| event.category == "dxgi" && event.call_id == "D3D11CreateDeviceAndSwapChain"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11Device::GetImmediateContext"));
    assert!(trace_record.events.iter().any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::GetBuffer"));
    assert!(trace_record.events.iter().any(|event| event.category == "d3d12" && event.call_id == "ID3D11DeviceContext::UpdateSubresource"));
    assert!(trace_record.events.iter().any(|event| event.category == "dxgi" && event.call_id == "IDXGISwapChain::Present"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "XAudio2Create"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "IXAudio2::CreateMasteringVoice"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "IXAudio2::CreateSourceVoice"));
    assert!(trace_record.events.iter().any(|event| event.category == "audio" && event.call_id == "XAudio2Render"));
    assert!(trace_record.events.iter().any(|event| event.category == "process" && event.call_id == "ExitProcess"));
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
    assert!(canonical_output.perf.iter().any(|metric| metric.metric_id == "pe_runtime_steps"));

    let trace_path = ge_root(&temp_dir, "pe-runtime-user32").join("traces/run-real-user32.json");
    let trace_record: TraceRecord = read_json(&trace_path);
    assert!(trace_record.events.iter().any(|event| event.category == "input" && event.call_id == "RegisterClassExW"));
    assert!(trace_record.events.iter().any(|event| event.category == "input" && event.call_id == "CreateWindowExW"));
    assert!(trace_record.events.iter().any(|event| event.category == "input" && event.call_id == "PeekMessageW"));
    assert!(trace_record.events.iter().any(|event| event.category == "input" && event.call_id == "DispatchMessageW"));
    assert!(trace_record.events.iter().any(|event| event.category == "process" && event.call_id == "ExitProcess"));
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
    assert_eq!(error.reason_code, ReasonCode::RcAnticheatDriverDetected.as_u32());
    assert!(error.message.contains("driver-required title"));
    assert!(error.reproduction_hints.iter().any(|hint| hint.contains("SCM fallback")));
    assert!(error
        .reproduction_hints
        .iter()
        .any(|hint| hint.contains("Easy Anti-Cheat kernel driver")));
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
        &["ge:create", "--name", name, "--arch", "x64", "--winver", "win11-23h2"],
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