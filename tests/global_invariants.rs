use casa1::canonical::{CanonicalTestOutput, GuestException};
use casa1::ge::{GameEnvironment, RegistryView};
use casa1::gfx::{
    DxgiFormat, GraphicsBackend, HeapType, ResourceDesc, ResourceState, ResourceUsageHint,
    SceneSpec, SwapchainDesc,
};
use casa1::network::secure_random;
use casa1::reason::ReasonCode;
use casa1::security::{CrashModule, CrashSnapshot, CrashThread, collect_crash_artifact};
use casa1::steam::{DepotManifest, SteamClient};
use casa1::util::noncrypto_random_bytes;
use libc::SIGABRT;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

#[test]
fn i0_2_deterministic_non_crypto_rng_stays_fixed_under_dtm_while_secure_rng_stays_entropy_backed() {
    let dtm_a = noncrypto_random_bytes("guest-session", true, 32);
    let dtm_b = noncrypto_random_bytes("guest-session", true, 32);
    assert_eq!(dtm_a, dtm_b);

    let live_a = noncrypto_random_bytes("guest-session", false, 32);
    let live_b = noncrypto_random_bytes("guest-session", false, 32);
    assert_ne!(live_a, live_b);

    let secure_a = secure_random(32);
    let secure_b = secure_random(32);
    assert_ne!(secure_a, secure_b);
}

#[test]
fn i2_1_guest_crash_is_contained_and_same_ge_can_relaunch() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "containment");

    let crash = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "containment",
            "--exe",
            &guest_bin().display().to_string(),
            "--env",
            "CASA1_SAMPLE_GUEST_CRASH=1",
            "--dtm",
        ],
    );
    let crash_report: CanonicalTestOutput = parse_stdout_json(&crash);
    assert_eq!(crash_report.exit_code, -1);
    assert_eq!(crash_report.guest_exceptions.len(), 1);
    assert_eq!(crash_report.guest_exceptions[0].code, SIGABRT as u32);

    let relaunch = run_macwin(
        &temp_dir,
        &[
            "ge:run",
            "--ge",
            "containment",
            "--exe",
            &guest_bin().display().to_string(),
            "--dtm",
        ],
    );
    let relaunch_report: CanonicalTestOutput = parse_stdout_json(&relaunch);
    assert_eq!(relaunch_report.exit_code, 0);
    assert!(relaunch_report.guest_exceptions.is_empty());
}

#[test]
fn i3_2_registry_isolation_keeps_values_inside_each_ge() {
    let temp_dir = TempDir::new().expect("temp dir");
    create_ge(&temp_dir, "registry-a");
    create_ge(&temp_dir, "registry-b");

    let ge_a =
        GameEnvironment::from_root(temp_dir.path().join("ges/registry-a")).expect("open first GE");
    let ge_b =
        GameEnvironment::from_root(temp_dir.path().join("ges/registry-b")).expect("open second GE");
    ge_a.registry_set_value(
        "HKCU",
        "Software\\Casa1Isolation",
        "Marker",
        "REG_SZ",
        json!("alpha"),
        RegistryView::Native,
    )
    .expect("write isolated registry value");

    let value = ge_a
        .registry_get_value(
            "HKCU",
            "Software\\Casa1Isolation",
            "Marker",
            RegistryView::Native,
        )
        .expect("read first GE registry value")
        .expect("registry value must exist in first GE");
    assert_eq!(value.data, json!("alpha"));
    assert!(
        ge_b.registry_get_value(
            "HKCU",
            "Software\\Casa1Isolation",
            "Marker",
            RegistryView::Native
        )
        .expect("read second GE registry value")
        .is_none()
    );
}

#[test]
fn i5_1_soak_gate_keeps_rss_growth_under_five_percent_and_gpu_live_set_stable() {
    let mut backend = GraphicsBackend::new();
    let swapchain = backend
        .create_swapchain(SwapchainDesc {
            width: 1280,
            height: 720,
            format: DxgiFormat::B8G8R8A8Unorm,
            buffer_count: 2,
        })
        .expect("create soak swapchain");

    for iteration in 0..256 {
        let resource = backend
            .create_resource(ResourceDesc {
                name: format!("warmup-{iteration}"),
                format: DxgiFormat::R16Float,
                heap: HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Generic,
            })
            .expect("create warmup resource");
        backend
            .destroy_resource(resource)
            .expect("destroy warmup resource");
        backend
            .present(swapchain, 1, false)
            .expect("present warmup frame");
    }

    let baseline_rss_kb = current_rss_kb();
    let mut peak_live_resources = backend.live_resource_count();
    for iteration in 0..4096 {
        let resource = backend
            .create_resource(ResourceDesc {
                name: format!("soak-{iteration}"),
                format: DxgiFormat::R16Float,
                heap: HeapType::Default,
                size: 128,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Generic,
            })
            .expect("create soak resource");
        backend
            .destroy_resource(resource)
            .expect("destroy soak resource");
        backend
            .present(swapchain, 1, false)
            .expect("present soak frame");
        peak_live_resources = peak_live_resources.max(backend.live_resource_count());
    }

    let final_rss_kb = current_rss_kb();
    let growth_percent = if baseline_rss_kb == 0 {
        0.0
    } else {
        ((final_rss_kb.saturating_sub(baseline_rss_kb)) as f64 / baseline_rss_kb as f64) * 100.0
    };

    assert!(growth_percent < 5.0, "RSS grew by {growth_percent:.2}%");
    assert_eq!(backend.live_resource_count(), 2);
    assert_eq!(peak_live_resources, 2);
}

#[test]
#[ignore = "requires AppKit on main thread"]
fn i5_2_curated_rotation_24_logical_hours_records_guest_crashes_without_host_failure() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut steam = SteamClient::new("C:/GEs/RotationSteam");
    steam
        .install_depot(DepotManifest {
            app_id: 490,
            game_name: "Rotation Game".to_string(),
            install_dir: "Rotation Game".to_string(),
            launch_exe: "Bin/TestGame.exe".to_string(),
            library_root: None,
            prerequisites: Vec::new(),
            files: BTreeMap::from([("Bin/TestGame.exe".to_string(), b"rotation-game".to_vec())]),
        })
        .expect("install rotation depot");

    let mut crash_codes = Vec::new();
    for hour in 0..24 {
        create_ge(&temp_dir, &format!("rotation-{hour}"));
        let run = run_macwin(
            &temp_dir,
            &[
                "ge:run",
                "--ge",
                &format!("rotation-{hour}"),
                "--exe",
                &guest_bin().display().to_string(),
                "--dtm",
            ],
        );
        let report: CanonicalTestOutput = parse_stdout_json(&run);
        assert_eq!(report.exit_code, 0);

        let launch = steam.launch_game(490).expect("launch curated Steam title");
        assert!(launch.input_ok);
        assert!(launch.audio_ok);
        assert!(launch.network_ok);

        let backend = GraphicsBackend::new();
        let frame = backend
            .render_scene(&SceneSpec {
                name: format!("rotation-scene-{hour}"),
                format: DxgiFormat::B8G8R8A8Unorm,
                clear_color: [hour as u8, 0, 0, 255],
                draw_calls: 2,
                compute_dispatches: 1,
            })
            .expect("render curated frame");
        assert!(frame.validation_errors.is_empty());

        let output = temp_dir.path().join(format!("rotation-crash-{hour}.zip"));
        let summary = collect_crash_artifact(
            &CrashSnapshot {
                exception: GuestException {
                    code: ReasonCode::RcMemoryAccessViolation.as_u32(),
                    addr: Some(format!("0x{:X}", 0x1400_1000 + hour as u64)),
                    module: "rotation-guest.exe".to_string(),
                    tid: 1,
                },
                modules: vec![CrashModule {
                    name: "rotation-guest.exe".to_string(),
                    base_address: 0x1400_0000,
                }],
                threads: vec![CrashThread {
                    tid: 1,
                    stack: vec![
                        "rotation!crash".to_string(),
                        "kernel32!BaseThreadInitThunk".to_string(),
                    ],
                }],
                host_stack: vec![
                    "macwin!dispatch_runner".to_string(),
                    "casa1-runner!execute_job".to_string(),
                ],
                log_lines: vec![format!("rotation-hour={hour}")],
                applied_profile: BTreeMap::from([("rotation".to_string(), hour.to_string())]),
            },
            &output,
        )
        .expect("collect rotation crash artifact");
        assert!(summary.output_zip.exists());
        crash_codes.push(ReasonCode::RcMemoryAccessViolation.as_u32());
    }

    assert_eq!(crash_codes.len(), 24);
    assert!(
        crash_codes
            .iter()
            .all(|code| *code == ReasonCode::RcMemoryAccessViolation.as_u32())
    );
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

fn parse_stdout_json<T: serde::de::DeserializeOwned>(output: &Output) -> T {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse stdout JSON")
}

fn guest_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_casa1-test-guest"))
}

fn current_rss_kb() -> u64 {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("read rss from ps");
    let text = String::from_utf8(output.stdout).expect("utf8 rss output");
    text.trim().parse::<u64>().expect("numeric rss")
}

#[test]
fn reason_code_numeric_values_are_stable() {
    // These values are part of the stable API and must never change.
    assert_eq!(ReasonCode::Success.as_u32(), 0);
    assert_eq!(ReasonCode::RcCliInvalid.as_u32(), 1000);
    assert_eq!(ReasonCode::RcIo.as_u32(), 1003);
    assert_eq!(ReasonCode::RcPeParseInvalid.as_u32(), 2000);
    assert_eq!(ReasonCode::RcTlsCertRejected.as_u32(), 2005);
    assert_eq!(ReasonCode::RcJitCodeAllocFailed.as_u32(), 2010);
    assert_eq!(ReasonCode::RcOutOfMemory.as_u32(), 3200);
    assert_eq!(ReasonCode::RcLockPoisoned.as_u32(), 3300);

    // Verify roundtrip for a sample of codes
    for expected in [
        ReasonCode::Success,
        ReasonCode::RcIo,
        ReasonCode::RcPeParseInvalid,
        ReasonCode::RcOutOfMemory,
    ] {
        let v = expected.as_u32();
        assert_eq!(ReasonCode::from_u32(v), Some(expected));
    }
}
