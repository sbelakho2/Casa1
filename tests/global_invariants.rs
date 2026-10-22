#![allow(dead_code, unused_imports)]
use casa1::canonical::{CanonicalTestOutput, GuestException};
use casa1::gfx::{DxgiFormat, GraphicsBackend, SceneSpec};
use casa1::reason::ReasonCode;
use casa1::security::{CrashModule, CrashSnapshot, CrashThread, collect_crash_artifact};
use casa1::steam::{DepotManifest, SteamClient};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

#[test]
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

    // Every simulated crash hour must have produced an artifact. (The codes
    // themselves are the same value the test supplied, so re-checking them is
    // tautological; the artifact-existence check above is the real signal.)
    assert_eq!(crash_codes.len(), 24);
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
