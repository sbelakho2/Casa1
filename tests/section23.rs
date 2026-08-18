//! Steam first-divergence diagnostic (artifact-driven).
//!
//! Runs the real Steam.exe through the runner's `execute_job` path with a
//! configured wall-clock deadline, then reads the authoritative
//! steam-bootstrap artifact and prints:
//!
//! - the last successfully observed milestone;
//! - the next missing mandatory stage (S0-S13 from `steam_acceptance`);
//! - the first failure per subsystem (fs/crt/thread/network/cef/gfx);
//! - the last dispatched thunk with guest PC / thread / wall time;
//! - the structured termination and JIT state.
//!
//! No fixed Steam version-specific crash RVA is assumed: this is a pure
//! first-divergence locator driven by the run artifact.
//!
//! Usage:
//!   CASA1_STEAM_E2E=1 cargo test --test section23 -- --ignored --nocapture

use casa1::runner::{self, RunIntent, RunnerJob};
use std::collections::BTreeMap;

const STEAM_GE: &str = "steam";

#[test]
#[ignore = "requires live Steam E2E environment"]
fn steam_first_divergence_diagnostic() {
    if std::env::var("CASA1_STEAM_E2E").as_deref() != Ok("1") {
        eprintln!("skipped: set CASA1_STEAM_E2E=1 to run the live Steam diagnostic");
        return;
    }

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ge_root = repo_root.join("ges").join(STEAM_GE);
    let steam_exe = ge_root.join("drive_c").join("Steam").join("Steam.exe");
    assert!(
        steam_exe.is_file(),
        "Steam executable missing at {}",
        steam_exe.display()
    );

    let job = RunnerJob {
        ge_name: STEAM_GE.to_string(),
        ge_root: ge_root.clone(),
        program: steam_exe.clone(),
        args: Vec::new(),
        cwd: ge_root.join("drive_c").join("Steam"),
        env: BTreeMap::new(),
        dtm: false,
        intent: RunIntent::Run,
        trace_categories: Vec::new(),
        test_id: "section23_first_divergence".to_string(),
        jit_mode: Default::default(),
        steam_ipc: false,
        window_width: None,
        window_height: None,
    };

    let outcome = runner::execute_job(&job).expect("runner execute_job");

    let artifact_path = outcome
        .steam_artifact_json
        .as_ref()
        .expect("Steam artifact must be produced for the real Steam executable");
    let artifact_text = std::fs::read_to_string(artifact_path).expect("read steam artifact");
    let artifact: casa1::runner::SteamBootstrapArtifact =
        serde_json::from_str(&artifact_text).expect("parse steam artifact");

    let milestones = &artifact.milestones;
    println!("=== Steam first-divergence diagnostic ===");
    println!("termination:       {:?}", artifact.termination);
    println!("termination detail: {:?}", artifact.termination_detail);
    println!("run_id:            {}", artifact.run_id);
    println!("program_sha256:    {}", artifact.program_sha256);
    println!(
        "jit:               requested={}, active={}",
        artifact.jit.requested, artifact.jit.active
    );
    if let Some(last) = &artifact.last_thunk {
        println!(
            "last thunk:        {} at guest_pc={:#x} after {}s",
            last.name, last.guest_pc, last.wall_secs_since_start
        );
    }
    println!("last milestone:    {}", last_observed_milestone(&artifact));
    println!("first failures:");
    let failures = &milestones.first_failures;
    for (category, record) in [
        ("fs", &failures.fs),
        ("crt", &failures.crt),
        ("thread", &failures.thread),
        ("network", &failures.network),
        ("cef", &failures.cef),
        ("gfx", &failures.gfx),
    ] {
        if let Some(record) = record {
            println!(
                "  {category}: api={:?} guest_error={:?} guest_pc={:#x} path={:?} detail={}",
                record.api, record.guest_error, record.guest_pc, record.windows_path, record.detail
            );
        }
    }

    // Next missing mandatory stage per the acceptance evaluator.
    let policy = casa1::steam_acceptance::SteamAcceptancePolicy::default();
    let result = casa1::steam_acceptance::evaluate(&artifact, &policy);
    println!("completed stages:  {:?}", result.completed_stages);
    println!("next missing:      {:?}", result.missing.first());
    println!("failures:          {:?}", result.failures);
}

fn last_observed_milestone(artifact: &casa1::runner::SteamBootstrapArtifact) -> String {
    let steam = &artifact.milestones.steam;
    let candidates = [
        ("bootstrap_started", &steam.bootstrap_started),
        ("manifest_opened", &steam.manifest_opened),
        ("manifest_full_read", &steam.manifest_full_read),
        (
            "package_writability_probe",
            &steam.package_writability_probe,
        ),
        ("client_main_started", &steam.client_main_started),
        (
            "webhelper_spawn_requested",
            &steam.webhelper_spawn_requested,
        ),
        (
            "webhelper_process_started",
            &steam.webhelper_process_started,
        ),
        ("cef_browser_created", &steam.cef_browser_created),
        ("cef_first_paint", &steam.cef_first_paint),
    ];
    for (name, evidence) in candidates.iter().rev() {
        if evidence.is_some() {
            return name.to_string();
        }
    }
    "none".to_string()
}
