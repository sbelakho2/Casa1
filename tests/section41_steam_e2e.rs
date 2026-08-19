//! Phase 41 — Real Steam E2E acceptance (S0-S13).
//!
//! Runs the REAL Steam client from `ges/steam/drive_c/Steam/Steam.exe`
//! through the BUILT `casa1-runner` BINARY as the root Steam host (the
//! signed/downloaded runner when `CASA1_STEAM_RUNNER` is set) with a
//! bounded wall-clock deadline (`CASA1_PE_RUNTIME_DEADLINE_SECS`, default
//! 300 s), loads the steam-bootstrap artifact the runner wrote for THIS run
//! (via `outcome.steam_artifact_json` — never an mtime scan of the
//! diagnostics directory), and evaluates it with
//! [`casa1::steam_acceptance::evaluate`] under a policy that requires
//! stages S0-S12 and allows the harness deadline.
//!
//! The job is the PRODUCTION Steam job: it is built by
//! [`casa1::steam_launch::prepare_steam_job`] from a
//! `SteamLaunchProfile::default()` — the exact construction `steam:launch`
//! dispatches — so the gate exercises the live PE host path (intent
//! `Play`), the profile's Steam IPC, JIT mode (Enabled), window dimensions
//! and launch environment.
//!
//! The runner is invoked OUT OF PROCESS — the test never calls
//! `execute_job` itself.  The runner process exit code is asserted 0 AND
//! the `RunnerOutcome` JSON is parsed from the runner's stdout: the gate
//! proves the real binary (the exact artifact CI signs) executes the
//! Steam job, not a library call inside the test executable.
//!
//! The gate is TRUTHFUL: the test PASSES only when the acceptance result
//! passes.  Missing stages are diagnostics, never success — the gate ends
//! with `assert!(result.passed, ...)`.
//!
//! A single machine-readable verdict line is emitted on stdout:
//! `STEAM_ACCEPTANCE=<JSON>` where the JSON is the serialized
//! [`SteamAcceptanceResult`] plus run identity — the CI workflow consumes
//! this line; it never re-derives S0-S13 by regex over stdout.
//!
//! Gated twice: `#[ignore]` keeps it out of the default suite, and the
//! `CASA1_STEAM_E2E=1` environment gate skips it (with a message) even
//! when `--ignored` forces the run.
//!
//! Usage:
//! ```bash
//! CASA1_STEAM_E2E=1 CASA1_PE_RUNTIME_DEADLINE_SECS=600 \
//!   cargo test --release --test section41_steam_e2e -- --ignored --nocapture
//! ```

use casa1::runner::{RunnerOutcome, SteamBootstrapArtifact};
use casa1::steam_acceptance::{MANDATORY_STAGES, SteamAcceptancePolicy, evaluate};
use casa1::steam_launch::{SteamLaunchProfile, prepare_steam_job};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The Steam GE whose `drive_c/Steam/Steam.exe` is the real client.
const STEAM_GE: &str = "steam";

/// The E2E gate: `CASA1_STEAM_E2E=1` is required even with `--ignored`.
fn steam_e2e_gate() -> bool {
    if std::env::var("CASA1_STEAM_E2E").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: CASA1_STEAM_E2E is not set to 1.\n\
             This test runs the REAL Steam client under the Casa1 PE runtime\n\
             and needs the live E2E environment. Re-run with:\n\
             \n\
             CASA1_STEAM_E2E=1 CASA1_PE_RUNTIME_DEADLINE_SECS=600 \\\n\
               cargo test --release --test section41_steam_e2e -- --ignored --nocapture"
        );
        return false;
    }
    true
}

/// Resolve the Steam GE root: the CI hydration stage points
/// `CASA1_STEAM_E2E_GE_ROOT` at the hydrated fixture it produced; locally the
/// tracked `ges/<name>` fixture is used.
fn e2e_ge_name() -> String {
    std::env::var("CASA1_STEAM_E2E_GE_NAME").unwrap_or_else(|_| STEAM_GE.to_string())
}

fn e2e_ge_root() -> PathBuf {
    match std::env::var_os("CASA1_STEAM_E2E_GE_ROOT") {
        Some(root) => PathBuf::from(root),
        None => Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("ges")
            .join(e2e_ge_name()),
    }
}

#[test]
#[ignore = "requires live Steam E2E environment"]
fn t41_steam_e2e_acceptance() {
    if !steam_e2e_gate() {
        return;
    }

    // ── Resolve the real client ──────────────────────────────────────────
    let ge_root = e2e_ge_root();
    let ge_name = e2e_ge_name();
    let steam_exe = ge_root.join("drive_c").join("Steam").join("Steam.exe");
    assert!(
        steam_exe.is_file(),
        "real Steam client missing at {} — the E2E test needs a hydrated GE with \
         drive_c/Steam/Steam.exe (default: ges/{STEAM_GE}/drive_c/Steam/Steam.exe)",
        steam_exe.display(),
    );

    // ── Bounded deadline ──────────────────────────────────────────────────
    // pe_runtime::execute reads CASA1_PE_RUNTIME_DEADLINE_SECS from the
    // process environment, so it must be set here (this test binary has a
    // single test; no parallel test can observe the mutation).
    let deadline_secs: u64 = std::env::var("CASA1_PE_RUNTIME_DEADLINE_SECS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(300);
    // SAFETY: single-test binary; setting the deadline before the run is
    // required for the bounded Steam execution.
    unsafe {
        std::env::set_var("CASA1_PE_RUNTIME_DEADLINE_SECS", deadline_secs.to_string());
        // Pin the GE root so the production job constructor resolves the
        // hydrated/tracked fixture (never a stray environment of the same
        // name).  The root is the fixture itself; open() looks one level up.
        std::env::set_var(
            "CASA1_GES_ROOT",
            ge_root.parent().expect("GE root has a parent"),
        );
    }

    // ── Build the PRODUCTION Steam job ────────────────────────────────────
    // prepare_steam_job is the exact job construction steam:launch uses:
    // intent Play (live PE host path), steam_ipc from the profile, JIT mode
    // from the profile (Enabled), window dimensions from the profile, and
    // the steam launch environment.  The gate never hand-constructs a
    // RunnerJob.
    let profile = SteamLaunchProfile {
        ge_name: ge_name.clone(),
        ..SteamLaunchProfile::default()
    };
    let job = match prepare_steam_job(&profile) {
        Ok(job) => job,
        Err(error) => {
            panic!(
                "[section41] prepare_steam_job failed (production Steam job construction): {}",
                error.message,
            );
        }
    };
    assert_eq!(
        job.program,
        steam_exe,
        "the production Steam job must run the real client at {}",
        steam_exe.display(),
    );
    assert!(
        job.intent == casa1::runner::RunIntent::Play,
        "the production Steam job must use intent Play (live PE host path), got {:?}",
        job.intent,
    );
    assert_eq!(
        job.jit_mode,
        casa1::runner::JitMode::Enabled,
        "the production Steam job must request JIT Enabled from the profile",
    );
    assert_eq!(job.steam_ipc, profile.steam_ipc);
    assert_eq!(
        job.window_width,
        (profile.resolution_width > 0).then_some(profile.resolution_width),
    );
    assert_eq!(
        job.window_height,
        (profile.resolution_height > 0).then_some(profile.resolution_height),
    );

    // ── Invoke the BUILT runner binary as the root Steam host ─────────────
    // The test never calls execute_job in-process: the runner is spawned as
    // a separate process with the production job on disk, its stdout is the
    // RunnerOutcome JSON (the runner prints nothing else to stdout), and
    // the gate asserts BOTH the runner process exit code 0 AND a parseable
    // outcome.  CASA1_STEAM_RUNNER selects the exact signed/downloaded
    // runner when set; otherwise cargo's CARGO_BIN_EXE_casa1-runner (the
    // binary this package builds) is used.
    let runner_path = match std::env::var_os("CASA1_STEAM_RUNNER") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(env!("CARGO_BIN_EXE_casa1-runner")),
    };
    assert!(
        runner_path.is_file(),
        "runner binary missing at {} — build the casa1-runner bin target",
        runner_path.display(),
    );
    let job_dir = std::env::temp_dir().join("casa1-section41");
    std::fs::create_dir_all(&job_dir).expect("create section41 job dir");
    let job_path = job_dir.join(format!("steam-job-{}.json", std::process::id()));
    std::fs::write(
        &job_path,
        serde_json::to_string(&job).expect("serialize production job"),
    )
    .expect("write production job JSON");
    eprintln!(
        "[section41] invoking runner binary (deadline {deadline_secs}s): {} --job {}",
        runner_path.display(),
        job_path.display(),
    );
    let runner_output = Command::new(&runner_path)
        .arg("--job")
        .arg(&job_path)
        .output()
        .expect("spawn the casa1 runner binary");
    let _ = std::fs::remove_file(&job_path);
    assert!(
        runner_output.status.success(),
        "the runner binary must exit 0 when it produced an outcome \
         (process exit: {:?}) — stderr:\n{}",
        runner_output.status.code(),
        String::from_utf8_lossy(&runner_output.stderr),
    );
    let outcome: RunnerOutcome =
        serde_json::from_slice(&runner_output.stdout).unwrap_or_else(|error| {
            panic!(
                "[section41] runner stdout is not a RunnerOutcome JSON: {error}\n\
             stdout:\n{}",
                String::from_utf8_lossy(&runner_output.stdout),
            )
        });
    // The outcome's guest-exit semantics must be honest: the runner's own
    // exit 0 only means an outcome was produced.  guest_exit_code is Some
    // exactly when the run ended in a real GuestExit.
    let outcome_termination_is_guest_exit = outcome.termination == "GuestExit";
    assert_eq!(
        outcome.guest_exit_code.is_some(),
        outcome_termination_is_guest_exit,
        "[section41] outcome guest_exit_code must be Some({:?}) exactly for a \
         GuestExit termination, got termination={:?} guest_exit_code={:?}",
        outcome.canonical_output.exit_code,
        outcome.termination,
        outcome.guest_exit_code,
    );
    eprintln!(
        "[section41] runner finished: process_exit=0 termination={} exit_code={} \
         report={}",
        outcome.termination,
        outcome.canonical_output.exit_code,
        outcome.report_path.display(),
    );

    // ── Load the artifact the runner wrote FOR THIS RUN ───────────────────
    // The outcome carries the authoritative artifact paths of this run —
    // never an mtime scan of the diagnostics directory.
    let artifact_path = outcome.steam_artifact_json.clone().unwrap_or_else(|| {
        panic!(
            "[section41] the runner produced no steam_artifact_json — the run did not \
             produce the steam-bootstrap artifact (run_id={}, test_id={})",
            outcome.run_id, job.test_id,
        );
    });
    let artifact_log_path = outcome.steam_artifact_log.clone().unwrap_or_else(|| {
        panic!("[section41] the runner produced no steam_artifact_log",);
    });
    assert!(
        artifact_path.is_file(),
        "[section41] steam artifact {} does not exist",
        artifact_path.display(),
    );
    assert!(
        artifact_log_path.is_file(),
        "[section41] steam artifact log {} does not exist",
        artifact_log_path.display(),
    );
    eprintln!("[section41] artifact: {}", artifact_path.display());
    let artifact_bytes = std::fs::read(&artifact_path).expect("read steam-bootstrap artifact");
    let artifact: SteamBootstrapArtifact =
        serde_json::from_slice(&artifact_bytes).expect("parse steam-bootstrap artifact JSON");

    // ── Authoritative artifact identity ────────────────────────────────────
    assert!(
        !artifact.run_id.is_empty(),
        "artifact must carry a non-empty run_id",
    );
    assert_eq!(
        artifact.run_id, outcome.run_id,
        "artifact.run_id must equal the outcome's run id (the artifact was read by \
         path, so a mismatch means the artifact does not belong to this run)",
    );
    assert_eq!(
        artifact.test_id, job.test_id,
        "artifact.test_id must equal the job's test id",
    );
    // The artifact must carry the sha256 of the exact binary that ran —
    // computed in the test, never trusted from the artifact itself.
    let program_sha = casa1::steam_milestones::file_content_hash(&steam_exe);
    assert_eq!(
        artifact.program_sha256, program_sha,
        "artifact program_sha256 must match the sha256 of the real binary that ran",
    );
    assert_eq!(
        artifact.provenance.steam_executable_hash, program_sha,
        "artifact steam_executable_hash must match the sha256 of the real binary \
         (artifact may be stale or from a different fixture)",
    );
    // The full artifact (including the authoritative termination) must
    // serialize; a serialization failure is an artifact-integrity failure.
    let serialized = serde_json::to_string(&artifact).expect("artifact must serialize");
    assert!(
        serialized.contains("\"termination\""),
        "artifact serialization must include the termination field",
    );

    // ── Evaluate against the S0-S12 mandatory policy ──────────────────────
    let policy = SteamAcceptancePolicy {
        require_stages: MANDATORY_STAGES.to_vec(),
        allow_harness_deadline_after_all_mandatory: true,
    };
    let result = evaluate(&artifact, &policy);

    let report = json!({
        "run_id": artifact.run_id,
        "commit_sha": artifact.provenance.commit_sha,
        "execution_mode": artifact.provenance.execution_mode,
        "steam_executable_hash": artifact.provenance.steam_executable_hash,
        "termination": artifact.termination,
        "termination_detail": artifact.termination_detail,
        "exit_code": artifact.exit_code,
        "guest_pid": artifact.guest_pid,
        "instruction_count": artifact.instruction_count,
        "network_exchanges": artifact.network_summary.len(),
        "artifact_path": artifact_path.display().to_string(),
        "acceptance": result,
    });
    eprintln!(
        "[section41] acceptance report:\n{}",
        serde_json::to_string_pretty(&report).expect("serialize acceptance report"),
    );

    // ── Machine-readable verdict line (single line, stdout) ───────────────
    // The CI workflow consumes ONLY this line; it must not re-implement
    // S0-S13 by regex over stdout.
    let verdict = json!({
        "result": result,
        "run_id": artifact.run_id,
        "test_id": job.test_id,
        "program_sha256": artifact.program_sha256,
        "exit_code": artifact.exit_code,
        "termination": artifact.termination,
    });
    println!(
        "STEAM_ACCEPTANCE={}",
        serde_json::to_string(&verdict).expect("serialize verdict")
    );

    // ── The gate ──────────────────────────────────────────────────────────
    // Missing stages are diagnostics, NEVER success: there is no
    // documented-stage-missing pass branch.  The gate ends with the
    // acceptance result.
    assert!(
        result.passed,
        "Steam E2E acceptance failed: completed={:?}, missing={:?}, failures={:?}",
        result.completed_stages, result.missing, result.failures,
    );
    eprintln!("[section41] PASS: acceptance passed (all stages S0-S13)");
}
