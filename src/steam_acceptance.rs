//! Steam E2E acceptance evaluation: the S0-S13 bootstrap stage ladder.
//!
//! [`evaluate`] maps a written [`SteamBootstrapArtifact`] onto the S0..S13
//! stage requirements and returns a structured [`SteamAcceptanceResult`].
//! The evaluator is pure: it reads only the artifact and the policy, never
//! the live process.  Stage-missing outcomes are recorded as
//! `StageNotReached` failures (documented stage-missing); run-level
//! problems (guest exceptions, illegal host terminations, encoder
//! imbalance, placeholder-only rendering, unproven network, model-mode
//! provenance) are recorded with their dedicated failure variants.
//!
//! Stage ladder (S0..S13):
//!
//! - `S0`  — program identity present (`provenance.steam_executable_hash`)
//!   AND the PE main loop was entered (`bootstrap_started`; reaching the
//!   main loop proves the PE parsed and executed).
//! - `S1`  — `bootstrap_started` evidence present.
//! - `S2`  — `manifest_opened` AND `manifest_full_read` (manifest fully read).
//! - `S3`  — `package_writability_probe` evidence present.
//! - `S4`  — at least one network exchange recorded in `network_summary`;
//!   an empty summary records `NetworkUnproven`.
//! - `S5`  — `client_main_started` evidence present.
//! - `S6`  — `webhelper_processes_started >= 1`.  The artifact's single counter
//!   records `CreateProcess` requests naming `steamwebhelper`, which covers
//!   both the spawn-request and process-started sub-criteria (a request
//!   that never started would not reach the guest-visible process layer).
//! - `S7`  — `cef_browser_created` evidence.
//! - `S8`  — `cef_first_paint` evidence.
//! - `S9`  — at least one non-placeholder graphics frame
//!   (`gdi_frames + cef_software_frames + cef_accelerated_frames >= 1`)
//!   AND at least one real present (`dxgi_presents >= 1` OR
//!   `metal_presented_frames >= 1`); placeholder-only rendering records
//!   `PlaceholderFrame`.
//! - `S10` — input consumption evidence (`milestones.input_events_consumed`
//!   observed); `None` means the stage is not yet verifiable.
//! - `S11` — audio initialization evidence (`milestones.audio_initialized`
//!   observed); `None` means the stage is not yet verifiable.
//! - `S12` — run health: `guest_exceptions` empty, no illegal host thread
//!   terminations, and Metal encoder lifecycle balanced (created == ended).
//! - `S13` — termination: `GuestExit`, or `HarnessDeadline` when the policy
//!   allows the harness deadline AND every mandatory policy stage
//!   completed.  A deadline fired without policy permission records
//!   `HarnessDeadlineBeforeAllMandatory`; other terminations are recorded
//!   as `StageNotReached(S13)`.

use crate::pe_runtime::ExecutionTermination;
use crate::runner::SteamBootstrapArtifact;
use serde::{Deserialize, Serialize};

/// The Steam bootstrap acceptance stages, S0..S13, in evaluation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Stage {
    /// Program identity + PE parse + main-loop entry.
    S0,
    /// Bootstrap started (first block dispatch of the PE main loop).
    S1,
    /// Manifest opened and fully read.
    S2,
    /// Package-writability probe observed.
    S3,
    /// At least one network exchange recorded.
    S4,
    /// Steam client main thread created.
    S5,
    /// steamwebhelper spawn requested and started.
    S6,
    /// CEF browser created.
    S7,
    /// First CEF paint.
    S8,
    /// First non-placeholder graphics frame + a real present.
    S9,
    /// Guest input consumption evidence.
    S10,
    /// Audio initialization evidence.
    S11,
    /// Run health: no guest exceptions, no illegal host terminations,
    /// balanced Metal encoder lifecycle.
    S12,
    /// Clean termination: guest exit, or harness deadline after all
    /// mandatory stages.
    S13,
}

impl Stage {
    /// Every stage in evaluation order.
    pub const ALL: [Stage; 14] = [
        Stage::S0,
        Stage::S1,
        Stage::S2,
        Stage::S3,
        Stage::S4,
        Stage::S5,
        Stage::S6,
        Stage::S7,
        Stage::S8,
        Stage::S9,
        Stage::S10,
        Stage::S11,
        Stage::S12,
        Stage::S13,
    ];

    /// Stable machine-readable label, e.g. `"S4"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::S0 => "S0",
            Stage::S1 => "S1",
            Stage::S2 => "S2",
            Stage::S3 => "S3",
            Stage::S4 => "S4",
            Stage::S5 => "S5",
            Stage::S6 => "S6",
            Stage::S7 => "S7",
            Stage::S8 => "S8",
            Stage::S9 => "S9",
            Stage::S10 => "S10",
            Stage::S11 => "S11",
            Stage::S12 => "S12",
            Stage::S13 => "S13",
        }
    }
}

/// The mandatory stages for the default acceptance policy: S0..S12.  S13
/// (termination) is evaluated against the policy's deadline rule instead.
pub const MANDATORY_STAGES: [Stage; 13] = [
    Stage::S0,
    Stage::S1,
    Stage::S2,
    Stage::S3,
    Stage::S4,
    Stage::S5,
    Stage::S6,
    Stage::S7,
    Stage::S8,
    Stage::S9,
    Stage::S10,
    Stage::S11,
    Stage::S12,
];

/// Acceptance policy: which stages are mandatory and whether a harness
/// deadline termination is acceptable once every mandatory stage completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteamAcceptancePolicy {
    /// Stages that must be completed for the run to pass.  S13 (termination)
    /// is always evaluated; when present in this list it must also complete.
    pub require_stages: Vec<Stage>,
    /// When true, a `HarnessDeadline` termination satisfies S13 provided
    /// every `require_stages` stage completed before the deadline.
    pub allow_harness_deadline_after_all_mandatory: bool,
}

impl Default for SteamAcceptancePolicy {
    fn default() -> Self {
        Self {
            require_stages: MANDATORY_STAGES.to_vec(),
            allow_harness_deadline_after_all_mandatory: true,
        }
    }
}

/// A single acceptance failure.  `StageNotReached` is the documented
/// stage-missing outcome; every other variant is a run-level problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SteamAcceptanceFailure {
    /// A stage was not reached (documented stage-missing).
    StageNotReached(Stage),
    /// The host terminated a guest thread it was not allowed to kill.
    IllegalHostTermination,
    /// One or more guest exceptions terminated the run.
    GuestException,
    /// Metal command encoders created != encoders ended at collection.
    MetalEncoderImbalance,
    /// Every observed graphics frame was a host placeholder.
    PlaceholderFrame,
    /// The artifact carries `model` execution provenance — the run is a
    /// synthetic zero-touch model, never real Steam execution.
    ModelExecution,
    /// The harness deadline terminated the run although the policy does not
    /// permit deadline termination.
    HarnessDeadlineBeforeAllMandatory,
    /// No network exchange was recorded (S4 unproven).
    NetworkUnproven,
}

/// The outcome of an acceptance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteamAcceptanceResult {
    /// True only when every stage completed and no failure was recorded.
    pub passed: bool,
    /// Stages that completed, in S0..S13 order.
    pub completed_stages: Vec<Stage>,
    /// Stages that did not complete, in S0..S13 order.
    pub missing: Vec<Stage>,
    /// Run-level and stage-level failures recorded during evaluation.
    pub failures: Vec<SteamAcceptanceFailure>,
}

/// Record a stage verdict into the completed/missing lists.
fn record_stage(stage: Stage, done: bool, completed: &mut Vec<Stage>, missing: &mut Vec<Stage>) {
    if done {
        completed.push(stage);
    } else {
        missing.push(stage);
    }
}

/// Evaluate `artifact` against `policy`, returning the structured result.
pub fn evaluate(
    artifact: &SteamBootstrapArtifact,
    policy: &SteamAcceptancePolicy,
) -> SteamAcceptanceResult {
    let steam = &artifact.milestones.steam;
    let graphics = &artifact.milestones.graphics;
    let threads = &artifact.milestones.threads;

    let mut completed: Vec<Stage> = Vec::new();
    let mut missing: Vec<Stage> = Vec::new();
    let mut failures: Vec<SteamAcceptanceFailure> = Vec::new();

    // S0 — program identity + PE parse + main-loop entry.
    let program_sha_present = !artifact.provenance.steam_executable_hash.is_empty()
        && artifact.provenance.steam_executable_hash != "unavailable";
    record_stage(
        Stage::S0,
        program_sha_present && steam.bootstrap_started.is_some(),
        &mut completed,
        &mut missing,
    );

    // S1 — bootstrap started.
    record_stage(
        Stage::S1,
        steam.bootstrap_started.is_some(),
        &mut completed,
        &mut missing,
    );

    // S2 — manifest opened and fully read.
    record_stage(
        Stage::S2,
        steam.manifest_opened.is_some() && steam.manifest_full_read.is_some(),
        &mut completed,
        &mut missing,
    );

    // S3 — package-writability probe.
    record_stage(
        Stage::S3,
        steam.package_writability_probe.is_some(),
        &mut completed,
        &mut missing,
    );

    // S4 — at least one recorded network exchange.
    if artifact.network_summary.is_empty() {
        missing.push(Stage::S4);
        failures.push(SteamAcceptanceFailure::NetworkUnproven);
    } else {
        completed.push(Stage::S4);
    }

    // S5 — client main thread created.
    record_stage(
        Stage::S5,
        steam.client_main_started.is_some(),
        &mut completed,
        &mut missing,
    );

    // S6 — steamwebhelper spawn request + process start.  The artifact's
    // single counter records CreateProcess requests naming steamwebhelper,
    // covering both sub-criteria.
    record_stage(
        Stage::S6,
        steam.webhelper_processes_started >= 1,
        &mut completed,
        &mut missing,
    );

    // S7/S8 — CEF browser created and first paint.
    record_stage(
        Stage::S7,
        steam.cef_browser_created.is_some(),
        &mut completed,
        &mut missing,
    );
    record_stage(
        Stage::S8,
        steam.cef_first_paint.is_some(),
        &mut completed,
        &mut missing,
    );

    // S9 — first non-placeholder frame + a real present.
    let non_placeholder_frames = graphics
        .gdi_frames
        .saturating_add(graphics.cef_software_frames)
        .saturating_add(graphics.cef_accelerated_frames);
    let real_present = graphics.dxgi_presents >= 1 || graphics.metal_presented_frames >= 1;
    if non_placeholder_frames >= 1 && real_present {
        completed.push(Stage::S9);
    } else {
        missing.push(Stage::S9);
        if graphics.host_placeholder_frames > 0 && non_placeholder_frames == 0 {
            failures.push(SteamAcceptanceFailure::PlaceholderFrame);
        }
    }

    // S10/S11 — evidence-based stages; None means not yet verifiable.
    let input_observed = artifact
        .milestones
        .input_events_consumed
        .as_ref()
        .is_some_and(|evidence| evidence.observed);
    record_stage(Stage::S10, input_observed, &mut completed, &mut missing);
    let audio_observed = artifact
        .milestones
        .audio_initialized
        .as_ref()
        .is_some_and(|evidence| evidence.observed);
    record_stage(Stage::S11, audio_observed, &mut completed, &mut missing);

    // S12 — run health.
    let exceptions_empty = artifact.guest_exceptions.is_empty();
    let illegal_terminations_ok = threads.illegal_host_terminations == 0;
    let encoders_balanced = artifact.metal_encoders_created == artifact.metal_encoders_ended;
    if exceptions_empty && illegal_terminations_ok && encoders_balanced {
        completed.push(Stage::S12);
    } else {
        missing.push(Stage::S12);
        if !exceptions_empty {
            failures.push(SteamAcceptanceFailure::GuestException);
        }
        if !illegal_terminations_ok {
            failures.push(SteamAcceptanceFailure::IllegalHostTermination);
        }
        if !encoders_balanced {
            failures.push(SteamAcceptanceFailure::MetalEncoderImbalance);
        }
    }

    // S13 — termination.
    let mandatory_completed = policy
        .require_stages
        .iter()
        .all(|required| completed.contains(required));
    match artifact.termination {
        ExecutionTermination::GuestExit { .. } => completed.push(Stage::S13),
        ExecutionTermination::HarnessDeadline => {
            if policy.allow_harness_deadline_after_all_mandatory && mandatory_completed {
                completed.push(Stage::S13);
            } else if !policy.allow_harness_deadline_after_all_mandatory {
                // The deadline is not a sanctioned termination under this
                // policy at all.
                missing.push(Stage::S13);
                failures.push(SteamAcceptanceFailure::HarnessDeadlineBeforeAllMandatory);
            } else {
                // Deadline sanctioned but mandatory stages were still
                // pending: documented stage-missing, no run-level failure.
                missing.push(Stage::S13);
            }
        }
        _ => {
            missing.push(Stage::S13);
            failures.push(SteamAcceptanceFailure::StageNotReached(Stage::S13));
        }
    }

    // Model provenance: the artifact is a synthetic zero-touch model run,
    // never real Steam execution — rejected outright.
    if artifact.provenance.execution_mode == "model" {
        failures.push(SteamAcceptanceFailure::ModelExecution);
    }

    SteamAcceptanceResult {
        passed: missing.is_empty() && failures.is_empty(),
        completed_stages: completed,
        missing,
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::SteamBootstrapArtifact;
    use crate::steam_milestones::{MilestoneEvidence, RunProvenance, SteamMilestones};

    fn artifact_with(
        milestones: SteamMilestones,
        termination: ExecutionTermination,
        network_summary: Vec<String>,
    ) -> SteamBootstrapArtifact {
        SteamBootstrapArtifact {
            run_id: "test-run".to_string(),
            test_id: "e2e-test".to_string(),
            program_path: r"C:\Steam\Steam.exe".to_string(),
            program_sha256: "ab".repeat(32),
            provenance: RunProvenance {
                execution_mode: "real_pe".to_string(),
                steam_executable_hash:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ..RunProvenance::default()
            },
            milestones,
            last_thunk: None,
            guest_pid: 1,
            jit: crate::pe_runtime::JitTelemetry::default(),
            termination,
            termination_detail: None,
            exit_code: 0,
            instruction_count: Some(100),
            guest_exceptions: Vec::new(),
            network_summary,
            metal_encoders_created: 0,
            metal_encoders_ended: 0,
        }
    }

    fn near_full_milestones() -> SteamMilestones {
        let mut milestones = SteamMilestones::default();
        milestones.steam.bootstrap_started = Some(MilestoneEvidence::default());
        milestones.steam.manifest_opened = Some(MilestoneEvidence::default());
        milestones.steam.manifest_full_read = Some(MilestoneEvidence::default());
        milestones.steam.package_writability_probe = Some(MilestoneEvidence::default());
        milestones.steam.client_main_started = Some(MilestoneEvidence::default());
        milestones.steam.webhelper_processes_started = 1;
        milestones.steam.cef_browser_created = Some(MilestoneEvidence::default());
        milestones.steam.cef_first_paint = Some(MilestoneEvidence::default());
        milestones.graphics.gdi_frames = 3;
        milestones.graphics.dxgi_presents = 2;
        milestones
    }

    /// Milestones with the S10/S11 evidence recorded, so the full ladder
    /// S0-S13 can complete.
    fn full_ladder_milestones() -> SteamMilestones {
        let mut milestones = near_full_milestones();
        milestones.input_events_consumed = Some(MilestoneEvidence {
            observed: true,
            detail: Some("guest consumed input".to_string()),
            ..Default::default()
        });
        milestones.audio_initialized = Some(MilestoneEvidence {
            observed: true,
            detail: Some("audio initialized".to_string()),
            ..Default::default()
        });
        milestones
    }

    #[test]
    fn full_pass_with_guest_exit() {
        let artifact = artifact_with(
            full_ladder_milestones(),
            ExecutionTermination::GuestExit { code: 0 },
            vec!["InternetOpenW -> 1".to_string()],
        );
        let result = evaluate(&artifact, &SteamAcceptancePolicy::default());
        assert!(result.passed, "{result:#?}");
        assert!(result.missing.is_empty());
        assert!(result.failures.is_empty());
        assert_eq!(result.completed_stages, Stage::ALL.to_vec());
    }

    #[test]
    fn harness_deadline_passes_when_mandatory_complete() {
        let artifact = artifact_with(
            full_ladder_milestones(),
            ExecutionTermination::HarnessDeadline,
            vec!["connect -> 0".to_string()],
        );
        let result = evaluate(&artifact, &SteamAcceptancePolicy::default());
        assert!(result.passed, "{result:#?}");
        assert_eq!(result.completed_stages, Stage::ALL.to_vec());
    }

    #[test]
    fn harness_deadline_is_documented_stage_missing_when_mandatory_pending() {
        // S10/S11 evidence absent: the stages are missing, but the deadline
        // was sanctioned, so the only failures are documented stage-missing.
        let artifact = artifact_with(
            near_full_milestones(),
            ExecutionTermination::HarnessDeadline,
            vec!["connect -> 0".to_string()],
        );
        let result = evaluate(&artifact, &SteamAcceptancePolicy::default());
        assert!(!result.passed);
        assert_eq!(result.missing, vec![Stage::S10, Stage::S11, Stage::S13]);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn harness_deadline_rejected_without_policy_permission() {
        let artifact = artifact_with(
            near_full_milestones(),
            ExecutionTermination::HarnessDeadline,
            vec!["connect -> 0".to_string()],
        );
        let policy = SteamAcceptancePolicy {
            allow_harness_deadline_after_all_mandatory: false,
            ..SteamAcceptancePolicy::default()
        };
        let result = evaluate(&artifact, &policy);
        assert!(!result.passed);
        assert!(
            result
                .failures
                .contains(&SteamAcceptanceFailure::HarnessDeadlineBeforeAllMandatory)
        );
    }

    #[test]
    fn network_unproven_records_networkunproven() {
        let artifact = artifact_with(
            near_full_milestones(),
            ExecutionTermination::GuestExit { code: 0 },
            Vec::new(),
        );
        let result = evaluate(&artifact, &SteamAcceptancePolicy::default());
        assert!(!result.passed);
        assert!(result.missing.contains(&Stage::S4));
        assert!(
            result
                .failures
                .contains(&SteamAcceptanceFailure::NetworkUnproven)
        );
    }

    #[test]
    fn placeholder_only_rendering_records_placeholderframe() {
        let mut milestones = near_full_milestones();
        milestones.graphics.gdi_frames = 0;
        milestones.graphics.cef_software_frames = 0;
        milestones.graphics.cef_accelerated_frames = 0;
        milestones.graphics.host_placeholder_frames = 4;
        let artifact = artifact_with(
            milestones,
            ExecutionTermination::GuestExit { code: 0 },
            vec!["connect -> 0".to_string()],
        );
        let result = evaluate(&artifact, &SteamAcceptancePolicy::default());
        assert!(!result.passed);
        assert!(result.missing.contains(&Stage::S9));
        assert!(
            result
                .failures
                .contains(&SteamAcceptanceFailure::PlaceholderFrame)
        );
    }

    #[test]
    fn run_health_failures_are_recorded() {
        let mut milestones = near_full_milestones();
        milestones.threads.illegal_host_terminations = 1;
        let mut artifact = artifact_with(
            milestones,
            ExecutionTermination::GuestExit { code: 0 },
            vec!["connect -> 0".to_string()],
        );
        artifact
            .guest_exceptions
            .push(crate::canonical::GuestException {
                code: 0xc0000005,
                addr: Some("0x401000".to_string()),
                module: "Steam.exe".to_string(),
                tid: 3,
            });
        artifact.metal_encoders_created = 5;
        artifact.metal_encoders_ended = 4;
        let result = evaluate(&artifact, &SteamAcceptancePolicy::default());
        assert!(!result.passed);
        assert!(result.missing.contains(&Stage::S12));
        assert!(
            result
                .failures
                .contains(&SteamAcceptanceFailure::GuestException)
        );
        assert!(
            result
                .failures
                .contains(&SteamAcceptanceFailure::IllegalHostTermination)
        );
        assert!(
            result
                .failures
                .contains(&SteamAcceptanceFailure::MetalEncoderImbalance)
        );
    }

    #[test]
    fn model_execution_is_rejected() {
        let mut artifact = artifact_with(
            near_full_milestones(),
            ExecutionTermination::GuestExit { code: 0 },
            vec!["connect -> 0".to_string()],
        );
        artifact.provenance.execution_mode = "model".to_string();
        let result = evaluate(&artifact, &SteamAcceptancePolicy::default());
        assert!(!result.passed);
        assert!(
            result
                .failures
                .contains(&SteamAcceptanceFailure::ModelExecution)
        );
    }

    #[test]
    fn evidence_stages_require_observed_evidence() {
        let mut milestones = near_full_milestones();
        milestones.input_events_consumed = Some(MilestoneEvidence {
            observed: false,
            detail: Some("probe ran, no events".to_string()),
            ..Default::default()
        });
        milestones.audio_initialized = Some(MilestoneEvidence {
            observed: true,
            detail: Some("DSOUND init ok".to_string()),
            ..Default::default()
        });
        let artifact = artifact_with(
            milestones,
            ExecutionTermination::GuestExit { code: 0 },
            vec!["connect -> 0".to_string()],
        );
        let result = evaluate(&artifact, &SteamAcceptancePolicy::default());
        assert!(!result.passed);
        assert_eq!(result.missing, vec![Stage::S10]);
        assert!(result.completed_stages.contains(&Stage::S11));
    }

    #[test]
    fn stage_labels_are_stable() {
        assert_eq!(Stage::S0.as_str(), "S0");
        assert_eq!(Stage::S13.as_str(), "S13");
        assert_eq!(Stage::ALL.len(), 14);
        assert_eq!(MANDATORY_STAGES.len(), 13);
    }

    #[test]
    fn result_serializes_as_json() {
        let artifact = artifact_with(
            full_ladder_milestones(),
            ExecutionTermination::GuestExit { code: 0 },
            vec!["connect -> 0".to_string()],
        );
        let result = evaluate(&artifact, &SteamAcceptancePolicy::default());
        let json = serde_json::to_string(&result).expect("serialize result");
        assert!(json.contains("\"passed\":true"));
        assert!(json.contains("\"completed_stages\""));
    }
}
