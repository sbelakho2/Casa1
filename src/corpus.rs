//! Real-application corpus harness.
//!
//! Discovers Windows `.exe`/`.dll` files, runs each *executable* through the
//! production `casa1-runner` binary in a fresh sandboxed working directory, and
//! records a deterministic, comparable outcome.  The harness is deliberately
//! sequential: titles never run in parallel by default, so timing/RSS and
//! classification are attributable to one title at a time.
//!
//! # Exact timeout/cancel semantics
//!
//! `timeout_ms` is authoritative.  The harness sets
//! `CASA1_PE_RUNTIME_DEADLINE_SECS=ceil(timeout_ms/1000)` on the runner as a
//! cooperative first line of defense (the runtime stops at a safepoint and
//! reports `HarnessDeadline`).  Independently, if the runner process is still
//! alive at `timeout_ms`, the harness sends `SIGKILL` to the runner's whole
//! process group and reaps it before continuing.  A wrapper kill is always
//! classified `timeout` with `cancel.mechanism =
//! "wrapper_sigkill_process_group"`; a runtime deadline is classified
//! `timeout` with `cancel.mechanism = "runtime_deadline"`.
//!
//! # Resume safety
//!
//! The previous `--out` report is read (when present).  A title whose content
//! SHA-256 and timeout are unchanged is carried forward with
//! `execution = "skipped_unchanged"` and is **not** executed again.  Any
//! content change, timeout change, or `--force` re-runs the title.

use crate::error::{AppError, AppResult};
use crate::ge::{GameEnvironment, GeArch};
use crate::pe;
use crate::reason::ReasonCode;
use crate::runner::{JitMode, RunIntent, RunnerJob};
use crate::trace::TraceCategory;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// Schema version for `corpus.json`.
pub const CORPUS_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Corpus-specific reason codes (outside the runtime ReasonCode ranges).
pub const RC_CORPUS_LIBRARY_NOT_RUNNABLE: (u32, &str) = (4000, "RC_CORPUS_LIBRARY_NOT_RUNNABLE");
pub const RC_CORPUS_TIMEOUT: (u32, &str) = (4001, "RC_CORPUS_TIMEOUT");
pub const RC_CORPUS_RUNNER_UNAVAILABLE: (u32, &str) = (4002, "RC_CORPUS_RUNNER_UNAVAILABLE");
pub const RC_CORPUS_RUNNER_CRASHED: (u32, &str) = (4003, "RC_CORPUS_RUNNER_CRASHED");

#[derive(Debug, Clone)]
pub struct CorpusConfig {
    pub corpus_dir: PathBuf,
    pub out: PathBuf,
    pub timeout_ms: u64,
    /// Root for per-title sandboxes.  Defaults to `<out parent>/.casa1-corpus-work`.
    pub work_dir: Option<PathBuf>,
    pub force: bool,
    /// Optional explicit `casa1-runner` path (defaults to a sibling binary of
    /// the current executable, then `CASA1_RUNNER`).
    pub runner: Option<PathBuf>,
    /// Optional cooperative runtime deadline override (seconds).  Production
    /// callers leave this `None`; the wrapper deadline remains authoritative.
    pub runtime_deadline_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusReport {
    pub schema_version: u32,
    pub timeout_ms: u64,
    pub corpus_fingerprint: String,
    pub discovered_title_count: usize,
    pub titles: Vec<TitleReport>,
    pub summary: CorpusSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusSummary {
    pub executed: usize,
    pub skipped_unchanged: usize,
    pub clean_exit: usize,
    pub non_zero_exit: usize,
    pub missing_import: usize,
    pub crash: usize,
    pub timeout: usize,
    pub instruction_budget: usize,
    pub startup_error: usize,
    pub invalid_image: usize,
    pub unsupported_image: usize,
    pub library_not_runnable: usize,
    pub runner_unavailable: usize,
}

impl Default for CorpusSummary {
    fn default() -> Self {
        Self {
            executed: 0,
            skipped_unchanged: 0,
            clean_exit: 0,
            non_zero_exit: 0,
            missing_import: 0,
            crash: 0,
            timeout: 0,
            instruction_budget: 0,
            startup_error: 0,
            invalid_image: 0,
            unsupported_image: 0,
            library_not_runnable: 0,
            runner_unavailable: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Executed,
    SkippedUnchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeClass {
    CleanExit,
    NonZeroExit,
    MissingImport,
    Crash,
    Timeout,
    InstructionBudget,
    StartupError,
    InvalidImage,
    UnsupportedImage,
    LibraryNotRunnable,
    RunnerUnavailable,
}

impl OutcomeClass {
    fn count(self, summary: &mut CorpusSummary) {
        match self {
            Self::CleanExit => summary.clean_exit += 1,
            Self::NonZeroExit => summary.non_zero_exit += 1,
            Self::MissingImport => summary.missing_import += 1,
            Self::Crash => summary.crash += 1,
            Self::Timeout => summary.timeout += 1,
            Self::InstructionBudget => summary.instruction_budget += 1,
            Self::StartupError => summary.startup_error += 1,
            Self::InvalidImage => summary.invalid_image += 1,
            Self::UnsupportedImage => summary.unsupported_image += 1,
            Self::LibraryNotRunnable => summary.library_not_runnable += 1,
            Self::RunnerUnavailable => summary.runner_unavailable += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TitleReport {
    /// Corpus-relative path using `/` separators.
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    /// `executable` (.exe) or `library` (.dll).
    pub kind: String,
    pub execution: ExecutionState,
    pub classification: OutcomeClass,
    /// First failure reason code, when the title failed.
    pub reason_code: Option<u32>,
    pub reason_name: Option<String>,
    /// Runner process exit status (`None` when killed by a signal).
    pub exit_code: Option<i32>,
    /// Guest process exit code (`Some` only for a real `GuestExit`).
    pub guest_exit_code: Option<i32>,
    /// Structured runner termination (`GuestExit`, `HarnessDeadline`, ...).
    pub termination: Option<String>,
    /// Human-readable status: `exited:0`, `signaled:9`, `timeout`, ... .
    pub status: String,
    pub startup_ms: u64,
    pub peak_rss_bytes: u64,
    /// True when the title ran with a fresh per-title working directory and GE
    /// root under the corpus work root.
    pub sandboxed_working_dir: bool,
    /// Failure before any real guest exit (startup error, invalid image,
    /// unsupported image, or runtime crash).
    pub crashed_early: bool,
    pub timed_out: bool,
    pub cancel: Option<CancelInfo>,
    /// SHA-256 of stdout/stderr, so the outcome hash is stable and bounded.
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    /// Deterministic hash of the outcome-defining fields (no timing/RSS/paths).
    pub outcome_hash: String,
    /// Sanitized first failure detail (absolute paths replaced with tags).
    pub detail: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelInfo {
    /// `runtime_deadline` or `wrapper_sigkill_process_group`.
    pub mechanism: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
struct DiscoveredTitle {
    path: String,
    absolute: PathBuf,
    sha256: String,
    size_bytes: u64,
    kind: TitleKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TitleKind {
    Executable,
    Library,
}

impl TitleKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Library => "library",
        }
    }
}

/// Run (or resume) a corpus and write the deterministic JSON report.
pub fn run_corpus(config: &CorpusConfig) -> AppResult<CorpusReport> {
    if config.timeout_ms == 0 {
        return Err(AppError::new(
            ReasonCode::RcInvalidParameter,
            "timeout_ms must be greater than zero",
        ));
    }
    let titles = discover(&config.corpus_dir)?;
    let corpus_fingerprint = corpus_fingerprint(&titles);
    let previous = load_previous(&config.out);
    let runner = resolve_runner(config.runner.as_deref());
    let work_root = config.work_dir.clone().unwrap_or_else(|| {
        config
            .out
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".casa1-corpus-work")
    });

    let mut reports = Vec::with_capacity(titles.len());
    let mut summary = CorpusSummary::default();
    for title in &titles {
        let reused = if config.force {
            None
        } else {
            previous.as_ref().and_then(|report| {
                report.titles.iter().find(|candidate| {
                    candidate.path == title.path
                        && candidate.sha256 == title.sha256
                        && candidate.timeout_ms == config.timeout_ms
                        && candidate.kind == title.kind.as_str()
                })
            })
        };
        let mut report = match reused {
            Some(previous_title) => {
                summary.skipped_unchanged += 1;
                let mut report = previous_title.clone();
                report.execution = ExecutionState::SkippedUnchanged;
                report
            }
            None => {
                summary.executed += 1;
                run_title(title, config, &work_root, runner.as_deref())
            }
        };
        report.execution = if reused.is_some() {
            ExecutionState::SkippedUnchanged
        } else {
            ExecutionState::Executed
        };
        report.classification.count(&mut summary);
        reports.push(report);
    }

    let report = CorpusReport {
        schema_version: CORPUS_SCHEMA_VERSION,
        timeout_ms: config.timeout_ms,
        corpus_fingerprint,
        discovered_title_count: titles.len(),
        titles: reports,
        summary,
    };
    write_report(&report, &config.out)?;
    Ok(report)
}

/// Write the deterministic JSON with a trailing newline.
pub fn write_report(report: &CorpusReport, out: &Path) -> AppResult<()> {
    let json = serde_json::to_string_pretty(report).map_err(|error| {
        AppError::new(ReasonCode::RcIo, "failed to encode corpus report")
            .with_hint(error.to_string())
    })?;
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", parent.display()),
                &error,
            )
        })?;
    }
    fs::write(out, format!("{json}\n")).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write {}", out.display()),
            &error,
        )
    })
}

/// Human-readable one-line-per-title summary (deterministic).
pub fn human_summary(report: &CorpusReport) -> String {
    let mut lines = vec![format!(
        "Casa1 corpus: {} title(s), {} executed, {} skipped unchanged, fingerprint {}",
        report.discovered_title_count,
        report.summary.executed,
        report.summary.skipped_unchanged,
        report.corpus_fingerprint
    )];
    for title in &report.titles {
        lines.push(format!(
            "  {} [{}] {:?} reason={} exit={:?} guest_exit={:?} startup_ms={} rss={} hash={}",
            title.path,
            title.kind,
            title.classification,
            title.reason_name.as_deref().unwrap_or("-"),
            title.exit_code,
            title.guest_exit_code,
            title.startup_ms,
            title.peak_rss_bytes,
            title.outcome_hash
        ));
    }
    lines.join("\n")
}

fn discover(root: &Path) -> AppResult<Vec<DiscoveredTitle>> {
    if !root.is_dir() {
        return Err(AppError::new(
            ReasonCode::RcFsNotFound,
            format!("corpus directory not found: {}", root.display()),
        ));
    }
    let mut titles = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("failed to walk corpus {}: {error}", root.display()),
                ));
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase());
        let kind = match extension.as_deref() {
            Some("exe") => TitleKind::Executable,
            Some("dll") => TitleKind::Library,
            _ => continue,
        };
        let relative = relative_slash(root, path);
        let bytes = fs::read(path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to read {}", path.display()),
                &error,
            )
        })?;
        titles.push(DiscoveredTitle {
            path: relative,
            absolute: path.to_path_buf(),
            sha256: util::sha256_bytes(&bytes),
            size_bytes: bytes.len() as u64,
            kind,
        });
    }
    titles.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(titles)
}

fn corpus_fingerprint(titles: &[DiscoveredTitle]) -> String {
    let mut lines = titles
        .iter()
        .map(|title| format!("{}\0{}\0{}", title.kind.as_str(), title.path, title.sha256))
        .collect::<Vec<_>>();
    lines.sort();
    util::sha256_bytes(lines.join("\n").as_bytes())
}

fn load_previous(out: &Path) -> Option<CorpusReport> {
    let bytes = fs::read(out).ok()?;
    let report = serde_json::from_slice::<CorpusReport>(&bytes).ok()?;
    if report.schema_version == CORPUS_SCHEMA_VERSION {
        Some(report)
    } else {
        None
    }
}

fn resolve_runner(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        // The runner is spawned with the title's sandbox as `cwd`, so a
        // relative `--runner` path must be resolved against the caller's cwd
        // now, not against the sandbox later.
        return Some(fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()));
    }
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        let sibling = parent.join("casa1-runner");
        if sibling.is_file() {
            return Some(sibling);
        }
    }
    std::env::var_os("CASA1_RUNNER").map(PathBuf::from)
}

fn run_title(
    title: &DiscoveredTitle,
    config: &CorpusConfig,
    work_root: &Path,
    runner: Option<&Path>,
) -> TitleReport {
    if title.kind == TitleKind::Library {
        return static_report(
            title,
            config.timeout_ms,
            OutcomeClass::LibraryNotRunnable,
            RC_CORPUS_LIBRARY_NOT_RUNNABLE,
            "DLL is an importable module, not a process entry point".to_string(),
        );
    }

    let bytes = match fs::read(&title.absolute) {
        Ok(bytes) => bytes,
        Err(error) => {
            return static_report(
                title,
                config.timeout_ms,
                OutcomeClass::InvalidImage,
                (ReasonCode::RcIo.as_u32(), ReasonCode::RcIo.name()),
                format!("failed to read title: {error}"),
            );
        }
    };
    let parsed = match pe::parse(&bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return static_report(
                title,
                config.timeout_ms,
                OutcomeClass::InvalidImage,
                (error.code.as_u32(), error.code.name()),
                error.message,
            );
        }
    };
    let arch = match parsed.machine {
        0x8664 => GeArch::X64,
        0x014c => GeArch::X86,
        machine => {
            return static_report(
                title,
                config.timeout_ms,
                OutcomeClass::UnsupportedImage,
                (
                    ReasonCode::RcUnsupportedPlatform.as_u32(),
                    ReasonCode::RcUnsupportedPlatform.name(),
                ),
                format!("unsupported PE machine 0x{machine:04x}"),
            );
        }
    };

    let Some(runner) = runner else {
        return static_report(
            title,
            config.timeout_ms,
            OutcomeClass::RunnerUnavailable,
            RC_CORPUS_RUNNER_UNAVAILABLE,
            "casa1-runner binary not found (pass --runner or build the bin)".to_string(),
        );
    };

    let sandbox = work_root.join(format!("title-{}", &title.sha256[..16]));
    if sandbox.exists()
        && let Err(error) = fs::remove_dir_all(&sandbox)
    {
        return static_report(
            title,
            config.timeout_ms,
            OutcomeClass::StartupError,
            (ReasonCode::RcIo.as_u32(), ReasonCode::RcIo.name()),
            format!("failed to reset sandbox: {error}"),
        );
    }
    let cwd = sandbox.join("cwd");
    if let Err(error) = fs::create_dir_all(&cwd) {
        return static_report(
            title,
            config.timeout_ms,
            OutcomeClass::StartupError,
            (ReasonCode::RcIo.as_u32(), ReasonCode::RcIo.name()),
            format!("failed to create sandbox: {error}"),
        );
    }
    let ge = match GameEnvironment::create_in(sandbox.join("ge"), "corpus", arch, "win11-23h2") {
        Ok(ge) => ge,
        Err(error) => {
            return static_report(
                title,
                config.timeout_ms,
                OutcomeClass::StartupError,
                (error.code.as_u32(), error.code.name()),
                error.message,
            );
        }
    };

    let job = RunnerJob {
        ge_name: ge.config.name.clone(),
        ge_root: ge.root.clone(),
        program: title.absolute.clone(),
        args: Vec::new(),
        cwd: cwd.clone(),
        env: BTreeMap::new(),
        dtm: true,
        intent: RunIntent::Run,
        trace_categories: vec![TraceCategory::Process],
        test_id: format!("corpus-{}", &title.sha256[..16]),
        jit_mode: JitMode::Auto,
        steam_ipc: false,
        window_width: None,
        window_height: None,
        thread_start: None,
    };
    let job_path = sandbox.join("job.json");
    let job_json = match serde_json::to_vec_pretty(&job) {
        Ok(json) => json,
        Err(error) => {
            return static_report(
                title,
                config.timeout_ms,
                OutcomeClass::StartupError,
                (ReasonCode::RcIo.as_u32(), ReasonCode::RcIo.name()),
                format!("failed to encode job: {error}"),
            );
        }
    };
    if let Err(error) = fs::write(&job_path, job_json) {
        return static_report(
            title,
            config.timeout_ms,
            OutcomeClass::StartupError,
            (ReasonCode::RcIo.as_u32(), ReasonCode::RcIo.name()),
            format!("failed to write job: {error}"),
        );
    }

    let runtime_deadline_secs = config
        .runtime_deadline_secs
        .unwrap_or_else(|| (config.timeout_ms / 1000).max(1));
    let raw = match execute_runner(
        runner,
        &job_path,
        &cwd,
        Duration::from_millis(config.timeout_ms),
        runtime_deadline_secs,
    ) {
        Ok(raw) => raw,
        Err(error) => {
            return static_report(
                title,
                config.timeout_ms,
                OutcomeClass::StartupError,
                (error.code.as_u32(), error.code.name()),
                error.message,
            );
        }
    };

    classify(title, config, &raw, &job.program, &sandbox)
}

fn static_report(
    title: &DiscoveredTitle,
    timeout_ms: u64,
    classification: OutcomeClass,
    reason: (u32, &str),
    detail: String,
) -> TitleReport {
    let status = match classification {
        OutcomeClass::LibraryNotRunnable => "not-runnable:dll".to_string(),
        OutcomeClass::RunnerUnavailable => "not-runnable:runner-unavailable".to_string(),
        _ => "not-runnable".to_string(),
    };
    let mut report = TitleReport {
        path: title.path.clone(),
        sha256: title.sha256.clone(),
        size_bytes: title.size_bytes,
        kind: title.kind.as_str().to_string(),
        execution: ExecutionState::Executed,
        classification,
        reason_code: Some(reason.0),
        reason_name: Some(reason.1.to_string()),
        exit_code: None,
        guest_exit_code: None,
        termination: None,
        status,
        startup_ms: 0,
        peak_rss_bytes: 0,
        sandboxed_working_dir: false,
        crashed_early: true,
        timed_out: false,
        cancel: None,
        stdout_sha256: util::sha256_bytes(b""),
        stderr_sha256: util::sha256_bytes(b""),
        outcome_hash: String::new(),
        detail: Some(detail),
        timeout_ms,
    };
    report.outcome_hash = outcome_hash(&report);
    report
}

fn classify(
    title: &DiscoveredTitle,
    config: &CorpusConfig,
    raw: &RawRun,
    program: &Path,
    sandbox: &Path,
) -> TitleReport {
    let stdout = raw.stdout.as_slice();
    let stderr = raw.stderr.as_slice();
    let stdout_text = String::from_utf8_lossy(stdout);
    let stderr_text = String::from_utf8_lossy(stderr);
    let outcome = parse_runner_outcome(&stdout_text);
    let error_response = parse_error_response(&stderr_text);

    let mut classification: OutcomeClass;
    let mut reason: Option<(u32, String)> = None;
    let mut guest_exit_code = None;
    let mut termination = None;
    let mut cancel = None;
    let mut timed_out = raw.timed_out;
    let mut status = status_text(&raw.status);
    let mut detail = None;
    let mut guest_stdout = String::new();
    let mut guest_stderr = String::new();

    if raw.timed_out {
        classification = OutcomeClass::Timeout;
        reason = Some((RC_CORPUS_TIMEOUT.0, RC_CORPUS_TIMEOUT.1.to_string()));
        cancel = Some(CancelInfo {
            mechanism: "wrapper_sigkill_process_group".to_string(),
            detail: format!(
                "runner exceeded {} ms; sent SIGKILL to process group and reaped",
                config.timeout_ms
            ),
        });
    } else if let Some(outcome) = outcome {
        termination = Some(outcome.termination.clone());
        guest_exit_code = outcome.guest_exit_code;
        guest_stdout = outcome.canonical_output.stdout.clone();
        guest_stderr = outcome.canonical_output.stderr.clone();
        if outcome.termination.starts_with("GuestExit") {
            let code = outcome
                .guest_exit_code
                .unwrap_or(outcome.canonical_output.exit_code);
            classification = if code == 0 {
                OutcomeClass::CleanExit
            } else {
                OutcomeClass::NonZeroExit
            };
        } else if outcome.termination == "HarnessDeadline" {
            timed_out = true;
            classification = OutcomeClass::Timeout;
            reason = Some((RC_CORPUS_TIMEOUT.0, RC_CORPUS_TIMEOUT.1.to_string()));
            cancel = Some(CancelInfo {
                mechanism: "runtime_deadline".to_string(),
                detail: format!(
                    "runtime hit CASA1_PE_RUNTIME_DEADLINE_SECS={} before the wrapper deadline",
                    (config.timeout_ms / 1000).max(1)
                ),
            });
        } else if outcome.termination == "InstructionBudget" {
            classification = OutcomeClass::InstructionBudget;
            reason = Some((
                ReasonCode::RcBufferLimitExceeded.as_u32(),
                ReasonCode::RcBufferLimitExceeded.name().to_string(),
            ));
        } else {
            let termination_detail = outcome.termination_detail.unwrap_or_default();
            detail = Some(sanitize_detail(&termination_detail, program, sandbox));
            classification = if termination_detail.contains("unsupported PE import")
                || termination_detail.contains("missing import")
            {
                OutcomeClass::MissingImport
            } else {
                OutcomeClass::Crash
            };
            reason = detail_reason(&termination_detail);
            if let Some(first) = outcome.canonical_output.guest_exceptions.first() {
                classification = OutcomeClass::Crash;
                reason = Some((
                    ReasonCode::SehException.as_u32(),
                    ReasonCode::SehException.name().to_string(),
                ));
                detail = Some(format!(
                    "guest exception 0x{:08x} in {} at {}",
                    first.code,
                    first.module,
                    first.addr.as_deref().unwrap_or("<unknown>")
                ));
            }
        }
    } else if let Some(error) = error_response {
        classification = if error.reason_name == ReasonCode::RcImportMissing.name() {
            OutcomeClass::MissingImport
        } else {
            OutcomeClass::StartupError
        };
        reason = Some((error.reason_code, error.reason_name));
        detail = Some(sanitize_detail(&error.message, program, sandbox));
    } else if status_signal(&raw.status).is_some() {
        classification = OutcomeClass::Crash;
        reason = Some((
            RC_CORPUS_RUNNER_CRASHED.0,
            RC_CORPUS_RUNNER_CRASHED.1.to_string(),
        ));
        detail = Some(format!(
            "runner terminated by signal {} without a JSON outcome",
            status_signal(&raw.status).unwrap_or_default()
        ));
    } else {
        classification = OutcomeClass::StartupError;
        reason = Some((
            ReasonCode::RcRunnerProtocolInvalid.as_u32(),
            ReasonCode::RcRunnerProtocolInvalid.name().to_string(),
        ));
        detail = Some("runner produced no JSON outcome".to_string());
    }

    if timed_out {
        status = "timeout".to_string();
    }
    let crashed_early = matches!(
        classification,
        OutcomeClass::Crash
            | OutcomeClass::MissingImport
            | OutcomeClass::StartupError
            | OutcomeClass::InvalidImage
            | OutcomeClass::UnsupportedImage
    );
    let mut report = TitleReport {
        path: title.path.clone(),
        sha256: title.sha256.clone(),
        size_bytes: title.size_bytes,
        kind: title.kind.as_str().to_string(),
        execution: ExecutionState::Executed,
        classification,
        reason_code: reason.as_ref().map(|reason| reason.0),
        reason_name: reason.map(|reason| reason.1),
        exit_code: raw.status.code(),
        guest_exit_code,
        termination,
        status,
        startup_ms: raw.elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        peak_rss_bytes: raw.peak_rss_bytes,
        sandboxed_working_dir: true,
        crashed_early,
        timed_out,
        cancel,
        stdout_sha256: util::sha256_bytes(guest_stdout.as_bytes()),
        stderr_sha256: util::sha256_bytes(guest_stderr.as_bytes()),
        outcome_hash: String::new(),
        detail,
        timeout_ms: config.timeout_ms,
    };
    report.outcome_hash = outcome_hash(&report);
    report
}

fn status_text(status: &ExitStatus) -> String {
    if let Some(signal) = status_signal(status) {
        format!("signaled:{signal}")
    } else if let Some(code) = status.code() {
        format!("exited:{code}")
    } else {
        "unknown".to_string()
    }
}

fn status_signal(status: &ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

fn sanitize_detail(detail: &str, program: &Path, sandbox: &Path) -> String {
    let mut sanitized = detail.to_string();
    for (needle, replacement) in [
        (program.display().to_string(), "<title>"),
        (sandbox.display().to_string(), "<sandbox>"),
    ] {
        if !needle.is_empty() {
            sanitized = sanitized.replace(&needle, replacement);
        }
    }
    sanitized
}

fn detail_reason(detail: &str) -> Option<(u32, String)> {
    let name = detail.split(':').next()?.trim();
    match name {
        "RC_UNIMPL_INSN" => Some((
            ReasonCode::RcUnimplInsn.as_u32(),
            ReasonCode::RcUnimplInsn.name().to_string(),
        )),
        "RC_IMPORT_MISSING" => Some((
            ReasonCode::RcImportMissing.as_u32(),
            ReasonCode::RcImportMissing.name().to_string(),
        )),
        "RC_PE_PARSE_INVALID" => Some((
            ReasonCode::RcPeParseInvalid.as_u32(),
            ReasonCode::RcPeParseInvalid.name().to_string(),
        )),
        "RC_MEMORY_ACCESS_VIOLATION" => Some((
            ReasonCode::RcMemoryAccessViolation.as_u32(),
            ReasonCode::RcMemoryAccessViolation.name().to_string(),
        )),
        "RC_UNSUPPORTED_PLATFORM" => Some((
            ReasonCode::RcUnsupportedPlatform.as_u32(),
            ReasonCode::RcUnsupportedPlatform.name().to_string(),
        )),
        _ => None,
    }
}

fn outcome_hash(report: &TitleReport) -> String {
    let value = serde_json::json!({
        "path": report.path,
        "sha256": report.sha256,
        "kind": report.kind,
        "classification": report.classification,
        "reason_code": report.reason_code,
        "reason_name": report.reason_name,
        "exit_code": report.exit_code,
        "guest_exit_code": report.guest_exit_code,
        "termination": report.termination,
        "status": report.status,
        "timed_out": report.timed_out,
        "crashed_early": report.crashed_early,
        "stdout_sha256": report.stdout_sha256,
        "stderr_sha256": report.stderr_sha256,
    });
    util::sha256_bytes(value.to_string().as_bytes())
}

#[derive(Debug, Clone, Deserialize)]
struct RunnerOutcomeView {
    #[serde(default)]
    canonical_output: CanonicalOutputView,
    #[serde(default)]
    termination: String,
    #[serde(default)]
    termination_detail: Option<String>,
    #[serde(default)]
    guest_exit_code: Option<i32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CanonicalOutputView {
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    exit_code: i32,
    #[serde(default)]
    guest_exceptions: Vec<GuestExceptionView>,
}

#[derive(Debug, Clone, Deserialize)]
struct GuestExceptionView {
    code: u32,
    #[serde(default)]
    addr: Option<String>,
    #[serde(default)]
    module: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ErrorResponseView {
    reason_code: u32,
    reason_name: String,
    #[serde(default)]
    message: String,
}

fn parse_runner_outcome(stdout: &str) -> Option<RunnerOutcomeView> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }
    let outcome = serde_json::from_str::<RunnerOutcomeView>(trimmed).ok()?;
    if outcome.termination.is_empty() {
        return None;
    }
    Some(outcome)
}

fn parse_error_response(stderr: &str) -> Option<ErrorResponseView> {
    for line in stderr.lines().rev() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        if let Ok(response) = serde_json::from_str::<ErrorResponseView>(trimmed)
            && !response.reason_name.is_empty()
        {
            return Some(response);
        }
    }
    None
}

struct RawRun {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    elapsed: Duration,
    peak_rss_bytes: u64,
    timed_out: bool,
}

#[cfg(unix)]
fn execute_runner(
    runner: &Path,
    job_path: &Path,
    cwd: &Path,
    timeout: Duration,
    runtime_deadline_secs: u64,
) -> AppResult<RawRun> {
    use std::os::unix::process::CommandExt as _;
    use std::os::unix::process::ExitStatusExt as _;

    let mut command = Command::new(runner);
    command
        .arg("--job")
        .arg(job_path)
        .current_dir(cwd)
        .env(
            "CASA1_PE_RUNTIME_DEADLINE_SECS",
            runtime_deadline_secs.to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Own process group: a timeout kill reaches the runner's children too and
    // can never signal the harness or the user's shell.
    command.process_group(0);
    let mut child = command.spawn().map_err(|error| {
        AppError::from_io(
            ReasonCode::RcRunnerSpawnFailed,
            format!("failed to spawn {}", runner.display()),
            &error,
        )
    })?;
    let pid = child.id() as libc::pid_t;
    let stdout = child.stdout.take().ok_or_else(|| {
        AppError::new(
            ReasonCode::RcRunnerProtocolInvalid,
            "runner stdout pipe was not created",
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        AppError::new(
            ReasonCode::RcRunnerProtocolInvalid,
            "runner stderr pipe was not created",
        )
    })?;
    let stdout_reader = std::thread::spawn(move || read_all(stdout));
    let stderr_reader = std::thread::spawn(move || read_all(stderr));

    let started = Instant::now();
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let mut raw_status: libc::c_int = 0;
    let mut timed_out = false;
    loop {
        let result = unsafe { libc::wait4(pid, &mut raw_status, libc::WNOHANG, &mut usage) };
        if result == pid {
            break;
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ECHILD) => {
                    // Another reaper won the race; fall back to std's status.
                    if let Ok(Some(status)) = child.try_wait() {
                        raw_status = status.into_raw();
                        break;
                    }
                    return Err(AppError::from_io(
                        ReasonCode::RcRunnerProtocolInvalid,
                        "runner child disappeared while waiting",
                        &error,
                    ));
                }
                _ => {
                    return Err(AppError::from_io(
                        ReasonCode::RcRunnerProtocolInvalid,
                        "failed to wait for runner",
                        &error,
                    ));
                }
            }
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            // SAFETY: pid is our unreaped child and the negative pid targets
            // exactly the process group created above.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            loop {
                let reaped = unsafe { libc::wait4(pid, &mut raw_status, 0, &mut usage) };
                if reaped == pid {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if error.raw_os_error() == Some(libc::ECHILD) {
                    break;
                }
                return Err(AppError::from_io(
                    ReasonCode::RcRunnerProtocolInvalid,
                    "failed to reap timed-out runner",
                    &error,
                ));
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let elapsed = started.elapsed();
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    let status = ExitStatus::from_raw(raw_status);
    let raw_rss = usage.ru_maxrss.max(0) as u64;
    let peak_rss_bytes = if cfg!(target_os = "macos") {
        raw_rss
    } else {
        raw_rss.saturating_mul(1024)
    };
    Ok(RawRun {
        status,
        stdout,
        stderr,
        elapsed,
        peak_rss_bytes,
        timed_out,
    })
}

#[cfg(not(unix))]
fn execute_runner(
    runner: &Path,
    job_path: &Path,
    cwd: &Path,
    _timeout: Duration,
    runtime_deadline_secs: u64,
) -> AppResult<RawRun> {
    let mut command = Command::new(runner);
    command
        .arg("--job")
        .arg(job_path)
        .current_dir(cwd)
        .env(
            "CASA1_PE_RUNTIME_DEADLINE_SECS",
            runtime_deadline_secs.to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let output = command.output().map_err(|error| {
        AppError::from_io(
            ReasonCode::RcRunnerSpawnFailed,
            format!("failed to spawn {}", runner.display()),
            &error,
        )
    })?;
    Ok(RawRun {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
        elapsed: started.elapsed(),
        peak_rss_bytes: 0,
        timed_out: false,
    })
}

fn read_all(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader.read_to_end(&mut bytes);
    bytes
}

fn relative_slash(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
