//! Corpus harness tests: synthetic PE titles only, no real Windows apps and no
//! network.  Each fixture is emitted at test time.

mod pe_fixture;

use casa1::corpus::{
    CorpusConfig, ExecutionState, OutcomeClass, RC_CORPUS_LIBRARY_NOT_RUNNABLE, RC_CORPUS_TIMEOUT,
    run_corpus,
};
use pe_fixture::{
    ImportSpec, ImportSymbolSpec, PeSpec, build, call_iat_then_exit, crash_code, exit_process_code,
    hang_code, patch_text, trivial_exit_code,
};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn runner_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("CASA1_RUNNER") {
        return PathBuf::from(path);
    }
    // `src/bin/casa1-runner.rs` is a normal package binary; the central gate
    // and the corpus CI script build it before running tests.  Resolve the
    // sibling of the test executable instead of `CARGO_BIN_EXE_*` so the test
    // target stays the last artifact selected by `ci/run_tests.py`.
    let executable = std::env::current_exe().expect("test executable path");
    let candidate = executable
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target dir")
        .join("casa1-runner");
    assert!(
        candidate.is_file(),
        "casa1-runner is not built at {}; run `cargo build --bin casa1-runner` or set CASA1_RUNNER",
        candidate.display()
    );
    candidate
}

fn write_built(root: &Path, relative: &str, spec: &PeSpec) -> PathBuf {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create title dir");
    }
    let built = build(spec);
    fs::write(&path, &built.bytes).expect("write title");
    path
}

fn corpus_config(corpus: &Path, out: &Path, work: &Path, timeout_ms: u64) -> CorpusConfig {
    CorpusConfig {
        corpus_dir: corpus.to_path_buf(),
        out: out.to_path_buf(),
        timeout_ms,
        work_dir: Some(work.to_path_buf()),
        force: false,
        runner: Some(runner_binary()),
        // Keep the cooperative deadline short so the hang title proves the
        // runtime-deadline path without waiting for the full title timeout.
        runtime_deadline_secs: Some(1),
    }
}

fn title<'a>(
    report: &'a casa1::corpus::CorpusReport,
    path: &str,
) -> &'a casa1::corpus::TitleReport {
    report
        .titles
        .iter()
        .find(|title| title.path == path)
        .unwrap_or_else(|| panic!("missing title {path}"))
}

#[test]
fn corpus_classifies_missing_import_crash_timeout_library_and_invalid_title_exactly() {
    let temp = TempDir::new().expect("temp dir");
    let corpus = temp.path().join("corpus");
    let work = temp.path().join("work");
    let out = temp.path().join("corpus.json");

    write_built(
        &corpus,
        "trivial.exe",
        &PeSpec {
            code: trivial_exit_code(0),
            ..PeSpec::default()
        },
    );
    let non_zero = build(&PeSpec {
        imports: vec![ImportSpec {
            dll: "kernel32.dll".to_string(),
            delay_load: false,
            symbols: vec![ImportSymbolSpec::Name("ExitProcess".to_string())],
        }],
        ..PeSpec::default()
    });
    let mut non_zero_bytes = non_zero.bytes.clone();
    patch_text(
        &mut non_zero_bytes,
        &exit_process_code(non_zero.iat_rvas[0].2, 7),
    );
    fs::write(corpus.join("non_zero.exe"), &non_zero_bytes).expect("write non-zero");
    let crash = build(&PeSpec {
        code: crash_code(),
        ..PeSpec::default()
    });
    fs::write(corpus.join("crash.exe"), &crash.bytes).expect("write crash");
    let hang = build(&PeSpec {
        code: hang_code(),
        ..PeSpec::default()
    });
    fs::write(corpus.join("hang.exe"), &hang.bytes).expect("write hang");
    let missing = build(&PeSpec {
        imports: vec![ImportSpec {
            dll: "does-not-exist.dll".to_string(),
            delay_load: false,
            symbols: vec![ImportSymbolSpec::Name("Nope".to_string())],
        }],
        ..PeSpec::default()
    });
    let mut missing_bytes = missing.bytes.clone();
    let iat_rva = missing.iat_rvas[0].2;
    patch_text(&mut missing_bytes, &call_iat_then_exit(iat_rva));
    fs::write(corpus.join("missing.exe"), &missing_bytes).expect("write missing");
    fs::write(corpus.join("module.dll"), &hang.bytes).expect("write dll");
    fs::write(corpus.join("invalid.exe"), b"MZ not a real image").expect("write invalid");

    let config = corpus_config(&corpus, &out, &work, 5000);
    let report = run_corpus(&config).expect("run corpus");
    assert_eq!(report.discovered_title_count, 7);
    assert_eq!(report.summary.executed, 7);

    let trivial = title(&report, "trivial.exe");
    assert_eq!(trivial.classification, OutcomeClass::CleanExit);
    assert_eq!(trivial.guest_exit_code, Some(0));
    assert_eq!(trivial.reason_name, None);
    assert!(!trivial.crashed_early);
    assert_eq!(trivial.cancel, None);

    let non_zero = title(&report, "non_zero.exe");
    assert_eq!(non_zero.classification, OutcomeClass::NonZeroExit);
    assert_eq!(non_zero.guest_exit_code, Some(7));

    let missing = title(&report, "missing.exe");
    assert_eq!(missing.classification, OutcomeClass::MissingImport);
    assert_eq!(missing.reason_name.as_deref(), Some("RC_UNIMPL_INSN"));
    assert!(missing.crashed_early);
    assert!(
        missing
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("unsupported PE import does-not-exist.dll!Nope")
    );

    let crash = title(&report, "crash.exe");
    assert_eq!(crash.classification, OutcomeClass::Crash);
    assert_eq!(crash.reason_name.as_deref(), Some("RC_UNIMPL_INSN"));
    assert!(crash.crashed_early);

    let hang = title(&report, "hang.exe");
    assert_eq!(hang.classification, OutcomeClass::Timeout);
    assert!(hang.timed_out);
    assert_eq!(hang.reason_code, Some(RC_CORPUS_TIMEOUT.0));
    assert_eq!(
        hang.cancel.as_ref().map(|cancel| cancel.mechanism.as_str()),
        Some("runtime_deadline")
    );

    let library = title(&report, "module.dll");
    assert_eq!(library.classification, OutcomeClass::LibraryNotRunnable);
    assert_eq!(library.reason_code, Some(RC_CORPUS_LIBRARY_NOT_RUNNABLE.0));
    assert_eq!(
        library.reason_name.as_deref(),
        Some(RC_CORPUS_LIBRARY_NOT_RUNNABLE.1)
    );

    let invalid = title(&report, "invalid.exe");
    assert_eq!(invalid.classification, OutcomeClass::InvalidImage);
    assert_eq!(invalid.reason_code, Some(2000));
    assert_eq!(invalid.reason_name.as_deref(), Some("RC_PE_PARSE_INVALID"));

    for title in &report.titles {
        assert!(!title.outcome_hash.is_empty());
        assert_eq!(title.outcome_hash.len(), 64);
    }
    let persisted: casa1::corpus::CorpusReport =
        serde_json::from_slice(&fs::read(&out).expect("read report")).expect("parse report");
    assert_eq!(persisted, report);
}

#[test]
fn corpus_timeout_cancels_the_runner_process_group_at_the_hard_deadline() {
    let temp = TempDir::new().expect("temp dir");
    let corpus = temp.path().join("corpus");
    let work = temp.path().join("work");
    let out = temp.path().join("corpus.json");
    let hang = build(&PeSpec {
        code: hang_code(),
        ..PeSpec::default()
    });
    fs::create_dir_all(&corpus).expect("corpus dir");
    fs::write(corpus.join("hang.exe"), &hang.bytes).expect("write hang");

    let mut config = corpus_config(&corpus, &out, &work, 1500);
    // Keep the cooperative runtime deadline out of the way so this test proves
    // the wrapper's hard SIGKILL path, not the runtime deadline path.
    config.runtime_deadline_secs = Some(10);
    let report = run_corpus(&config).expect("run corpus");
    let hang = title(&report, "hang.exe");
    assert_eq!(hang.classification, OutcomeClass::Timeout);
    assert!(hang.timed_out);
    assert_eq!(hang.reason_code, Some(RC_CORPUS_TIMEOUT.0));
    let cancel = hang.cancel.as_ref().expect("cancel evidence");
    assert_eq!(cancel.mechanism, "wrapper_sigkill_process_group");
    assert_eq!(hang.status, "timeout");
}

#[test]
fn corpus_resume_keeps_stale_unchanged_titles_out_of_the_runner() {
    let temp = TempDir::new().expect("temp dir");
    let corpus = temp.path().join("corpus");
    let work = temp.path().join("work");
    let out = temp.path().join("corpus.json");
    write_built(
        &corpus,
        "trivial.exe",
        &PeSpec {
            code: trivial_exit_code(0),
            ..PeSpec::default()
        },
    );

    let config = corpus_config(&corpus, &out, &work, 5000);
    let first = run_corpus(&config).expect("first run");
    assert_eq!(first.summary.executed, 1);
    assert_eq!(first.summary.skipped_unchanged, 0);
    let first_hash = first.titles[0].outcome_hash.clone();
    assert_eq!(first.titles[0].execution, ExecutionState::Executed);

    // Simulate a stale report on disk: the title content is unchanged, so the
    // second run must reuse the recorded outcome and never spawn the runner.
    let mut stale = first.clone();
    stale.titles[0].startup_ms = 999_999;
    stale.titles[0].peak_rss_bytes = 123_456;
    fs::write(&out, serde_json::to_string_pretty(&stale).expect("json")).expect("write stale");

    let second = run_corpus(&config).expect("second run");
    assert_eq!(second.summary.executed, 0);
    assert_eq!(second.summary.skipped_unchanged, 1);
    assert_eq!(second.titles[0].execution, ExecutionState::SkippedUnchanged);
    assert_eq!(second.titles[0].outcome_hash, first_hash);
    assert_eq!(second.titles[0].startup_ms, 999_999);
    assert_eq!(second.titles[0].peak_rss_bytes, 123_456);
}
