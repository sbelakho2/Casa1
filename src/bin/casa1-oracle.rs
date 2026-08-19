//! Casa1 differential-oracle harness.
//!
//! This binary is ONLY the harness: differential vector corpus generation
//! and result comparison.  ALL semantic Windows truth lives in the
//! standalone reference executable `windows_reference/` that runs on real
//! Windows 10/11 — there is deliberately NO Casa1-side semantic model.
//!
//! Modes:
//!   - `vectors --out <path>`: write the deterministic differential vector
//!     corpus (schema_version 1).
//!   - `compare --results <path> [--vectors <path>] [--categories ...]
//!     [--required-categories ...] [--report-only]`: run the Casa1 RUNTIME
//!     behavior per vector and compare against the captured reference
//!     results; exits non-zero on any diff (unless --report-only) and on any
//!     required-category coverage gap (always).
//!
//! Environment-driven comparison (for ad-hoc use on a Windows host):
//!   - `CASA1_WINDOWS_REFERENCE_RESULTS=<path>`: compare against an existing
//!     reference results file.
//!   - `CASA1_WINDOWS_REFERENCE_EXE=<path>`: run the reference executable on
//!     the generated corpus and compare its output.

use casa1::windows_oracle::{
    self, ComparisonReport, ReferenceResultsFile, VectorFile, WINDOWS_ORACLE_SCHEMA_VERSION,
};
use clap::{Parser, Subcommand};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Parser)]
struct OracleCli {
    #[command(subcommand)]
    command: OracleCommand,
}

#[derive(Debug, Subcommand)]
enum OracleCommand {
    /// Emit api-completeness.json for the quantitative Windows API
    /// completeness database (per-DLL counts + production-gate violations).
    #[command(name = "api-report")]
    ApiReport {
        /// Destination path for the api-completeness.json report.
        out: std::path::PathBuf,
    },
    /// Write the deterministic differential vector corpus (schema_version 1).
    Vectors {
        /// Output path (defaults to stdout when omitted).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Comma-separated category filter (default: all categories).
        #[arg(long)]
        categories: Option<String>,
    },
    /// Compare the Casa1 runtime's behavior per vector against the captured
    /// Windows reference results. Exits 1 on any diff unless --report-only,
    /// and on any required-category coverage gap (always).
    /// The reference results are the ONLY semantic truth — there is no
    /// Casa1-side model to fall back on.
    Compare {
        /// Reference results file (reference exe output or golden fixture).
        #[arg(long)]
        results: PathBuf,
        /// Vector file (default: the generated default corpus).
        #[arg(long)]
        vectors: Option<PathBuf>,
        /// Comma-separated category filter (default: categories present in
        /// the reference results file).
        #[arg(long)]
        categories: Option<String>,
        /// Comma-separated categories whose coverage is MANDATORY: the
        /// compare fails (exit 1) when any of them is runtime-uncovered or
        /// missing from the reference results, even with --report-only.
        /// Default: all ten advertised categories.
        #[arg(long)]
        required_categories: Option<String>,
        /// Report diffs without failing.
        #[arg(long)]
        report_only: bool,
    },
}

fn main() {
    let cli = OracleCli::parse();
    if let OracleCommand::ApiReport { out } = &cli.command {
        write_api_report(out);
        return;
    }
    if run_env_driven_comparison() {
        return;
    }
    match cli.command {
        OracleCommand::ApiReport { .. } => {
            // Handled by the pre-match special case above.
            unreachable!("ApiReport is handled before the match")
        }
        OracleCommand::Vectors { out, categories } => {
            let vectors = windows_oracle::generate_vectors(&parse_categories(categories));
            let file = VectorFile {
                schema_version: WINDOWS_ORACLE_SCHEMA_VERSION,
                vectors,
            };
            write_json_file_or_stdout(out, &file, "vector corpus");
        }
        OracleCommand::Compare {
            results,
            vectors,
            categories,
            required_categories,
            report_only,
        } => {
            let report = run_comparison(vectors.as_ref(), &results, &parse_categories(categories));
            print_report(&report);
            let required = parse_required_categories(required_categories);
            let coverage_missing = windows_oracle::required_coverage_missing(&report, &required);
            if !coverage_missing.is_empty() {
                eprintln!(
                    "compare: REQUIRED categories are not covered by the differential: {}",
                    coverage_missing.join(", ")
                );
                std::process::exit(1);
            }
            if report.has_diffs() && !report_only {
                std::process::exit(1);
            }
        }
    }
}

/// Generate the api-completeness.json report from the seeded database and
/// write it to `out`.
fn write_api_report(out: &std::path::Path) {
    let report = casa1::api_database::ApiDatabase::from_thunk_metadata().completeness_report();
    let json = match serde_json::to_string_pretty(&report) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("failed to encode api-completeness report: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = std::fs::write(out, json) {
        eprintln!("failed to write {}: {error}", out.display());
        std::process::exit(1);
    }
    eprintln!("wrote {}", out.display());
}

// ── Environment-driven comparison modes ─────────────────────────────────────

/// When `CASA1_WINDOWS_REFERENCE_EXE` or `CASA1_WINDOWS_REFERENCE_RESULTS` is
/// set, the harness switches to comparison mode over the default corpus:
/// Casa1's runtime results are validated against the reference executable's
/// output (running the exe itself when `CASA1_WINDOWS_REFERENCE_EXE` is set,
/// or reading an existing results file). Exits 1 on any diff or on any
/// required-category coverage gap (all ten advertised categories).
fn run_env_driven_comparison() -> bool {
    let required = all_required_categories();
    let Some(exe) = std::env::var_os("CASA1_WINDOWS_REFERENCE_EXE") else {
        let Some(results_path) = std::env::var_os("CASA1_WINDOWS_REFERENCE_RESULTS") else {
            return false;
        };
        let report = run_comparison(None, &PathBuf::from(results_path), &Vec::new());
        print_report(&report);
        exit_if_coverage_missing(&report, &required);
        if report.has_diffs() {
            std::process::exit(1);
        }
        return true;
    };
    let vectors = windows_oracle::generate_vectors(&Vec::new());
    let vectors_path = std::env::temp_dir().join("casa1-windows-vectors.json");
    let results_path = std::env::temp_dir().join("casa1-windows-reference-results.json");
    let vector_file = VectorFile {
        schema_version: WINDOWS_ORACLE_SCHEMA_VERSION,
        vectors,
    };
    write_json_file(&vectors_path, &vector_file, "vector corpus");
    let status = Command::new(&exe)
        .arg(&vectors_path)
        .arg(&results_path)
        .status()
        .expect("run CASA1_WINDOWS_REFERENCE_EXE");
    if !status.success() {
        eprintln!(
            "CASA1_WINDOWS_REFERENCE_EXE failed with status {status} (exe: {})",
            exe.to_string_lossy()
        );
        std::process::exit(1);
    }
    let report = run_comparison(Some(&vectors_path), &results_path, &Vec::new());
    print_report(&report);
    exit_if_coverage_missing(&report, &required);
    if report.has_diffs() {
        std::process::exit(1);
    }
    true
}

fn all_required_categories() -> Vec<String> {
    windows_oracle::ALL_CATEGORIES
        .iter()
        .map(|category| (*category).to_string())
        .collect()
}

fn parse_required_categories(required: Option<String>) -> Vec<String> {
    match required {
        Some(value) => parse_categories(Some(value)),
        None => all_required_categories(),
    }
}

/// Enforce the required-coverage gate: any required category that is
/// runtime-uncovered or missing from the reference results fails the run,
/// regardless of --report-only.
fn exit_if_coverage_missing(report: &ComparisonReport, required: &[String]) {
    let missing = windows_oracle::required_coverage_missing(report, required);
    if !missing.is_empty() {
        eprintln!(
            "compare: REQUIRED categories are not covered by the differential: {}",
            missing.join(", ")
        );
        std::process::exit(1);
    }
}

// ── Comparison pipeline ─────────────────────────────────────────────────────

fn run_comparison(
    vectors_path: Option<&PathBuf>,
    results_path: &PathBuf,
    categories: &[String],
) -> ComparisonReport {
    let vectors = match vectors_path {
        Some(path) => read_vector_file(path).vectors,
        None => windows_oracle::generate_vectors(&Vec::new()),
    };
    let reference_file: ReferenceResultsFile = read_json(results_path, "reference results");
    if reference_file.schema_version != WINDOWS_ORACLE_SCHEMA_VERSION {
        eprintln!(
            "reference results schema_version {} does not match protocol version {}",
            reference_file.schema_version, WINDOWS_ORACLE_SCHEMA_VERSION
        );
        std::process::exit(1);
    }
    let wanted: BTreeSet<String> = categories.iter().cloned().collect();
    let vectors = if wanted.is_empty() {
        vectors
    } else {
        vectors
            .into_iter()
            .filter(|vector| wanted.contains(&vector.category))
            .collect()
    };
    let runtime_results = vectors
        .iter()
        .map(windows_oracle::compute_runtime_result)
        .collect::<Vec<_>>();
    windows_oracle::compare_results(&vectors, &runtime_results, &reference_file.results)
}

fn print_report(report: &ComparisonReport) {
    let json = serde_json::to_string_pretty(report).expect("encode comparison report");
    println!("{json}");
    if report.has_diffs() {
        eprintln!(
            "compare: {} diffs across {} compared vectors ({} vectors total)",
            report.diff_count, report.compared, report.vectors_total
        );
    } else {
        eprintln!(
            "compare: OK — {} vectors compared, no diffs",
            report.compared
        );
    }
}

// ── Shared helpers ──────────────────────────────────────────────────────────

fn parse_categories(categories: Option<String>) -> Vec<String> {
    match categories {
        Some(value) => value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect(),
        None => Vec::new(),
    }
}

fn read_vector_file(path: &PathBuf) -> VectorFile {
    let file: VectorFile = read_json(path, "vector corpus");
    if file.schema_version != WINDOWS_ORACLE_SCHEMA_VERSION {
        eprintln!(
            "vector file schema_version {} does not match protocol version {}",
            file.schema_version, WINDOWS_ORACLE_SCHEMA_VERSION
        );
        std::process::exit(1);
    }
    file
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf, label: &str) -> T {
    let bytes = std::fs::read(path).unwrap_or_else(|error| {
        eprintln!("failed to read {label} file {}: {error}", path.display());
        std::process::exit(1);
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        eprintln!("failed to parse {label} file {}: {error}", path.display());
        std::process::exit(1);
    })
}

fn write_json_file<T: serde::Serialize>(path: &PathBuf, value: &T, label: &str) {
    let json = serde_json::to_string_pretty(value)
        .unwrap_or_else(|error| panic!("failed to encode {label}: {error}"));
    std::fs::write(path, format!("{json}\n")).unwrap_or_else(|error| {
        eprintln!("failed to write {label} file {}: {error}", path.display());
        std::process::exit(1);
    });
}

fn write_json_file_or_stdout<T: serde::Serialize>(out: Option<PathBuf>, value: &T, label: &str) {
    match out {
        Some(path) => write_json_file(&path, value, label),
        None => {
            let json = serde_json::to_string_pretty(value)
                .unwrap_or_else(|error| panic!("failed to encode {label}: {error}"));
            println!("{json}");
        }
    }
}
