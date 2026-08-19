//! Casa1 differential-oracle harness.
//!
//! This binary is ONLY the harness: suite generation (legacy section2/section3
//! expectations), differential vector corpus generation, and result
//! comparison. All semantic Windows implementations live in
//! `casa1::oracle_model` (MODEL ONLY — not Windows truth) or in the
//! standalone reference executable `windows_reference/`.
//!
//! Modes:
//!   - `section2-*` / `section3-*`: legacy expectation suites (unchanged
//!     output shape, consumed by tests/section2.rs and tests/section3.rs).
//!   - `vectors --out <path>`: write the deterministic differential vector
//!     corpus (schema_version 1).
//!   - `model-results --vectors <path> --out <path>`: compute Casa1's
//!     expected results with the model implementations (bootstrap/golden
//!     fixtures; never Windows truth).
//!   - `compare --results <path> [--vectors <path>] [--categories ...]
//!     [--report-only]`: compare Casa1's model results against reference
//!     results; exits non-zero on any diff (unless --report-only).
//!
//! Environment-driven comparison (for ad-hoc use on a Windows host):
//!   - `CASA1_WINDOWS_REFERENCE_RESULTS=<path>`: compare against an existing
//!     reference results file.
//!   - `CASA1_WINDOWS_REFERENCE_EXE=<path>`: run the reference executable on
//!     the generated corpus and compare its output.

use casa1::oracle_model::{
    ApiSetSuite, CaseCollisionSuite, DelayLoadSuite, DllOrderSuite, ExportSpec, ExportSpecTarget,
    LockShareSuite, PathEdgeSuite, RegistryNotifyOperation, RegistryNotifySuite,
    resolve_delay_expectation,
};
use casa1::windows_oracle::{
    self, CaptureHeader, ComparisonReport, ReferenceResultsFile, VectorFile, VectorResult,
    WINDOWS_ORACLE_SCHEMA_VERSION,
};
use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Parser)]
struct OracleCli {
    #[command(subcommand)]
    command: OracleCommand,
}

#[derive(Debug, Subcommand)]
enum OracleCommand {
    #[command(name = "section2-path")]
    Section2Path,
    #[command(name = "section2-case")]
    Section2Case,
    #[command(name = "section2-lock")]
    Section2Lock,
    #[command(name = "section2-registry")]
    Section2Registry,
    #[command(name = "section3-dll-order")]
    Section3DllOrder,
    #[command(name = "section3-delay-load")]
    Section3DelayLoad,
    #[command(name = "section3-apiset")]
    Section3ApiSet,
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
    /// Compute Casa1's expected results with the MODEL implementations and
    /// write them as a results file. For bootstrapping golden fixtures only;
    /// the output is explicitly marked as model-generated, never Windows
    /// truth.
    ModelResults {
        #[arg(long)]
        vectors: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Comma-separated category filter (default: all categories in the
        /// vector file).
        #[arg(long)]
        categories: Option<String>,
    },
    /// Compare Casa1's model results against reference results. Exits 1 on
    /// any diff unless --report-only.
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
    if run_env_driven_comparison() {
        return;
    }
    match cli.command {
        OracleCommand::ApiReport { .. } => {
            // Handled by the pre-match special case above.
            unreachable!("ApiReport is handled before the match")
        }
        OracleCommand::Section2Path => print_suite(&section2_path_suite()),
        OracleCommand::Section2Case => print_suite(&section2_case_suite()),
        OracleCommand::Section2Lock => print_suite(&section2_lock_suite()),
        OracleCommand::Section2Registry => print_suite(&section2_registry_suite()),
        OracleCommand::Section3DllOrder => print_suite(&section3_dll_order_suite()),
        OracleCommand::Section3DelayLoad => print_suite(&section3_delay_load_suite()),
        OracleCommand::Section3ApiSet => print_suite(&section3_api_set_suite()),
        OracleCommand::Vectors { out, categories } => {
            let vectors = windows_oracle::generate_vectors(&parse_categories(categories));
            let file = VectorFile {
                schema_version: WINDOWS_ORACLE_SCHEMA_VERSION,
                vectors,
            };
            write_json_file_or_stdout(out, &file, "vector corpus");
        }
        OracleCommand::ModelResults {
            vectors,
            out,
            categories,
        } => {
            let vector_file = read_vector_file(&vectors);
            let wanted = parse_categories(categories);
            let filtered = vector_file
                .vectors
                .iter()
                .filter(|vector| wanted.is_empty() || wanted.contains(&vector.category))
                .cloned()
                .collect::<Vec<_>>();
            let results = write_results_file(&out, &filtered);
            eprintln!(
                "model-results: wrote {} results to {}",
                results.len(),
                out.display()
            );
        }
        OracleCommand::Compare {
            results,
            vectors,
            categories,
            report_only,
        } => {
            let report = run_comparison(vectors.as_ref(), &results, &parse_categories(categories));
            print_report(&report);
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
/// Casa1's model results are validated against the reference executable's
/// output (running the exe itself when `CASA1_WINDOWS_REFERENCE_EXE` is set,
/// or reading an existing results file). Exits 1 on any diff.
fn run_env_driven_comparison() -> bool {
    let Some(exe) = std::env::var_os("CASA1_WINDOWS_REFERENCE_EXE") else {
        let Some(results_path) = std::env::var_os("CASA1_WINDOWS_REFERENCE_RESULTS") else {
            return false;
        };
        let report = run_comparison(None, &PathBuf::from(results_path), &Vec::new());
        print_report(&report);
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
    if report.has_diffs() {
        std::process::exit(1);
    }
    true
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
    let model_results = windows_oracle::compute_model_results(&vectors);
    windows_oracle::compare_results(&vectors, &model_results, &reference_file.results)
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

// ── Results-file writer (model results with capture header) ────────────────

fn write_results_file(
    out: &PathBuf,
    vectors: &[casa1::windows_oracle::Vector],
) -> Vec<VectorResult> {
    let results = windows_oracle::compute_model_results(vectors);
    let file = ReferenceResultsFile {
        schema_version: WINDOWS_ORACLE_SCHEMA_VERSION,
        capture: CaptureHeader::model_generated(),
        results,
    };
    write_json_file(out, &file, "model results");
    file.results
}

// ── Legacy suite generation (unchanged output shapes) ──────────────────────

fn section2_path_suite() -> PathEdgeSuite {
    let long_path = format!(
        "C:\\{}",
        (0..40)
            .map(|index| format!("segment{index:02}"))
            .collect::<Vec<_>>()
            .join("\\")
    );
    PathEdgeSuite {
        cases: vec![
            (
                "C:\\Alpha\\Beta\\.\\Gamma\\..\\File.txt. ".to_string(),
                false,
            ),
            ("\\\\?\\C:\\Alpha\\Beta. ".to_string(), false),
            ("\\\\.\\pipe\\steam".to_string(), false),
            ("C:\\Temp\\NUL".to_string(), false),
            (long_path.clone(), false),
            (long_path, true),
        ]
        .into_iter()
        .map(|(input, long_paths_enabled)| {
            use casa1::oracle_model::PathEdgeCase;
            PathEdgeCase {
                outcome: casa1::oracle_model::oracle_parse_windows_path(&input, long_paths_enabled),
                input,
                long_paths_enabled,
            }
        })
        .collect(),
    }
}

fn section2_case_suite() -> CaseCollisionSuite {
    use casa1::oracle_model::{OracleDirectory, RC_FS_ALREADY_EXISTS};
    let mut directory = OracleDirectory::default();
    directory.create("ReadMe.TXT").expect("ASCII insert");
    directory.create("Σ.txt").expect("unicode insert");
    let unicode_collision_code = directory.create("ς.txt").expect_err("collision");
    let resolved_unicode_name = directory.resolve("ς.txt").expect("resolve unicode");
    CaseCollisionSuite {
        create_directory: "C:\\Case".to_string(),
        collision_directory: "C:\\case".to_string(),
        ascii_file: "C:\\Case\\ReadMe.TXT".to_string(),
        unicode_file: "C:\\Case\\Σ.txt".to_string(),
        unicode_lookup: "C:\\case\\ς.txt".to_string(),
        enumeration_path: "C:\\CASE".to_string(),
        directory_collision_code: RC_FS_ALREADY_EXISTS,
        unicode_collision_code,
        resolved_unicode_path: format!("C:\\case\\{}", resolved_unicode_name.to_lowercase()),
        enumeration: directory.enumeration(),
    }
}

fn section2_lock_suite() -> LockShareSuite {
    use casa1::oracle_model::{
        OracleFileAccess, OracleOpenState, OracleShareMode, RC_FS_LOCK_VIOLATION,
        RC_FS_SHARING_VIOLATION, ranges_overlap, share_conflict,
    };
    let first = OracleOpenState {
        desired_access: OracleFileAccess {
            read: true,
            write: true,
            delete: false,
        },
        share_mode: OracleShareMode {
            read: false,
            write: false,
            delete: false,
        },
    };
    let second_access = OracleFileAccess {
        read: true,
        write: false,
        delete: false,
    };
    let second_share = OracleShareMode {
        read: true,
        write: true,
        delete: true,
    };
    LockShareSuite {
        path: "C:\\Locks\\data.bin".to_string(),
        share_violation_code: if share_conflict(&first, second_access, second_share) {
            RC_FS_SHARING_VIOLATION
        } else {
            0
        },
        lock_violation_code: if ranges_overlap(0, 8, 4, 4) {
            RC_FS_LOCK_VIOLATION
        } else {
            0
        },
        first_lock_offset: 0,
        first_lock_length: 8,
        overlap_offset: 4,
        overlap_length: 4,
    }
}

fn section2_registry_suite() -> RegistryNotifySuite {
    let operations = vec![
        RegistryNotifyOperation::Set {
            value: "Alpha".to_string(),
            value_type: "REG_SZ".to_string(),
            data: serde_json::json!("one"),
        },
        RegistryNotifyOperation::Set {
            value: "Beta".to_string(),
            value_type: "REG_DWORD".to_string(),
            data: serde_json::json!(7),
        },
        RegistryNotifyOperation::Delete {
            value: "Alpha".to_string(),
        },
    ];
    RegistryNotifySuite {
        hive: "HKCU".to_string(),
        key: "Software\\Casa1\\OracleNotify".to_string(),
        recursive: true,
        expected_wake_count: operations.len() as u64,
        operations,
    }
}

fn section3_dll_order_suite() -> DllOrderSuite {
    use casa1::oracle_model::{oracle_lifecycle_log_lines, oracle_load_order};
    let dependencies = BTreeMap::from([
        (
            "game.exe".to_string(),
            vec!["kernel32.dll".to_string(), "user32.dll".to_string()],
        ),
        ("user32.dll".to_string(), vec!["gdi32.dll".to_string()]),
        ("gdi32.dll".to_string(), Vec::new()),
        ("kernel32.dll".to_string(), Vec::new()),
    ]);
    let tls_callbacks = BTreeMap::from([
        ("kernel32.dll".to_string(), vec![0x1800_2000]),
        ("game.exe".to_string(), vec![0x1400_1010]),
    ]);
    let load_order = oracle_load_order("game.exe", &dependencies);
    DllOrderSuite {
        root_module: "game.exe".to_string(),
        dependencies,
        tls_callbacks: tls_callbacks.clone(),
        expected_log_lines: oracle_lifecycle_log_lines(&load_order, &tls_callbacks),
    }
}

fn section3_delay_load_suite() -> DelayLoadSuite {
    use casa1::oracle_model::{
        DelayLoadCase, DelayLoadExpectation, DelayLoadSymbol, STATUS_DLL_NOT_FOUND,
        STATUS_ENTRYPOINT_NOT_FOUND,
    };
    let resolved_provider_exports = BTreeMap::from([
        (
            "kernel32.dll".to_string(),
            vec![ExportSpec {
                ordinal: 18,
                name: Some("Forwarded".to_string()),
                target: ExportSpecTarget::Forwarder {
                    value: "KERNELBASE.Sleep".to_string(),
                },
            }],
        ),
        (
            "kernelbase.dll".to_string(),
            vec![ExportSpec {
                ordinal: 1,
                name: Some("Sleep".to_string()),
                target: ExportSpecTarget::Rva { value: 0x2500 },
            }],
        ),
    ]);
    DelayLoadSuite {
        cases: vec![
            DelayLoadCase {
                scenario: "resolved_forwarder".to_string(),
                requested_module: "kernel32.dll".to_string(),
                symbol: DelayLoadSymbol::ByName {
                    name: "Forwarded".to_string(),
                },
                expected: resolve_delay_expectation(
                    "kernel32.dll",
                    &DelayLoadSymbol::ByName {
                        name: "Forwarded".to_string(),
                    },
                    &resolved_provider_exports,
                ),
                provider_exports: resolved_provider_exports,
            },
            DelayLoadCase {
                scenario: "missing_provider".to_string(),
                requested_module: "missing.dll".to_string(),
                symbol: DelayLoadSymbol::ByName {
                    name: "Forwarded".to_string(),
                },
                expected: DelayLoadExpectation::StructuredException {
                    code: STATUS_DLL_NOT_FOUND,
                },
                provider_exports: BTreeMap::new(),
            },
            DelayLoadCase {
                scenario: "missing_entrypoint".to_string(),
                requested_module: "kernel32.dll".to_string(),
                symbol: DelayLoadSymbol::ByName {
                    name: "Forwarded".to_string(),
                },
                expected: DelayLoadExpectation::StructuredException {
                    code: STATUS_ENTRYPOINT_NOT_FOUND,
                },
                provider_exports: BTreeMap::from([("kernel32.dll".to_string(), Vec::new())]),
            },
        ],
    }
}

fn section3_api_set_suite() -> ApiSetSuite {
    use casa1::oracle_model::{ApiSetCase, oracle_api_set_resolve};
    ApiSetSuite {
        cases: [
            "api-ms-win-core-file-l1-1-0.dll",
            "api-ms-win-core-com-l1-1-0.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "ext-ms-win-ntuser-window-l1-1-0.dll",
            "custom.dll",
        ]
        .into_iter()
        .map(|contract| ApiSetCase {
            contract: contract.to_string(),
            expected_host: oracle_api_set_resolve(contract),
        })
        .collect(),
    }
}

// ── Shared helpers ──────────────────────────────────────────────────────────

fn print_suite<T: serde::Serialize>(suite: &T) {
    match serde_json::to_string(suite) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to encode oracle suite: {error}");
            std::process::exit(1);
        }
    }
}

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
