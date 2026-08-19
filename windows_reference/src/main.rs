//! The Windows differential-oracle reference executable.
//!
//! Usage: `casa1-windows-reference <vectors.json> <results.json>`
//!
//! Reads a schema-version-1 vector file, executes every vector with REAL
//! Win32/CRT calls (never reimplemented semantics — this binary IS Windows),
//! and writes a canonical results file with a capture header. Vectors are
//! executed strictly in file order (the `crt_printf` corpus depends on the
//! UCRT invalid-parameter handler and %n state evolving across vectors).

mod exec;
mod schema;

use schema::{CaptureHeader, Result, ResultsFile, SCHEMA_VERSION, VectorFile};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "usage: {} <vectors.json> <results.json>",
            args.first()
                .map(String::as_str)
                .unwrap_or("casa1-windows-reference")
        );
        std::process::exit(2);
    }
    let vector_file: VectorFile = read_json(&args[1], "vectors");
    if vector_file.schema_version != SCHEMA_VERSION {
        eprintln!(
            "vector file schema_version {} does not match protocol version {}",
            vector_file.schema_version, SCHEMA_VERSION
        );
        std::process::exit(2);
    }
    let results: Vec<Result> = vector_file
        .vectors
        .iter()
        .map(|vector| Result {
            id: vector.id.clone(),
            category: vector.category.clone(),
            output: exec::execute(&vector.category, &vector.input),
        })
        .collect();
    let out = ResultsFile {
        schema_version: SCHEMA_VERSION,
        capture: CaptureHeader::windows_capture(),
        results,
    };
    let json = serde_json::to_string_pretty(&out).expect("encode results");
    std::fs::write(&args[2], format!("{json}\n")).unwrap_or_else(|error| {
        eprintln!("failed to write results file {}: {error}", args[2]);
        std::process::exit(2);
    });
    eprintln!("wrote {} results to {}", out.results.len(), args[2]);
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str, label: &str) -> T {
    let bytes = std::fs::read(path).unwrap_or_else(|error| {
        eprintln!("failed to read {label} file {path}: {error}");
        std::process::exit(2);
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        eprintln!("failed to parse {label} file {path}: {error}");
        std::process::exit(2);
    })
}
