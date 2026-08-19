//! Wire schema for the Windows differential oracle.
//!
//! The reference executable is a standalone crate (excluded from the Casa1
//! workspace) so it can build on Windows without pulling in the host crate.
//! The wire schema is therefore duplicated here; keep it in lockstep with
//! `src/windows_oracle.rs` in the Casa1 crate (see docs/WINDOWS_ORACLE.md).

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Deserialize)]
pub struct VectorFile {
    pub schema_version: u64,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
pub struct Vector {
    pub id: String,
    pub category: String,
    pub input: Value,
}

#[derive(Debug, Serialize)]
pub struct ResultsFile {
    pub schema_version: u64,
    pub capture: CaptureHeader,
    pub results: Vec<Result>,
}

#[derive(Debug, Serialize)]
pub struct CaptureHeader {
    pub source: String,
    pub captured_by: String,
    pub captured_on: String,
    pub capture_date: String,
    pub note: Option<String>,
    /// Windows edition of the capture machine (registry EditionID,
    /// e.g. "Professional"); "unknown" on non-Windows builds.
    pub os_edition: String,
    /// `major.minor.build` from RtlGetVersion (e.g. "10.0.22631");
    /// "unknown" on non-Windows builds.
    pub os_build: String,
    /// Capture machine architecture ("x86"/"x64"/"arm64" from
    /// GetNativeSystemInfo; the host arch name elsewhere).
    pub arch: String,
    /// Compiler target triple of the reference executable (env!("TARGET")) —
    /// distinguishes an x86 capture from an x64 capture.
    pub target_triple: String,
    /// SHA-256 (lowercase hex) of the reference executable itself.
    pub reference_sha256: String,
    /// SHA-256 (lowercase hex) of the vector corpus file the capture ran on.
    pub corpus_sha256: String,
}

/// Actual capture-machine provenance, computed by the reference executable
/// at runtime (never hardcoded).
#[derive(Debug, Clone)]
pub struct CaptureProvenance {
    pub os_edition: String,
    pub os_build: String,
    pub arch: String,
    pub reference_sha256: String,
    pub corpus_sha256: String,
}

impl CaptureHeader {
    /// Provenance header for a real capture on Windows 10/11, carrying the
    /// capture machine's ACTUAL os edition/build/arch and the SHA-256s of
    /// the reference executable and the input corpus.
    pub fn windows_capture(provenance: CaptureProvenance) -> Self {
        CaptureHeader {
            source: "windows".to_string(),
            captured_by: "casa1-windows-reference".to_string(),
            captured_on: "windows-10-11".to_string(),
            capture_date: iso_date_now(),
            note: None,
            os_edition: provenance.os_edition,
            os_build: provenance.os_build,
            arch: provenance.arch,
            target_triple: env!("CASA1_REFERENCE_TARGET").to_string(),
            reference_sha256: provenance.reference_sha256,
            corpus_sha256: provenance.corpus_sha256,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Result {
    pub id: String,
    pub category: String,
    pub output: Value,
}

/// Current date as `YYYY-MM-DD` (UTC), format-compatible with the host-side
/// capture header.
fn iso_date_now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}Z",
        hour = (day_seconds / 3600) % 24,
        minute = (day_seconds / 60) % 60
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
}
