//! # Crash Recovery System
//!
//! Provides automated crash detection, dump collection, and restart logic
//! for the emulated Windows process.  When a crash is detected (non-zero exit
//! code, signal, or timeout), the system saves a crash dump containing
//! telemetry snapshots, installer state, and process metadata, then optionally
//! restarts the process up to a configurable number of times.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use casa1::crash_recovery::CrashRecovery;
//!
//! let mut recovery = CrashRecovery::new("/tmp/casa1_crashes", 3);
//! recovery.record_crash(12345, Some(-6), "SIGABRT", &telemetry_snapshot, &installer_state);
//! if recovery.should_restart() {
//!     recovery.restart(|| {
//!         // re-launch the emulated process
//!         Ok(())
//!     });
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::installer::InstallerEngine;
use crate::telemetry::TelemetryData;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum number of restart attempts.
pub const DEFAULT_MAX_RESTART_ATTEMPTS: u32 = 3;

/// Default crash dump directory base name (under `$TMPDIR` or `/tmp`).
pub const DEFAULT_DUMP_DIR_NAME: &str = "casa1_crashes";

/// Maximum number of crash dumps to keep on disk.
pub const MAX_DUMP_FILES: usize = 10;

/// Maximum age of crash dumps in seconds (24 hours).
pub const MAX_DUMP_AGE_SECS: u64 = 86400;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single crash dump saved to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashDump {
    /// Unix timestamp (seconds since epoch) when the crash occurred.
    pub timestamp: u64,
    /// ISO-8601 formatted timestamp string for human readability.
    pub timestamp_iso: String,
    /// The process ID that crashed.
    pub pid: u32,
    /// The exit code of the process (0 for normal exit, non-zero for crash).
    pub exit_code: i32,
    /// Signal number that caused the crash, if known (e.g. `-6` for SIGABRT
    /// on Unix, `-11` for SIGSEGV).  `None` if the process exited normally
    /// or the signal is unknown.
    pub signal: Option<i32>,
    /// Human-readable signal name, if known.
    pub signal_name: Option<String>,
    /// Snapshot of telemetry data at the time of crash.
    pub telemetry_snapshot: TelemetryData,
    /// Snapshot of the installer engine state at the time of crash.
    pub installer_state: InstallerStateSnapshot,
    /// The restart attempt number (0 = first crash, 1 = first restart crash, ...).
    pub attempt: u32,
}

/// A lightweight, serialisable snapshot of [`InstallerEngine`] state.
///
/// This captures the minimal information needed to restore the installer
/// environment after a restart: file paths, registry keys, and installed
/// packages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallerStateSnapshot {
    /// File paths present in the engine (without content, to keep dumps small).
    pub file_paths: Vec<String>,
    /// Registry key-value pairs.
    pub registry_entries: Vec<(String, String)>,
    /// Product codes of installed MSI packages.
    pub installed_packages: Vec<String>,
    /// Number of telemetry log entries.
    pub telemetry_log_count: usize,
}

impl InstallerStateSnapshot {
    /// Capture a snapshot from an [`InstallerEngine`].
    pub fn capture(engine: &InstallerEngine) -> Self {
        Self {
            file_paths: engine.files().keys().cloned().collect(),
            registry_entries: engine
                .registry()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            installed_packages: Vec::new(), // not directly exposed; could be extended
            telemetry_log_count: engine.telemetry_log().len(),
        }
    }
}

// ---------------------------------------------------------------------------
// CrashRecovery
// ---------------------------------------------------------------------------

/// Manages crash detection, dump collection, and restart logic for the
/// emulated Windows process.
///
/// The recovery system is designed to be integrated into the PE runtime
/// execution loop.  After each process execution completes, the caller
/// should check the exit code and call [`record_crash`] if non-zero, then
/// call [`should_restart`] to decide whether to retry.
pub struct CrashRecovery {
    /// Directory where crash dumps are stored.
    dump_dir: PathBuf,
    /// Maximum number of restart attempts before giving up.
    max_attempts: u32,
    /// Current attempt counter.
    attempt_count: u32,
    /// The most recent crash dump (loaded from disk or recorded in memory).
    last_dump: Option<CrashDump>,
}

impl CrashRecovery {
    /// Create a new `CrashRecovery` instance.
    ///
    /// `dump_dir` is the directory for crash dumps.  If empty, the default
    /// `$TMPDIR/casa1_crashes/` or `/tmp/casa1_crashes/` is used.
    /// `max_attempts` limits the number of restart attempts (0 = no restarts).
    pub fn new(dump_dir: Option<&str>, max_attempts: u32) -> Self {
        let dir = dump_dir
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(default_dump_dir);

        Self {
            dump_dir: dir,
            max_attempts,
            attempt_count: 0,
            last_dump: None,
        }
    }

    /// Create a `CrashRecovery` with default settings:
    /// - Dump directory: `$TMPDIR/casa1_crashes/` or `/tmp/casa1_crashes/`
    /// - Max restart attempts: [`DEFAULT_MAX_RESTART_ATTEMPTS`] (3)
    pub fn default_with_defaults() -> Self {
        Self::new(None, DEFAULT_MAX_RESTART_ATTEMPTS)
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Returns the current crash dump directory.
    pub fn dump_dir(&self) -> &Path {
        &self.dump_dir
    }

    /// Returns the maximum number of restart attempts.
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Returns the current attempt count.
    pub fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    /// Returns a reference to the most recent crash dump, if any.
    pub fn last_dump(&self) -> Option<&CrashDump> {
        self.last_dump.as_ref()
    }

    /// Returns `true` if the process should be restarted (attempt count
    /// is less than or equal to the maximum number of allowed attempts).
    ///
    /// This means that after the first crash with `max_attempts=3`,
    /// `attempt_count` is 1 and the call returns `true`.  After three
    /// crashes the count reaches 4 (if each restart crashes again),
    /// at which point this returns `false`.
    pub fn should_restart(&self) -> bool {
        self.attempt_count <= self.max_attempts
    }

    /// Returns the number of remaining restart attempts.
    pub fn remaining_attempts(&self) -> u32 {
        self.max_attempts.saturating_sub(self.attempt_count)
    }

    /// Resets the attempt counter (call after a successful run).
    pub fn reset_attempts(&mut self) {
        self.attempt_count = 0;
        self.last_dump = None;
    }

    // ------------------------------------------------------------------
    // Crash recording
    // ------------------------------------------------------------------

    /// Record a crash, save a dump to disk, and increment the attempt counter.
    ///
    /// * `pid` — the process ID of the crashed process.
    /// * `exit_code` — the exit code (0 if the process was killed by a signal).
    /// * `signal` — the signal number (e.g. `-6` for SIGABRT, `-11` for
    ///   SIGSEGV), or `None` if the process exited normally.
    /// * `signal_name` — a human-readable signal name (e.g. `"SIGABRT"`),
    ///   or `None` if unknown.
    /// * `telemetry` — a snapshot of the current telemetry data.
    /// * `installer` — an optional reference to the installer engine for
    ///   state capture.
    pub fn record_crash(
        &mut self,
        pid: u32,
        exit_code: i32,
        signal: Option<i32>,
        signal_name: Option<&str>,
        telemetry: TelemetryData,
        installer: Option<&InstallerEngine>,
    ) -> CrashDump {
        self.attempt_count += 1;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let timestamp = now.as_secs();
        let timestamp_iso = format_timestamp_iso(timestamp);

        let installer_state = installer
            .map(InstallerStateSnapshot::capture)
            .unwrap_or_else(|| InstallerStateSnapshot {
                file_paths: Vec::new(),
                registry_entries: Vec::new(),
                installed_packages: Vec::new(),
                telemetry_log_count: 0,
            });

        let dump = CrashDump {
            timestamp,
            timestamp_iso,
            pid,
            exit_code,
            signal,
            signal_name: signal_name.map(|s| s.to_string()),
            telemetry_snapshot: telemetry,
            installer_state,
            attempt: self.attempt_count,
        };

        // Save to disk
        if let Err(e) = self.save_dump(&dump) {
            eprintln!("[crash_recovery] failed to save crash dump: {e}");
        }

        // Cleanup old dumps
        if let Err(e) = self.cleanup_old_dumps() {
            eprintln!("[crash_recovery] failed to clean up old dumps: {e}");
        }

        self.last_dump = Some(dump.clone());
        dump
    }

    /// Record a crash with a simple exit code (no signal details).
    pub fn record_crash_simple(
        &mut self,
        pid: u32,
        exit_code: i32,
        telemetry: TelemetryData,
        installer: Option<&InstallerEngine>,
    ) -> CrashDump {
        let (signal, signal_name) = if exit_code < 0 {
            (Some(exit_code), Some(signal_name(exit_code)))
        } else {
            (None, None)
        };
        self.record_crash(
            pid,
            exit_code,
            signal,
            signal_name.as_deref(),
            telemetry,
            installer,
        )
    }

    // ------------------------------------------------------------------
    // Restart logic
    // ------------------------------------------------------------------

    /// Attempt to restart the emulated process.
    ///
    /// `launcher` is a closure that should re-launch the process.  It
    /// receives the most recent crash dump (if any) so it can restore state.
    ///
    /// Returns `Ok(())` if the launcher succeeded, or the error from the
    /// launcher if it failed.
    ///
    /// Call [`should_restart`] before calling this method.
    pub fn restart<F>(&mut self, launcher: F) -> Result<(), String>
    where
        F: FnOnce(Option<&CrashDump>) -> Result<(), String>,
    {
        if !self.should_restart() {
            return Err(format!(
                "max restart attempts ({}) reached",
                self.max_attempts
            ));
        }

        launcher(self.last_dump.as_ref())
    }

    // ------------------------------------------------------------------
    // Dump file management
    // ------------------------------------------------------------------

    /// Save a crash dump to the dump directory as a JSON file.
    fn save_dump(&self, dump: &CrashDump) -> Result<PathBuf, String> {
        fs::create_dir_all(&self.dump_dir)
            .map_err(|e| format!("failed to create dump dir {:?}: {e}", self.dump_dir))?;

        let filename = format!("crash_{}_{}.json", dump.timestamp, dump.pid);
        let path = self.dump_dir.join(&filename);

        let json = serde_json::to_string_pretty(dump)
            .map_err(|e| format!("crash dump serialisation error: {e}"))?;

        // Atomically write via a temporary file
        let tmp_path = self.dump_dir.join(format!("{}.tmp", filename));
        fs::write(&tmp_path, &json).map_err(|e| format!("crash dump write error: {e}"))?;
        fs::rename(&tmp_path, &path).map_err(|e| format!("crash dump rename error: {e}"))?;

        eprintln!(
            "[crash_recovery] crash dump saved to {} (attempt {}/{}, pid={}, exit_code={})",
            path.display(),
            dump.attempt,
            self.max_attempts,
            dump.pid,
            dump.exit_code,
        );

        Ok(path)
    }

    /// Load all crash dumps from the dump directory, sorted by timestamp
    /// (newest first).
    pub fn load_all_dumps(&self) -> Vec<CrashDump> {
        let mut dumps = Vec::new();
        if !self.dump_dir.is_dir() {
            return dumps;
        }

        let entries = match fs::read_dir(&self.dump_dir) {
            Ok(e) => e,
            Err(_) => return dumps,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(true, |e| e != "json") {
                continue;
            }
            if let Ok(json) = fs::read_to_string(&path) {
                if let Ok(dump) = serde_json::from_str::<CrashDump>(&json) {
                    dumps.push(dump);
                }
            }
        }

        // Sort newest-first by timestamp, breaking ties by pid (highest first)
        // so the order is deterministic even when timestamps are identical.
        dumps.sort_by(|a, b| {
            b.timestamp
                .cmp(&a.timestamp)
                .then_with(|| b.pid.cmp(&a.pid))
        });
        dumps
    }

    /// Remove old crash dumps, keeping at most [`MAX_DUMP_FILES`] files or
    /// those newer than [`MAX_DUMP_AGE_SECS`] seconds.
    pub fn cleanup_old_dumps(&self) -> Result<usize, String> {
        if !self.dump_dir.is_dir() {
            return Ok(0);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut dump_files: Vec<(PathBuf, u64)> = Vec::new();

        let entries =
            fs::read_dir(&self.dump_dir).map_err(|e| format!("failed to read dump dir: {e}"))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(true, |e| e != "json") {
                continue;
            }
            // Try to extract timestamp from filename: crash_{timestamp}_{pid}.json
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if let Some(ts_str) = stem
                .strip_prefix("crash_")
                .and_then(|s| s.split('_').next())
            {
                if let Ok(ts) = ts_str.parse::<u64>() {
                    dump_files.push((path, ts));
                }
            }
        }

        // Sort by timestamp (oldest first for removal), breaking ties by
        // filename (which includes pid) so the order is deterministic even
        // when timestamps are identical.
        dump_files.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.0.file_name().cmp(&b.0.file_name()))
        });

        let mut removed = 0_usize;

        // Remove files older than MAX_DUMP_AGE_SECS
        while let Some((path, ts)) = dump_files.first() {
            if now.saturating_sub(*ts) > MAX_DUMP_AGE_SECS {
                if fs::remove_file(path).is_ok() {
                    removed += 1;
                }
                dump_files.remove(0);
            } else {
                break;
            }
        }

        // If still over the limit, remove oldest
        while dump_files.len() > MAX_DUMP_FILES {
            let (path, _) = dump_files.remove(0);
            if fs::remove_file(path).is_ok() {
                removed += 1;
            }
        }

        if removed > 0 {
            eprintln!("[crash_recovery] cleaned up {removed} old crash dump(s)");
        }

        Ok(removed)
    }
}

impl Default for CrashRecovery {
    fn default() -> Self {
        Self::default_with_defaults()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine the default crash dump directory.
///
/// Uses `$TMPDIR/casa1_crashes` on macOS/Linux, falling back to
/// `/tmp/casa1_crashes`.
fn default_dump_dir() -> PathBuf {
    let base = std::env::var("TMPDIR")
        .or_else(|_| std::env::var("TMP"))
        .or_else(|_| std::env::var("TEMP"))
        .unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(base).join(DEFAULT_DUMP_DIR_NAME)
}

/// Map a Unix signal number to a human-readable name.
fn signal_name(sig: i32) -> String {
    match sig {
        -1 => "SIGHUP".to_string(),
        -2 => "SIGINT".to_string(),
        -3 => "SIGQUIT".to_string(),
        -4 => "SIGILL".to_string(),
        -5 => "SIGTRAP".to_string(),
        -6 => "SIGABRT".to_string(),
        -7 => "SIGEMT".to_string(),
        -8 => "SIGFPE".to_string(),
        -9 => "SIGKILL".to_string(),
        -10 => "SIGBUS".to_string(),
        -11 => "SIGSEGV".to_string(),
        -12 => "SIGSYS".to_string(),
        -13 => "SIGPIPE".to_string(),
        -14 => "SIGALRM".to_string(),
        -15 => "SIGTERM".to_string(),
        -16 => "SIGURG".to_string(),
        -17 => "SIGSTOP".to_string(),
        -18 => "SIGTSTP".to_string(),
        -19 => "SIGCONT".to_string(),
        -20 => "SIGCHLD".to_string(),
        -21 => "SIGTTIN".to_string(),
        -22 => "SIGTTOU".to_string(),
        -23 => "SIGIO".to_string(),
        -24 => "SIGXCPU".to_string(),
        -25 => "SIGXFSZ".to_string(),
        -26 => "SIGVTALRM".to_string(),
        -27 => "SIGPROF".to_string(),
        -28 => "SIGWINCH".to_string(),
        -29 => "SIGINFO".to_string(),
        -30 => "SIGUSR1".to_string(),
        -31 => "SIGUSR2".to_string(),
        n if n < 0 => format!("SIGUNKNOWN({})", -n),
        _ => format!("exit({})", sig),
    }
}

/// Format a Unix timestamp as a basic ISO-8601 string.
///
/// This avoids pulling in a datetime dependency.  The format is
/// `YYYY-MM-DDTHH:MM:SSZ` in UTC.
fn format_timestamp_iso(ts: u64) -> String {
    // Days since Unix epoch
    let days = ts / 86400;
    // Seconds since midnight
    let secs_of_day = ts % 86400;

    // Algorithm to convert days to year/month/day (from Howard Hinnant's
    // public-domain date algorithms)
    let z = days + 719468;
    #[allow(unused_comparisons)]
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let hour = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, min, sec
    )
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetryData;

    /// Create a unique temporary directory for each test that needs file I/O,
    /// so parallel test execution does not cause race conditions on the dump dir.
    fn temp_dump_dir() -> tempfile::TempDir {
        tempfile::TempDir::with_prefix("casa1_crash_test_")
            .expect("should create temp dir for crash tests")
    }

    #[test]
    fn test_default_dump_dir() {
        let dir = default_dump_dir();
        assert!(dir.to_string_lossy().contains("casa1_crashes"));
    }

    #[test]
    fn test_crash_recovery_new() {
        let r = CrashRecovery::new(Some("/tmp/test_crashes"), 5);
        assert_eq!(r.max_attempts(), 5);
        assert_eq!(r.attempt_count(), 0);
        assert!(r.should_restart());
        assert_eq!(r.remaining_attempts(), 5);
    }

    #[test]
    fn test_crash_recovery_defaults() {
        let r = CrashRecovery::default_with_defaults();
        assert_eq!(r.max_attempts(), DEFAULT_MAX_RESTART_ATTEMPTS);
        assert_eq!(r.attempt_count(), 0);
    }

    #[test]
    fn test_record_crash() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let telemetry = TelemetryData::default();

        let dump = r.record_crash_simple(12345, -6, telemetry, None);

        assert_eq!(dump.pid, 12345);
        assert_eq!(dump.exit_code, -6);
        assert_eq!(dump.signal, Some(-6));
        assert_eq!(dump.signal_name, Some("SIGABRT".to_string()));
        assert_eq!(dump.attempt, 1);
        assert_eq!(r.attempt_count(), 1);
        assert!(r.should_restart());
        assert_eq!(r.remaining_attempts(), 2);
    }

    #[test]
    fn test_max_attempts_exceeded() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            2,
        );
        let telemetry = TelemetryData::default();

        // First crash
        r.record_crash_simple(1, -11, telemetry.clone(), None);
        assert!(r.should_restart());

        // Second crash
        r.record_crash_simple(2, -11, telemetry.clone(), None);
        assert!(r.should_restart());

        // Third crash — exceeds max
        r.record_crash_simple(3, -11, telemetry.clone(), None);
        assert!(!r.should_restart());
        assert_eq!(r.remaining_attempts(), 0);
    }

    #[test]
    fn test_restart_ok() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let telemetry = TelemetryData::default();
        r.record_crash_simple(1, -11, telemetry, None);

        let result = r.restart(|_last| Ok(()));
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn test_restart_fails_when_exhausted() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            1,
        );
        let telemetry = TelemetryData::default();
        r.record_crash_simple(1, -11, telemetry, None);
        // restart should succeed (attempt 1 of 1)
        assert!(
            r.restart(|_| Ok(())).is_ok(),
            "restart should succeed within max attempts"
        );
        // Now attempts exhausted
        r.record_crash_simple(2, -11, TelemetryData::default(), None);
        assert!(!r.should_restart());
        let result = r.restart(|_| Ok(()));
        assert!(
            result.is_err(),
            "restart should fail when exhausted, got {result:?}"
        );
        let err = result.expect_err("result should be Err");
        assert!(
            err.contains("max restart attempts"),
            "error should mention max attempts, got: {err}"
        );
    }

    #[test]
    fn test_reset_attempts() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let telemetry = TelemetryData::default();
        r.record_crash_simple(1, -11, telemetry, None);
        r.record_crash_simple(2, -11, TelemetryData::default(), None);
        assert_eq!(r.attempt_count(), 2);

        r.reset_attempts();
        assert_eq!(r.attempt_count(), 0);
        assert!(r.should_restart());
        assert!(r.last_dump().is_none());
    }

    #[test]
    fn test_signal_name() {
        assert_eq!(signal_name(-6), "SIGABRT");
        assert_eq!(signal_name(-11), "SIGSEGV");
        assert_eq!(signal_name(-9), "SIGKILL");
        assert_eq!(signal_name(-15), "SIGTERM");
        assert_eq!(signal_name(0), "exit(0)");
        assert_eq!(signal_name(-99), "SIGUNKNOWN(99)");
    }

    #[test]
    fn test_format_timestamp_iso() {
        // 2024-01-15T12:30:00Z = 1705312200
        let ts = 1705312200;
        let iso = format_timestamp_iso(ts);
        assert!(iso.contains("2024"));
        assert!(iso.ends_with('Z'));
        assert_eq!(iso.len(), 20); // "YYYY-MM-DDTHH:MM:SSZ"
    }

    #[test]
    fn test_installer_state_snapshot_empty() {
        let snapshot = InstallerStateSnapshot {
            file_paths: Vec::new(),
            registry_entries: Vec::new(),
            installed_packages: Vec::new(),
            telemetry_log_count: 0,
        };
        assert!(snapshot.file_paths.is_empty());
        assert!(snapshot.registry_entries.is_empty());
    }

    #[test]
    fn test_cleanup_old_dumps_no_dir() {
        let r = CrashRecovery::new(Some("/tmp/nonexistent_crashes_xyz"), 3);
        let result = r.cleanup_old_dumps();
        assert!(
            result.is_ok(),
            "cleanup on nonexistent dir should succeed, got {result:?}"
        );
        assert_eq!(
            result.expect("cleanup should succeed"),
            0,
            "nonexistent dir should yield 0 cleaned dumps"
        );
    }

    #[test]
    fn test_save_and_load_dumps() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let telemetry = TelemetryData::default();
        r.record_crash_simple(100, -6, telemetry, None);

        // Load dumps back
        let dumps = r.load_all_dumps();
        assert_eq!(dumps.len(), 1);
        assert_eq!(dumps[0].pid, 100);
        assert_eq!(dumps[0].exit_code, -6);
    }

    // ── Corrupted state tests ──────────────────────────────────────────────

    #[test]
    fn test_load_dumps_ignores_corrupted_json() {
        let dir = temp_dump_dir();

        // Write a corrupted (non-JSON) file that looks like a crash dump
        let bad_path = dir.path().join("crash_99999_100.json");
        std::fs::write(&bad_path, "this is not valid json{{{")
            .expect("should write corrupted test file");

        // Write a valid dump alongside it
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        r.record_crash_simple(200, -11, TelemetryData::default(), None);

        // load_all_dumps should skip the corrupted file and return only the valid one
        let dumps = r.load_all_dumps();
        assert_eq!(dumps.len(), 1, "corrupted files should be skipped");
        assert_eq!(dumps[0].pid, 200);
    }

    #[test]
    fn test_load_dumps_ignores_non_json_files() {
        let dir = temp_dump_dir();

        // Write a .tmp file (should be ignored)
        let tmp_path = dir.path().join("crash_99999_100.tmp");
        std::fs::write(&tmp_path, "temporary data").expect("should write tmp test file");

        // Write a .log file (should be ignored)
        let log_path = dir.path().join("crash_99999_100.log");
        std::fs::write(&log_path, "log data").expect("should write log test file");

        let r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let dumps = r.load_all_dumps();
        assert!(
            dumps.is_empty(),
            "non-JSON files should be ignored, got {} dumps",
            dumps.len()
        );
    }

    #[test]
    fn test_load_dumps_handles_partial_json() {
        let dir = temp_dump_dir();

        // Write a JSON file that starts valid but is truncated
        let partial_path = dir.path().join("crash_99999_100.json");
        std::fs::write(
            &partial_path,
            r#"{"timestamp":12345,"timestamp_iso":"2024-01-01T00:00:00Z","pid":100,"exit_code":-6,"signal":-6,"signal_name":"SIGABRT","telemetry_snapshot":{"unsupported_imports":{},"unsupported_methods":{},"shader_models":{},"unimplemented_instructions":{}},"installer_state":{"file_paths":[],"registry_entries":[],"installed_packages":[],"telemetry_log_count":0},"attempt":1"#,
        )
        .expect("should write partial JSON test file");

        let r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let dumps = r.load_all_dumps();
        assert!(
            dumps.is_empty(),
            "truncated JSON should be skipped, got {} dumps",
            dumps.len()
        );
    }

    // ── Partial write recovery tests ───────────────────────────────────────

    #[test]
    fn test_atomic_write_prevents_partial_reads() {
        let dir = temp_dump_dir();
        let path_str = dir
            .path()
            .to_str()
            .expect("temp dir path should be valid UTF-8")
            .to_string();

        let mut r = CrashRecovery::new(Some(&path_str), 3);

        // Record a crash — this uses atomic write (write to .tmp then rename)
        r.record_crash_simple(100, -6, TelemetryData::default(), None);

        // Verify the dump was written correctly (no partial file)
        let dumps = r.load_all_dumps();
        assert_eq!(dumps.len(), 1);
        assert_eq!(dumps[0].pid, 100);

        // No .tmp files should remain
        let tmp_files: Vec<_> = std::fs::read_dir(&dir.path())
            .expect("should read temp dir")
            .flatten()
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "tmp")
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            tmp_files.is_empty(),
            "no .tmp files should remain after atomic write"
        );
    }

    #[test]
    fn test_leftover_tmp_files_ignored_on_load() {
        let dir = temp_dump_dir();

        // Simulate a leftover .tmp file from a crashed previous run
        let tmp_path = dir.path().join("crash_99999_100.json.tmp");
        std::fs::write(&tmp_path, "partial write data").expect("should write tmp test file");

        let r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let dumps = r.load_all_dumps();
        assert!(
            dumps.is_empty(),
            "leftover .tmp files should not be loaded as dumps"
        );
    }

    // ── Repeated crash recovery tests ──────────────────────────────────────

    #[test]
    fn test_repeated_crash_recovery_accumulates_dumps() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            5,
        );

        for i in 1..=3 {
            r.record_crash_simple(i * 100, -11, TelemetryData::default(), None);
        }

        let dumps = r.load_all_dumps();
        assert_eq!(dumps.len(), 3, "should have 3 dump files");
        assert_eq!(r.attempt_count(), 3);
        assert!(r.should_restart(), "should still have attempts remaining");
    }

    #[test]
    fn test_repeated_crash_recovery_stops_at_max() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            2,
        );

        // Crash 3 times (max_attempts = 2)
        for i in 1..=3 {
            r.record_crash_simple(i * 100, -6, TelemetryData::default(), None);
        }

        assert!(
            !r.should_restart(),
            "should be exhausted after 3 crashes with max_attempts=2"
        );
        assert_eq!(r.remaining_attempts(), 0);
    }

    #[test]
    fn test_reset_allows_recovery_after_exhaustion() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            1,
        );

        // Exhaust attempts
        r.record_crash_simple(100, -6, TelemetryData::default(), None);
        r.record_crash_simple(200, -6, TelemetryData::default(), None);
        assert!(!r.should_restart());

        // Reset and verify recovery is possible again
        r.reset_attempts();
        assert!(r.should_restart());
        assert_eq!(r.attempt_count(), 0);
        assert!(r.last_dump().is_none());
    }

    // ── Corrupted snapshot / partial write recovery tests ────────────────────

    #[test]
    fn test_recovery_from_corrupted_snapshot_file() {
        let dir = temp_dump_dir();

        // Write a corrupted crash dump file
        let bad_path = dir.path().join("crash_100_1.json");
        std::fs::write(&bad_path, "{{{corrupted garbage}}}")
            .expect("should write corrupted test file");

        // Write a valid dump
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        r.record_crash_simple(42, -11, TelemetryData::default(), None);

        // load_all_dumps should skip the corrupted file
        let dumps = r.load_all_dumps();
        assert_eq!(dumps.len(), 1, "corrupted snapshot should be skipped");
        assert_eq!(dumps[0].pid, 42);
    }

    #[test]
    fn test_recovery_from_partial_write_crash_dump() {
        let dir = temp_dump_dir();

        // Simulate a crash dump file that was only partially written
        let partial_path = dir.path().join("crash_200_2.json");
        let partial_json =
            r#"{"timestamp":12345,"timestamp_iso":"2024-01-01T00:00:00Z","pid":200,"exit_code":-6"#;
        std::fs::write(&partial_path, partial_json).expect("should write partial JSON test file");

        let r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let dumps = r.load_all_dumps();
        assert!(
            dumps.is_empty(),
            "partially written crash dump should be skipped"
        );
    }

    #[test]
    fn test_interrupted_write_leaves_tmp_file() {
        let dir = temp_dump_dir();

        // Simulate an interrupted write: .tmp file exists but no .json file
        let tmp_path = dir.path().join("crash_300_3.json.tmp");
        std::fs::write(&tmp_path, "partial tmp data").expect("should write tmp test file");

        let r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let dumps = r.load_all_dumps();
        assert!(
            dumps.is_empty(),
            "tmp file from interrupted write should not be loaded"
        );

        // Verify .tmp file is still present (we don't clean it up on load)
        assert!(tmp_path.exists(), "tmp file should remain on disk");
    }

    #[test]
    fn test_repeated_crash_restart_cycles() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            2,
        );

        // Cycle 1: crash + restart
        r.record_crash_simple(100, -11, TelemetryData::default(), None);
        assert_eq!(r.attempt_count(), 1);
        assert!(r.should_restart());
        assert!(
            r.restart(|_| Ok(())).is_ok(),
            "restart cycle 1 should succeed"
        );

        // Cycle 2: crash + restart
        r.record_crash_simple(101, -6, TelemetryData::default(), None);
        assert_eq!(r.attempt_count(), 2);
        assert!(r.should_restart());
        assert!(
            r.restart(|_| Ok(())).is_ok(),
            "restart cycle 2 should succeed"
        );

        // Cycle 3: crash - exceeds max_attempts (2), should NOT allow restart
        r.record_crash_simple(102, -11, TelemetryData::default(), None);
        assert_eq!(r.attempt_count(), 3);
        assert!(
            !r.should_restart(),
            "should be exhausted after 3 crashes with max_attempts=2"
        );
        let restart_result = r.restart(|_| Ok(()));
        assert!(
            restart_result.is_err(),
            "restart should fail when exhausted, got {restart_result:?}"
        );
        let err = restart_result.expect_err("restart result should be Err");
        assert!(
            err.contains("max restart attempts"),
            "error should mention max attempts, got: {err}"
        );

        // Reset and verify recovery is possible again
        r.reset_attempts();
        assert_eq!(r.attempt_count(), 0);
        assert!(r.should_restart(), "after reset, should allow restart");
        assert!(
            r.last_dump().is_none(),
            "last_dump should be cleared after reset"
        );
    }

    #[test]
    fn test_many_crashes_with_cleanup_limit() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            20,
        );

        // Record more crashes than MAX_DUMP_FILES (10)
        for i in 1..=15 {
            r.record_crash_simple(i * 100, -11, TelemetryData::default(), None);
        }

        let dumps = r.load_all_dumps();
        assert!(
            dumps.len() <= MAX_DUMP_FILES,
            "should not keep more than MAX_DUMP_FILES ({}) dumps, got {}",
            MAX_DUMP_FILES,
            dumps.len()
        );

        // The newest dumps (highest pids) should be kept
        if !dumps.is_empty() {
            // Dumps are sorted newest-first
            assert_eq!(dumps[0].pid, 1500, "newest dump (pid=1500) should be first");
        }
    }

    #[test]
    fn test_restart_closure_receives_last_dump() {
        let dir = temp_dump_dir();
        let mut r = CrashRecovery::new(
            Some(
                dir.path()
                    .to_str()
                    .expect("temp dir path should be valid UTF-8"),
            ),
            3,
        );
        let telemetry = TelemetryData::default();

        r.record_crash_simple(999, -6, telemetry, None);
        assert!(r.last_dump().is_some());
        assert_eq!(
            r.last_dump()
                .expect("last_dump should be Some after crash")
                .pid,
            999
        );

        // The restart closure should receive the last dump
        let received_pid = std::cell::Cell::new(0u32);
        r.restart(|dump| {
            if let Some(d) = dump {
                received_pid.set(d.pid);
            }
            Ok(())
        })
        .expect("restart should succeed");

        assert_eq!(
            received_pid.get(),
            999,
            "restart closure should receive the crash dump"
        );
    }
}
