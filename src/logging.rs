use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Severity used both by the structured JSONL logger and by the rate-limited
/// stderr helper. Ordering is Error < Warn < Info < Debug: a configured
/// minimum level enables itself and everything more severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" | "trace" => Some(Self::Debug),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    fn enabled(self, minimum: Self) -> bool {
        self <= minimum
    }
}

/// Default per-file cap before the JSONL log rotates to `<path>.1`.
pub const DEFAULT_MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub event_id: u32,
    pub ts_ticks: u64,
    pub pid: u32,
    pub tid: u64,
    pub module: String,
    pub severity: String,
    pub reason_code: u32,
    pub win32_err: Option<u32>,
    pub ntstatus: Option<u32>,
    pub msg: String,
    pub kv: BTreeMap<String, Value>,
}

pub struct JsonlLogger {
    writer: BufWriter<File>,
    path: PathBuf,
    next_event_id: u32,
    started_at: Instant,
    pid: u32,
    dtm: bool,
    max_bytes: u64,
    written_bytes: u64,
    min_level: LogLevel,
}

impl JsonlLogger {
    pub fn new(path: &Path, pid: u32, dtm: bool) -> AppResult<Self> {
        Self::with_limits(path, pid, dtm, DEFAULT_MAX_LOG_BYTES, LogLevel::Info)
    }

    /// Construct a logger with an explicit rotation size cap and minimum
    /// severity. `log()` silently drops events more verbose than `min_level`.
    pub fn with_limits(
        path: &Path,
        pid: u32,
        dtm: bool,
        max_bytes: u64,
        min_level: LogLevel,
    ) -> AppResult<Self> {
        crate::util::ensure_parent(path)?;
        let file = File::create(path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", path.display()),
                &error,
            )
        })?;
        Ok(Self {
            writer: BufWriter::new(file),
            path: path.to_path_buf(),
            next_event_id: 1,
            started_at: Instant::now(),
            pid,
            dtm,
            max_bytes: max_bytes.max(1),
            written_bytes: 0,
            min_level,
        })
    }

    /// Rotate `<path>` to `<path>.1` (replacing the previous backup) once the
    /// current file would exceed `max_bytes`. The new file starts empty.
    fn rotate(&mut self) -> AppResult<()> {
        self.writer.flush().map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to flush JSONL logger", &error)
        })?;
        let backup = PathBuf::from(format!("{}.1", self.path.display()));
        if backup.exists() {
            std::fs::remove_file(&backup).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to remove {}", backup.display()),
                    &error,
                )
            })?;
        }
        std::fs::rename(&self.path, &backup).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!(
                    "failed to rotate {} to {}",
                    self.path.display(),
                    backup.display()
                ),
                &error,
            )
        })?;
        let file = File::create(&self.path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to recreate {}", self.path.display()),
                &error,
            )
        })?;
        self.writer = BufWriter::new(file);
        self.written_bytes = 0;
        Ok(())
    }

    pub fn log(
        &mut self,
        module: &str,
        severity: &str,
        reason_code: ReasonCode,
        message: impl Into<String>,
        kv: BTreeMap<String, Value>,
    ) -> AppResult<LogEvent> {
        let level = LogLevel::parse(severity).unwrap_or(LogLevel::Info);
        let event = LogEvent {
            event_id: self.next_event_id,
            ts_ticks: if self.dtm {
                self.next_event_id as u64
            } else {
                self.started_at.elapsed().as_micros() as u64
            },
            pid: self.pid,
            tid: 1,
            module: module.to_string(),
            severity: severity.to_string(),
            reason_code: reason_code.as_u32(),
            win32_err: None,
            ntstatus: None,
            msg: redact_sensitive(&message.into()),
            kv: redact_sensitive_values(kv),
        };
        self.next_event_id += 1;
        if !level.enabled(self.min_level) {
            return Ok(event);
        }
        let line = serde_json::to_string(&event).map_err(|error| {
            AppError::new(ReasonCode::RcIo, "failed to encode JSONL event")
                .with_hint(error.to_string())
        })?;
        let line_len = line.len() as u64 + 1;
        if self.written_bytes > 0 && self.written_bytes + line_len > self.max_bytes {
            self.rotate()?;
        }
        writeln!(self.writer, "{line}").map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to write JSONL log event", &error)
        })?;
        self.written_bytes += line_len;
        Ok(event)
    }

    /// Flush buffered log events to disk.
    pub fn flush(&mut self) -> AppResult<()> {
        self.writer.flush().map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to flush JSONL logger", &error)
        })
    }
}

impl Drop for JsonlLogger {
    fn drop(&mut self) {
        // Best-effort flush so buffered events are not lost; `BufWriter`
        // would flush anyway on drop, but this surfaces errors before teardown.
        let _ = self.writer.flush();
    }
}

// ---------------------------------------------------------------------------
// Rate-limited stderr logging
// ---------------------------------------------------------------------------

/// Sliding-window limiter: at most one emitted message per `window` per key.
#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl RateLimiter {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            last: None,
            suppressed: 0,
        }
    }

    /// Record an event at `now`. Returns `Some(suppressed_count)` when the
    /// caller should emit (the count of messages dropped since the previous
    /// emission), or `None` when this event is suppressed.
    pub fn observe(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            None => {
                self.last = Some(now);
                Some(0)
            }
            Some(last) if now.checked_duration_since(last).unwrap_or_default() >= self.window => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
            Some(_) => {
                self.suppressed = self.suppressed.saturating_add(1);
                None
            }
        }
    }
}

static RATE_LIMITERS: LazyLock<Mutex<HashMap<&'static str, RateLimiter>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static MIN_LOG_LEVEL: LazyLock<LogLevel> = LazyLock::new(|| {
    std::env::var("CASA1_LOG_LEVEL")
        .ok()
        .as_deref()
        .and_then(LogLevel::parse)
        .unwrap_or(LogLevel::Info)
});

/// Emit a rate-limited stderr line. Hot paths (DllMain, failed guest opens)
/// call this instead of an unconditional `eprintln!`; repeated identical keys
/// inside `window` are collapsed and the count is reported on the next emit.
///
/// `CASA1_LOG_LEVEL` (error|warn|info|debug) filters messages below the
/// configured level; the default is `info`.
pub fn log_rate_limited(
    level: LogLevel,
    key: &'static str,
    window: Duration,
    message: impl FnOnce() -> String,
) {
    if !level.enabled(*MIN_LOG_LEVEL) {
        return;
    }
    let suppressed = {
        let mut limiters = match RATE_LIMITERS.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let limiter = limiters
            .entry(key)
            .or_insert_with(|| RateLimiter::new(window));
        limiter.observe(Instant::now())
    };
    if let Some(suppressed) = suppressed {
        let text = message();
        if suppressed > 0 {
            eprintln!(
                "[{}] {text} (suppressed {suppressed} similar messages)",
                level.label()
            );
        } else {
            eprintln!("[{}] {text}", level.label());
        }
    }
}

/// Recursively redact sensitive values from a log event's KV map so
/// guest-controlled strings cannot leak credentials into log files.
fn redact_sensitive_values(kv: BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    kv.into_iter()
        .map(|(key, value)| (key, redact_sensitive_value(value)))
        .collect()
}

fn redact_sensitive_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_sensitive(&text)),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(redact_sensitive_value).collect())
        }
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, redact_sensitive_value(value)))
                .collect(),
        ),
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Redaction patterns
// ---------------------------------------------------------------------------

static REDACTION_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        // Bearer / token headers.
        // Bare "token" matches are restricted to the `token=` / `token:`
        // forms so ordinary prose ("no token found") is not mangled; the
        // `bearer\s+` prefix only matches an explicit Bearer scheme.
        (
            "bearer_token",
            Regex::new(r"(?i)(bearer\s+|token[=:])[^\s,;]+").unwrap(),
        ),
        // Authorization header (Basic, Digest, Negotiate, etc.)
        (
            "auth_header",
            Regex::new(r"(?i)(authorization[=:\s]*(?:basic|digest|negotiate|bearer)\s*)[^\s,;]+")
                .unwrap(),
        ),
        // Cookies
        (
            "cookie",
            Regex::new(r"(?i)(cookie[=:\s]*)[^\s,;]+").unwrap(),
        ),
        // Set-Cookie
        (
            "set_cookie",
            Regex::new(r"(?i)(set-cookie[=:\s]*)[^\s,;]+").unwrap(),
        ),
        // Password / passwd in URLs or params
        (
            "password",
            Regex::new(r"(?i)((?:password|passwd|pwd)[=:\s]+)[^\s,;&]+").unwrap(),
        ),
        // API keys
        (
            "api_key",
            Regex::new(r"(?i)((?:api[_-]?key|apikey)[=:\s]+)[^\s,;&]+").unwrap(),
        ),
        // Secret keys
        (
            "secret_key",
            Regex::new(r"(?i)((?:secret[_-]?key|secretkey)[=:\s]+)[^\s,;&]+").unwrap(),
        ),
        // Access tokens (OAuth, etc.)
        (
            "access_token",
            Regex::new(r"(?i)((?:access[_-]?token)[=:\s]+)[^\s,;&]+").unwrap(),
        ),
        // Refresh tokens
        (
            "refresh_token",
            Regex::new(r"(?i)((?:refresh[_-]?token)[=:\s]+)[^\s,;&]+").unwrap(),
        ),
        // Credentials in URLs: http://user:pass@host
        (
            "url_credentials",
            Regex::new(r"(?i)(://[^/\s:]+:)[^@\s]+(@)").unwrap(),
        ),
        // PEM-encoded certificates (multi-line)
        (
            "certificate_pem",
            Regex::new(r"(?is)(-----BEGIN [A-Z ]+-----).+?(-----END [A-Z ]+-----)").unwrap(),
        ),
        // Certificate thumbprint / hash / serial number
        (
            "cert_thumbprint",
            Regex::new(r"(?i)(cert(?:ificate)?[._-]?(?:thumbprint|hash|serial|sha256|sha1)?[=:\s]*)[a-f0-9]{32,}()").unwrap(),
        ),
        // JWT tokens: header.payload.signature (standalone, without "Bearer " prefix).
        // Bearer+JWT cases are handled by the bearer_token pattern above which
        // redacts the entire token.  First segment >= 15 chars avoids matching
        // short hostname labels; the signature segment must also be >= 15
        // chars (real JWT signatures are base64url and far longer), which
        // excludes hostnames like "www.verylongdomainname.example.com".  The
        // signature is the non-captured part so the shared `${1}[REDACTED]${2}`
        // replacement redacts it (group 2 is the empty trailing capture).
        (
            "jwt_token",
            Regex::new(r"(?i)([a-z0-9_-]{15,}\.[a-z0-9_-]{3,}\.)[a-z0-9_-]{15,}()").unwrap(),
        ),
        // Session tokens / session IDs
        (
            "session_token",
            Regex::new(r"(?i)(session[._-]?(?:id|token|key)[=:\s]*)[a-f0-9]{16,64}()").unwrap(),
        ),
        // X.509 Distinguished Name fields (word boundary before prefix to avoid
        // matching e.g. the trailing 'e' in "certificate:").
        // Uses a consuming (?:^|[^a-zA-Z]) group instead of (?<![a-zA-Z])
        // lookbehind because the `regex` crate does not support lookarounds.
        // The value class excludes ',' so adjacent DN fields ("CN=MyCA,O=MyOrg")
        // are redacted field-by-field without eating the separator.
        (
            "x509_dn",
            Regex::new(r"(?i)((?:^|[^a-zA-Z])(?:CN|O|OU|L|ST|C|E)[=:]\s*)[a-zA-Z0-9\s.'()-]{3,80}()").unwrap(),
        ),
    ]
});

/// Redact sensitive values from a log message string.
///
/// Replaces values associated with tokens, cookies, passwords, API keys,
/// and other credentials with `[REDACTED]`. The key/name portion is preserved
/// so the log remains useful for debugging.
pub fn redact_sensitive(input: &str) -> String {
    let mut result = input.to_string();
    for (_name, pattern) in REDACTION_PATTERNS.iter() {
        result = pattern
            .replace_all(&result, "${1}[REDACTED]${2}")
            .to_string();
    }
    result
}

// ---------------------------------------------------------------------------
// Subsystem boundary event helpers
// ---------------------------------------------------------------------------

/// Create a standard set of KV pairs for a subsystem boundary crossing.
///
/// Every major subsystem (PE loader, thread creator, graphics init, audio init,
/// network connect) should log a structured boundary event on entry and exit
/// so operational flow can be traced without embedding secrets in log messages.
pub fn boundary_kv(
    subsystem: &str,
    direction: &str,
    detail: Option<&str>,
) -> BTreeMap<String, Value> {
    let mut kv = BTreeMap::new();
    kv.insert("boundary".to_string(), Value::String(subsystem.to_string()));
    kv.insert(
        "direction".to_string(),
        Value::String(direction.to_string()),
    );
    if let Some(d) = detail {
        kv.insert("detail".to_string(), Value::String(d.to_string()));
    }
    kv
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;

    fn temp_log_path() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "casa1_log_test_{}_{unique}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn test_redact_bearer_token() {
        let input = "Sending request with Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(redacted.contains("Bearer"));
    }

    #[test]
    fn test_redact_password() {
        let input = "Login with password=supersecret123 failed";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("password=[REDACTED]"));
        assert!(!redacted.contains("supersecret123"));
    }

    #[test]
    fn test_redact_api_key() {
        let input = "api_key=sk-abc123def456&user=test";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("api_key=[REDACTED]"));
        assert!(!redacted.contains("sk-abc123def456"));
        assert!(redacted.contains("user=test"));
    }

    #[test]
    fn test_redact_cookie() {
        let input = "Cookie: session_id=abc123; auth_token=xyz789";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("abc123"));
    }

    #[test]
    fn test_redact_access_token() {
        let input = "access_token=ghp_abcdefghijklmnop";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("access_token=[REDACTED]"));
        assert!(!redacted.contains("ghp_abcdefghijklmnop"));
    }

    #[test]
    fn test_redact_url_credentials() {
        let input = "Connecting to ftp://admin:s3cr3t@ftp.example.com/files";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("s3cr3t"));
        assert!(redacted.contains("ftp.example.com"));
    }

    #[test]
    fn test_redact_case_insensitive() {
        let input = "PASSWORD=Secret123 API_KEY=key456";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("Secret123"));
        assert!(!redacted.contains("key456"));
    }

    #[test]
    fn test_redact_secret_key() {
        let input = "secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCY";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("secret_key=[REDACTED]"));
        assert!(!redacted.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn test_redact_pem_certificate() {
        let input =
            "Loaded certificate:\n-----BEGIN CERTIFICATE-----\nMIIF9DCB\n-----END CERTIFICATE-----";
        let redacted = redact_sensitive(input);
        assert!(
            redacted.contains("-----BEGIN CERTIFICATE-----[REDACTED]-----END CERTIFICATE-----"),
            "PEM certificate body should be redacted; got: {redacted:?}"
        );
        assert!(
            !redacted.contains("MIIF9DCB"),
            "PEM body data leaked through"
        );
    }

    #[test]
    fn test_redact_cert_thumbprint() {
        let input = "cert_thumbprint=abcdef0123456789abcdef0123456789abcdef01";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("cert_thumbprint=[REDACTED]"));
        assert!(!redacted.contains("abcdef0123456789abcdef0123456789abcdef01"));
    }

    #[test]
    fn test_redact_jwt_token() {
        // Standalone JWT (no "Bearer " or "token=" prefix — those are handled
        // by the bearer_token pattern which redacts the entire token).
        let input = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234567890";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("signature1234567890"));
        // The pattern should keep the prefix up to the second dot
        assert!(redacted.contains("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."));
    }

    #[test]
    fn test_redact_does_not_mangle_plain_language() {
        // Bare "token" followed by a space must not be treated as a secret.
        assert_eq!(
            redact_sensitive("no token found for this session"),
            "no token found for this session"
        );
        // Long hostnames must not be mistaken for JWTs.
        let hostname = "connecting to www.verylongdomainname.example.com";
        assert_eq!(redact_sensitive(hostname), hostname);
        // "token=" forms are still redacted.
        let with_value = "auth failed: token=abcdef123456";
        let redacted = redact_sensitive(with_value);
        assert!(!redacted.contains("abcdef123456"));
        assert!(redacted.contains("token=[REDACTED]"));
    }

    #[test]
    fn test_redact_session_token() {
        let input = "session_token=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("session_token=[REDACTED]"));
        assert!(!redacted.contains("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"));
    }

    #[test]
    fn test_redact_x509_dn() {
        let input = "Issuer: CN=MyCA,O=MyOrg,C=US";
        let redacted = redact_sensitive(input);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("MyCA"));
    }

    #[test]
    fn test_boundary_kv_enter() {
        let kv = boundary_kv("pe_loader", "enter", Some("kernel32.dll"));
        assert_eq!(kv.get("boundary").unwrap(), "pe_loader");
        assert_eq!(kv.get("direction").unwrap(), "enter");
        assert_eq!(kv.get("detail").unwrap(), "kernel32.dll");
    }

    #[test]
    fn test_boundary_kv_exit_no_detail() {
        let kv = boundary_kv("network", "exit", None);
        assert_eq!(kv.get("boundary").unwrap(), "network");
        assert_eq!(kv.get("direction").unwrap(), "exit");
        assert!(!kv.contains_key("detail"));
    }

    #[test]
    fn test_boundary_kv_all_subsystems() {
        for (subsystem, detail) in &[
            ("pe_loader", "kernel32.dll"),
            ("thread", "12345"),
            ("graphics", "metal"),
            ("audio", "coreaudio"),
            ("network", "steam://connect"),
        ] {
            let kv = boundary_kv(subsystem, "enter", Some(detail));
            assert_eq!(kv.get("boundary").unwrap(), subsystem);
            assert_eq!(kv.get("direction").unwrap(), "enter");
            assert_eq!(kv.get("detail").unwrap(), detail);
        }
    }

    #[test]
    fn test_jsonl_logger_redacts_guest_strings() {
        let path = temp_log_path();
        let mut logger = JsonlLogger::new(&path, 1234, false).expect("create logger");
        let mut kv = BTreeMap::new();
        kv.insert(
            "header".to_string(),
            Value::String("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret".to_string()),
        );
        kv.insert(
            "args".to_string(),
            Value::Array(vec![
                Value::String("--token".to_string()),
                Value::String("token=supersecret123".to_string()),
            ]),
        );
        logger
            .log("test", "info", ReasonCode::Success, "token=also-secret", kv)
            .expect("log event");

        logger.flush().expect("flush logger");
        let mut contents = String::new();
        File::open(&path)
            .expect("open log")
            .read_to_string(&mut contents)
            .expect("read log");
        assert!(
            !contents.contains("supersecret123"),
            "kv value leaked: {contents}"
        );
        assert!(!contents.contains("also-secret"), "msg leaked: {contents}");
        assert!(!contents.contains("eyJhbGciOiJIUzI1NiJ9.secret"));

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    fn temp_log_path_with(tag: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "casa1_log_{tag}_{}_{unique}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn log_level_ordering_filters_more_verbose_levels() {
        assert!(LogLevel::Error < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert_eq!(LogLevel::parse("WARNING"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("nonsense"), None);
        assert!(LogLevel::Error.enabled(LogLevel::Warn));
        assert!(!LogLevel::Debug.enabled(LogLevel::Warn));
    }

    #[test]
    fn rate_limiter_suppresses_duplicates_and_reports_dropped_count() {
        let base = Instant::now();
        let mut limiter = RateLimiter::new(Duration::from_secs(10));
        assert_eq!(limiter.observe(base), Some(0));
        assert_eq!(limiter.observe(base + Duration::from_secs(1)), None);
        assert_eq!(limiter.observe(base + Duration::from_secs(2)), None);
        assert_eq!(
            limiter.observe(base + Duration::from_secs(11)),
            Some(2),
            "the next window reports the two suppressed messages"
        );
        assert_eq!(limiter.observe(base + Duration::from_secs(12)), None);
    }

    #[test]
    fn jsonl_logger_drops_events_below_the_configured_level() {
        let path = temp_log_path_with("level_filter");
        let mut logger =
            JsonlLogger::with_limits(&path, 7, false, DEFAULT_MAX_LOG_BYTES, LogLevel::Warn)
                .expect("logger");
        logger
            .log(
                "test",
                "info",
                ReasonCode::Success,
                "suppressed",
                BTreeMap::new(),
            )
            .expect("log");
        logger.flush().expect("flush");
        assert_eq!(
            std::fs::metadata(&path).expect("metadata").len(),
            0,
            "info event must be filtered at warn level"
        );

        logger
            .log("test", "error", ReasonCode::RcIo, "kept", BTreeMap::new())
            .expect("log");
        logger.flush().expect("flush");
        assert!(
            std::fs::metadata(&path).expect("metadata").len() > 0,
            "error event must be written"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn jsonl_logger_rotates_at_the_size_boundary_and_creates_backup() {
        let path = temp_log_path_with("rotation");
        let backup = PathBuf::from(format!("{}.1", path.display()));
        let mut logger =
            JsonlLogger::with_limits(&path, 9, false, 256, LogLevel::Debug).expect("logger");
        for _ in 0..40 {
            logger
                .log(
                    "test",
                    "info",
                    ReasonCode::Success,
                    "x".repeat(80),
                    BTreeMap::new(),
                )
                .expect("log");
        }
        logger.flush().expect("flush");
        assert_eq!(path.exists(), true, "active log must exist");
        assert_eq!(backup.exists(), true, "rotation must create <path>.1");
        assert_eq!(
            std::fs::metadata(&path).expect("active").len() > 0,
            true,
            "active log must contain events"
        );
        assert_eq!(
            std::fs::metadata(&backup).expect("backup").len() > 0,
            true,
            "backup must contain the rotated events"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn log_level_labels_cover_the_severity_boundary_exactly() {
        assert_eq!(LogLevel::Error.label(), "error");
        assert_eq!(LogLevel::Warn.label(), "warn");
        assert_eq!(LogLevel::Info.label(), "info");
        assert_eq!(LogLevel::Debug.label(), "debug");
    }

    #[test]
    fn jsonl_logger_new_pins_the_default_info_level_boundary_and_dtm_ticks() {
        let path = temp_log_path_with("new_default");
        let mut logger = JsonlLogger::new(&path, 4242, true).expect("new logger");
        let event = logger
            .log(
                "test",
                "info",
                ReasonCode::Success,
                "default-cap event",
                BTreeMap::new(),
            )
            .expect("log");
        assert_eq!(event.event_id, 1, "the first event id is exactly 1");
        assert_eq!(
            event.ts_ticks, 1,
            "dtm mode must stamp the monotonic event id, never wall time"
        );
        logger.flush().expect("flush");
        assert_eq!(
            std::fs::metadata(&path).expect("metadata").len() > 0,
            true,
            "the default Info level must keep the info event"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rotation_flush_failure_surfaces_the_exact_io_error() {
        let path = temp_log_path_with("flush_fail");
        let mut logger =
            JsonlLogger::with_limits(&path, 3, false, 1, LogLevel::Debug).expect("logger");
        logger
            .log(
                "test",
                "info",
                ReasonCode::Success,
                "x".repeat(80),
                BTreeMap::new(),
            )
            .expect("first event");
        // Swap in a read-only handle: the rotation flush must fail with the
        // pinned message instead of silently succeeding.
        logger.writer = BufWriter::new(File::open(&path).expect("read-only handle"));
        // Re-buffer without flushing so rotate() has data to write to the
        // read-only descriptor.
        writeln!(logger.writer, "buffered junk").expect("buffer into the read-only handle");
        let error = logger
            .log(
                "test",
                "info",
                ReasonCode::Success,
                "x".repeat(80),
                BTreeMap::new(),
            )
            .expect_err("flush of a read-only handle must fail rotation");
        assert_eq!(error.message, "failed to flush JSONL logger");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rotation_backup_removal_of_a_directory_fails_with_the_exact_error() {
        let path = temp_log_path_with("backup_dir");
        let backup = PathBuf::from(format!("{}.1", path.display()));
        let mut logger =
            JsonlLogger::with_limits(&path, 3, false, 1, LogLevel::Debug).expect("logger");
        logger
            .log(
                "test",
                "info",
                ReasonCode::Success,
                "x".repeat(80),
                BTreeMap::new(),
            )
            .expect("first event");
        std::fs::create_dir_all(&backup).expect("directory occupies the backup slot");
        let error = logger
            .log(
                "test",
                "info",
                ReasonCode::Success,
                "x".repeat(80),
                BTreeMap::new(),
            )
            .expect_err("remove_file of a directory must fail rotation");
        assert_eq!(
            error.message,
            format!("failed to remove {}", backup.display())
        );
        let _ = std::fs::remove_dir_all(&backup);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rotation_rename_into_a_read_only_directory_fails_with_the_exact_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "casa1_log_rename_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("rotate.jsonl");
        let backup = PathBuf::from(format!("{}.1", path.display()));
        let mut logger =
            JsonlLogger::with_limits(&path, 3, false, 1, LogLevel::Debug).expect("logger");
        logger
            .log(
                "test",
                "info",
                ReasonCode::Success,
                "x".repeat(80),
                BTreeMap::new(),
            )
            .expect("first event");
        let mut permissions = std::fs::metadata(&dir).expect("metadata").permissions();
        permissions.set_mode(0o555);
        std::fs::set_permissions(&dir, permissions.clone())
            .expect("make the rotation directory read-only");
        let error = logger
            .log(
                "test",
                "info",
                ReasonCode::Success,
                "x".repeat(80),
                BTreeMap::new(),
            )
            .expect_err("rename into a read-only directory must fail rotation");
        assert_eq!(
            error.message,
            format!(
                "failed to rotate {} to {}",
                path.display(),
                backup.display()
            )
        );
        permissions.set_mode(0o755);
        std::fs::set_permissions(&dir, permissions).expect("restore the directory");
        drop(logger);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_recreate_under_emfile_child_reports_the_exact_error() {
        const CHILD_ENV: &str = "CASA1_LOG_RECREATE_CHILD";
        if let Ok(tag) = std::env::var(CHILD_ENV) {
            let path = temp_log_path_with(&tag);
            let backup = PathBuf::from(format!("{}.1", path.display()));
            let mut logger =
                JsonlLogger::with_limits(&path, 1, false, 1, LogLevel::Debug).expect("logger");
            logger
                .log(
                    "test",
                    "info",
                    ReasonCode::Success,
                    "x".repeat(80),
                    BTreeMap::new(),
                )
                .expect("first event");
            let mut highest = 3;
            for fd in 3..256 {
                if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
                    highest = fd;
                }
            }
            let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
                0
            );
            let original = limit;
            limit.rlim_cur = (highest + 1) as libc::rlim_t;
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
            let error = logger
                .log(
                    "test",
                    "info",
                    ReasonCode::Success,
                    "x".repeat(80),
                    BTreeMap::new(),
                )
                .expect_err("File::create during rotation must fail under EMFILE");
            assert_eq!(
                error.message,
                format!("failed to recreate {}", path.display())
            );
            limit.rlim_cur = original.rlim_cur;
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&backup);
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "casa1_log_emfile_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let status = std::process::Command::new(std::env::current_exe().expect("current exe"))
            .arg("--exact")
            .arg("logging::tests::rotation_recreate_under_emfile_child_reports_the_exact_error")
            .arg("--nocapture")
            .env(CHILD_ENV, "emfile_recreate")
            .status()
            .expect("spawn the RLIMIT child");
        assert_eq!(
            status.success(),
            true,
            "the EMFILE child must complete the pinned failure path"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rate_limited_stderr_reports_suppressed_counts_after_the_window_boundary() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let key: &'static str = "test.logging.suppressed_boundary";
        let window = Duration::from_millis(80);
        let emissions = AtomicU32::new(0);
        log_rate_limited(LogLevel::Info, key, window, || {
            emissions.fetch_add(1, Ordering::Relaxed);
            "first".to_string()
        });
        log_rate_limited(LogLevel::Info, key, window, || {
            emissions.fetch_add(1, Ordering::Relaxed);
            "second".to_string()
        });
        assert_eq!(
            emissions.load(Ordering::Relaxed),
            1,
            "the duplicate inside the window must be suppressed"
        );
        std::thread::sleep(window + Duration::from_millis(60));
        log_rate_limited(LogLevel::Info, key, window, || {
            emissions.fetch_add(1, Ordering::Relaxed);
            "third".to_string()
        });
        assert_eq!(
            emissions.load(Ordering::Relaxed),
            2,
            "the post-window event must emit exactly once"
        );
    }

    #[test]
    fn rate_limited_stderr_rejects_debug_events_below_the_default_level() {
        let mut emitted = false;
        log_rate_limited(
            LogLevel::Debug,
            "test.logging.debug_filter",
            Duration::ZERO,
            || {
                emitted = true;
                "debug".to_string()
            },
        );
        assert_eq!(
            emitted, false,
            "debug must be filtered out at the default info level"
        );
    }

    #[test]
    fn rate_limited_stderr_fallback_for_a_poisoned_locker_still_emits_the_event() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let _ = std::thread::spawn(|| {
            let _guard = super::RATE_LIMITERS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            panic!("poison the rate limiter registry");
        })
        .join();
        let key: &'static str = "test.logging.poisoned_locker";
        let emissions = AtomicU32::new(0);
        log_rate_limited(LogLevel::Info, key, Duration::from_secs(60), || {
            emissions.fetch_add(1, Ordering::Relaxed);
            "recovered".to_string()
        });
        assert_eq!(
            emissions.load(Ordering::Relaxed),
            1,
            "a poisoned rate-limiter registry must not swallow the event"
        );
    }
}
