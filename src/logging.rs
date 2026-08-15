use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

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
    next_event_id: u32,
    started_at: Instant,
    pid: u32,
    dtm: bool,
}

impl JsonlLogger {
    pub fn new(path: &Path, pid: u32, dtm: bool) -> AppResult<Self> {
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
            next_event_id: 1,
            started_at: Instant::now(),
            pid,
            dtm,
        })
    }

    pub fn log(
        &mut self,
        module: &str,
        severity: &str,
        reason_code: ReasonCode,
        message: impl Into<String>,
        kv: BTreeMap<String, Value>,
    ) -> AppResult<LogEvent> {
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
        let line = serde_json::to_string(&event).map_err(|error| {
            AppError::new(ReasonCode::RcIo, "failed to encode JSONL event")
                .with_hint(error.to_string())
        })?;
        writeln!(self.writer, "{line}").map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to write JSONL log event", &error)
        })?;
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
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(redact_sensitive_value)
                .collect(),
        ),
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
    fn test_redact_no_match() {
        let input = "Normal log message with no sensitive data";
        assert_eq!(redact_sensitive(input), input);
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
    fn test_jsonl_logger_writes_events() {
        let path = temp_log_path();
        let mut logger = JsonlLogger::new(&path, 1234, false).expect("create logger");
        let event = logger
            .log("test", "info", ReasonCode::RcIo, "hello", BTreeMap::new())
            .expect("log event");
        assert_eq!(event.event_id, 1);
        assert_eq!(event.pid, 1234);
        assert_eq!(event.module, "test");

        // Read back and verify
        logger.flush().expect("flush logger");
        let mut contents = String::new();
        File::open(&path)
            .expect("open log")
            .read_to_string(&mut contents)
            .expect("read log");
        assert!(contents.contains("hello"));

        // Cleanup
        let _ = std::fs::remove_file(&path);
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
        assert!(!contents.contains("supersecret123"), "kv value leaked: {contents}");
        assert!(!contents.contains("also-secret"), "msg leaked: {contents}");
        assert!(!contents.contains("eyJhbGciOiJIUzI1NiJ9.secret"));

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }
}
