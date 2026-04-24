use crate::canonical::GuestException;
use crate::error::{AppError, AppResult};
use crate::ge::NetworkProfile;
use crate::reason::ReasonCode;
use crate::util;
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const WSAENETUNREACH: i32 = 10051;
const DRIVER_REQUIRED_HINT: &str = "driver-required title detected; launch via SCM fallback when available";
const DRIVER_REQUIRED_RULES: [(&str, &str); 12] = [
    ("easyanticheat.sys", "Easy Anti-Cheat kernel driver"),
    ("easyanticheat_eos.sys", "Easy Anti-Cheat EOS kernel driver"),
    ("eac.sys", "Easy Anti-Cheat kernel driver"),
    ("bedaisy.sys", "BattlEye kernel driver"),
    ("beservice.exe", "BattlEye service helper"),
    ("vgk.sys", "Riot Vanguard kernel driver"),
    ("vgc.exe", "Riot Vanguard service helper"),
    ("xhunter1.sys", "Xigncode/XHunter kernel driver"),
    ("faceit.sys", "FACEIT kernel driver"),
    ("mhyprot2.sys", "HoYoverse kernel driver"),
    ("nprotect", "nProtect/GameGuard component"),
    ("easyanticheat", "Easy Anti-Cheat component"),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntitlementAuditTarget {
    pub binary_name: String,
    pub entitlements_xml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntitlementAuditReport {
    pub approved: bool,
    pub jit_owner: String,
    pub jit_targets: Vec<String>,
    pub unexpected_targets: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FilesystemSandbox {
    ge_root: String,
    allow_list: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedPath {
    pub canonical_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConnectLog {
    pub host: String,
    pub ip: String,
    pub allowed: bool,
    pub winsock_error: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct NetworkPolicyEnforcer {
    profile: NetworkProfile,
    log: Vec<NetworkConnectLog>,
    last_winsock_error: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedHttpRequest {
    pub method: String,
    pub path: String,
    pub header_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashModule {
    pub name: String,
    pub base_address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashThread {
    pub tid: u32,
    pub stack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashSnapshot {
    pub exception: GuestException,
    pub modules: Vec<CrashModule>,
    pub threads: Vec<CrashThread>,
    pub host_stack: Vec<String>,
    pub log_lines: Vec<String>,
    pub applied_profile: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashArtifactSummary {
    pub output_zip: PathBuf,
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriverRequirementReport {
    pub launch_target: String,
    pub indicators: Vec<String>,
}

pub fn audit_entitlement_targets(
    targets: &[EntitlementAuditTarget],
    jit_owner: &str,
) -> AppResult<EntitlementAuditReport> {
    let mut jit_targets = Vec::new();
    let mut unexpected = Vec::new();
    for target in targets {
        let flags = parse_entitlement_flags(&target.entitlements_xml)?;
        let has_allow_jit = flags
            .get("com.apple.security.cs.allow-jit")
            .copied()
            .unwrap_or(false);
        let has_unsigned = flags
            .get("com.apple.security.cs.allow-unsigned-executable-memory")
            .copied()
            .unwrap_or(false);
        if has_allow_jit || has_unsigned {
            jit_targets.push(target.binary_name.clone());
        }
        if target.binary_name == jit_owner {
            if !has_allow_jit {
                unexpected.push(format!("{jit_owner}:missing_allow_jit"));
            }
            if has_unsigned {
                unexpected.push(format!("{jit_owner}:unexpected_unsigned_executable_memory"));
            }
        } else if has_allow_jit || has_unsigned {
            unexpected.push(target.binary_name.clone());
        }
    }
    jit_targets.sort();
    unexpected.sort();
    Ok(EntitlementAuditReport {
        approved: unexpected.is_empty(),
        jit_owner: jit_owner.to_string(),
        jit_targets,
        unexpected_targets: unexpected,
    })
}

pub fn audit_embedded_entitlements(
    binaries: &[PathBuf],
    jit_owner: &str,
) -> AppResult<EntitlementAuditReport> {
    let mut targets = Vec::new();
    for binary in binaries {
        let output = Command::new("/usr/bin/codesign")
            .arg("-d")
            .arg("--entitlements")
            .arg(":-")
            .arg(binary)
            .output()
            .map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to run codesign for {}", binary.display()),
                    &error,
                )
            })?;
        let excerpt = if output.stdout.is_empty() {
            String::from_utf8_lossy(&output.stderr).to_string()
        } else {
            String::from_utf8_lossy(&output.stdout).to_string()
        };
        targets.push(EntitlementAuditTarget {
            binary_name: binary
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_string(),
            entitlements_xml: excerpt,
        });
    }
    audit_entitlement_targets(&targets, jit_owner)
}

pub fn detect_driver_requirement_on_disk(executable: &Path) -> AppResult<Option<DriverRequirementReport>> {
    let launch_target = executable.display().to_string();
    let mut paths = Vec::new();
    for root in candidate_scan_roots(executable) {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(root).max_depth(4).into_iter().filter_map(Result::ok) {
            paths.push(entry.path().display().to_string());
        }
    }
    Ok(detect_driver_requirement_paths(&launch_target, paths.iter().map(String::as_str)))
}

pub fn detect_driver_requirement_paths<'a, I>(
    launch_target: &str,
    candidate_paths: I,
) -> Option<DriverRequirementReport>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut indicators = candidate_paths
        .into_iter()
        .filter_map(driver_requirement_indicator)
        .collect::<Vec<_>>();
    indicators.sort();
    indicators.dedup();
    if indicators.is_empty() {
        None
    } else {
        Some(DriverRequirementReport {
            launch_target: launch_target.to_string(),
            indicators,
        })
    }
}

pub fn driver_requirement_error(report: &DriverRequirementReport) -> AppError {
    let mut error = AppError::new(
        ReasonCode::RcAnticheatDriverDetected,
        format!("driver-required title detected for {}", report.launch_target),
    )
    .with_hint(DRIVER_REQUIRED_HINT);
    for indicator in &report.indicators {
        error = error.with_hint(format!("indicator: {indicator}"));
    }
    error
}

impl FilesystemSandbox {
    pub fn new(ge_root: &str, allow_list: &[String]) -> Self {
        Self {
            ge_root: normalize_path(ge_root),
            allow_list: allow_list.iter().map(|path| normalize_path(path)).collect(),
        }
    }

    pub fn authorize(
        &self,
        requested_path: &str,
        realpath_before_open: &str,
        realpath_after_open: &str,
    ) -> AppResult<AuthorizedPath> {
        if requested_path.split('/').any(|segment| segment == "..")
            || requested_path.split('\\').any(|segment| segment == "..")
        {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("path traversal denied: {requested_path}"),
            ));
        }
        let before = normalize_path(realpath_before_open);
        let after = normalize_path(realpath_after_open);
        if before != after {
            return Err(AppError::new(
                ReasonCode::RcFsSandboxEscape,
                format!("TOCTOU path swap denied: {requested_path}"),
            ));
        }
        if is_sensitive_path(&before) {
            if before.starts_with(&self.ge_root)
                || self.allow_list.iter().any(|root| before.starts_with(root))
            {
                return Ok(AuthorizedPath { canonical_path: after });
            }
            return Err(AppError::new(
                ReasonCode::RcFsSandboxEscape,
                format!("sensitive path denied: {requested_path}"),
            ));
        }
        if before.starts_with(&self.ge_root)
            || self.allow_list.iter().any(|root| before.starts_with(root))
        {
            Ok(AuthorizedPath { canonical_path: after })
        } else {
            Err(AppError::new(
                ReasonCode::RcFsSandboxEscape,
                format!("sandbox deny outside GE: {requested_path}"),
            ))
        }
    }
}

impl NetworkPolicyEnforcer {
    pub fn new(profile: NetworkProfile) -> Self {
        Self {
            profile,
            log: Vec::new(),
            last_winsock_error: None,
        }
    }

    pub fn connect(&mut self, host: &str, ip: &str) -> AppResult<()> {
        let allowed = match self.profile.policy {
            crate::ge::NetworkPolicy::AllowAll => true,
            crate::ge::NetworkPolicy::DenyAll => false,
            crate::ge::NetworkPolicy::AllowOnlyWhitelist => self
                .profile
                .whitelist
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(host) || entry == ip),
        };
        if !allowed {
            self.last_winsock_error = Some(WSAENETUNREACH);
            self.log.push(NetworkConnectLog {
                host: host.to_string(),
                ip: ip.to_string(),
                allowed: false,
                winsock_error: self.last_winsock_error,
            });
            return Err(AppError::new(
                ReasonCode::RcNetworkUnreachable,
                format!("network denied for {host} ({ip})"),
            )
            .with_hint(format!("winsock_error={WSAENETUNREACH}")));
        }
        self.last_winsock_error = None;
        self.log.push(NetworkConnectLog {
            host: host.to_string(),
            ip: ip.to_string(),
            allowed: true,
            winsock_error: None,
        });
        Ok(())
    }

    pub fn last_winsock_error(&self) -> Option<i32> {
        self.last_winsock_error
    }

    pub fn log(&self) -> &[NetworkConnectLog] {
        &self.log
    }
}

pub fn parse_http_request(data: &[u8]) -> AppResult<ParsedHttpRequest> {
    if data.is_empty() {
        return Err(AppError::new(
            ReasonCode::RcNetworkProtocolInvalid,
            "HTTP request is empty",
        ));
    }
    if data.contains(&0) {
        return Err(AppError::new(
            ReasonCode::RcNetworkProtocolInvalid,
            "HTTP request contains NUL byte",
        ));
    }
    let text = std::str::from_utf8(data).map_err(|error| {
        AppError::new(
            ReasonCode::RcNetworkProtocolInvalid,
            "HTTP request is not valid UTF-8",
        )
        .with_hint(error.to_string())
    })?;
    let (head, _) = text.split_once("\r\n\r\n").ok_or_else(|| {
        AppError::new(
            ReasonCode::RcNetworkProtocolInvalid,
            "HTTP request missing header terminator",
        )
    })?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        AppError::new(
            ReasonCode::RcNetworkProtocolInvalid,
            "HTTP request missing request line",
        )
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| {
        AppError::new(
            ReasonCode::RcNetworkProtocolInvalid,
            "HTTP request missing method",
        )
    })?;
    let path = parts.next().ok_or_else(|| {
        AppError::new(
            ReasonCode::RcNetworkProtocolInvalid,
            "HTTP request missing path",
        )
    })?;
    let version = parts.next().ok_or_else(|| {
        AppError::new(
            ReasonCode::RcNetworkProtocolInvalid,
            "HTTP request missing version",
        )
    })?;
    if !version.starts_with("HTTP/") {
        return Err(AppError::new(
            ReasonCode::RcNetworkProtocolInvalid,
            "HTTP request version is invalid",
        ));
    }
    let mut header_count = 0;
    for line in lines {
        if line.len() > 8192 || !line.contains(':') {
            return Err(AppError::new(
                ReasonCode::RcNetworkProtocolInvalid,
                "HTTP header is malformed",
            ));
        }
        header_count += 1;
    }
    Ok(ParsedHttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        header_count,
    })
}

pub fn http_fuzz_summary(data: &[u8]) -> String {
    match parse_http_request(data) {
        Ok(parsed) => format!("ok:{}:{}:{}", parsed.method, parsed.path, parsed.header_count),
        Err(error) => format!("err:{}:{}", error.code.as_u32(), error.message),
    }
}

pub fn collect_crash_artifact(snapshot: &CrashSnapshot, output_zip: &Path) -> AppResult<CrashArtifactSummary> {
    util::ensure_parent(output_zip)?;
    let file = File::create(output_zip).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcDiagnosticsExportFailed,
            format!("failed to create {}", output_zip.display()),
            &error,
        )
    })?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut entries = Vec::new();
    let payloads = BTreeMap::from([
        (
            "artifact/exception.json".to_string(),
            util::stable_json(&snapshot.exception)?.into_bytes(),
        ),
        (
            "artifact/host_stack.json".to_string(),
            util::stable_json(&snapshot.host_stack)?.into_bytes(),
        ),
        (
            "artifact/log_tail.txt".to_string(),
            tail_log_bytes(&snapshot.log_lines).into_bytes(),
        ),
        (
            "artifact/modules.json".to_string(),
            util::stable_json(&snapshot.modules)?.into_bytes(),
        ),
        (
            "artifact/profile.json".to_string(),
            util::stable_json(&snapshot.applied_profile)?.into_bytes(),
        ),
        (
            "artifact/threads.json".to_string(),
            util::stable_json(&snapshot.threads)?.into_bytes(),
        ),
    ]);
    for (path, bytes) in payloads {
        writer.start_file(&path, options).map_err(zip_error)?;
        writer.write_all(&bytes).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcDiagnosticsExportFailed,
                format!("failed to write crash artifact entry {path}"),
                &error,
            )
        })?;
        entries.push(path);
    }
    writer.finish().map_err(zip_error)?;
    Ok(CrashArtifactSummary {
        output_zip: output_zip.to_path_buf(),
        entries,
    })
}

pub fn nightly_sanitizer_commands(target: &str) -> Vec<String> {
    vec![format!(
        "RUSTFLAGS='-Zsanitizer=address' cargo +nightly test -Zbuild-std --target {target} -- --test-threads=1"
    )]
}

fn candidate_scan_roots(executable: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut current = executable.parent();
    for _ in 0..3 {
        let Some(path) = current else {
            break;
        };
        roots.push(path.to_path_buf());
        current = path.parent();
    }
    roots.sort();
    roots.dedup();
    roots
}

fn parse_entitlement_flags(xml: &str) -> AppResult<BTreeMap<String, bool>> {
    let sanitized = sanitize_entitlement_xml(xml);
    if sanitized.is_empty() {
        return Ok(BTreeMap::new());
    }
    let document = Document::parse(&sanitized).map_err(|error| {
        AppError::new(ReasonCode::RcIo, "failed to parse entitlement XML")
            .with_hint(error.to_string())
    })?;
    let dict = document
        .descendants()
        .find(|node| node.has_tag_name("dict"))
        .ok_or_else(|| AppError::new(ReasonCode::RcIo, "entitlement XML missing dict"))?;
    let mut flags = BTreeMap::new();
    let mut pending_key = None::<String>;
    for child in dict.children().filter(|node| node.is_element()) {
        if child.has_tag_name("key") {
            pending_key = child.text().map(|text| text.to_string());
            continue;
        }
        if let Some(key) = pending_key.take() {
            let value = child.has_tag_name("true");
            flags.insert(key, value);
        }
    }
    Ok(flags)
}

/// Strips DOCTYPE declarations from an XML string to prevent entity expansion attacks.
///
/// **Known limitation:** Uses simple string matching rather than a proper XML parser.
/// This may miss edge cases such as nested DOCTYPE declarations, CDATA sections
/// containing `<!DOCTYPE`, or unusual whitespace patterns. This is acceptable for
/// the controlled entitlement XML inputs in Casa1, but should not be used for
/// arbitrary untrusted XML documents.
fn sanitize_entitlement_xml(xml: &str) -> String {
    let trimmed = if let Some(start) = xml.find("<?xml") {
        &xml[start..]
    } else if let Some(start) = xml.find("<plist") {
        &xml[start..]
    } else {
        ""
    };

    let mut sanitized = String::new();
    let mut remainder = trimmed;
    while let Some(start) = remainder.find("<!DOCTYPE") {
        sanitized.push_str(&remainder[..start]);
        let Some(end) = remainder[start..].find('>') else {
            remainder = &remainder[..start];
            break;
        };
        remainder = &remainder[start + end + 1..];
    }
    sanitized.push_str(remainder);
    sanitized.trim().to_string()
}

fn driver_requirement_indicator(path: &str) -> Option<String> {
    let normalized = normalize_path(path);
    DRIVER_REQUIRED_RULES.iter().find_map(|(needle, label)| {
        normalized.contains(needle).then(|| format!("{label}: {path}"))
    })
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

/// Checks whether a normalized path refers to a sensitive system directory.
///
/// **Note:** This check relies on `normalize_path()` having already lowercased the
/// input path. The comparisons are intentionally case-sensitive for performance. If
/// `normalize_path()` is ever changed to preserve case, this function must be updated
/// to use case-insensitive comparisons (e.g., `path.to_ascii_lowercase().starts_with(...)`).
fn is_sensitive_path(path: &str) -> bool {
    path.starts_with("/system")
        || path.starts_with("/library")
        || path.starts_with("/applications")
        || path.starts_with("/dev/")
        || path.starts_with("\\\\.\\physicaldrive")
        || (path.starts_with("/users/") && !path.contains("/ges/"))
}

fn tail_log_bytes(lines: &[String]) -> String {
    let redacted = lines
        .iter()
        .map(|line| redact_pii(line))
        .collect::<Vec<_>>()
        .join("\n");
    if redacted.len() <= 4096 {
        return redacted;
    }
    String::from_utf8_lossy(&redacted.as_bytes()[redacted.len() - 4096..]).to_string()
}

fn redact_pii(line: &str) -> String {
    let mut redacted = line.to_string();
    if let Some(start) = redacted.find("/Users/") {
        if let Some(end) = redacted[start + 7..].find('/') {
            let prefix = &redacted[..start + 7];
            let suffix = &redacted[start + 7 + end..];
            redacted = format!("{prefix}<redacted>{suffix}");
        }
    }
    redacted
        .split_whitespace()
        .map(|token| if token.contains('@') && token.contains('.') { "<redacted-email>" } else { token })
        .collect::<Vec<_>>()
        .join(" ")
}

fn zip_error(error: zip::result::ZipError) -> AppError {
    AppError::new(ReasonCode::RcDiagnosticsExportFailed, "zip export failed")
        .with_hint(error.to_string())
}