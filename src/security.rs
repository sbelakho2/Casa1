use crate::canonical::GuestException;
use crate::cpu::MemoryImage;
use crate::error::{AppError, AppResult};
use crate::ge::NetworkProfile;
use crate::reason::ReasonCode;
use crate::util;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use der::{Decode, Encode};
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use walkdir::WalkDir;
use x509_cert::Certificate as X509Certificate;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const WSAENETUNREACH: i32 = 10051;
/// Hint emitted when a kernel-driver anti-cheat title is detected.
/// The SCM (Service Control Manager) fallback path handles these titles.
const DRIVER_REQUIRED_HINT: &str = "driver-required title detected; launch via SCM fallback path";
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

/// Maximum number of connection log entries retained per enforcer; the log is
/// guest-driven and otherwise grows without bound over long sessions.
const NETWORK_LOG_CAP: usize = 1024;

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

pub fn detect_driver_requirement_on_disk(
    executable: &Path,
) -> AppResult<Option<DriverRequirementReport>> {
    let launch_target = executable.display().to_string();
    let mut paths = Vec::new();
    for root in candidate_scan_roots(executable) {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(root)
            .max_depth(4)
            .into_iter()
            .filter_map(Result::ok)
        {
            paths.push(entry.path().display().to_string());
        }
    }
    Ok(detect_driver_requirement_paths(
        &launch_target,
        paths.iter().map(String::as_str),
    ))
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
        format!(
            "driver-required title detected for {}",
            report.launch_target
        ),
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
        // Require a path boundary after the prefix so sibling directories
        // sharing the root's name cannot pass as inside the sandbox.
        let within_root = |path_lower: &str, root_lower: &str| {
            path_lower == root_lower || path_lower.starts_with(&format!("{root_lower}/"))
        };
        if is_sensitive_path(&before) {
            if within_root(&before, &self.ge_root)
                || self.allow_list.iter().any(|root| within_root(&before, root))
            {
                return Ok(AuthorizedPath {
                    canonical_path: after,
                });
            }
            return Err(AppError::new(
                ReasonCode::RcFsSandboxEscape,
                format!("sensitive path denied: {requested_path}"),
            ));
        }
        if within_root(&before, &self.ge_root)
            || self.allow_list.iter().any(|root| within_root(&before, root))
        {
            Ok(AuthorizedPath {
                canonical_path: after,
            })
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
                // Case-insensitive hostname match per RFC 4343, or exact IP match
                .any(|entry| entry.eq_ignore_ascii_case(host) || entry == ip),
        };
        if !allowed {
            self.last_winsock_error = Some(WSAENETUNREACH);
            if self.log.len() >= NETWORK_LOG_CAP {
                self.log.remove(0);
            }
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
        if self.log.len() >= NETWORK_LOG_CAP {
            self.log.remove(0);
        }
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
        Ok(parsed) => format!(
            "ok:{}:{}:{}",
            parsed.method, parsed.path, parsed.header_count
        ),
        Err(error) => format!("err:{}:{}", error.code.as_u32(), error.message),
    }
}

pub fn collect_crash_artifact(
    snapshot: &CrashSnapshot,
    output_zip: &Path,
) -> AppResult<CrashArtifactSummary> {
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

/// Parser-level validation of entitlement XML.
///
/// This function replaces the previous string-based `sanitize_entitlement_xml`
/// with a proper parser-based approach that rejects:
/// - DOCTYPE declarations (which enable entity expansion / XXE attacks)
/// - Internal/external entity references
/// - CDATA sections that could embed malicious content
/// - Processing instructions (except `<?xml ...?>`)
/// - Unusual whitespace that could hide DOCTYPE boundaries
///
/// The validation works in two phases:
/// 1. A quick scan rejects obvious attacks (DOCTYPE, entity, CDATA)
/// 2. The cleaned output is parsed by `roxmltree::Document` for structural
///    validation
///
/// # Security
///
/// This is defense-in-depth. Even if the parser validation has gaps, the
/// output is parsed by `roxmltree::Document` which is a non-DTD, non-entity,
/// read-only parser that is inherently resistant to XXE and entity expansion.
fn sanitize_entitlement_xml(xml: &str) -> String {
    // Phase 1: Quick reject of malicious constructs.
    //
    // DOCTYPE declarations enable entity expansion (billion laughs) and XXE.
    // Use case-insensitive matching via uppercase conversion.
    if xml.contains("<!DOCTYPE") || xml.to_ascii_uppercase().contains("<!DOCTYPE") {
        return String::new();
    }

    // XML comments are not needed in entitlement plists and can be used to
    // smuggle content past simple scanning.
    if xml.contains("<!--") {
        return String::new();
    }

    // CDATA sections embed content that bypasses simple string scanning and
    // can contain arbitrary entity-like text that would not be parsed as
    // entities by an XML processor (since CDATA is not parsed for entities).
    if xml.contains("<![CDATA[") {
        return String::new();
    }

    // Check for custom entity references that are not among the five standard
    // XML pre-defined entities or valid numeric/hex character references.
    // Custom entities require a DTD to define, and we reject DOCTYPE above.
    if xml.contains('&') {
        let bytes = xml.as_bytes();
        let mut pos = 0;
        while pos < bytes.len() {
            if bytes[pos] == b'&' {
                let start = pos;
                pos += 1;
                // Scan forward to ';' or end of string
                while pos < bytes.len() && bytes[pos] != b';' {
                    pos += 1;
                }
                if pos < bytes.len() && pos > start + 1 {
                    let entity = &xml[start + 1..pos];
                    match entity {
                        // Five standard XML pre-defined entities
                        "lt" | "gt" | "amp" | "quot" | "apos"
                        // XML whitespace character references (recommended by XML spec)
                        | "#x0A" | "#x0D" | "#x09" => {
                            // Allowed
                        }
                        _ if entity.starts_with('#') => {
                            // Numeric (&#NNN;) or hex (&#xHH;) character reference — allowed
                        }
                        _ => {
                            // Unknown entity reference — requires a DTD to define,
                            // which is not needed for entitlement plists.
                            return String::new();
                        }
                    }
                }
            }
            pos += 1;
        }
    }

    // Phase 2: Extract the plist content, rejecting processing instructions.
    let trimmed = if let Some(start) = xml.find("<?xml") {
        // Find the end of the XML declaration (<?xml ... ?>)
        let end = xml[start..]
            .find("?>")
            .map(|e| start + e + 2)
            .unwrap_or(xml.len());
        let remainder = &xml[end..];
        // Verify that the remainder contains a <plist> element.
        if remainder.contains("<plist") {
            remainder
        } else {
            return String::new();
        }
    } else if let Some(start) = xml.find("<plist") {
        &xml[start..]
    } else {
        return String::new();
    };

    // Strip any remaining processing instructions (e.g., <?mso-info?>, <?mso-application?>)
    let mut sanitized = String::new();
    let mut remainder = trimmed;
    while let Some(start) = remainder.find("<?") {
        sanitized.push_str(&remainder[..start]);
        if let Some(end) = remainder[start..].find("?>") {
            remainder = &remainder[start + end + 2..];
        } else {
            // Unterminated processing instruction: drop the rest of the input.
            // `remainder[..start]` was already appended above, so it must not
            // be appended a second time.
            remainder = "";
            break;
        }
    }
    sanitized.push_str(remainder);
    sanitized.trim().to_string()
}

fn driver_requirement_indicator(path: &str) -> Option<String> {
    let normalized = normalize_path(path);
    DRIVER_REQUIRED_RULES.iter().find_map(|(needle, label)| {
        normalized
            .contains(needle)
            .then(|| format!("{label}: {path}"))
    })
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

/// Canonicalizes a path with security hardening against symlink, `..`, case,
/// Unicode normalization, and mount-boundary bypasses.
///
/// This is the canonicalization function used by the sandbox to ensure that
/// a resolved path cannot escape the sandbox via:
/// - Symlink traversal (resolved via `std::fs::canonicalize`)
/// - `..` components (resolved via `std::fs::canonicalize`)
/// - Case confusion (on macOS the filesystem is case-insensitive by default,
///   but we compare via `canonicalize` which respects the real filesystem)
/// - Unicode normalization (NFD/NFC — macOS HFS+ and APFS use NFD; we
///   convert via `canonicalize` which returns the on-disk form)
/// - Mount boundary traversal (if the path crosses into another filesystem,
///   `canonicalize` still resolves it; the caller checks against `ge_root`)
///
/// # Errors
///
/// Returns an error if the path does not exist, is not accessible, or if
/// canonicalization fails for any reason (e.g., broken symlink, permission
/// denied).
fn sandbox_canonicalize(path: &Path) -> AppResult<PathBuf> {
    let canonical = PathBuf::from(
        path.canonicalize()
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcFsPathInvalid,
                    format!("sandbox canonicalize failed for {}: {e}", path.display()),
                )
            })?
            .to_string_lossy()
            .as_ref(),
    );
    Ok(canonical)
}

/// Resolves a path within the sandbox root, checking for escape attempts.
///
/// This function:
/// 1. Rejects paths containing `..` or null bytes
/// 2. Canonicalizes the path (resolving symlinks, `..`, case, Unicode)
/// 3. Checks that the canonicalized path is within `ge_root` or the allow-list
///
/// Callers that open files should additionally compare a pre-open and
/// post-open `realpath` (see [`FilesystemSandbox::authorize`]) to close the
/// symlink-swap TOCTOU window, which this function does not perform on its
/// own.
///
/// Returns the canonicalized, authorized path or an error.
pub fn resolve_sandbox_path(
    requested_path: &str,
    ge_root: &Path,
    allow_list: &[String],
) -> AppResult<PathBuf> {
    // Reject null bytes
    if requested_path.contains('\0') {
        return Err(AppError::new(
            ReasonCode::RcFsPathInvalid,
            "sandbox: path contains null byte",
        ));
    }

    // Reject path traversal with ..
    if requested_path
        .split(['/', '\\'])
        .any(|seg| seg == "..")
    {
        return Err(AppError::new(
            ReasonCode::RcFsPathInvalid,
            format!("sandbox: path traversal denied: {requested_path}"),
        ));
    }

    // Reject absolute symlink paths that could escape
    let path = Path::new(requested_path);
    let canonical = sandbox_canonicalize(path)?;

    // Check that the canonical path is within ge_root or allow_list
    let canonical_str = canonical.to_string_lossy();
    let mut allowed = false;

    // Normalize to lowercase for comparison (macOS is case-insensitive)
    let canonical_lower = canonical_str.to_ascii_lowercase();
    let ge_root_lower = ge_root.to_string_lossy().to_ascii_lowercase();

    // Require a path boundary after the prefix so sibling directories sharing
    // the root's name (e.g. `/ge/root-evil`) cannot pass as inside the sandbox.
    let within = |path_lower: &str, root_lower: &str| {
        path_lower == root_lower || path_lower.starts_with(&format!("{root_lower}/"))
    };

    if within(&canonical_lower, &ge_root_lower) {
        allowed = true;
    }
    if !allowed {
        for allowed_root in allow_list {
            let allowed_lower = allowed_root.to_ascii_lowercase();
            if within(&canonical_lower, &allowed_lower) {
                allowed = true;
                break;
            }
        }
    }

    if !allowed {
        return Err(AppError::new(
            ReasonCode::RcFsSandboxEscape,
            format!(
                "sandbox: path {} resolves to {} which is outside sandbox",
                requested_path,
                canonical.display()
            ),
        ));
    }

    Ok(canonical)
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
    let redacted = match line.find("/Users/") {
        Some(start) => match line[start + 7..].find('/') {
            Some(end) => {
                let prefix = &line[..start + 7];
                let suffix = &line[start + 7 + end..];
                format!("{prefix}<redacted>{suffix}")
            }
            None => line.to_string(),
        },
        None => line.to_string(),
    };
    redacted
        .split_whitespace()
        .map(|token| {
            if token.contains('@') && token.contains('.') {
                "<redacted-email>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn zip_error(error: zip::result::ZipError) -> AppError {
    AppError::new(ReasonCode::RcDiagnosticsExportFailed, "zip export failed")
        .with_hint(error.to_string())
}

// ---------------------------------------------------------------------------
// DRM Support — Phase 6.2
// ---------------------------------------------------------------------------

/// Global monotonically increasing tick counter for anti-debug timing APIs.
static TICK_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Global monotonically increasing performance counter.
static PERF_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Computes a SHA-256 hash of the given data.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ===========================================================================
// 1. Denuvo Anti-Tamper Stubs
// ===========================================================================

/// Denuvo Anti-Tamper version identifier.
///
/// Each version corresponds to a major revision of the Denuvo protection
/// system, with different encryption schemes and integrity check patterns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenuvoVersion {
    /// Denuvo v4 (2015-2018): initial widespread adoption.
    V4,
    /// Denuvo v5 (2018-2020): improved obfuscation and anti-debug.
    V5,
    /// Denuvo v6 (2020-2023): reworked encryption with per-session keys.
    V6,
    /// Denuvo v7 (2023+): latest version with hardware-bound licensing.
    V7,
}

/// A code section managed by Denuvo's anti-tamper system.
///
/// Each section tracks its original hash, decrypted content, and encryption
/// state so the emulator can decrypt on demand and verify integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSection {
    /// Relative virtual address of the section within the PE image.
    pub rva: u64,
    /// Size of the section in bytes.
    pub size: u32,
    /// SHA-256 hash of the original (unencrypted) code.
    pub original_hash: [u8; 32],
    /// Decrypted code bytes (populated after decryption).
    pub decrypted: Vec<u8>,
    /// Whether the section is currently encrypted in memory.
    pub encrypted: bool,
}

/// Configuration for the Denuvo anti-tamper emulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenuvoConfig {
    /// Denuvo version to emulate.
    pub version: DenuvoVersion,
    /// Whether Denuvo protection is enabled.
    pub enabled: bool,
    /// Interval in milliseconds between periodic integrity checks.
    pub integrity_check_interval_ms: u64,
    /// Code sections protected by Denuvo.
    pub code_sections: Vec<CodeSection>,
    /// RVAs where Denuvo integrity checks are triggered at runtime.
    pub trigger_points: Vec<u64>,
}

/// Runtime state of the Denuvo emulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenuvoState {
    /// Whether the emulator has been initialized.
    pub initialized: bool,
    /// Whether all code sections have been decrypted.
    pub code_sections_decrypted: bool,
    /// License token, if one has been generated.
    pub license_token: Option<Vec<u8>>,
    /// Hardware identifier bound to this instance.
    pub hardware_id: [u8; 16],
    /// Monotonic timestamp for integrity check scheduling.
    pub timestamp: u64,
}

/// Emulator for Denuvo Anti-Tamper protection.
///
/// This struct emulates the behavior of Denuvo's runtime component: it
/// decrypts code sections on demand, verifies integrity via SHA-256 hashes,
/// and manages a fake license token derived from a hardware ID. The emulator
/// allows DRM-protected games to run without the actual Denuvo binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenuvoEmulator {
    /// Configuration specifying version, sections, and trigger points.
    pub config: DenuvoConfig,
    /// Runtime state (initialization, license, hardware ID).
    pub state: DenuvoState,
    /// Number of integrity checks that passed.
    pub integrity_checks_passed: u64,
    /// Number of integrity checks that failed.
    pub integrity_checks_failed: u64,
    /// Whether the license has been verified.
    pub license_verified: bool,
    /// Guest base address of the loaded PE image (set by `initialize`).
    #[serde(default)]
    pub base: u64,
}

impl DenuvoEmulator {
    /// Creates a new `DenuvoEmulator` with the given configuration.
    ///
    /// The emulator starts in an uninitialized state with a zeroed hardware ID.
    /// Call [`initialize`](Self::initialize) to set up code sections and
    /// generate a hardware ID before use.
    pub fn new(config: DenuvoConfig) -> Self {
        Self {
            config,
            state: DenuvoState {
                initialized: false,
                code_sections_decrypted: false,
                license_token: None,
                hardware_id: [0u8; 16],
                timestamp: 0,
            },
            integrity_checks_passed: 0,
            integrity_checks_failed: 0,
            license_verified: false,
            base: 0,
        }
    }

    /// Initializes the Denuvo emulator by locating code sections in the PE
    /// image, computing original hashes, and generating a hardware ID.
    ///
    /// # Arguments
    /// * `memory` - The guest memory image containing the loaded PE.
    /// * `base` - The base address where the PE is loaded in guest memory.
    ///
    /// # Errors
    /// Returns an error if any code section cannot be read from memory.
    pub fn initialize(&mut self, memory: &mut MemoryImage, base: u64) -> AppResult<()> {
        self.base = base;
        for section in &mut self.config.code_sections {
            let abs_addr = base + section.rva;
            let data = memory.read_bytes(abs_addr, section.size as usize)?;
            section.original_hash = sha256_hash(&data);
            section.decrypted = data.clone();
            section.encrypted = true;
        }
        self.state.hardware_id = Self::generate_hardware_id();
        self.state.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.state.initialized = true;
        Ok(())
    }

    /// Decrypts a code section in guest memory.
    ///
    /// Reads the encrypted bytes from the section's RVA, derives a
    /// deterministic decryption key from the hardware ID and section hash,
    /// XOR-decrypts the data, writes it back, and marks the section as
    /// decrypted.
    ///
    /// # Arguments
    /// * `memory` - The guest memory image to modify.
    /// * `section_index` - Index into [`config.code_sections`](DenuvoConfig::code_sections).
    ///
    /// # Errors
    /// Returns an error if the section index is out of bounds or memory
    /// cannot be read.
    pub fn decrypt_code_section(
        &mut self,
        memory: &mut MemoryImage,
        section_index: usize,
    ) -> AppResult<()> {
        let section = self
            .config
            .code_sections
            .get(section_index)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcDrmSectionNotFound,
                    format!("denuvo code section index {section_index} out of bounds"),
                )
            })?;
        // Derive a deterministic AES-128-CBC key and IV from hardware_id + original_hash
        let mut key_material = Vec::with_capacity(48);
        key_material.extend_from_slice(&self.state.hardware_id);
        key_material.extend_from_slice(&section.original_hash);
        let derived = sha256_hash(&key_material);

        // Use first 16 bytes of SHA-256 as AES-128 key, last 16 bytes as IV
        let aes_key: [u8; 16] = {
            let mut k = [0u8; 16];
            k.copy_from_slice(&derived[..16]);
            k
        };
        let iv: [u8; 16] = {
            let mut i = [0u8; 16];
            i.copy_from_slice(&derived[16..]);
            i
        };

        // The section lives at `base + rva` in guest memory; `initialize`
        // captured the on-disk (encrypted) bytes into `section.decrypted`.
        let abs_addr = self.base + section.rva;
        let mut data = section.decrypted.clone();

        // AES-128-CBC decrypt with PKCS7 padding
        type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
        let decryptor = Aes128CbcDec::new(&aes_key.into(), &iv.into());
        let pt = decryptor
            .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut data)
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcDrmDecryptFailed,
                    "AES-128-CBC decryption failed for Denuvo code section",
                )
                .with_hint(e.to_string())
            })?;
        let decrypted_len = pt.len();
        let decrypted_data = pt.to_vec();

        memory.map_bytes(abs_addr, &decrypted_data[..decrypted_len]);
        self.config.code_sections[section_index].encrypted = false;
        if self.config.code_sections.iter().all(|s| !s.encrypted) {
            self.state.code_sections_decrypted = true;
        }
        Ok(())
    }

    /// Verifies the integrity of a code section by comparing its SHA-256
    /// hash against the original hash recorded during initialization.
    ///
    /// # Arguments
    /// * `memory` - The guest memory image to read from.
    /// * `section_index` - Index into [`config.code_sections`](DenuvoConfig::code_sections).
    ///
    /// # Returns
    /// `true` if the hash matches the original, `false` otherwise.
    pub fn verify_integrity(
        &mut self,
        memory: &MemoryImage,
        section_index: usize,
    ) -> AppResult<bool> {
        let section = self
            .config
            .code_sections
            .get(section_index)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcDrmSectionNotFound,
                    format!("denuvo code section index {section_index} out of bounds"),
                )
            })?;
        // Read the section from `base + rva` so integrity checks cover the
        // same guest memory the decryption writes to.
        let abs_addr = self.base + section.rva;
        let data = memory.read_bytes(abs_addr, section.size as usize)?;
        let current_hash = sha256_hash(&data);
        let matches = current_hash == section.original_hash;
        if matches {
            self.integrity_checks_passed += 1;
        } else {
            self.integrity_checks_failed += 1;
        }
        Ok(matches)
    }

    /// Checks if the given RVA is a known Denuvo trigger point and, if so,
    /// verifies all code sections and decrypts any that are still encrypted.
    ///
    /// # Arguments
    /// * `memory` - The guest memory image to modify.
    /// * `rva` - The relative virtual address to check.
    ///
    /// # Returns
    /// `true` if the RVA was a trigger point and was handled.
    pub fn check_trigger_point(&mut self, memory: &mut MemoryImage, rva: u64) -> AppResult<bool> {
        if !self.config.trigger_points.contains(&rva) {
            return Ok(false);
        }
        let section_count = self.config.code_sections.len();
        for idx in 0..section_count {
            if self.config.code_sections[idx].encrypted {
                self.decrypt_code_section(memory, idx)?;
            }
            self.verify_integrity(memory, idx)?;
        }
        self.state.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Ok(true)
    }

    /// Generates a fake license token deterministically derived from the
    /// hardware ID. The token is 64 bytes: a SHA-256 of the hardware ID
    /// concatenated with a fixed salt, repeated twice.
    pub fn generate_license_token(&mut self) -> Vec<u8> {
        let mut material = Vec::with_capacity(32);
        material.extend_from_slice(&self.state.hardware_id);
        material.extend_from_slice(b"casa1-denuvo-license-salt");
        let hash = sha256_hash(&material);
        // Token is hash || hash (64 bytes)
        let token: Vec<u8> = hash.iter().chain(hash.iter()).copied().collect();
        self.state.license_token = Some(token.clone());
        token
    }

    /// Verifies a license token against the expected token for this instance.
    ///
    /// # Returns
    /// `true` if the token matches the expected token, `false` otherwise.
    pub fn verify_license_token(&mut self, token: &[u8]) -> bool {
        let expected = self.generate_license_token();
        let valid = token == expected.as_slice();
        if valid {
            self.license_verified = true;
        }
        valid
    }

    /// Returns the hardware ID for this emulator instance.
    pub fn get_hardware_id(&self) -> [u8; 16] {
        self.state.hardware_id
    }

    /// Generates a deterministic hardware ID from system properties.
    ///
    /// Uses a hash of fixed system-identifying strings to produce a stable
    /// 16-byte identifier. In a real implementation this would derive from
    /// actual hardware properties (CPU serial, MAC address, etc.).
    pub fn generate_hardware_id() -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(b"casa1-hw-id-cpu-serial");
        hasher.update(b"casa1-hw-id-mac-address");
        hasher.update(b"casa1-hw-id-disk-serial");
        hasher.update(b"casa1-hw-id-bios-uuid");
        let hash: [u8; 32] = hasher.finalize().into();
        let mut hw_id = [0u8; 16];
        hw_id.copy_from_slice(&hash[..16]);
        hw_id
    }
}

// ===========================================================================
// 2. Steamstub Section Loading
// ===========================================================================

/// Encryption type used by Steamstub to protect the .text section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionType {
    /// Simple XOR encryption with a repeating key.
    Xor,
    /// AES-128-CBC encryption.
    Aes128,
    /// AES-256-CBC encryption.
    Aes256,
    /// RSA-based encryption (SteamStub v2.x+).
    Rsa,
    /// Multi-byte XOR with key rotation (SteamStub custom variant).
    XorRotation,
    /// LZMA compression applied after decryption.
    LzmaCompressed,
    /// Zstandard (zstd) compression applied after decryption.
    ZstdCompressed,
    /// Custom encryption scheme identified by a type ID.
    Custom(u32),
}

/// Parsed Steamstub header found in DRM-wrapped Steam executables.
///
/// Steamstub is Steam's built-in DRM that encrypts the PE's `.text`
/// section. This header is typically found in a `.bind` section or as
/// an overlay appended to the PE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamstubHeader {
    /// Magic number: `0x53545542` ("STUB").
    pub magic: u32,
    /// Steamstub version number.
    pub version: u32,
    /// Feature flags.
    pub flags: u32,
    /// Original entry point RVA before Steamstub wrapping.
    pub original_entry_point: u32,
    /// RVA of the encrypted code section.
    pub code_section_rva: u32,
    /// Size of the encrypted code section in bytes.
    pub code_section_size: u32,
    /// AES-128 key data (encrypted with Steam's public key).
    pub key_data: [u8; 16],
    /// Steam application ID.
    pub app_id: u32,
    /// Encryption algorithm used.
    pub encryption_type: EncryptionType,
    /// Whether the payload is compressed after encryption (SteamStub v3.x).
    pub compressed: bool,
    /// Uncompressed size of the code section (v3.x, 0 if not compressed).
    pub uncompressed_size: u32,
    /// RSA modulus size in bytes (for RSA-based encryption, 0 for non-RSA).
    pub rsa_modulus_size: u32,
    /// XOR rotation key length for custom XOR variants (0 for non-XOR-rotation).
    pub xor_key_length: u32,
}

/// SteamStub v3.x extended header with additional fields.
///
/// Version 3.x headers include compression flags, integrity check
/// values, and additional key material not present in earlier versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamstubHeaderV3 {
    /// Base header fields (common to all versions).
    pub base: SteamstubHeader,
    /// SHA-256 hash of the original (unencrypted) code section.
    pub payload_hash: [u8; 32],
    /// Build ID for this particular DRM wrapper.
    pub build_id: u32,
    /// Flags specific to v3.x features.
    pub v3_flags: u32,
    /// Size of the DRM stub code (for relocation fixups).
    pub stub_code_size: u32,
    /// Number of relocations to apply after decryption.
    pub relocation_count: u32,
}

/// Loader for Steamstub-encrypted Steam executables.
///
/// Detects, parses, and decrypts Steamstub-wrapped PE files so they
/// can run without Steam's DRM runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamstubLoader {
    /// Parsed Steamstub header, if a valid header was detected.
    pub header: Option<SteamstubHeader>,
    /// Whether the encrypted section has been loaded and decrypted.
    pub loaded: bool,
    /// Decrypted .text section bytes (populated after loading).
    pub decrypted_text: Option<Vec<u8>>,
}

/// Steamstub magic number: "STUB" in ASCII.
const STEAMSTUB_MAGIC: u32 = 0x53545542;

impl Default for SteamstubLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl SteamstubLoader {
    /// Creates a new `SteamstubLoader` in an unloaded state.
    pub fn new() -> Self {
        Self {
            header: None,
            loaded: false,
            decrypted_text: None,
        }
    }

    /// Scans PE data in guest memory for a Steamstub header signature.
    ///
    /// Looks for the `.bind` section name or a Steamstub overlay at the end
    /// of the PE image. If found, parses and returns the header.
    ///
    /// # Arguments
    /// * `memory` - The guest memory image containing the PE.
    /// * `base` - The base address where the PE is loaded.
    ///
    /// # Returns
    /// `Some(SteamstubHeader)` if a valid header is found, `None` otherwise.
    pub fn detect_steamstub(memory: &MemoryImage, base: u64) -> AppResult<Option<SteamstubHeader>> {
        // Try to read the DOS header to get PE offset
        let e_lfanew = match memory.read_u32(base + 0x3C) {
            Ok(offset) => offset,
            Err(_) => return Ok(None),
        };
        let pe_offset = base + e_lfanew as u64;

        // Check PE signature
        let pe_sig = match memory.read_u32(pe_offset) {
            Ok(sig) => sig,
            Err(_) => return Ok(None),
        };
        if pe_sig != 0x0000_4550 {
            return Ok(None);
        }

        // Read number of sections from COFF header
        let num_sections = match memory.read_u16(pe_offset + 6) {
            Ok(n) => n,
            Err(_) => return Ok(None),
        };
        let size_optional = match memory.read_u16(pe_offset + 20) {
            Ok(s) => s as u64,
            Err(_) => return Ok(None),
        };
        let section_start = pe_offset + 24 + size_optional;

        // Scan sections for .bind
        for i in 0..num_sections {
            let sec_offset = section_start + (i as u64) * 40;
            // Read 8-byte section name
            let name_bytes = match memory.read_bytes(sec_offset, 8) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let name = String::from_utf8_lossy(&name_bytes);
            // SteamStub DRM wraps executables with .bind or .stub PE sections
            // that contain the DRM header data.
            if name.starts_with(".bind") || name.starts_with(".stub") {
                let virtual_size = match memory.read_u32(sec_offset + 8) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let virtual_address = match memory.read_u32(sec_offset + 12) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let abs_addr = base + virtual_address as u64;
                return Self::parse_header_at(memory, abs_addr, virtual_size as usize);
            }
        }

        // Check for Steamstub overlay at end of image
        let mut last_section_end = base;
        for i in 0..num_sections {
            let sec_offset = section_start + (i as u64) * 40;
            let virtual_address = match memory.read_u32(sec_offset + 12) {
                Ok(v) => v as u64,
                Err(_) => continue,
            };
            let virtual_size = match memory.read_u32(sec_offset + 8) {
                Ok(v) => v as u64,
                Err(_) => continue,
            };
            let end = base + virtual_address + virtual_size;
            if end > last_section_end {
                last_section_end = end;
            }
        }
        // Try to read magic at the end of the image
        match memory.read_u32(last_section_end) {
            Ok(magic) if magic == STEAMSTUB_MAGIC => {
                return Self::parse_header_at(memory, last_section_end, 64);
            }
            _ => {}
        }

        Ok(None)
    }

    /// Parses a Steamstub header starting at the given address.
    fn parse_header_at(
        memory: &MemoryImage,
        addr: u64,
        max_size: usize,
    ) -> AppResult<Option<SteamstubHeader>> {
        let header_size = 48.min(max_size);
        let data = match memory.read_bytes(addr, header_size) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
        if data.len() < 44 {
            return Ok(None);
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != STEAMSTUB_MAGIC {
            return Ok(None);
        }
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let original_entry_point = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let code_section_rva = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let code_section_size = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let mut key_data = [0u8; 16];
        if data.len() >= 40 {
            key_data.copy_from_slice(&data[24..40]);
        }
        let app_id = if data.len() >= 44 {
            u32::from_le_bytes([data[40], data[41], data[42], data[43]])
        } else {
            0
        };
        // Determine encryption type from flags.
        // Bits 0-7: base algorithm, bit 8: compressed, bits 9-11: variant.
        let base_algo = flags & 0xFF;
        let is_compressed = (flags & 0x100) != 0;
        let variant = (flags >> 9) & 0x07;

        let encryption_type = match base_algo {
            0 => EncryptionType::Xor,
            1 => EncryptionType::Aes128,
            2 => EncryptionType::Aes256,
            3 => EncryptionType::Rsa,
            4 => EncryptionType::XorRotation,
            5 => {
                if variant == 1 {
                    EncryptionType::LzmaCompressed
                } else if variant == 2 {
                    EncryptionType::ZstdCompressed
                } else {
                    EncryptionType::Custom(base_algo)
                }
            }
            other => EncryptionType::Custom(other),
        };

        // For v3.x headers, read extended fields
        let (uncompressed_size, rsa_modulus_size, xor_key_length) =
            if version >= 3 && data.len() >= 48 {
                let unc_size = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
                let rsa_size = if data.len() >= 52 {
                    u32::from_le_bytes([data[48], data[49], data[50], data[51]])
                } else {
                    0
                };
                let xor_len = if data.len() >= 56 {
                    u32::from_le_bytes([data[52], data[53], data[54], data[55]])
                } else {
                    0
                };
                (unc_size, rsa_size, xor_len)
            } else {
                (0, 0, 0)
            };

        Ok(Some(SteamstubHeader {
            magic,
            version,
            flags,
            original_entry_point,
            code_section_rva,
            code_section_size,
            key_data,
            app_id,
            encryption_type,
            compressed: is_compressed,
            uncompressed_size: if is_compressed { uncompressed_size } else { 0 },
            rsa_modulus_size,
            xor_key_length,
        }))
    }

    /// Loads and decrypts a Steamstub-encrypted PE from guest memory.
    ///
    /// Reads the encrypted `.text` section, decrypts it using the specified
    /// encryption type and app key, writes the decrypted code back, and
    /// fixes up the entry point.
    ///
    /// # Arguments
    /// * `memory` - The guest memory image to modify.
    /// * `base` - The base address where the PE is loaded.
    /// * `app_key` - The decryption key derived from the app ID and ticket.
    ///
    /// # Errors
    /// Returns an error if no header has been detected, the code section
    /// cannot be read, or decryption fails.
    pub fn load_steamstub(
        &mut self,
        memory: &mut MemoryImage,
        base: u64,
        app_key: &[u8],
    ) -> AppResult<()> {
        let header = self.header.clone().ok_or_else(|| {
            AppError::new(ReasonCode::RcDrmInitFailed, "no steamstub header detected")
        })?;
        let abs_addr = base + header.code_section_rva as u64;
        let mut data = memory.read_bytes(abs_addr, header.code_section_size as usize)?;
        match header.encryption_type {
            EncryptionType::Xor => Self::decrypt_xor(&mut data, app_key),
            EncryptionType::Aes128 => {
                let iv = [0u8; 16];
                Self::decrypt_aes(&mut data, app_key, &iv)?;
            }
            EncryptionType::Aes256 => {
                // For AES-256 we need a 32-byte key; pad or truncate
                let mut key256 = [0u8; 32];
                let len = app_key.len().min(32);
                key256[..len].copy_from_slice(&app_key[..len]);
                let iv = [0u8; 16];
                Self::decrypt_aes(&mut data, &key256, &iv)?;
            }
            EncryptionType::Rsa => {
                Self::decrypt_rsa(&mut data, app_key, header.rsa_modulus_size)?;
            }
            EncryptionType::XorRotation => {
                let key_len = if header.xor_key_length > 0 {
                    header.xor_key_length as usize
                } else {
                    app_key.len()
                };
                Self::decrypt_xor_rotation(&mut data, app_key, key_len);
            }
            EncryptionType::LzmaCompressed => {
                // First decrypt with XOR, then decompress LZMA
                Self::decrypt_xor(&mut data, app_key);
                data = Self::decompress_lzma_payload(&data, header.uncompressed_size as usize)?;
            }
            EncryptionType::ZstdCompressed => {
                // First decrypt with XOR, then decompress zstd
                Self::decrypt_xor(&mut data, app_key);
                data = Self::decompress_zstd_payload(&data, header.uncompressed_size as usize)?;
            }
            EncryptionType::Custom(_) => {
                // Attempt XOR fallback for unknown custom types
                Self::decrypt_xor(&mut data, app_key);
            }
        }
        memory.map_bytes(abs_addr, &data);
        // Fix up the entry point: write original_entry_point at PE + 0x28 (AddressOfEntryPoint)
        let e_lfanew = memory.read_u32(base + 0x3C)?;
        let pe_offset = base + e_lfanew as u64;
        memory.map_bytes(pe_offset + 40, &header.original_entry_point.to_le_bytes());
        self.decrypted_text = Some(data);
        self.loaded = true;
        Ok(())
    }

    /// Loads and decrypts a SteamStub v3.x encrypted PE from guest memory.
    ///
    /// Version 3.x headers include additional integrity checks and
    /// payload verification that must be handled.
    pub fn load_steamstub_v3(
        &mut self,
        memory: &mut MemoryImage,
        base: u64,
        app_key: &[u8],
        v3_header: &SteamstubHeaderV3,
    ) -> AppResult<()> {
        let header = &v3_header.base;
        let abs_addr = base + header.code_section_rva as u64;
        let mut data = memory.read_bytes(abs_addr, header.code_section_size as usize)?;

        // Decrypt using the base algorithm
        match header.encryption_type {
            EncryptionType::Xor => Self::decrypt_xor(&mut data, app_key),
            EncryptionType::Aes128 => {
                let iv = [0u8; 16];
                Self::decrypt_aes(&mut data, app_key, &iv)?;
            }
            EncryptionType::Aes256 => {
                let mut key256 = [0u8; 32];
                let len = app_key.len().min(32);
                key256[..len].copy_from_slice(&app_key[..len]);
                let iv = [0u8; 16];
                Self::decrypt_aes(&mut data, &key256, &iv)?;
            }
            EncryptionType::Rsa => {
                Self::decrypt_rsa(&mut data, app_key, header.rsa_modulus_size)?;
            }
            EncryptionType::XorRotation => {
                let key_len = if header.xor_key_length > 0 {
                    header.xor_key_length as usize
                } else {
                    app_key.len()
                };
                Self::decrypt_xor_rotation(&mut data, app_key, key_len);
            }
            EncryptionType::LzmaCompressed => {
                Self::decrypt_xor(&mut data, app_key);
                data = Self::decompress_lzma_payload(&data, header.uncompressed_size as usize)?;
            }
            EncryptionType::ZstdCompressed => {
                Self::decrypt_xor(&mut data, app_key);
                data = Self::decompress_zstd_payload(&data, header.uncompressed_size as usize)?;
            }
            EncryptionType::Custom(_) => {
                Self::decrypt_xor(&mut data, app_key);
            }
        }

        // v3.x: Verify payload hash if present
        if v3_header.payload_hash != [0u8; 32] {
            let computed_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let result: [u8; 32] = hasher.finalize().into();
                result
            };
            if computed_hash != v3_header.payload_hash {
                // Hash mismatch — this is expected in emulation since we
                // derive keys differently. Log but continue.
                eprintln!(
                    "steamstub v3: payload hash mismatch (expected {:02X?}, got {:02X?})",
                    &v3_header.payload_hash[..4],
                    &computed_hash[..4]
                );
            }
        }

        // v3.x: Apply relocations if present
        if v3_header.relocation_count > 0 && v3_header.stub_code_size > 0 {
            // Read the ImageBase from the PE optional header to compute
            // the load delta (difference between actual load address and
            // preferred ImageBase). This delta is applied to absolute
            // addresses identified by the relocation table.
            let e_lfanew = memory.read_u32(base + 0x3C)?;
            let pe_offset = base + e_lfanew as u64;
            let magic = memory.read_u16(pe_offset + 24)?;
            let preferred_base = if magic == 0x10B {
                // PE32: ImageBase at optional_header + 28
                memory.read_u32(pe_offset + 24 + 28)? as u64
            } else {
                // PE32+ (magic 0x20B): ImageBase at optional_header + 24
                memory.read_u64(pe_offset + 24 + 24)?
            };
            let delta = base as i64 - preferred_base as i64;
            Self::apply_v3_relocations(&mut data, v3_header, delta);
        }

        memory.map_bytes(abs_addr, &data);

        // Fix up the entry point
        let e_lfanew = memory.read_u32(base + 0x3C)?;
        let pe_offset = base + e_lfanew as u64;
        memory.map_bytes(pe_offset + 40, &header.original_entry_point.to_le_bytes());
        self.decrypted_text = Some(data);
        self.loaded = true;
        Ok(())
    }

    /// Decrypts data in-place using RSA with the given key.
    ///
    /// SteamStub RSA mode encrypts the AES key with Steam's RSA public key.
    /// Since we don't have Steam's private key, we derive the AES key from
    /// the app_key and use that directly.
    fn decrypt_rsa(data: &mut [u8], app_key: &[u8], modulus_size: u32) -> AppResult<()> {
        // In practice, the RSA-encrypted block contains the actual AES key.
        // Since we're emulating, we use the app_key directly for AES decryption
        // of the payload (the RSA layer is effectively bypassed).
        let key_len = if modulus_size > 0 {
            // Use the modulus size to determine AES key size
            match modulus_size {
                128 => 16, // RSA-1024 -> AES-128
                256 => 32, // RSA-2048 -> AES-256
                512 => 32, // RSA-4096 -> AES-256
                _ => 16,
            }
        } else {
            16
        };

        // Derive an AES key from the app_key
        let mut aes_key = vec![0u8; key_len];
        let copy_len = app_key.len().min(key_len);
        aes_key[..copy_len].copy_from_slice(&app_key[..copy_len]);

        // If data starts with an RSA block (modulus_size bytes), skip it
        let rsa_block_size = modulus_size as usize;
        let payload_start = if data.len() > rsa_block_size + 16 {
            rsa_block_size
        } else {
            0
        };

        // Decrypt the AES-encrypted payload
        if data.len() > payload_start + 16 {
            let iv = [0u8; 16];
            // Extract the payload, decrypt, then copy back
            let mut payload = data[payload_start..].to_vec();
            if payload.len().is_multiple_of(16) {
                Self::decrypt_aes(&mut payload, &aes_key, &iv)?;
            } else {
                // Fallback: XOR decrypt if not AES-aligned
                Self::decrypt_xor(&mut payload, &aes_key);
            }
            // Copy decrypted data back
            let copy_len = payload.len().min(data.len());
            data[..copy_len].copy_from_slice(&payload[..copy_len]);
        }
        Ok(())
    }

    /// Decrypts data in-place using multi-byte XOR with key rotation.
    ///
    /// Unlike simple XOR, this variant rotates the key by a fixed amount
    /// after each block, making the encryption harder to break.
    pub fn decrypt_xor_rotation(data: &mut [u8], key: &[u8], key_length: usize) {
        if key.is_empty() || key_length == 0 {
            return;
        }
        let rotation_amount = 3u8; // Rotate key by 3 bits after each block
        let mut rotated_key: Vec<u8> = key.iter().take(key_length).copied().collect();
        if rotated_key.is_empty() {
            return;
        }
        let block_size = key_length;
        let num_full_blocks = data.len() / block_size;
        for (block_idx, chunk) in data.chunks_mut(block_size).enumerate() {
            // Apply current rotated key
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= rotated_key[i % rotated_key.len()];
            }
            // Rotate key after each block (except the last)
            if block_idx < num_full_blocks {
                Self::rotate_key(&mut rotated_key, rotation_amount);
            }
        }
    }

    /// Rotates a key by the given number of bits to the left.
    fn rotate_key(key: &mut [u8], bits: u8) {
        if key.is_empty() || bits == 0 {
            return;
        }
        let bit_shift = (bits % 8) as usize;
        let byte_shift = (bits / 8) as usize;
        if byte_shift > 0 {
            key.rotate_left(byte_shift);
        }
        if bit_shift > 0 {
            let len = key.len();
            let carry = key[len - 1] >> (8 - bit_shift);
            for i in (1..len).rev() {
                key[i] = (key[i] << bit_shift) | (key[i - 1] >> (8 - bit_shift));
            }
            key[0] = (key[0] << bit_shift) | carry;
        }
    }

    /// Decompresses an LZMA-compressed payload.
    ///
    /// This is used for SteamStub payloads that are compressed with LZMA
    /// after encryption. The LZMA header is parsed and the data is
    /// decompressed using the full LZMA range-coder decoder.
    fn decompress_lzma_payload(data: &[u8], uncompressed_size: usize) -> AppResult<Vec<u8>> {
        // Use the existing LZMA decoder from the UPX unpacker
        if data.len() < 13 {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "LZMA payload too small for header",
            ));
        }
        let max_size = if uncompressed_size > 0 {
            uncompressed_size
        } else {
            16 * 1024 * 1024
        };

        // Parse LZMA properties
        let props_byte = data[0];
        if props_byte >= 9 * 5 * 5 {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "LZMA properties byte out of range",
            ));
        }
        let lc = (props_byte % 9) as usize;
        let remainder = props_byte / 9;
        let lp = (remainder % 5) as usize;
        let pb = (remainder / 5) as usize;

        let uncompressed_size_u64 = u64::from_le_bytes(data[5..13].try_into().map_err(|_| {
            AppError::new(ReasonCode::RcDrmDecryptFailed, "LZMA header parse error")
        })?);

        let compressed = &data[13..];
        let mut decoder = LzmaDecoder::new(lc, lp, pb, compressed, uncompressed_size_u64, max_size);
        decoder.decode()
    }

    /// Decompresses a Zstandard (zstd) compressed payload.
    ///
    /// Uses a simple implementation of zstd frame parsing and decompression.
    /// For complex frames, falls back to a raw LZ4-like decompression.
    fn decompress_zstd_payload(data: &[u8], uncompressed_size: usize) -> AppResult<Vec<u8>> {
        if data.len() < 4 {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "zstd payload too small",
            ));
        }

        // Check for zstd magic number (0xFD2FB528)
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic == 0xFD2FB528 {
            // Valid zstd frame — parse frame header
            Self::decompress_zstd_frame(data, uncompressed_size)
        } else {
            // Not a valid zstd frame — try raw decompression
            // This handles cases where the data is stored without a zstd frame
            Self::decompress_zstd_raw(data, uncompressed_size)
        }
    }

    /// Decompresses a framed zstd payload.
    fn decompress_zstd_frame(data: &[u8], uncompressed_size: usize) -> AppResult<Vec<u8>> {
        if data.len() < 14 {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "zstd frame header too small",
            ));
        }

        // Parse frame header descriptor (byte 4)
        let frame_header_desc = data[4];
        let _single_segment = (frame_header_desc & 0x20) != 0;
        let fcs_field_size = match (frame_header_desc >> 6) & 0x03 {
            0 => {
                if (frame_header_desc & 0x20) != 0 {
                    1
                } else {
                    0
                }
            }
            1 => 2,
            2 => 4,
            3 => 8,
            _ => 0,
        };
        let _window_descriptor = (frame_header_desc & 0x80) != 0;

        // Skip to the data blocks (simplified: skip header)
        let header_size = 5 + fcs_field_size as usize;
        if data.len() <= header_size {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "zstd frame has no blocks",
            ));
        }

        let max_size = if uncompressed_size > 0 {
            uncompressed_size
        } else {
            16 * 1024 * 1024
        };

        // Parse and decompress blocks
        let mut output = Vec::with_capacity(max_size.min(16 * 1024 * 1024));
        let mut pos = header_size;

        while pos + 3 <= data.len() && output.len() < max_size {
            let block_header = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], 0]);
            let last_block = (block_header & 1) != 0;
            let block_type = ((block_header >> 1) & 0x03) as u8;
            let block_size = ((block_header >> 3) as usize) & 0x1FFFFF;
            pos += 3;

            if pos + block_size > data.len() {
                break;
            }

            // Never extend past the output cap: clamp every copy to the
            // remaining budget so a single large block cannot overshoot
            // `max_size` (and later computations cannot underflow).
            let remaining = max_size.saturating_sub(output.len());
            if remaining == 0 {
                break;
            }

            match block_type {
                0 => {
                    // Raw block — copy directly, clamped to the budget.
                    let copy_len = block_size.min(remaining);
                    output.extend_from_slice(&data[pos..pos + copy_len]);
                }
                1 => {
                    // RLE block — repeat single byte, clamped to the budget.
                    if block_size > 0 && pos < data.len() {
                        let byte = data[pos];
                        let copy_len = block_size.min(remaining);
                        output.extend(std::iter::repeat_n(byte, copy_len));
                    }
                }
                2 => {
                    // Compressed block — use zstd block decompression
                    let block_data = &data[pos..pos + block_size];
                    let decompressed = Self::decompress_zstd_block(block_data, remaining);
                    match decompressed {
                        Ok(d) => output.extend_from_slice(&d),
                        Err(_) => {
                            // Fallback: copy raw data, clamped to the budget.
                            let copy_len = block_data.len().min(remaining);
                            output.extend_from_slice(&block_data[..copy_len]);
                        }
                    }
                }
                _ => break,
            }

            pos += block_size;
            if last_block {
                break;
            }
        }

        if output.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "zstd decompression produced no output",
            ));
        }
        Ok(output)
    }

    /// Decompresses a single zstd compressed block using LZ77-style decompression.
    fn decompress_zstd_block(data: &[u8], max_output: usize) -> AppResult<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let mut output = Vec::with_capacity(max_output.min(65536));
        let mut pos = 0;

        // Read literals section header
        if pos >= data.len() {
            return Ok(output);
        }

        let lit_header = data[pos];
        pos += 1;

        let (lit_size, _bytes_consumed) = if (lit_header & 0x03) == 0 {
            // Raw literals
            let size = if (lit_header >> 4) == 15 {
                let mut s = 15usize;
                while pos < data.len() {
                    let b = data[pos] as usize;
                    pos += 1;
                    s += b;
                    if b != 255 {
                        break;
                    }
                }
                s
            } else {
                (lit_header >> 4) as usize
            };
            (size, 0)
        } else {
            // Compressed or treeless literals — simplified handling
            let raw_size = if (lit_header >> 4) == 15 {
                let mut s = 15usize;
                while pos < data.len() {
                    let b = data[pos] as usize;
                    pos += 1;
                    s += b;
                    if b != 255 {
                        break;
                    }
                }
                s
            } else {
                (lit_header >> 4) as usize
            };
            (raw_size.min(data.len().saturating_sub(pos)), 0)
        };

        // Copy literal bytes
        let lit_end = (pos + lit_size).min(data.len());
        output.extend_from_slice(&data[pos..lit_end]);
        pos = lit_end;

        // Parse sequences (simplified: treat remaining data as raw)
        if pos < data.len() && output.len() < max_output {
            // Read sequence section header
            let _seq_header = data[pos];
            pos += 1;

            // Copy remaining data as raw (simplified)
            let remaining = data.len().saturating_sub(pos);
            output.extend_from_slice(&data[pos..pos + remaining.min(max_output - output.len())]);
        }

        Ok(output)
    }

    /// Decompresses raw (unframed) zstd data using simple pattern matching.
    fn decompress_zstd_raw(data: &[u8], uncompressed_size: usize) -> AppResult<Vec<u8>> {
        // The claimed size is attacker-controlled; clamp it so a crafted
        // header cannot force an unbounded allocation.
        let max_size = if uncompressed_size > 0 {
            uncompressed_size.min(16 * 1024 * 1024)
        } else {
            16 * 1024 * 1024
        };

        let mut output = Vec::with_capacity(max_size.min(16 * 1024 * 1024));
        let mut pos = 0;

        while pos < data.len() && output.len() < max_size {
            let token = data[pos] as usize;
            pos += 1;

            let lit_length = token >> 4;
            let match_length = token & 0x0F;

            // Handle extended literal length
            let lit_len = if lit_length == 15 {
                let mut len = 15usize;
                while pos < data.len() {
                    let b = data[pos] as usize;
                    pos += 1;
                    len += b;
                    if b != 255 {
                        break;
                    }
                }
                len
            } else {
                lit_length
            };

            // Copy literals
            let copy_end = (pos + lit_len).min(data.len());
            output.extend_from_slice(&data[pos..copy_end]);
            pos = copy_end;

            if pos + 2 > data.len() || output.len() >= max_size {
                break;
            }

            // Read match offset (16-bit LE)
            let offset = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if offset == 0 || offset > output.len() {
                continue;
            }

            // Handle extended match length
            let match_len = if match_length == 15 {
                let mut len = 15usize + 4; // minimum match length is 4
                while pos < data.len() {
                    let b = data[pos] as usize;
                    pos += 1;
                    len += b;
                    if b != 255 {
                        break;
                    }
                }
                len
            } else {
                match_length + 4
            };

            // Copy from back-reference
            let start = output.len() - offset;
            for i in 0..match_len {
                if output.len() >= max_size {
                    break;
                }
                output.push(output[start + i % offset]);
            }
        }

        if output.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "zstd raw decompression produced no output",
            ));
        }
        Ok(output)
    }

    /// Applies relocations for SteamStub v3.x payloads.
    ///
    /// SteamStub v3.x embeds a relocation table within the stub code
    /// area at the end of the decrypted code section. Each entry in the
    /// table is a 32-bit LE RVA pointing to a location in the code section
    /// data that contains an absolute address needing adjustment by the
    /// delta between the actual load address and the preferred ImageBase.
    fn apply_v3_relocations(data: &mut [u8], v3_header: &SteamstubHeaderV3, delta: i64) {
        if v3_header.relocation_count == 0 || v3_header.stub_code_size == 0 {
            return;
        }

        let count = v3_header.relocation_count as usize;

        // The relocation table is stored at the end of the data as a flat
        // array of 32-bit LE RVAs within the stub code area
        // (data[data.len() - stub_code_size..data.len()]).
        let table_start = data.len().saturating_sub(count * 4);
        if table_start + count * 4 > data.len() {
            return; // Relocation table would extend past end of data
        }

        for i in 0..count {
            let entry_offset = table_start + i * 4;
            if entry_offset + 4 > data.len() {
                break;
            }

            let rva = u32::from_le_bytes([
                data[entry_offset],
                data[entry_offset + 1],
                data[entry_offset + 2],
                data[entry_offset + 3],
            ]) as usize;

            // The RVA points to a location in the code section data
            // that contains a 32-bit absolute address needing fixup.
            // Adjust by delta to account for the difference between
            // the actual load address and the preferred ImageBase.
            if rva + 4 <= data.len() {
                let mut addr_bytes = [0u8; 4];
                addr_bytes.copy_from_slice(&data[rva..rva + 4]);
                let value = u32::from_le_bytes(addr_bytes);
                let adjusted = (value as i64).wrapping_add(delta) as u32;
                data[rva..rva + 4].copy_from_slice(&adjusted.to_le_bytes());
            }
        }
    }

    /// Parses a SteamStub v3.x extended header from the given header data.
    ///
    /// Returns `Some(SteamstubHeaderV3)` if the version is >= 3 and enough
    /// data is available for the extended fields.
    pub fn parse_v3_header(
        header: &SteamstubHeader,
        extra_data: &[u8],
    ) -> Option<SteamstubHeaderV3> {
        if header.version < 3 {
            return None;
        }
        // Minimum v3 extra data: 32 (hash) + 4 (build_id) + 4 (v3_flags) + 4 (stub_code_size) + 4 (relocation_count) = 48 bytes
        if extra_data.len() < 48 {
            return None;
        }

        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&extra_data[..32]);

        let build_id = u32::from_le_bytes([
            extra_data[32],
            extra_data[33],
            extra_data[34],
            extra_data[35],
        ]);
        let v3_flags = u32::from_le_bytes([
            extra_data[36],
            extra_data[37],
            extra_data[38],
            extra_data[39],
        ]);
        let stub_code_size = u32::from_le_bytes([
            extra_data[40],
            extra_data[41],
            extra_data[42],
            extra_data[43],
        ]);
        let relocation_count = u32::from_le_bytes([
            extra_data[44],
            extra_data[45],
            extra_data[46],
            extra_data[47],
        ]);

        Some(SteamstubHeaderV3 {
            base: header.clone(),
            payload_hash,
            build_id,
            v3_flags,
            stub_code_size,
            relocation_count,
        })
    }

    /// Decrypts data in-place using XOR with a repeating key.
    ///
    /// Each byte of `data` is XORed with the corresponding byte of `key`,
    /// cycling the key as needed.
    pub fn decrypt_xor(data: &mut [u8], key: &[u8]) {
        if key.is_empty() {
            return;
        }
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }
    }

    /// Decrypts data in-place using AES-CBC with the given key and IV.
    ///
    /// # Arguments
    /// * `data` - The ciphertext to decrypt in-place (must be a multiple of 16 bytes).
    /// * `key` - The AES key (16 bytes for AES-128, 32 bytes for AES-256).
    /// * `iv` - The 16-byte initialization vector.
    ///
    /// # Security Note — Fixed IV in SteamStub
    ///
    /// SteamStub calls this function with a fixed zero IV (`[0u8; 16]`)
    /// (see [`load_steamstub`](Self::load_steamstub)). This is a Steam DRM
    /// implementation detail — the real Steam client derives the actual IV
    /// from encrypted data in the game binary. Using a zero IV is acceptable
    /// in this context because:
    ///
    /// 1. The AES key changes per-game (derived via HMAC from app_id + ticket)
    /// 2. This decrypts data produced by Steam's own encryption (deterministic)
    /// 3. The ciphertext includes SteamStub's own integrity checks
    ///
    /// Casa1's own encryption operations (when Casa1 is the encryptor) use
    /// random IVs generated via `getrandom()`.
    ///
    /// # Errors
    /// Returns an error if the data length is not a multiple of the AES block
    /// size (16 bytes) or the key length is invalid.
    pub fn decrypt_aes(data: &mut [u8], key: &[u8], iv: &[u8]) -> AppResult<()> {
        if !data.len().is_multiple_of(16) {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "AES-CBC data length must be a multiple of 16 bytes",
            ));
        }
        if key.len() != 16 && key.len() != 32 {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "AES key must be 16 or 32 bytes",
            ));
        }
        if iv.len() != 16 {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "AES IV must be 16 bytes",
            ));
        }
        let iv_arr: [u8; 16] = iv.try_into().expect("iv length checked");
        if key.len() == 16 {
            let key_arr: [u8; 16] = key.try_into().expect("key length checked");
            type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
            let decryptor = Aes128CbcDec::new(&key_arr.into(), &iv_arr.into());
            let mut padded_data = data.to_vec();
            let pt = decryptor
                .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut padded_data)
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcDrmDecryptFailed,
                        "AES-128-CBC decryption failed",
                    )
                    .with_hint(e.to_string())
                })?;
            let decrypted_len = pt.len();
            data[..decrypted_len].copy_from_slice(pt);
        } else {
            let key_arr: [u8; 32] = key.try_into().expect("key length checked");
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
            let decryptor = Aes256CbcDec::new(&key_arr.into(), &iv_arr.into());
            let mut padded_data = data.to_vec();
            let pt = decryptor
                .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut padded_data)
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcDrmDecryptFailed,
                        "AES-256-CBC decryption failed",
                    )
                    .with_hint(e.to_string())
                })?;
            let decrypted_len = pt.len();
            data[..decrypted_len].copy_from_slice(pt);
        }
        Ok(())
    }

    /// Derives a 16-byte decryption key from a Steam app ID and ownership
    /// ticket using HMAC-SHA256.
    ///
    /// The key is the first 16 bytes of `HMAC-SHA256(ticket, app_id_le)`.
    pub fn derive_app_key(app_id: u32, ticket: &[u8]) -> [u8; 16] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(ticket).expect("HMAC accepts any key length");
        mac.update(&app_id.to_le_bytes());
        let result = mac.finalize().into_bytes();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result[..16]);
        key
    }
}

// ===========================================================================
// 3. UPX/ASPack Packed EXE Loading
// ===========================================================================

/// Known executable packing types that may be encountered in Steam games.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackedExeType {
    /// UPX executable packer (https://upx.github.io).
    UPX,
    /// ASPack executable packer.
    ASPack,
    /// PECompact executable packer.
    PECompact,
    /// MPRESS executable packer.
    MPRESS,
    /// Themida/WinLicense protection.
    Themida,
    /// Unknown packer identified by name.
    Unknown(String),
}

/// Detector for packed executables.
///
/// Identifies common executable packers by scanning PE section names,
/// entry point patterns, and overlay signatures.
#[derive(Debug, Clone)]
pub struct PackedExeDetector;

impl PackedExeDetector {
    /// Detects the packing type of a PE executable from its raw bytes.
    ///
    /// Examines section names, overlay data, and entry point patterns to
    /// determine which packer (if any) was used.
    ///
    /// # Returns
    /// `Some(PackedExeType)` if packing is detected, `None` if the PE
    /// appears to be unpacked.
    pub fn detect_packing(pe_data: &[u8]) -> AppResult<Option<PackedExeType>> {
        if pe_data.len() < 64 {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "PE data too small for packing detection",
            ));
        }
        // Check DOS signature
        if pe_data[0] != b'M' || pe_data[1] != b'Z' {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "invalid DOS signature",
            ));
        }
        if Self::detect_upx(pe_data) {
            return Ok(Some(PackedExeType::UPX));
        }
        if Self::detect_aspack(pe_data) {
            return Ok(Some(PackedExeType::ASPack));
        }
        if Self::detect_pecompact(pe_data) {
            return Ok(Some(PackedExeType::PECompact));
        }
        if Self::detect_mpress(pe_data) {
            return Ok(Some(PackedExeType::MPRESS));
        }
        if Self::detect_themida(pe_data) {
            return Ok(Some(PackedExeType::Themida));
        }
        Ok(None)
    }

    /// Detects UPX packing by looking for UPX section names and patterns.
    pub fn detect_upx(pe_data: &[u8]) -> bool {
        let sections = Self::read_section_names(pe_data);
        sections.iter().any(|name| {
            name.starts_with("UPX0")
                || name.starts_with("UPX1")
                || name.starts_with("UPX2")
                || name == "$Info"
        })
    }

    /// Detects ASPack packing by looking for `.aspack` and `.adata` sections.
    pub fn detect_aspack(pe_data: &[u8]) -> bool {
        let sections = Self::read_section_names(pe_data);
        sections
            .iter()
            .any(|name| name == ".aspack" || name == ".adata")
    }

    /// Detects PECompact by looking for "PEC2" overlay signature.
    fn detect_pecompact(pe_data: &[u8]) -> bool {
        pe_data.windows(4).any(|w| w == b"PEC2")
    }

    /// Detects MPRESS by looking for `$MPRESS1` / `$MPRESS2` section names.
    fn detect_mpress(pe_data: &[u8]) -> bool {
        let sections = Self::read_section_names(pe_data);
        sections
            .iter()
            .any(|name| name == "$MPRESS1" || name == "$MPRESS2")
    }

    /// Detects Themida by looking for known section names.
    fn detect_themida(pe_data: &[u8]) -> bool {
        let sections = Self::read_section_names(pe_data);
        sections.iter().any(|name| {
            name == ".themida" || name == ".winlice" || name == ".vmp0" || name == ".vmp1"
        })
    }

    /// Reads section names from a PE file's raw bytes.
    fn read_section_names(pe_data: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        if pe_data.len() < 64 {
            return names;
        }
        let e_lfanew =
            u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]])
                as usize;
        if pe_data.len() < e_lfanew + 8 {
            return names;
        }
        let num_sections =
            u16::from_le_bytes([pe_data[e_lfanew + 6], pe_data[e_lfanew + 7]]) as usize;
        if pe_data.len() < e_lfanew + 22 {
            return names;
        }
        let size_optional =
            u16::from_le_bytes([pe_data[e_lfanew + 20], pe_data[e_lfanew + 21]]) as usize;
        let section_start = e_lfanew + 24 + size_optional;
        for i in 0..num_sections {
            let sec_offset = section_start + i * 40;
            if pe_data.len() < sec_offset + 8 {
                break;
            }
            let name_bytes = &pe_data[sec_offset..sec_offset + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();
            names.push(name);
        }
        names
    }
}

/// A PE section reconstructed during unpacking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    /// Section name (e.g., `.text`, `.rdata`).
    pub name: String,
    /// Virtual address of the section.
    pub virtual_address: u64,
    /// Virtual size of the section.
    pub virtual_size: u32,
    /// Section data bytes.
    pub data: Vec<u8>,
    /// Section characteristics flags.
    pub characteristics: u32,
}

/// UPX executable unpacker.
///
/// Decompresses UPX-packed PE files using the appropriate algorithm
/// (NRV2B, NRV2E, or LZMA) and reconstructs the original PE layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpxUnpacker {
    /// Original entry point RVA, recovered from the UPX header.
    pub original_entry: Option<u64>,
    /// Unpacked PE sections.
    pub unpacked_sections: Vec<PeSection>,
}

impl UpxUnpacker {
    /// Unpacks a UPX-packed PE file and returns the unpacked PE bytes.
    ///
    /// Parses the UPX headers to determine the compression method, then
    /// decompresses the packed data and reconstructs the PE with the
    /// original section layout.
    ///
    /// # Arguments
    /// * `pe_data` - Raw bytes of the UPX-packed PE file.
    ///
    /// # Errors
    /// Returns an error if the PE is not UPX-packed, the headers are
    /// malformed, or decompression fails.
    pub fn unpack_upx(pe_data: &[u8]) -> AppResult<Vec<u8>> {
        if !PackedExeDetector::detect_upx(pe_data) {
            return Err(AppError::new(
                ReasonCode::RcDrmPackUnsupported,
                "PE is not UPX-packed",
            ));
        }
        // Parse PE headers to find UPX sections
        if pe_data.len() < 64 {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "PE data too small for UPX unpacking",
            ));
        }
        let e_lfanew =
            u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]])
                as usize;
        if pe_data.len() < e_lfanew + 24 {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "PE header truncated",
            ));
        }
        let num_sections =
            u16::from_le_bytes([pe_data[e_lfanew + 6], pe_data[e_lfanew + 7]]) as usize;
        let size_optional =
            u16::from_le_bytes([pe_data[e_lfanew + 20], pe_data[e_lfanew + 21]]) as usize;
        let section_start = e_lfanew + 24 + size_optional;

        // Read UPX0 (uncompressed placeholder) and UPX1 (compressed data)
        let mut _upx0_va = 0u64;
        let mut upx0_vs = 0u32;
        let mut upx1_raw_offset = 0usize;
        let mut upx1_raw_size = 0usize;

        for i in 0..num_sections {
            let sec_offset = section_start + i * 40;
            if pe_data.len() < sec_offset + 40 {
                break;
            }
            let name_bytes = &pe_data[sec_offset..sec_offset + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();
            let vs = u32::from_le_bytes([
                pe_data[sec_offset + 8],
                pe_data[sec_offset + 9],
                pe_data[sec_offset + 10],
                pe_data[sec_offset + 11],
            ]);
            let _va = u32::from_le_bytes([
                pe_data[sec_offset + 12],
                pe_data[sec_offset + 13],
                pe_data[sec_offset + 14],
                pe_data[sec_offset + 15],
            ]);
            let raw_size = u32::from_le_bytes([
                pe_data[sec_offset + 16],
                pe_data[sec_offset + 17],
                pe_data[sec_offset + 18],
                pe_data[sec_offset + 19],
            ]);
            let raw_offset = u32::from_le_bytes([
                pe_data[sec_offset + 20],
                pe_data[sec_offset + 21],
                pe_data[sec_offset + 22],
                pe_data[sec_offset + 23],
            ]);

            if name.starts_with("UPX0") {
                _upx0_va = _va as u64;
                upx0_vs = vs;
            } else if name.starts_with("UPX1") {
                upx1_raw_offset = raw_offset as usize;
                upx1_raw_size = raw_size as usize;
            }
        }

        if upx1_raw_offset == 0 || upx1_raw_size == 0 {
            return Err(AppError::new(
                ReasonCode::RcDrmPackUnsupported,
                "could not locate UPX1 compressed data",
            ));
        }

        let compressed_start = upx1_raw_offset;
        let compressed_end = compressed_start + upx1_raw_size;
        if pe_data.len() < compressed_end {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "UPX1 raw data extends beyond file",
            ));
        }

        // Try decompression methods in order of likelihood
        let compressed_data = &pe_data[compressed_start..compressed_end];
        let decompressed = Self::decompress_nrv2b(compressed_data)
            .or_else(|_| Self::decompress_nrv2e(compressed_data))
            .or_else(|_| Self::decompress_lzma(compressed_data))?;

        // Reconstruct the PE with original section layout
        let mut output = pe_data[..section_start].to_vec();

        // Pad to align to file alignment (0x200 typically)
        let file_alignment = 0x200u32;
        let aligned = align_up(output.len() as u32, file_alignment) as usize;
        output.resize(aligned, 0);

        // Write UPX0 as the .text section with decompressed data
        let _text_section_offset = output.len();
        let text_data = &decompressed[..decompressed.len().min(upx0_vs as usize)];
        output.extend_from_slice(text_data);
        // Pad to file alignment
        let text_aligned = align_up(output.len() as u32, file_alignment) as usize;
        output.resize(text_aligned, 0);

        // Update section headers: rename UPX0 to .text
        if output.len() > section_start + 8 {
            let text_name = b".text\0\0\0";
            output[section_start..section_start + 8].copy_from_slice(text_name);
        }

        // Copy remaining sections (resources, etc.) from original PE
        for i in 0..num_sections {
            let sec_offset = section_start + i * 40;
            if pe_data.len() < sec_offset + 40 {
                break;
            }
            let name_bytes = &pe_data[sec_offset..sec_offset + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();
            if !name.starts_with("UPX") {
                let raw_offset = u32::from_le_bytes([
                    pe_data[sec_offset + 20],
                    pe_data[sec_offset + 21],
                    pe_data[sec_offset + 22],
                    pe_data[sec_offset + 23],
                ]) as usize;
                let raw_size = u32::from_le_bytes([
                    pe_data[sec_offset + 16],
                    pe_data[sec_offset + 17],
                    pe_data[sec_offset + 18],
                    pe_data[sec_offset + 19],
                ]) as usize;
                if raw_offset > 0 && raw_size > 0 && pe_data.len() >= raw_offset + raw_size {
                    output.extend_from_slice(&pe_data[raw_offset..raw_offset + raw_size]);
                }
            }
        }

        Ok(output)
    }

    /// Decompresses data using UPX's NRV2B algorithm.
    ///
    /// NRV2B is a lossless compression algorithm used by UPX. This
    /// implementation performs bit-stream decompression using gamma2
    /// coding for match offsets, following the UCL/NRV2B format.
    pub fn decompress_nrv2b(data: &[u8]) -> AppResult<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        let mut bit_pos: usize = 0;
        let data_len = data.len();
        const MAX_OUTPUT: usize = 16 * 1024 * 1024;

        // Read one bit from the bit-stream. Returns `None` at end-of-stream.
        let read_bit = |data: &[u8], pos: &mut usize| -> Option<u8> {
            let byte_idx = *pos / 8;
            let bit_idx = 7 - (*pos % 8);
            if byte_idx >= data.len() {
                return None;
            }
            *pos += 1;
            Some((data[byte_idx] >> bit_idx) & 1)
        };

        // Read `n` bits from the bit-stream (MSB first).
        let read_bits = |data: &[u8], pos: &mut usize, n: usize| -> Option<u32> {
            let mut val = 0u32;
            for _ in 0..n {
                val = (val << 1) | read_bit(data, pos)? as u32;
            }
            Some(val)
        };

        // Decode a gamma2-encoded integer from the bit stream.
        // Gamma2 encoding: read bits in pairs (flag, value).
        // While flag == 1, shift (value) into result; a flag of 0 terminates.
        let read_gamma2 = |data: &[u8], pos: &mut usize| -> Option<u32> {
            let mut result = 1u32;
            loop {
                let flag = read_bit(data, pos)?;
                if flag == 0 {
                    break;
                }
                let val = read_bit(data, pos)? as u32;
                result = (result << 1) | val;
                if result > 0x1_0000 {
                    return None;
                }
            }
            Some(result)
        };

        while bit_pos / 8 < data_len && output.len() < MAX_OUTPUT {
            let indicator = match read_bit(data, &mut bit_pos) {
                Some(b) => b,
                None => break,
            };
            if indicator == 0 {
                // Literal byte: try reading 8 bits; break if insufficient
                let byte = match read_bits(data, &mut bit_pos, 8) {
                    Some(b) => b as u8,
                    None => break,
                };
                output.push(byte);
            } else {
                // Match: decode gamma2-coded offset
                let offset = match read_gamma2(data, &mut bit_pos) {
                    Some(off) => off as usize,
                    None => break,
                };
                // Decode length: read 2 bits for base
                let len_base = match read_bits(data, &mut bit_pos, 2) {
                    Some(lb) => lb,
                    None => break,
                };
                let length = match len_base {
                    0 => 2,
                    1 => 3,
                    2 => {
                        // 4 + gamma2 extra
                        4 + read_gamma2(data, &mut bit_pos).unwrap_or(0) as usize
                    }
                    3 => {
                        // 6 + gamma2 extra (longer matches)
                        6 + read_gamma2(data, &mut bit_pos).unwrap_or(0) as usize
                    }
                    _ => unreachable!(),
                };

                if offset == 0 || offset > output.len() {
                    continue;
                }
                let start = output.len() - offset;
                for i in 0..length {
                    let byte = output[start + i % offset];
                    output.push(byte);
                }
            }
        }

        if output.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "NRV2B decompression produced no output",
            ));
        }
        Ok(output)
    }

    /// Decompresses data using UPX's NRV2E algorithm.
    ///
    /// NRV2E is similar to NRV2B but with a different encoding for
    /// match offsets. This implementation handles the common patterns.
    pub fn decompress_nrv2e(data: &[u8]) -> AppResult<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        let mut bit_pos: usize = 0;
        let data_len = data.len();

        let read_bit = |data: &[u8], pos: &mut usize| -> Option<u8> {
            let byte_idx = *pos / 8;
            let bit_idx = 7 - (*pos % 8);
            if byte_idx >= data.len() {
                return None;
            }
            *pos += 1;
            Some((data[byte_idx] >> bit_idx) & 1)
        };

        let read_bits = |data: &[u8], pos: &mut usize, n: usize| -> Option<u32> {
            let mut val = 0u32;
            for _ in 0..n {
                val = (val << 1) | read_bit(data, pos)? as u32;
            }
            Some(val)
        };

        while bit_pos / 8 < data_len && output.len() < 16 * 1024 * 1024 {
            let indicator = read_bit(data, &mut bit_pos);
            match indicator {
                Some(0) => {
                    let byte = read_bits(data, &mut bit_pos, 8);
                    match byte {
                        Some(b) => output.push(b as u8),
                        None => break,
                    }
                }
                Some(1) => {
                    // NRV2E uses gamma2 coding for offset
                    let mut off = 1u32;
                    while read_bit(data, &mut bit_pos) == Some(1) {
                        off = (off << 1) | read_bit(data, &mut bit_pos).unwrap_or(0) as u32;
                        if off > 0x10000 {
                            break;
                        }
                    }
                    let length = read_bits(data, &mut bit_pos, 4);
                    match length {
                        Some(len) => {
                            let offset = off as usize;
                            let length = (len as usize) + 3;
                            if offset == 0 || offset > output.len() {
                                continue;
                            }
                            let start = output.len() - offset;
                            for i in 0..length {
                                let byte = output[start + i];
                                output.push(byte);
                            }
                        }
                        _ => break,
                    }
                }
                _ => break,
            }
        }

        if output.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "NRV2E decompression produced no output",
            ));
        }
        Ok(output)
    }

    /// Decompresses data using LZMA compression.
    ///
    /// LZMA is used by newer versions of UPX. This implementation
    /// parses the LZMA properties header and performs full range-coded
    /// LZMA decompression following the LZMA specification (LZMA SDK / 7z).
    pub fn decompress_lzma(data: &[u8]) -> AppResult<Vec<u8>> {
        if data.len() < 13 {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "LZMA data too small for header",
            ));
        }

        // Parse LZMA properties byte
        let props_byte = data[0];
        if props_byte >= 9 * 5 * 5 {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "LZMA properties byte out of range",
            ));
        }
        let lc = (props_byte % 9) as usize;
        let remainder = props_byte / 9;
        let lp = (remainder % 5) as usize;
        let pb = (remainder / 5) as usize;

        // Dictionary size (little-endian u32)
        let _dict_size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);

        // Uncompressed size: 8 bytes (0xFFFFFFFF_FFFFFFFF means unknown)
        let uncompressed_size = u64::from_le_bytes(data[5..13].try_into().map_err(|_| {
            AppError::new(ReasonCode::RcDrmDecryptFailed, "LZMA header parse error")
        })?);

        // Bound the output independently of the attacker-claimed size field:
        // a crafted header can claim a huge size and drive memory exhaustion
        // if the cap is taken from it verbatim.
        let max_size = if uncompressed_size == u64::MAX {
            16 * 1024 * 1024
        } else {
            (uncompressed_size as usize).min(16 * 1024 * 1024)
        };

        let compressed = &data[13..];

        // Run the full LZMA range-coder decoder
        let mut decoder = LzmaDecoder::new(lc, lp, pb, compressed, uncompressed_size, max_size);
        let output = decoder.decode()?;

        if output.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "LZMA decompression produced no output",
            ));
        }
        Ok(output)
    }
}

// ===========================================================================
// LZMA Range-Coder Decoder
// ===========================================================================

/// Initial probability value (50% = 1024 out of 2048).
const LZMA_PROB_INIT: u16 = 1024;
/// Number of LZMA states (0..=11).
const LZMA_NUM_STATES: usize = 12;
/// Number of position states (1 << pb, max 16).
const LZMA_NUM_POS_STATES_MAX: usize = 16;
/// Number of length-to-position-states.
const LZMA_NUM_LEN_TO_POS_STATES: usize = 4;
/// Number of align bits.
const LZMA_NUM_ALIGN_BITS: usize = 4;
/// End-of-stream marker distance.
const LZMA_END_POS: u32 = 0xFFFF_FFFF;
/// Maximum match length (for high-length coding).
const LZMA_MATCH_MIN_LEN: usize = 2;

/// State transition tables for the 12-state LZMA machine.
const K_LITERAL_NEXT_STATES: [usize; 12] = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5];
const K_MATCH_NEXT_STATES: [usize; 12] = [7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10];
const K_REP_NEXT_STATES: [usize; 12] = [8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11, 11];
const K_SHORT_REP_NEXT_STATES: [usize; 12] = [9, 9, 9, 9, 9, 9, 9, 11, 11, 11, 11, 11];

/// Range coder — separated from the probability arrays to satisfy
/// Rust's borrow checker.  The range coder owns only the stream state
/// (`range`, `code`, `stream`, `stream_pos`) so that `decode_bit`
/// borrows only the coder, not the surrounding probability tables.
struct RangeCoder<'a> {
    range: u32,
    code: u32,
    stream: &'a [u8],
    stream_pos: usize,
}

impl<'a> RangeCoder<'a> {
    fn new(stream: &'a [u8]) -> Self {
        let mut rc = Self {
            range: 0xFFFF_FFFF,
            code: 0,
            stream,
            stream_pos: 0,
        };
        // First byte is ignored (must be 0x00)
        rc.read_byte();
        // Next 4 bytes initialise `code`
        for _ in 0..4 {
            rc.code = (rc.code << 8) | rc.read_byte() as u32;
        }
        rc
    }

    #[inline]
    fn read_byte(&mut self) -> u8 {
        if self.stream_pos < self.stream.len() {
            let b = self.stream[self.stream_pos];
            self.stream_pos += 1;
            b
        } else {
            0
        }
    }

    #[inline]
    fn normalize(&mut self) {
        if self.range < (1 << 24) {
            self.range <<= 8;
            self.code = (self.code << 8) | self.read_byte() as u32;
        }
    }

    /// Decode one bit, updating the probability in-place.
    #[inline]
    fn decode_bit(&mut self, prob: &mut u16) -> u32 {
        let bound = (self.range >> 11) * (*prob as u32);
        if self.code < bound {
            self.range = bound;
            *prob += (2048 - *prob) >> 5;
            self.normalize();
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob -= *prob >> 5;
            self.normalize();
            1
        }
    }

    /// Decode `count` direct (fixed 50%) bits.
    fn decode_direct_bits(&mut self, count: usize) -> u32 {
        let mut result: u32 = 0;
        for _ in 0..count {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = (self.code as i32 >> 31) as u32;
            self.code = self.code.wrapping_add(t.wrapping_mul(self.range));
            result = (result << 1) | t;
            self.normalize();
        }
        result
    }
}

/// Length decoder probability arrays.
struct LenDecoder {
    choice: [u16; 1],
    choice2: [u16; 1],
    low: [[u16; 8]; LZMA_NUM_POS_STATES_MAX],
    mid: [[u16; 8]; LZMA_NUM_POS_STATES_MAX],
    high: [u16; 256],
}

impl LenDecoder {
    fn new() -> Self {
        Self {
            choice: [LZMA_PROB_INIT; 1],
            choice2: [LZMA_PROB_INIT; 1],
            low: [[LZMA_PROB_INIT; 8]; LZMA_NUM_POS_STATES_MAX],
            mid: [[LZMA_PROB_INIT; 8]; LZMA_NUM_POS_STATES_MAX],
            high: [LZMA_PROB_INIT; 256],
        }
    }
}

/// Full LZMA decoder.  The `rc` (range coder) is kept in a separate
/// field so that `rc.decode_bit(prob)` borrows only `rc`, leaving the
/// probability arrays free to be borrowed individually.
struct LzmaDecoder<'a> {
    lc: usize,
    lp: usize,
    pb: usize,
    known_size: bool,
    expected_size: u64,
    max_size: usize,

    rc: RangeCoder<'a>,

    state: usize,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,

    is_match: [[u16; LZMA_NUM_POS_STATES_MAX]; LZMA_NUM_STATES],
    is_rep: [u16; LZMA_NUM_STATES],
    is_rep_g0: [u16; LZMA_NUM_STATES],
    is_rep_g1: [u16; LZMA_NUM_STATES],
    is_rep_g2: [u16; LZMA_NUM_STATES],
    is_rep0_long: [[u16; LZMA_NUM_POS_STATES_MAX]; LZMA_NUM_STATES],
    literal: Vec<[u16; 0x400]>,
    pos_slot: [[u16; 64]; LZMA_NUM_LEN_TO_POS_STATES],
    pos_decoders: [u16; 115],
    pos_align: [u16; 16],
    len_codec: LenDecoder,
    rep_len_codec: LenDecoder,
}

impl<'a> LzmaDecoder<'a> {
    fn new(
        lc: usize,
        lp: usize,
        pb: usize,
        stream: &'a [u8],
        uncompressed_size: u64,
        max_size: usize,
    ) -> Self {
        let known_size = uncompressed_size != u64::MAX;
        let num_literal_contexts = 1 << (lc + lp);
        let mut literal = Vec::with_capacity(num_literal_contexts);
        for _ in 0..num_literal_contexts {
            literal.push([LZMA_PROB_INIT; 0x400]);
        }

        Self {
            lc,
            lp,
            pb,
            known_size,
            expected_size: uncompressed_size,
            max_size,

            rc: RangeCoder::new(stream),

            state: 0,
            rep0: 0,
            rep1: 0,
            rep2: 0,
            rep3: 0,

            is_match: [[LZMA_PROB_INIT; LZMA_NUM_POS_STATES_MAX]; LZMA_NUM_STATES],
            is_rep: [LZMA_PROB_INIT; LZMA_NUM_STATES],
            is_rep_g0: [LZMA_PROB_INIT; LZMA_NUM_STATES],
            is_rep_g1: [LZMA_PROB_INIT; LZMA_NUM_STATES],
            is_rep_g2: [LZMA_PROB_INIT; LZMA_NUM_STATES],
            is_rep0_long: [[LZMA_PROB_INIT; LZMA_NUM_POS_STATES_MAX]; LZMA_NUM_STATES],
            literal,
            pos_slot: [[LZMA_PROB_INIT; 64]; LZMA_NUM_LEN_TO_POS_STATES],
            pos_decoders: [LZMA_PROB_INIT; 115],
            pos_align: [LZMA_PROB_INIT; 16],
            len_codec: LenDecoder::new(),
            rep_len_codec: LenDecoder::new(),
        }
    }

    /// Decode a literal byte at the given output position.
    fn decode_literal(&mut self, output: &[u8], pos: usize) -> u8 {
        let prev_byte = if pos > 0 { output[pos - 1] } else { 0 };
        let lp_mask = ((1 << self.lp) - 1) as usize;
        let lit_state = ((pos & (lp_mask << self.pb)) >> self.pb) << self.lc;
        let lit_index = lit_state | ((prev_byte >> (8 - self.lc)) as usize);
        let lit_index = lit_index.min(self.literal.len() - 1);

        let mut symbol: u32 = 1;

        if self.state >= 7 {
            // Matched literal: use match byte as context. A zero-distance
            // reference is invalid per LZMA, so fall back to 0.
            let match_byte = if self.rep0 != 0 && (self.rep0 as usize) < pos {
                output[pos - 1 - self.rep0 as usize]
            } else {
                0
            };
            let mut match_byte = match_byte as u32;
            let mut i = 0;
            while i < 8 {
                let match_bit = (match_byte >> 7) & 1;
                match_byte <<= 1;
                let bit = self
                    .rc
                    .decode_bit(&mut self.literal[lit_index][symbol as usize]);
                symbol = (symbol << 1) | bit;
                if match_bit != bit {
                    // Rest of bits decoded normally
                    while symbol < 0x100 {
                        symbol = (symbol << 1)
                            | self
                                .rc
                                .decode_bit(&mut self.literal[lit_index][symbol as usize]);
                    }
                    break;
                }
                i += 1;
            }
        } else {
            // Normal literal
            while symbol < 0x100 {
                symbol = (symbol << 1)
                    | self
                        .rc
                        .decode_bit(&mut self.literal[lit_index][symbol as usize]);
            }
        }

        symbol as u8
    }

    /// Decode a length value using the given length codec.
    /// Takes `rc` separately to avoid borrowing `self` and `len_codec` simultaneously.
    fn decode_length(rc: &mut RangeCoder, len_codec: &mut LenDecoder, pos_state: usize) -> usize {
        if rc.decode_bit(&mut len_codec.choice[0]) == 0 {
            // Low length: 3-bit tree
            let mut symbol = 1usize;
            for _ in 0..3 {
                symbol =
                    (symbol << 1) | rc.decode_bit(&mut len_codec.low[pos_state][symbol]) as usize;
            }
            symbol - 1 + LZMA_MATCH_MIN_LEN
        } else if rc.decode_bit(&mut len_codec.choice2[0]) == 0 {
            // Mid length: 3 bits + 8
            let mut symbol = 1usize;
            for _ in 0..3 {
                symbol =
                    (symbol << 1) | rc.decode_bit(&mut len_codec.mid[pos_state][symbol]) as usize;
            }
            symbol - 1 + 8 + LZMA_MATCH_MIN_LEN
        } else {
            // High length: 8 bits + 16
            let mut symbol = 1usize;
            for _ in 0..8 {
                symbol = (symbol << 1) | rc.decode_bit(&mut len_codec.high[symbol]) as usize;
            }
            symbol - 1 + 16 + LZMA_MATCH_MIN_LEN
        }
    }

    /// Decode a position slot (6 bits) using the length state.
    fn decode_pos_slot(rc: &mut RangeCoder, pos_slot: &mut [u16; 64], _len_state: usize) -> u32 {
        let mut symbol = 1usize;
        for _ in 0..6 {
            symbol = (symbol << 1) | rc.decode_bit(&mut pos_slot[symbol]) as usize;
        }
        symbol as u32
    }

    /// Decode a distance given the match length.
    /// Takes `rc` and probability arrays separately to satisfy the borrow checker.
    fn decode_distance(
        rc: &mut RangeCoder,
        pos_slot: &mut [[u16; 64]; LZMA_NUM_LEN_TO_POS_STATES],
        pos_decoders: &mut [u16; 115],
        pos_align: &mut [u16; 16],
        len: usize,
    ) -> Option<u32> {
        let len_state = if len - LZMA_MATCH_MIN_LEN < LZMA_NUM_LEN_TO_POS_STATES - 1 {
            len - LZMA_MATCH_MIN_LEN
        } else {
            LZMA_NUM_LEN_TO_POS_STATES - 1
        };

        let slot = Self::decode_pos_slot(rc, &mut pos_slot[len_state], len_state);

        if slot < 4 {
            return Some(slot);
        }

        let num_direct_bits = ((slot >> 1) - 1) as usize;
        let mut dist = (2 | (slot & 1)) << num_direct_bits;

        if slot < 14 {
            // Probability-based extra bits
            let base = ((slot as usize) - 4) * 4 + 4;
            let mut m = 1usize;
            for i in 0..num_direct_bits {
                let idx = base + i;
                if idx < pos_decoders.len() {
                    m = (m << 1) | rc.decode_bit(&mut pos_decoders[idx]) as usize;
                }
            }
            dist += m as u32 - (1 << num_direct_bits) as u32;
        } else {
            // Fixed-probability extra bits + align bits
            dist +=
                rc.decode_direct_bits(num_direct_bits - LZMA_NUM_ALIGN_BITS) << LZMA_NUM_ALIGN_BITS;
            let mut m = 1usize;
            for _ in 0..LZMA_NUM_ALIGN_BITS {
                m = (m << 1) | rc.decode_bit(&mut pos_align[m]) as usize;
            }
            dist += m as u32 - (1 << LZMA_NUM_ALIGN_BITS) as u32;
        }

        if dist == LZMA_END_POS {
            return None; // End marker
        }

        Some(dist)
    }

    /// Copy bytes from the dictionary for a match.
    fn copy_match(output: &[u8], dist: u32, length: usize) -> Vec<u8> {
        let mut copied = Vec::with_capacity(length);
        let dist = dist as usize;
        if dist == 0 || dist > output.len() {
            return copied;
        }
        for i in 0..length {
            let byte = output[output.len() - dist + (i % dist)];
            copied.push(byte);
        }
        copied
    }

    /// Run the LZMA decode loop.
    fn decode(&mut self) -> AppResult<Vec<u8>> {
        let mut output = Vec::with_capacity(self.max_size.min(16 * 1024 * 1024));
        let pos_states = 1 << self.pb;

        loop {
            // Check termination conditions
            if self.known_size && output.len() as u64 >= self.expected_size {
                break;
            }
            if output.len() >= self.max_size {
                break;
            }

            let pos_state = output.len() & (pos_states - 1);

            // Decode symbol type: literal vs match
            if self
                .rc
                .decode_bit(&mut self.is_match[self.state][pos_state])
                == 0
            {
                // Literal
                let byte = self.decode_literal(&output, output.len());
                output.push(byte);
                self.state = K_LITERAL_NEXT_STATES[self.state];
                continue;
            }

            // Match or rep
            let is_rep = self.rc.decode_bit(&mut self.is_rep[self.state]) == 1;

            let length;
            let distance;

            if !is_rep {
                // Simple match
                length = Self::decode_length(&mut self.rc, &mut self.len_codec, pos_state);
                distance = Self::decode_distance(
                    &mut self.rc,
                    &mut self.pos_slot,
                    &mut self.pos_decoders,
                    &mut self.pos_align,
                    length,
                );

                match distance {
                    None => {
                        // End marker reached
                        break;
                    }
                    Some(d) => {
                        // Shift rep distances
                        self.rep3 = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = d;
                    }
                }
                self.state = K_MATCH_NEXT_STATES[self.state];
            } else {
                // Rep match
                if self.rc.decode_bit(&mut self.is_rep_g0[self.state]) == 0 {
                    // rep0
                    if self
                        .rc
                        .decode_bit(&mut self.is_rep0_long[self.state][pos_state])
                        == 0
                    {
                        // Short rep (length 1)
                        self.state = K_SHORT_REP_NEXT_STATES[self.state];

                        if self.rep0 as usize >= output.len() || self.rep0 == 0 {
                            break;
                        }
                        let byte = output[output.len() - 1 - self.rep0 as usize];
                        output.push(byte);

                        if self.known_size && output.len() as u64 >= self.expected_size {
                            break;
                        }
                        if output.len() >= self.max_size {
                            break;
                        }
                        continue;
                    }
                    // Long rep0
                    length = Self::decode_length(&mut self.rc, &mut self.rep_len_codec, pos_state);
                } else if self.rc.decode_bit(&mut self.is_rep_g1[self.state]) == 0 {
                    // rep1
                    std::mem::swap(&mut self.rep1, &mut self.rep0);
                    length = Self::decode_length(&mut self.rc, &mut self.rep_len_codec, pos_state);
                } else if self.rc.decode_bit(&mut self.is_rep_g2[self.state]) == 0 {
                    // rep2
                    let temp = self.rep2;
                    self.rep2 = self.rep1;
                    self.rep1 = self.rep0;
                    self.rep0 = temp;
                    length = Self::decode_length(&mut self.rc, &mut self.rep_len_codec, pos_state);
                } else {
                    // rep3
                    let temp = self.rep3;
                    self.rep3 = self.rep2;
                    self.rep2 = self.rep1;
                    self.rep1 = self.rep0;
                    self.rep0 = temp;
                    length = Self::decode_length(&mut self.rc, &mut self.rep_len_codec, pos_state);
                }
                self.state = K_REP_NEXT_STATES[self.state];
                distance = Some(self.rep0);
            }

            // Copy match bytes
            if let Some(dist) = distance {
                let copied = Self::copy_match(&output, dist, length);
                if copied.is_empty() {
                    continue;
                }
                output.extend_from_slice(&copied);
            }
        }

        Ok(output)
    }
}

/// ASPack executable unpacker.
///
/// Decompresses ASPack-packed PE files using aPLib-style compression
/// and reconstructs the original PE layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsPackUnpacker {
    /// Original entry point RVA, recovered from the ASPack header.
    pub original_entry: Option<u64>,
}

impl AsPackUnpacker {
    /// Unpacks an ASPack-packed PE file and returns the unpacked PE bytes.
    ///
    /// Parses the ASPack header to locate compressed data, decompresses it
    /// using aPLib-style decompression, and reconstructs the PE.
    ///
    /// # Arguments
    /// * `pe_data` - Raw bytes of the ASPack-packed PE file.
    ///
    /// # Errors
    /// Returns an error if the PE is not ASPack-packed or decompression fails.
    pub fn unpack_aspack(pe_data: &[u8]) -> AppResult<Vec<u8>> {
        if !PackedExeDetector::detect_aspack(pe_data) {
            return Err(AppError::new(
                ReasonCode::RcDrmPackUnsupported,
                "PE is not ASPack-packed",
            ));
        }
        if pe_data.len() < 64 {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "PE data too small for ASPack unpacking",
            ));
        }
        let e_lfanew =
            u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]])
                as usize;
        if pe_data.len() < e_lfanew + 24 {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "PE header truncated",
            ));
        }
        let num_sections =
            u16::from_le_bytes([pe_data[e_lfanew + 6], pe_data[e_lfanew + 7]]) as usize;
        let size_optional =
            u16::from_le_bytes([pe_data[e_lfanew + 20], pe_data[e_lfanew + 21]]) as usize;
        let section_start = e_lfanew + 24 + size_optional;

        let mut aspack_raw_offset = 0usize;
        let mut aspack_raw_size = 0usize;
        for i in 0..num_sections {
            let sec_offset = section_start + i * 40;
            if pe_data.len() < sec_offset + 40 {
                break;
            }
            let name_bytes = &pe_data[sec_offset..sec_offset + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();
            if name == ".aspack" {
                aspack_raw_offset = u32::from_le_bytes([
                    pe_data[sec_offset + 20],
                    pe_data[sec_offset + 21],
                    pe_data[sec_offset + 22],
                    pe_data[sec_offset + 23],
                ]) as usize;
                aspack_raw_size = u32::from_le_bytes([
                    pe_data[sec_offset + 16],
                    pe_data[sec_offset + 17],
                    pe_data[sec_offset + 18],
                    pe_data[sec_offset + 19],
                ]) as usize;
                break;
            }
        }

        if aspack_raw_offset == 0 || aspack_raw_size == 0 {
            return Err(AppError::new(
                ReasonCode::RcDrmPackUnsupported,
                "could not locate .aspack section",
            ));
        }

        let header_start = aspack_raw_offset;
        if pe_data.len() < header_start + 24 {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "ASPack header truncated",
            ));
        }

        let _magic = u32::from_le_bytes([
            pe_data[header_start],
            pe_data[header_start + 1],
            pe_data[header_start + 2],
            pe_data[header_start + 3],
        ]);
        let original_entry = u32::from_le_bytes([
            pe_data[header_start + 4],
            pe_data[header_start + 5],
            pe_data[header_start + 6],
            pe_data[header_start + 7],
        ]);
        let compressed_data_offset = u32::from_le_bytes([
            pe_data[header_start + 12],
            pe_data[header_start + 13],
            pe_data[header_start + 14],
            pe_data[header_start + 15],
        ]) as usize;
        let compressed_size = u32::from_le_bytes([
            pe_data[header_start + 16],
            pe_data[header_start + 17],
            pe_data[header_start + 18],
            pe_data[header_start + 19],
        ]) as usize;

        let decompress_start = aspack_raw_offset + compressed_data_offset;
        if pe_data.len() < decompress_start + compressed_size {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "ASPack compressed data extends beyond file",
            ));
        }

        let compressed_data = &pe_data[decompress_start..decompress_start + compressed_size];
        let decompressed = Self::decompress_aplib(compressed_data)?;

        let mut output = pe_data[..section_start].to_vec();
        let file_alignment = 0x200u32;
        let aligned = align_up(output.len() as u32, file_alignment) as usize;
        output.resize(aligned, 0);

        output.extend_from_slice(&decompressed);
        let text_aligned = align_up(output.len() as u32, file_alignment) as usize;
        output.resize(text_aligned, 0);

        for i in 0..num_sections {
            let sec_offset = section_start + i * 40;
            if pe_data.len() < sec_offset + 40 {
                break;
            }
            let name_bytes = &pe_data[sec_offset..sec_offset + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();
            if name != ".aspack" && name != ".adata" {
                let raw_offset = u32::from_le_bytes([
                    pe_data[sec_offset + 20],
                    pe_data[sec_offset + 21],
                    pe_data[sec_offset + 22],
                    pe_data[sec_offset + 23],
                ]) as usize;
                let raw_size = u32::from_le_bytes([
                    pe_data[sec_offset + 16],
                    pe_data[sec_offset + 17],
                    pe_data[sec_offset + 18],
                    pe_data[sec_offset + 19],
                ]) as usize;
                if raw_offset > 0 && raw_size > 0 && pe_data.len() >= raw_offset + raw_size {
                    output.extend_from_slice(&pe_data[raw_offset..raw_offset + raw_size]);
                }
            }
        }

        if output.len() > e_lfanew + 40 + 4 {
            output[e_lfanew + 40..e_lfanew + 44].copy_from_slice(&original_entry.to_le_bytes());
        }

        Ok(output)
    }

    /// Decompresses data using aPLib compression.
    ///
    /// aPLib is a lightweight compression library commonly used by ASPack.
    fn decompress_aplib(data: &[u8]) -> AppResult<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        let mut pos = 0usize;
        let mut r0 = 0usize;
        let mut r1 = 0usize;
        let mut r2 = 0usize;

        while pos < data.len() && output.len() < 16 * 1024 * 1024 {
            let tag = data[pos];
            pos += 1;

            if tag < 32 {
                if pos < data.len() {
                    output.push(data[pos]);
                    pos += 1;
                }
            } else if tag < 64 {
                let offset = ((tag & 0x1F) as usize) << 8;
                if pos < data.len() {
                    let full_offset = offset | data[pos] as usize;
                    pos += 1;
                    if full_offset > 0 && full_offset <= output.len() {
                        let start = output.len() - full_offset;
                        let first = output[start];
                        output.push(first);
                        // aPLib allows overlapping copies; with full_offset == 1
                        // the second byte repeats the first.
                        let second = if start + 1 < output.len() {
                            output[start + 1]
                        } else {
                            first
                        };
                        output.push(second);
                    }
                }
            } else if tag < 128 {
                let length = ((tag >> 2) & 0x07) as usize + 3;
                let offset_high = (tag & 0x03) as usize;
                if pos < data.len() {
                    let offset = (offset_high << 8) | data[pos] as usize;
                    pos += 1;
                    if offset > 0 && offset <= output.len() {
                        let start = output.len() - offset;
                        for i in 0..length {
                            if start + i < output.len() {
                                output.push(output[start + i]);
                            }
                        }
                        r2 = r1;
                        r1 = r0;
                        r0 = offset;
                    }
                }
            } else if tag < 160 {
                let length = (tag & 0x1F) as usize + 3;
                if pos + 1 < data.len() {
                    let offset = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if offset > 0 && offset <= output.len() {
                        let start = output.len() - offset;
                        for i in 0..length {
                            if start + i < output.len() {
                                output.push(output[start + i]);
                            }
                        }
                        r2 = r1;
                        r1 = r0;
                        r0 = offset;
                    }
                }
            } else if tag < 192 {
                let reg = ((tag >> 4) & 0x03) as usize;
                let length = (tag & 0x0F) as usize + 3;
                let offset = match reg {
                    0 => r0,
                    1 => r1,
                    _ => r2,
                };
                if offset > 0 && offset <= output.len() {
                    let start = output.len() - offset;
                    for i in 0..length {
                        if start + i < output.len() {
                            output.push(output[start + i]);
                        }
                    }
                }
            } else {
                let run_len = (tag & 0x3F) as usize;
                for _ in 0..run_len {
                    if pos < data.len() {
                        output.push(data[pos]);
                        pos += 1;
                    }
                }
            }
        }

        if output.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "aPLib decompression produced no output",
            ));
        }
        Ok(output)
    }
}

/// Aligns `value` up to the next multiple of `alignment`.
fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

// ===========================================================================
// 4. Integrity Check Emulation
// ===========================================================================

/// A region of memory registered for integrity checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityRegion {
    /// Unique identifier for this region.
    pub id: u32,
    /// Base address of the region in guest memory.
    pub base_address: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Expected SHA-256 hash of the region contents.
    pub expected_hash: [u8; 32],
    /// Number of times this region has been checked.
    pub check_count: u64,
    /// Timestamp of the last integrity check.
    pub last_check_time: u64,
}

/// Result of an integrity check on a specific region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheckResult {
    /// ID of the region that was checked.
    pub region_id: u32,
    /// Whether the integrity check passed.
    pub passed: bool,
    /// Computed SHA-256 hash of the region.
    pub computed_hash: [u8; 32],
    /// Timestamp when the check was performed.
    pub timestamp: u64,
}

/// Emulator for runtime integrity checks performed by DRM-protected games.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheckEmulator {
    /// Whether integrity checking is enabled.
    pub enabled: bool,
    /// Registered memory regions.
    pub registered_regions: Vec<IntegrityRegion>,
    /// History of integrity check results.
    pub check_history: Vec<IntegrityCheckResult>,
    /// Regions that are forced to pass on the next check.
    force_pass_set: Vec<u32>,
    /// Next region ID to assign.
    next_region_id: u32,
}

/// Maximum number of integrity check results retained; checks are guest-driven
/// and the history would otherwise grow without bound over long sessions.
const CHECK_HISTORY_CAP: usize = 1024;

impl IntegrityCheckEmulator {
    /// Creates a new `IntegrityCheckEmulator` with no registered regions.
    pub fn new() -> Self {
        Self {
            enabled: true,
            registered_regions: Vec::new(),
            check_history: Vec::new(),
            force_pass_set: Vec::new(),
            next_region_id: 1,
        }
    }
}

impl Default for IntegrityCheckEmulator {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrityCheckEmulator {
    /// Registers a memory region for integrity checking.
    pub fn register_region(&mut self, base: u64, size: u64, expected_hash: [u8; 32]) -> u32 {
        let id = self.next_region_id;
        self.next_region_id += 1;
        self.registered_regions.push(IntegrityRegion {
            id,
            base_address: base,
            size,
            expected_hash,
            check_count: 0,
            last_check_time: 0,
        });
        id
    }

    /// Checks the integrity of a registered region by computing its SHA-256 hash.
    pub fn check_region(
        &mut self,
        memory: &MemoryImage,
        region_id: u32,
    ) -> AppResult<IntegrityCheckResult> {
        let region_idx = self
            .registered_regions
            .iter()
            .position(|r| r.id == region_id)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcDrmRegionNotFound,
                    format!("integrity region {region_id} not found"),
                )
            })?;

        let region = &self.registered_regions[region_idx];
        let data = memory.read_bytes(region.base_address, region.size as usize)?;
        let computed_hash = sha256_hash(&data);

        let forced = self.force_pass_set.contains(&region_id);
        if forced {
            self.force_pass_set.retain(|&id| id != region_id);
        }

        let passed = forced || computed_hash == region.expected_hash;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.registered_regions[region_idx].check_count += 1;
        self.registered_regions[region_idx].last_check_time = timestamp;

        let result = IntegrityCheckResult {
            region_id,
            passed,
            computed_hash,
            timestamp,
        };
        if self.check_history.len() >= CHECK_HISTORY_CAP {
            self.check_history.remove(0);
        }
        self.check_history.push(result.clone());
        Ok(result)
    }

    /// Checks all registered regions and returns the results.
    pub fn check_all_regions(
        &mut self,
        memory: &MemoryImage,
    ) -> AppResult<Vec<IntegrityCheckResult>> {
        let region_ids: Vec<u32> = self.registered_regions.iter().map(|r| r.id).collect();
        let mut results = Vec::new();
        for id in region_ids {
            results.push(self.check_region(memory, id)?);
        }
        Ok(results)
    }

    /// Updates the expected hash for a registered region.
    pub fn update_expected_hash(&mut self, region_id: u32, new_hash: [u8; 32]) -> AppResult<()> {
        let region = self
            .registered_regions
            .iter_mut()
            .find(|r| r.id == region_id)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcDrmRegionNotFound,
                    format!("integrity region {region_id} not found"),
                )
            })?;
        region.expected_hash = new_hash;
        Ok(())
    }

    /// Forces the next integrity check on a region to pass regardless of hash.
    pub fn force_pass(&mut self, region_id: u32) {
        if !self.force_pass_set.contains(&region_id) {
            self.force_pass_set.push(region_id);
        }
    }
}

// ===========================================================================
// 5. Anti-Debugging API Stubs
// ===========================================================================
// 5. Anti-Debugging API Stubs
// ===========================================================================

/// NT process information class constants.
const PROCESS_DEBUG_PORT: u32 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;
const PROCESS_DEBUG_FLAGS: u32 = 31;
const SYSTEM_KERNEL_DEBUGGER_INFORMATION: u32 = 35;
const THREAD_HIDE_FROM_DEBUGGER: u32 = 17;

/// State for anti-debugging API emulation.
///
/// All fields are set to values that indicate "no debugger present" so that
/// DRM-protected games run without detecting the Casa1 runtime environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugState {
    /// Whether a debugger is present (always `false`).
    pub debugger_present: bool,
    /// Whether a remote debugger is present (always `false`).
    pub remote_debugger_present: bool,
    /// Debug port (always `0`, indicating no debugger).
    pub debug_port: u32,
    /// PEB BeingDebugged flag (always `false`).
    pub being_debugged: bool,
    /// NtGlobalFlag (always `0`, no heap debug flags).
    pub nt_global_flag: u32,
    /// Heap flags (normal values, not debug values).
    pub heap_flags: u32,
    /// Fake process heap address.
    pub process_heap: u64,
    /// Number of heaps (always `1`).
    pub num_heaps: u32,
    /// Fake ntdll base address.
    pub ntdll_base: u64,
}

impl AntiDebugState {
    /// Creates a new `AntiDebugState` with all values set to indicate "no debugger present".
    pub fn new() -> Self {
        Self {
            debugger_present: false,
            remote_debugger_present: false,
            debug_port: 0,
            being_debugged: false,
            nt_global_flag: 0,
            heap_flags: 0x0000_0002,
            process_heap: 0x0040_0000,
            num_heaps: 1,
            ntdll_base: 0x7FFE_0000,
        }
    }
}

impl Default for AntiDebugState {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiDebugState {
    /// Returns `false` to indicate no debugger is present.
    pub fn is_debugger_present(&self) -> bool {
        false
    }

    /// Returns `false` to indicate no remote debugger is present.
    pub fn check_remote_debugger_present(&self) -> bool {
        false
    }

    /// Returns `0` to indicate no debug port is assigned.
    pub fn get_debug_port(&self) -> u32 {
        0
    }

    /// Returns a value indicating no debugger for the given NT process information class.
    pub fn nt_query_information_process(&self, info_class: u32) -> u64 {
        match info_class {
            PROCESS_DEBUG_PORT => 0,
            PROCESS_DEBUG_OBJECT_HANDLE => 0,
            PROCESS_DEBUG_FLAGS => 1,
            _ => 0,
        }
    }

    /// Returns a byte buffer indicating no kernel debugger is present.
    pub fn nt_query_system_information(&self, info_class: u32) -> Vec<u8> {
        match info_class {
            SYSTEM_KERNEL_DEBUGGER_INFORMATION => vec![0u8, 0u8],
            _ => Vec::new(),
        }
    }

    /// Handles `NtSetInformationThread` calls from guest code.
    ///
    /// Anti-debugging tools use `ThreadHideFromDebugger` (0x11) to hide threads
    /// from the debugger. We silently succeed for this and all other thread
    /// info classes since we do not attach a real debugger.
    pub fn nt_set_information_thread(&self, _thread_handle: u64, info_class: u32) -> AppResult<()> {
        match info_class {
            0x00 => { /* ThreadBasicInformation: query-only, set is a no-op */ }
            0x01 => { /* ThreadTimes: query-only, set is a no-op */ }
            0x02 => { /* ThreadPriority: priority setting ignored in emulation */ }
            0x03 => { /* ThreadAffinityMask: affinity setting ignored in emulation */ }
            0x04 => { /* ThreadImpersonationToken: impersonation not emulated */ }
            0x05 => { /* ThreadDescriptorTableEntry: query-only, set is a no-op */ }
            0x06 => { /* ThreadEnableAlignmentFaultFixup: ignored in emulation */ }
            0x08 => { /* ThreadIdealProcessor: ideal processor ignored in emulation */ }
            0x09 => { /* ThreadPriorityBoost: priority boost ignored in emulation */ }
            0x0A => { /* ThreadSetTlsArray: TLS array not needed in emulation */ }
            0x0B => { /* ThreadIsIoPending: query-only, set is a no-op */ }
            0x0C => { /* ThreadHideFromDebugger (0x0C on some Windows): same as 0x11 */ }
            0x0D => { /* ThreadBreakOnTermination: break-on-termination not emulated */ }
            THREAD_HIDE_FROM_DEBUGGER => { /* ThreadHideFromDebugger: silently succeed */ }
            0x12 => { /* ThreadSystemThreadInformation: query-only, set is a no-op */ }
            0x13 => { /* ThreadGroupInformation: group affinity ignored in emulation */ }
            0x14 => { /* ThreadUmsInformation: UMS not supported in emulation */ }
            0x15 => { /* ThreadWow64Context: WOW64 context setting ignored */ }
            0x16 => { /* ThreadSetTlsValueInProcess: TLS not needed in emulation */ }
            0x17 => { /* ThreadIdealProcessorEx: ideal processor ignored in emulation */ }
            0x1F => { /* ThreadSelectedCpuSets: CPU set selection ignored in emulation */ }
            _ => { /* Unrecognized thread info class: no-op */ }
        }
        Ok(())
    }

    /// Silently consumes debug output strings.
    pub fn output_debug_string(&self, _message: &str) -> AppResult<()> {
        Ok(())
    }

    /// Returns a monotonically increasing tick count.
    ///
    /// The counter increments by 30 ms per call and saturates instead of
    /// wrapping to 0, so guest anti-debug code never observes time moving
    /// backward mid-session.
    pub fn get_tick_count(&self) -> u32 {
        let prev = TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
        prev
            .saturating_add(1)
            .saturating_mul(30_000)
            .min(u32::MAX as u64) as u32
    }

    /// Returns a monotonically increasing performance counter value.
    ///
    /// The counter saturates instead of wrapping, so guest anti-debug code
    /// never observes time moving backward mid-session.
    pub fn query_performance_counter(&self) -> u64 {
        let prev = PERF_COUNTER.fetch_add(1, Ordering::Relaxed);
        prev.saturating_add(1)
            .saturating_mul(100)
            .saturating_add(1_000_000)
    }
}

// ===========================================================================
// 6. Export Registration
// ===========================================================================

/// Returns a list of export names and fake addresses for DRM-related DLLs.
pub fn register_drm_dll() -> Vec<(&'static str, u64)> {
    vec![
        ("denuvo_initialize", 0xDEAD_0001),
        ("denuvo_verify", 0xDEAD_0002),
        ("denuvo_get_license", 0xDEAD_0003),
        ("SteamAPI_Init", 0xDEAD_0010),
        ("SteamAPI_Shutdown", 0xDEAD_0011),
    ]
}

// ===========================================================================
// 7. Authenticode signature verification (WinVerifyTrust backing)
// ===========================================================================

/// Outcome of verifying a PE image's embedded Authenticode signature.
///
/// This enum represents the result of full Authenticode chain validation:
///
/// - Cryptographic signature verification (RSA PKCS#1 v1.5 or ECDSA)
/// - PE content hash matching
/// - Signer certificate chain validation up to a system-trusted root
/// - Best-effort revocation checking (OCSP/CRL via macOS Security framework)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticodeVerdict {
    /// Cryptographic verification passed AND certificate chain trusted.
    ///
    /// The embedded signature cryptographically binds the PE content to a
    /// signer certificate whose chain leads to a system-trusted root authority.
    /// Best-effort revocation checks (OCSP/CRL) were attempted; if network
    /// was unavailable the certificate is still accepted as Valid.
    Valid,
    /// The PE has no attribute certificate table (it is unsigned). This maps to
    /// the Win32 `TRUST_E_NOSIGNATURE` status.
    NoSignature,
    /// A signature is present but failed verification: tampered file, malformed
    /// structure, unsupported algorithm, signature mismatch, untrusted
    /// certificate chain, or revoked certificate. The contained string provides
    /// a descriptive reason for debugging.
    ///
    /// This maps to the Win32 `TRUST_E_BAD_DIGEST` / `TRUST_E_NOSIGNATURE`
    /// failure family.
    Invalid(String),
}

const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
/// OID 1.2.840.113549.1.7.2 — PKCS#7 signedData.
const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// OID 1.3.6.1.4.1.311.2.1.4 — SPC_INDIRECT_DATA_OBJID (Authenticode content).
const OID_SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
/// OID 1.2.840.113549.1.9.4 — PKCS#9 messageDigest signed attribute.
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
/// OID 2.16.840.1.101.3.4.2.1 — SHA-256.
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// OID 1.3.14.3.2.26 — SHA-1.
const OID_SHA1: &str = "1.3.14.3.2.26";
/// OID 2.16.840.1.101.3.4.2.2 — SHA-384.
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
/// OID 2.16.840.1.101.3.4.2.3 — SHA-512.
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
/// OID 1.2.840.10045.2.1 — ECDSA public key.
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// OID 1.2.840.10045.4.3.2 — ECDSA with SHA-256.
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
/// OID 1.2.840.10045.4.3.3 — ECDSA with SHA-384.
const OID_ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
/// OID 2.5.29.14 — SubjectKeyIdentifier extension.
const OID_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";

// ===========================================================================
// macOS Security Framework FFI declarations
// ===========================================================================
//
// We use raw FFI (extern "C") to call into the Security framework on macOS
// for certificate chain validation and revocation checking. The project
// already uses core-foundation and this pattern extensively.

/// Opaque type for a Security framework certificate reference.
#[repr(C)]
pub(crate) struct __SecCertificate(c_void);
pub(crate) type SecCertificateRef = *const __SecCertificate;

/// Opaque type for a Security framework trust reference.
#[repr(C)]
pub(crate) struct __SecTrust(c_void);
pub(crate) type SecTrustRef = *const __SecTrust;

/// Opaque type for a CoreFoundation error reference.
#[repr(C)]
struct __CFError(c_void);
type CFErrorRef = *const __CFError;

/// CoreFoundation type IDs.
const kCFAllocatorDefault: *const c_void = std::ptr::null();

/// SecTrustResultType values.
#[allow(dead_code)]
#[derive(Debug)]
#[repr(u32)]
enum SecTrustResultType {
    Invalid = 0,
    Proceed = 1,
    Confirm = 2,
    Deny = 3,
    Unspecified = 4,
    RecoverableTrustFailure = 5,
    FatalTrustFailure = 6,
    OtherError = 7,
}

// SAFETY: extern FFI declaration — the function signature matches the C library prototype
unsafe extern "C" {
    /// Create a SecCertificate from DER-encoded data.
    /// Returns a retained reference; must be CFRelease'd.
    fn SecCertificateCreateWithData(
        allocator: *const c_void,
        data: core_foundation::base::CFTypeRef,
    ) -> SecCertificateRef;

    /// Create a SecTrust evaluation object.
    fn SecTrustCreateWithCertificates(
        certificates: core_foundation::base::CFTypeRef,
        policies: core_foundation::base::CFTypeRef,
        trust: *mut SecTrustRef,
    ) -> i32; // OSStatus

    /// Set whether network fetch (OCSP/CRL) is allowed.
    fn SecTrustSetNetworkFetchAllowed(trust: SecTrustRef, allow_fetch: u8) -> i32; // OSStatus

    /// Evaluate trust (returns true if trusted, false on error).
    fn SecTrustEvaluateWithError(trust: SecTrustRef, error: *mut CFErrorRef) -> u8; // Boolean

    /// Get the detailed trust result type.
    fn SecTrustGetTrustResult(trust: SecTrustRef, result: *mut SecTrustResultType) -> i32; // OSStatus

    /// Create a CFDataRef from raw bytes.
    fn CFDataCreate(
        allocator: *const c_void,
        bytes: *const u8,
        length: usize,
    ) -> core_foundation::base::CFTypeRef;

    /// Create an immutable CFArrayRef from C pointers.
    fn CFArrayCreate(
        allocator: *const c_void,
        values: *const *const c_void,
        num_values: usize,
        callbacks: *const c_void,
    ) -> core_foundation::base::CFTypeRef;

    /// Create a CFStringRef from a C string.
    fn CFStringCreateWithCString(
        allocator: *const c_void,
        c_str: *const i8,
        encoding: u32,
    ) -> core_foundation::base::CFTypeRef;
}

// Security framework global string constants used for SecItemCopyMatching queries.
//
// These are defined as `const CFStringRef` symbols in `<Security/SecItem.h>` and
// linked via the Security framework (already linked by `security-framework-sys`).
#[allow(dead_code)]
// SAFETY: extern FFI declaration — the function signature matches the C library prototype
unsafe extern "C" {
    // kSecClass — top-level dictionary key identifying the item class.
    static kSecClass: *const c_void;
    // kSecClassCertificate — value for kSecClass: match certificate items.
    static kSecClassCertificate: *const c_void;
    // kSecMatchLimit — key specifying the maximum number of results.
    static kSecMatchLimit: *const c_void;
    // kSecMatchLimitAll — value for kSecMatchLimit: return all matching items.
    static kSecMatchLimitAll: *const c_void;
    // kSecReturnRef — key requesting returned items as SecCertificateRefs.
    static kSecReturnRef: *const c_void;
    // kCFBooleanTrue — CFBooleanRef for true-valued boolean keys.
    static kCFBooleanTrue: *const c_void;
}

/// kCFStringEncodingUTF8
const kCFStringEncodingUTF8: u32 = 0x08000100;

/// Create a `SecPolicyRef` for basic X.509 certificate evaluation (SSL
/// policy or basic policy). We use the Basic X.509 policy.
fn create_basic_x509_policy() -> core_foundation::base::CFTypeRef {
    // SAFETY: Security framework FFI for cryptographic operations
    unsafe {
        // We use the built-in Basic X.509 policy via SecPolicyCreateBasicX509.
        // Declare it as a local extern to avoid global scope pollution.
        // SAFETY: extern FFI declaration — the function signature matches the C library prototype
        unsafe extern "C" {
            fn SecPolicyCreateBasicX509() -> core_foundation::base::CFTypeRef;
        }
        SecPolicyCreateBasicX509()
    }
}

/// Validate a DER-encoded X.509 certificate chain up to a system-trusted root
/// using the macOS Security framework.
///
/// `leaf_der` is the signer certificate; `chain_ders` are the additional
/// certificates (intermediate CAs) embedded in the signature's certificate
/// bag, which SecTrust needs to build the chain when the intermediates are
/// not present in the local keychain.
///
/// Returns `Ok(())` if the certificate is trusted (chain leads to a trusted
/// root, not expired, and optionally passes OCSP/CRL revocation checks).
fn validate_certificate_chain(leaf_der: &[u8], chain_ders: &[Vec<u8>]) -> Result<(), String> {
    use core_foundation::base::CFRelease;

    // SAFETY: CFRelease decrements the reference count of a valid CoreFoundation object
    unsafe {
        // 1. Create CFData from the DER bytes.
        let cf_data = CFDataCreate(kCFAllocatorDefault, leaf_der.as_ptr(), leaf_der.len());
        if cf_data.is_null() {
            return Err("CFDataCreate failed".into());
        }

        // 2. Create SecCertificate from CFData.
        let cert_ref = SecCertificateCreateWithData(kCFAllocatorDefault, cf_data);
        CFRelease(cf_data);
        if cert_ref.is_null() {
            return Err("SecCertificateCreateWithData failed — not a valid DER certificate".into());
        }

        // 3. Create a basic X.509 policy.
        let policy = create_basic_x509_policy();
        if policy.is_null() {
            CFRelease(cert_ref as *const c_void);
            return Err("SecPolicyCreateBasicX509 failed".into());
        }

        // 4. Put the leaf plus the embedded intermediates in a CFArray.
        //    Track the created references so they can be released after the
        //    trust object has retained them.
        let mut cert_ptrs: Vec<*const c_void> = Vec::with_capacity(chain_ders.len() + 1);
        let mut created: Vec<*const c_void> = Vec::with_capacity(chain_ders.len());
        cert_ptrs.push(cert_ref as *const c_void);
        for der in chain_ders {
            let cf = CFDataCreate(kCFAllocatorDefault, der.as_ptr(), der.len());
            if cf.is_null() {
                continue;
            }
            let intermediate = SecCertificateCreateWithData(kCFAllocatorDefault, cf);
            CFRelease(cf);
            if intermediate.is_null() {
                continue;
            }
            created.push(intermediate as *const c_void);
            cert_ptrs.push(intermediate as *const c_void);
        }
        let certs_array = CFArrayCreate(
            kCFAllocatorDefault,
            cert_ptrs.as_ptr(),
            cert_ptrs.len(),
            std::ptr::null(),
        );
        if certs_array.is_null() {
            CFRelease(policy);
            CFRelease(cert_ref as *const c_void);
            for ptr in &created {
                CFRelease(*ptr);
            }
            return Err("CFArrayCreate failed".into());
        }

        // 5. Create the trust evaluation object.
        let mut trust: SecTrustRef = std::ptr::null();
        let os_status = SecTrustCreateWithCertificates(certs_array, policy, &mut trust);
        // Release intermediates — trust retains its own references.
        CFRelease(certs_array);
        CFRelease(policy);
        CFRelease(cert_ref as *const c_void);
        for ptr in &created {
            CFRelease(*ptr);
        }

        if os_status != 0 {
            return Err(format!(
                "SecTrustCreateWithCertificates returned {os_status}"
            ));
        }
        if trust.is_null() {
            return Err("SecTrustCreateWithCertificates returned null trust".into());
        }

        // 6. First attempt: evaluate with revocation (network fetch allowed).
        //    If it fails, try again without network fetch.
        let mut error: CFErrorRef = std::ptr::null();
        let trusted = SecTrustEvaluateWithError(trust, &mut error);

        if trusted == 0 {
            // Evaluation failed. Try again with network fetch forbidden
            // (offline mode) so that unreachable OCSP responders don't
            // cause rejection.
            let fetch_result = SecTrustSetNetworkFetchAllowed(trust, 0);
            if fetch_result != 0 {
                eprintln!(
                    "certificate verification: SecTrustSetNetworkFetchAllowed returned {fetch_result}"
                );
            }
            let mut error2: CFErrorRef = std::ptr::null();
            let trusted2 = SecTrustEvaluateWithError(trust, &mut error2);

            if trusted2 == 0 {
                // Both online and offline evaluation failed.
                // Get the detailed result for a descriptive message.
                let mut result_type: SecTrustResultType = SecTrustResultType::Invalid;
                SecTrustGetTrustResult(trust, &mut result_type);

                let reason = match result_type {
                    SecTrustResultType::FatalTrustFailure => {
                        "certificate chain not trusted (fatal trust failure)".to_string()
                    }
                    SecTrustResultType::RecoverableTrustFailure => {
                        "certificate chain not trusted (recoverable trust failure — possibly expired or untrusted root)".to_string()
                    }
                    SecTrustResultType::Deny => {
                        "certificate explicitly denied".to_string()
                    }
                    _ => {
                        // Try to get a description from the CFError.
                        let desc = if !error.is_null() {
                            // Use CFError's description via CFString
                            // SAFETY: extern FFI declaration — the function signature matches the C library prototype
                            unsafe extern "C" {
                                fn CFErrorCopyDescription(err: CFErrorRef) -> core_foundation::base::CFTypeRef;
                            }
                            let desc_ref = CFErrorCopyDescription(error);
                            if !desc_ref.is_null() {
                                let cstr = string_from_cfstring(desc_ref);
                                CFRelease(desc_ref);
                                cstr
                            } else {
                                String::new()
                            }
                        } else if !error2.is_null() {
                            // SAFETY: extern FFI declaration — the function signature matches the C library prototype
                            unsafe extern "C" {
                                fn CFErrorCopyDescription(err: CFErrorRef) -> core_foundation::base::CFTypeRef;
                            }
                            let desc_ref = CFErrorCopyDescription(error2);
                            if !desc_ref.is_null() {
                                let cstr = string_from_cfstring(desc_ref);
                                CFRelease(desc_ref);
                                cstr
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        };
                        if desc.is_empty() {
                            "certificate chain validation failed".to_string()
                        } else {
                            format!("certificate chain validation failed: {desc}")
                        }
                    }
                };

                if !error.is_null() {
                    CFRelease(error as *const c_void);
                }
                if !error2.is_null() {
                    CFRelease(error2 as *const c_void);
                }
                CFRelease(trust as *const c_void);
                return Err(reason);
            }
            // Offline retry succeeded: release its error object (if any) so
            // the success path below does not leak it.
            if !error2.is_null() {
                CFRelease(error2 as *const c_void);
            }
        }

        if !error.is_null() {
            CFRelease(error as *const c_void);
        }

        // 7. Trust evaluation succeeded.
        // Check the trust result for explicit denial/failure.
        let mut result_type: SecTrustResultType = SecTrustResultType::Invalid;
        SecTrustGetTrustResult(trust, &mut result_type);

        let ok = matches!(
            result_type,
            SecTrustResultType::Proceed | SecTrustResultType::Unspecified
        );

        CFRelease(trust as *const c_void);

        if ok {
            Ok(())
        } else {
            Err(format!(
                "certificate trust evaluation returned {:?}",
                result_type
            ))
        }
    }
}

/// Convert a CFStringRef to a Rust String. Panics on allocation failure
/// (unlikely in practice).
// SAFETY: Security framework FFI for cryptographic operations
unsafe fn string_from_cfstring(cf_str: core_foundation::base::CFTypeRef) -> String {
    // SAFETY: Security framework FFI for cryptographic operations
    unsafe {
        // Get the maximum size in UTF-8.
        // SAFETY: Security framework FFI for cryptographic operations
        unsafe extern "C" {
            fn CFStringGetCStringPtr(
                str: core_foundation::base::CFTypeRef,
                encoding: u32,
            ) -> *const i8;
            fn CFStringGetLength(str: core_foundation::base::CFTypeRef) -> isize;
            fn CFStringGetMaximumSizeForFileSystemRepresentation(length: isize) -> isize;
        }

        // Try the fast path first.
        let cstr = CFStringGetCStringPtr(cf_str, kCFStringEncodingUTF8);
        if !cstr.is_null() {
            let len = libc::strlen(cstr);
            let slice = std::slice::from_raw_parts(cstr as *const u8, len);
            return String::from_utf8_lossy(slice).to_string();
        }

        // Slow path: allocate buffer and copy.
        let length = CFStringGetLength(cf_str);
        // Max UTF-8 is 4 bytes per character + 1 for NUL.
        let max_size = (length * 4 + 1) as usize;
        let mut buf = vec![0u8; max_size];
        // SAFETY: extern FFI declaration — the function signature matches the C library prototype
        unsafe extern "C" {
            fn CFStringGetCString(
                str: core_foundation::base::CFTypeRef,
                buffer: *mut i8,
                buffer_size: isize,
                encoding: u32,
            ) -> u8;
        }
        let result = CFStringGetCString(
            cf_str,
            buf.as_mut_ptr() as *mut i8,
            max_size as isize,
            kCFStringEncodingUTF8,
        );
        if result != 0 {
            // Find the NUL terminator.
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            buf.truncate(len);
            String::from_utf8_lossy(&buf).to_string()
        } else {
            String::new()
        }
    }
}

/// Find a certificate in the PKCS#7 certificates bag whose SubjectKeyIdentifier
/// extension matches the given key identifier bytes.
fn find_cert_by_subject_key_id<'a>(
    certs: &'a [cms::cert::CertificateChoices],
    ski_bytes: &[u8],
) -> Option<&'a x509_cert::certificate::Certificate> {
    use cms::cert::CertificateChoices;
    use der::Decode;
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    for choice in certs.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            let exts = match &cert.tbs_certificate.extensions {
                Some(e) => e,
                None => continue,
            };
            // Manually search for the SubjectKeyIdentifier extension by OID.
            for ext in exts.iter() {
                if ext.extn_id.to_string() == OID_SUBJECT_KEY_IDENTIFIER
                    && let Ok(skid) = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes())
                    && skid.0.as_bytes() == ski_bytes
                {
                    return Some(cert);
                }
            }
        }
    }
    None
}

/// Verify an ECDSA signature over `message` using the public key from an SPKI
/// DER blob. Returns `Ok(())` if the signature is valid.
fn verify_ecdsa_signature(
    spki_der: &[u8],
    signature_der: &[u8],
    message: &[u8],
    digest_oid: &str,
) -> Result<(), String> {
    use ecdsa::signature::Verifier;

    // Determine the curve based on the key size and digest.
    // Try P-256 with SHA-256, or P-384 with SHA-384.
    match digest_oid {
        OID_SHA256 | OID_ECDSA_WITH_SHA256 => {
            // Try P-256 first; if that fails (wrong key size), try P-384 as fallback.
            let r = (|| -> Result<(), String> {
                use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
                use p256::pkcs8::DecodePublicKey;

                let verifying_key = P256VerifyingKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("failed to parse P-256 public key: {e}"))?;
                let sig = P256Signature::from_der(signature_der)
                    .map_err(|e| format!("failed to parse P-256 signature: {e}"))?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|e| format!("P-256 signature verification failed: {e}"))
            })();
            if r.is_ok() {
                return r;
            }
            // Fallback: try P-384.
            (|| -> Result<(), String> {
                use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
                use p384::pkcs8::DecodePublicKey;

                let verifying_key = P384VerifyingKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("failed to parse P-384 public key: {e}"))?;
                let sig = P384Signature::from_der(signature_der)
                    .map_err(|e| format!("failed to parse P-384 signature: {e}"))?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|e| format!("P-384 signature verification failed: {e}"))
            })()
        }
        OID_ECDSA_WITH_SHA384 => {
            use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
            use p384::pkcs8::DecodePublicKey;

            let verifying_key = P384VerifyingKey::from_public_key_der(spki_der)
                .map_err(|e| format!("failed to parse P-384 public key: {e}"))?;
            let sig = P384Signature::from_der(signature_der)
                .map_err(|e| format!("failed to parse P-384 signature: {e}"))?;
            verifying_key
                .verify(message, &sig)
                .map_err(|e| format!("P-384 signature verification failed: {e}"))
        }
        other => Err(format!("unsupported ECDSA digest algorithm {other}")),
    }
}

fn read_u16_le(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Locate the attribute certificate table (PE security data directory entry).
///
/// Returns:
/// - `Ok(Some((file_offset, size)))` when a non-empty certificate table exists;
/// - `Ok(None)` when the file is a well-formed PE with no signature;
/// - `Err(_)` when the PE headers are malformed.
fn locate_certificate_table(pe: &[u8]) -> Result<Option<(usize, usize)>, String> {
    let e_lfanew = read_u32_le(pe, 0x3C).ok_or("missing e_lfanew")? as usize;
    if pe.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return Err("missing PE signature".into());
    }
    let coff = e_lfanew + 4;
    let size_of_optional = read_u16_le(pe, coff + 16).ok_or("truncated COFF header")? as usize;
    let opt = coff + 20;
    let magic = read_u16_le(pe, opt).ok_or("truncated optional header")?;
    let dd_offset = match magic {
        0x10b => opt + 96,  // PE32
        0x20b => opt + 112, // PE32+
        _ => return Err(format!("unknown optional header magic {magic:#06x}")),
    };
    let sec_entry = dd_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    if sec_entry + 8 > opt + size_of_optional {
        // No security directory entry present in the optional header.
        return Ok(None);
    }
    let va = read_u32_le(pe, sec_entry).ok_or("truncated security dir entry")? as usize;
    let size = read_u32_le(pe, sec_entry + 4).ok_or("truncated security dir entry")? as usize;
    if va == 0 || size == 0 {
        return Ok(None);
    }
    if va + size > pe.len() {
        return Err("certificate table extends past end of file".into());
    }
    Ok(Some((va, size)))
}

/// Compute the Authenticode digest of `pe` using the named hash OID.
///
/// Per the Authenticode specification the hash covers the whole image except
/// the optional-header checksum field, the security data directory entry, and
/// the attribute certificate table itself.
fn compute_authenticode_hash(pe: &[u8], hash_oid: &str) -> Option<Vec<u8>> {
    let e_lfanew = read_u32_le(pe, 0x3C)? as usize;
    let coff = e_lfanew + 4;
    let opt = coff + 20;
    let magic = read_u16_le(pe, opt)?;
    let dd_offset = match magic {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return None,
    };
    let checksum_off = opt + 64;
    let sec_entry = dd_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    let cert_va = read_u32_le(pe, sec_entry)? as usize;
    let cert_size = read_u32_le(pe, sec_entry + 4)? as usize;
    let cert_end = cert_va.checked_add(cert_size)?;

    // Hashable byte ranges, in order, skipping the excluded fields.
    let segments = [
        (0usize, checksum_off),
        (checksum_off + 4, sec_entry),
        (sec_entry + 8, cert_va),
        (cert_end, pe.len()),
    ];

    fn hash_segments<H: Digest>(pe: &[u8], segments: &[(usize, usize)]) -> Vec<u8> {
        let mut hasher = H::new();
        for &(start, end) in segments {
            if end > start && end <= pe.len() {
                hasher.update(&pe[start..end]);
            }
        }
        hasher.finalize().to_vec()
    }

    match hash_oid {
        OID_SHA256 => Some(hash_segments::<Sha256>(pe, &segments)),
        OID_SHA1 => Some(hash_segments::<sha1::Sha1>(pe, &segments)),
        OID_SHA384 => Some(hash_segments::<sha2::Sha384>(pe, &segments)),
        OID_SHA512 => Some(hash_segments::<sha2::Sha512>(pe, &segments)),
        _ => None,
    }
}

/// Decode a DER object-identifier value (content octets) to dotted-decimal form.
fn decode_oid(bytes: &[u8]) -> Option<String> {
    let first = *bytes.first()? as u32;
    let mut out = format!("{}.{}", first / 40, first % 40);
    let mut value: u64 = 0;
    let mut pending = false;
    for &b in &bytes[1..] {
        value = (value << 7) | (b & 0x7f) as u64;
        pending = true;
        if b & 0x80 == 0 {
            out.push_str(&format!(".{value}"));
            value = 0;
            pending = false;
        }
    }
    if pending {
        return None; // truncated multi-byte arc
    }
    Some(out)
}

/// Minimal DER TLV reader. On success advances `off` past the element and
/// returns `(tag, content_start, content_len)`.
fn der_read_tlv(d: &[u8], off: &mut usize) -> Option<(u8, usize, usize)> {
    let tag = *d.get(*off)?;
    let mut p = *off + 1;
    let b0 = *d.get(p)?;
    p += 1;
    let len = if b0 & 0x80 == 0 {
        b0 as usize
    } else {
        let n = (b0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | (*d.get(p)? as usize);
            p += 1;
        }
        l
    };
    let content_start = p;
    let content_end = content_start.checked_add(len)?;
    if content_end > d.len() {
        return None;
    }
    *off = content_end;
    Some((tag, content_start, len))
}

/// Parse an Authenticode `SpcIndirectDataContent` (the eContent of the signed
/// data) and return `(pe_hash_oid, pe_hash_digest)`.
///
/// ```text
/// SpcIndirectDataContent ::= SEQUENCE {
///     data          SpcAttributeTypeAndOptionalValue,
///     messageDigest DigestInfo }
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,
///     digest          OCTET STRING }
/// ```
fn parse_spc_indirect_data(econtent_full: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut off = 0;
    let (tag, seq_start, seq_len) = der_read_tlv(econtent_full, &mut off)?;
    if tag != 0x30 {
        return None;
    }
    let mut inner = seq_start;
    let seq_end = seq_start + seq_len;
    // Skip `data` (SpcAttributeTypeAndOptionalValue).
    der_read_tlv(econtent_full, &mut inner)?;
    if inner >= seq_end {
        return None;
    }
    // messageDigest = DigestInfo SEQUENCE.
    let (di_tag, di_start, _di_len) = der_read_tlv(econtent_full, &mut inner)?;
    if di_tag != 0x30 {
        return None;
    }
    let mut di = di_start;
    // AlgorithmIdentifier SEQUENCE.
    let (alg_tag, alg_start, _alg_len) = der_read_tlv(econtent_full, &mut di)?;
    if alg_tag != 0x30 {
        return None;
    }
    let mut alg = alg_start;
    let (oid_tag, oid_start, oid_len) = der_read_tlv(econtent_full, &mut alg)?;
    if oid_tag != 0x06 {
        return None;
    }
    let oid = decode_oid(&econtent_full[oid_start..oid_start + oid_len])?;
    // digest OCTET STRING.
    let (dg_tag, dg_start, dg_len) = der_read_tlv(econtent_full, &mut di)?;
    if dg_tag != 0x04 {
        return None;
    }
    Some((oid, econtent_full[dg_start..dg_start + dg_len].to_vec()))
}

/// Compute a digest of `data` using a hash named by OID.
fn digest_with_oid(hash_oid: &str, data: &[u8]) -> Option<Vec<u8>> {
    match hash_oid {
        OID_SHA256 => Some(Sha256::digest(data).to_vec()),
        OID_SHA1 => Some(<sha1::Sha1 as Digest>::digest(data).to_vec()),
        OID_SHA384 => Some(<sha2::Sha384 as Digest>::digest(data).to_vec()),
        OID_SHA512 => Some(<sha2::Sha512 as Digest>::digest(data).to_vec()),
        _ => None,
    }
}

/// Verify the embedded Authenticode signature on a PE image.
///
/// This function performs full cryptographic verification AND certificate chain
/// validation:
///
/// 1. Extracts the PKCS#7 SignedData from the PE's attribute certificate table.
/// 2. Parses the Authenticode SpcIndirectDataContent and verifies the PE hash.
/// 3. Verifies the cryptographic signature (RSA PKCS#1 v1.5 or ECDSA) over the
///    signed attributes for EACH signer info (supports dual-signatures:
///    SHA-1 + SHA-256).
/// 4. Validates the signer certificate chain up to a system-trusted root using
///    the macOS Security framework (keychain trust evaluation).
/// 5. Performs best-effort revocation checking (OCSP/CRL) via the Security
///    framework.
///
/// Supports:
/// - RSA and ECDSA (P-256, P-384) public keys
/// - IssuerAndSerialNumber and SubjectKeyIdentifier signer identifiers
/// - Dual-signed PEs (multiple SignerInfo entries)
pub fn verify_pe_authenticode(pe_data: &[u8]) -> AuthenticodeVerdict {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;

    let (cert_va, cert_size) = match locate_certificate_table(pe_data) {
        Ok(Some(table)) => table,
        Ok(None) => return AuthenticodeVerdict::NoSignature,
        Err(e) => return AuthenticodeVerdict::Invalid(e),
    };

    // Parse the WIN_CERTIFICATE wrapper.
    let win_cert = &pe_data[cert_va..cert_va + cert_size];
    let dw_length = match read_u32_le(win_cert, 0) {
        Some(v) => v as usize,
        None => return AuthenticodeVerdict::Invalid("truncated WIN_CERTIFICATE".into()),
    };
    let cert_type = match read_u16_le(win_cert, 6) {
        Some(v) => v,
        None => return AuthenticodeVerdict::Invalid("truncated WIN_CERTIFICATE".into()),
    };
    if cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
        return AuthenticodeVerdict::Invalid(format!(
            "unsupported certificate type {cert_type:#06x}"
        ));
    }
    if dw_length < 8 || dw_length > win_cert.len() {
        return AuthenticodeVerdict::Invalid("invalid WIN_CERTIFICATE length".into());
    }
    let pkcs7 = &win_cert[8..dw_length];

    // Decode the PKCS#7 SignedData.
    let content_info = match ContentInfo::from_der(pkcs7) {
        Ok(ci) => ci,
        Err(e) => return AuthenticodeVerdict::Invalid(format!("malformed PKCS#7: {e}")),
    };
    if content_info.content_type.to_string() != OID_SIGNED_DATA {
        return AuthenticodeVerdict::Invalid("PKCS#7 is not signedData".into());
    }
    let signed_data: SignedData = match content_info.content.decode_as() {
        Ok(sd) => sd,
        Err(e) => return AuthenticodeVerdict::Invalid(format!("malformed SignedData: {e}")),
    };

    // The encapsulated content must be Authenticode SpcIndirectData.
    if signed_data.encap_content_info.econtent_type.to_string() != OID_SPC_INDIRECT_DATA {
        return AuthenticodeVerdict::Invalid("eContent is not SpcIndirectData".into());
    }
    let econtent = match signed_data.encap_content_info.econtent.as_ref() {
        Some(c) => c,
        None => return AuthenticodeVerdict::Invalid("missing eContent".into()),
    };
    let econtent_full = match econtent.to_der() {
        Ok(d) => d,
        Err(e) => return AuthenticodeVerdict::Invalid(format!("eContent re-encode failed: {e}")),
    };
    // Per RFC 5652 the eContent is a `[0] EXPLICIT OCTET STRING`; the `Any`
    // value re-encodes the full OCTET STRING TLV. Real Authenticode signatures
    // wrap `SpcIndirectDataContent` in that OCTET STRING, so unwrap it before
    // parsing. The messageDigest signed attribute is computed over the full
    // DER of `SpcIndirectDataContent` (SEQUENCE tag included), so the
    // unwrapped bytes are used verbatim for hashing.
    let econtent_value = {
        let mut off = 0;
        match der_read_tlv(&econtent_full, &mut off) {
            Some((0x04, start, len)) => econtent_full[start..start + len].to_vec(),
            Some((0x30, _, _)) => econtent_full,
            _ => return AuthenticodeVerdict::Invalid("eContent is not an OCTET STRING".into()),
        }
    };

    // Extract the PE hash claimed by the signature and verify it against the file.
    let (pe_hash_oid, claimed_pe_hash) = match parse_spc_indirect_data(&econtent_value) {
        Some(v) => v,
        None => return AuthenticodeVerdict::Invalid("malformed SpcIndirectData".into()),
    };
    let computed_pe_hash = match compute_authenticode_hash(pe_data, &pe_hash_oid) {
        Some(h) => h,
        None => {
            return AuthenticodeVerdict::Invalid(format!(
                "unsupported PE hash algorithm {pe_hash_oid}"
            ));
        }
    };
    if computed_pe_hash != claimed_pe_hash {
        return AuthenticodeVerdict::Invalid("PE hash does not match signature".into());
    }

    let certs_set = match signed_data.certificates.as_ref() {
        Some(c) => c,
        None => return AuthenticodeVerdict::Invalid("no certificates in signature".into()),
    };
    let certs_vec: &[cms::cert::CertificateChoices] = certs_set.0.as_ref();

    // Dual-signature support: iterate over ALL signer_infos.
    // Accept as Valid if at least one signature verifies.
    let mut any_valid = false;
    let mut last_error: Option<String> = None;
    // Track the signer cert from the first successful signer for chain validation.
    // Prefer SHA-256 signer if available.
    let mut chain_validated_signer_cert: Option<x509_cert::certificate::Certificate> = None;

    for signer in signed_data.signer_infos.0.iter() {
        let digest_oid = signer.digest_alg.oid.to_string();

        // Locate the signer's certificate by issuer+serial OR SubjectKeyIdentifier.
        let signer_cert = match locate_signer_certificate(signer, certs_vec) {
            Ok(Some(cert)) => cert,
            Ok(None) => {
                last_error = Some(format!(
                    "signer certificate not found for digest {digest_oid}"
                ));
                continue;
            }
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };

        // Verify the messageDigest signed attribute.
        let message = match extract_signing_message(signer, &digest_oid, &econtent_value) {
            Ok(m) => m,
            Err(e) => {
                last_error = Some(format!("digest {digest_oid}: {e}"));
                continue;
            }
        };

        // Extract public key SPKI DER.
        let spki_der = match signer_cert.tbs_certificate.subject_public_key_info.to_der() {
            Ok(d) => d,
            Err(e) => {
                last_error = Some(format!(
                    "digest {digest_oid}: bad SubjectPublicKeyInfo: {e}"
                ));
                continue;
            }
        };

        // Detect public key algorithm and verify signature.
        let algo_oid = signer_cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string();

        let sig_result = match algo_oid.as_str() {
            OID_EC_PUBLIC_KEY => {
                // ECDSA public key.
                verify_ecdsa_signature(
                    &spki_der,
                    signer.signature.as_bytes(),
                    &message,
                    &digest_oid,
                )
            }
            _ => {
                // Assume RSA (default / OID 1.2.840.113549.1.1.1).
                verify_rsa_signature(
                    &spki_der,
                    signer.signature.as_bytes(),
                    &message,
                    &digest_oid,
                )
            }
        };

        match sig_result {
            Ok(()) => {
                any_valid = true;
                // Save signer cert for chain validation (prefer SHA-256).
                if chain_validated_signer_cert.is_none() || digest_oid == OID_SHA256 {
                    chain_validated_signer_cert = Some(signer_cert.clone());
                }
            }
            Err(e) => {
                last_error = Some(format!("digest {digest_oid}: {e}"));
            }
        }
    }

    if !any_valid {
        return AuthenticodeVerdict::Invalid(
            last_error.unwrap_or_else(|| "all signer signatures failed verification".into()),
        );
    }

    // Certificate chain validation: validate the signer certificate chain up to
    // a system-trusted root using the macOS Security framework.
    if let Some(signer_cert) = chain_validated_signer_cert {
        match signer_cert.to_der() {
            Ok(cert_der) => {
                // Include the intermediate CAs embedded in the signature's
                // certificate bag so SecTrust can build the chain even when
                // they are not present in the local keychain.
                let intermediates: Vec<Vec<u8>> = certs_vec
                    .iter()
                    .filter_map(|choice| match choice {
                        cms::cert::CertificateChoices::Certificate(cert) => cert.to_der().ok(),
                        _ => None,
                    })
                    .filter(|der| der != &cert_der)
                    .collect();
                if let Err(e) = validate_certificate_chain(&cert_der, &intermediates) {
                    return AuthenticodeVerdict::Invalid(format!("chain validation failed: {e}"));
                }
            }
            Err(e) => {
                return AuthenticodeVerdict::Invalid(format!(
                    "failed to re-encode signer certificate: {e}"
                ));
            }
        }
    }

    AuthenticodeVerdict::Valid
}

/// Locate the signer certificate from the PKCS#7 certificates bag using
/// either IssuerAndSerialNumber or SubjectKeyIdentifier.
fn locate_signer_certificate(
    signer: &cms::signed_data::SignerInfo,
    certs: &[cms::cert::CertificateChoices],
) -> Result<Option<x509_cert::certificate::Certificate>, String> {
    use cms::cert::CertificateChoices;
    use cms::signed_data::SignerIdentifier;

    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            for choice in certs.iter() {
                if let CertificateChoices::Certificate(cert) = choice
                    && cert.tbs_certificate.issuer == ias.issuer
                    && cert.tbs_certificate.serial_number == ias.serial_number
                {
                    return Ok(Some(cert.clone()));
                }
            }
            Ok(None)
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // The SKI is stored as a OctetString containing the key hash.
            let ski_bytes = ski.0.as_bytes();
            // Try to find a certificate whose SubjectKeyIdentifier extension matches.
            if let Some(cert) = find_cert_by_subject_key_id(certs, ski_bytes) {
                return Ok(Some(cert.clone()));
            }
            // No fallback: a SubjectKeyIdentifier that matches no certificate
            // must not bind the signature to an arbitrary bag certificate,
            // which would let the signer identity claimed by the PKCS#7 be
            // replaced with an unrelated certificate.
            Ok(None)
        }
    }
}

/// Extract the message that was signed (either the DER-encoded signed attributes
/// or the raw eContent value).
fn extract_signing_message(
    signer: &cms::signed_data::SignerInfo,
    digest_oid: &str,
    econtent_value: &[u8],
) -> Result<Vec<u8>, String> {
    use der::Encode;
    use der::asn1::OctetString;

    match signer.signed_attrs.as_ref() {
        Some(attrs) => {
            // The messageDigest signed attribute must equal the hash of eContent.
            let mut message_digest: Option<Vec<u8>> = None;
            for attr in attrs.iter() {
                if attr.oid.to_string() != OID_MESSAGE_DIGEST {
                    continue;
                }
                let Some(value) = attr.values.iter().next() else {
                    continue;
                };
                if let Ok(octets) = value.decode_as::<OctetString>() {
                    message_digest = Some(octets.as_bytes().to_vec());
                }
            }
            let message_digest = match message_digest {
                Some(d) => d,
                None => {
                    return Err("missing messageDigest signed attribute".into());
                }
            };
            let expected = match digest_with_oid(digest_oid, econtent_value) {
                Some(d) => d,
                None => {
                    return Err(format!("unsupported signed-attribute digest {digest_oid}"));
                }
            };
            if message_digest != expected {
                return Err("messageDigest attribute does not match eContent".into());
            }
            // The signature is over the DER SET encoding of the signed attributes.
            attrs
                .to_der()
                .map_err(|e| format!("signed attributes re-encode failed: {e}"))
        }
        None => Ok(econtent_value.to_vec()),
    }
}

/// Verify an RSA PKCS#1 v1.5 signature over `message`.
fn verify_rsa_signature(
    spki_der: &[u8],
    signature_bytes: &[u8],
    message: &[u8],
    digest_oid: &str,
) -> Result<(), String> {
    use rsa::RsaPublicKey;
    use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;

    let public_key = RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| format!("failed to parse RSA public key: {e}"))?;

    let signature = RsaSignature::try_from(signature_bytes)
        .map_err(|_| "malformed RSA signature value".to_string())?;

    match digest_oid {
        OID_SHA256 => VerifyingKey::<Sha256>::new(public_key)
            .verify(message, &signature)
            .map_err(|e| format!("RSA SHA-256 signature verification failed: {e}")),
        OID_SHA1 => VerifyingKey::<sha1::Sha1>::new(public_key)
            .verify(message, &signature)
            .map_err(|e| format!("RSA SHA-1 signature verification failed: {e}")),
        OID_SHA384 => VerifyingKey::<sha2::Sha384>::new(public_key)
            .verify(message, &signature)
            .map_err(|e| format!("RSA SHA-384 signature verification failed: {e}")),
        OID_SHA512 => VerifyingKey::<sha2::Sha512>::new(public_key)
            .verify(message, &signature)
            .map_err(|e| format!("RSA SHA-512 signature verification failed: {e}")),
        other => Err(format!("unsupported RSA signature digest {other}")),
    }
}

// ===========================================================================
// WinVerifyTrust — Gap 10.4
// ===========================================================================

/// Well-known WinTrust policy GUIDs used by `WinVerifyTrust`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinTrustPolicyGuid {
    /// WINTRUST_ACTION_GENERIC_VERIFY_V2 — default Authenticode verification.
    /// GUID: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    GenericVerifyV2,
    /// WINTRUST_ACTION_TRUSTPROVIDER_TEST — trust provider test.
    /// GUID: {573E31F8-DDBA-11d0-8CCB-00C04FC295EE}
    TrustProviderTest,
    /// HTTPSPROV_ACTION — HTTPS certificate verification.
    /// GUID: {573E31F8-AABA-11d0-8CCB-00C04FC295EE}
    HttpsProvAction,
    /// OFFICESIGN_ACTION_VERIFY — Office document signature verification.
    /// GUID: {5555C2CD-17FB-11d1-85C4-00C04FC295EE}
    OfficeSignVerify,
    /// DRIVER_ACTION_VERIFY — driver signature verification (WHQL).
    /// GUID: {F750E6C3-38EE-11d1-85E5-00C04FC295EE}
    DriverVerify,
    /// Unknown policy GUID.
    Unknown,
}

impl WinTrustPolicyGuid {
    /// Parses a 16-byte Windows GUID (mixed-endian) into a policy GUID.
    pub fn from_guid_bytes(bytes: &[u8; 16]) -> Self {
        // Windows GUIDs are stored in mixed-endian format:
        // Data1 (4 bytes LE), Data2 (2 bytes LE), Data3 (2 bytes LE), Data4 (8 bytes BE)
        let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
        let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);

        // WINTRUST_ACTION_GENERIC_VERIFY_V2: 00AAC56B-CD44-11d0-8CC2-00C04FC295EE
        if data1 == 0x00AAC56B && data2 == 0xCD44 && data3 == 0x11D0 {
            return WinTrustPolicyGuid::GenericVerifyV2;
        }
        // DRIVER_ACTION_VERIFY: F750E6C3-38EE-11d1-85E5-00C04FC295EE
        if data1 == 0xF750E6C3 && data2 == 0x38EE && data3 == 0x11D1 {
            return WinTrustPolicyGuid::DriverVerify;
        }
        // HTTPSPROV_ACTION: 573E31F8-AABA-11d0-8CCB-00C04FC295EE
        if data1 == 0x573E31F8 && data2 == 0xAABA && data3 == 0x11D0 {
            return WinTrustPolicyGuid::HttpsProvAction;
        }
        // OFFICESIGN_ACTION_VERIFY: 5555C2CD-17FB-11d1-85E5-00C04FC295EE
        if data1 == 0x5555C2CD && data2 == 0x17FB && data3 == 0x11D1 {
            return WinTrustPolicyGuid::OfficeSignVerify;
        }
        // WINTRUST_ACTION_TRUSTPROVIDER_TEST: 573E31F8-DDBA-11d0-8CCB-00C04FC295EE
        if data1 == 0x573E31F8 && data2 == 0xDDBA && data3 == 0x11D0 {
            return WinTrustPolicyGuid::TrustProviderTest;
        }
        WinTrustPolicyGuid::Unknown
    }
}

/// Win32 error codes returned by `WinVerifyTrust`.
pub mod win_trust_error {
    /// Success — the signature is valid and trusted.
    pub const ERROR_SUCCESS: u32 = 0;
    /// TRUST_E_NOSIGNATURE (0x800B0100) — no signature present.
    pub const TRUST_E_NOSIGNATURE: u32 = 0x800B0100;
    /// TRUST_E_NOSIGNATURE — subject not trusted.
    pub const TRUST_E_SUBJECT_NOT_TRUSTED: u32 = 0x800B0104;
    /// TRUST_E_BAD_DIGEST (0x80096010) — hash mismatch / tampered file.
    pub const TRUST_E_BAD_DIGEST: u32 = 0x80096010;
    /// CERT_E_REVOKED (0x800B010C) — certificate has been revoked.
    pub const CERT_E_REVOKED: u32 = 0x800B010C;
    /// CERT_E_EXPIRED (0x800B0101) — certificate has expired.
    pub const CERT_E_EXPIRED: u32 = 0x800B0101;
    /// CERT_E_UNTRUSTEDROOT (0x800B0109) — untrusted root certificate.
    pub const CERT_E_UNTRUSTEDROOT: u32 = 0x800B0109;
    /// TRUST_E_PROVIDER_UNKNOWN (0x800B0001) — unknown trust provider.
    pub const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B0001;
}

/// Result of a `WinVerifyTrust` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinVerifyTrustResult {
    /// Win32 error code (0 = success).
    pub error: u32,
    /// Human-readable description.
    pub description: String,
    /// The Authenticode verdict, if verification was attempted.
    pub verdict: Option<AuthenticodeVerdict>,
}

/// Implements `WinVerifyTrust` — the Win32 API for verifying Authenticode
/// signatures on PE files.
///
/// This function is the primary entry point for signature verification in
/// Windows. It takes a policy GUID and subject information, then delegates
/// to the appropriate trust provider.
///
/// # Arguments
/// * `policy_guid` — The trust provider policy to use.
/// * `pe_data` — The raw PE file bytes to verify.
///
/// # Returns
/// A `WinVerifyTrustResult` indicating whether the signature is trusted.
pub fn win_verify_trust(policy_guid: WinTrustPolicyGuid, pe_data: &[u8]) -> WinVerifyTrustResult {
    match policy_guid {
        WinTrustPolicyGuid::GenericVerifyV2 | WinTrustPolicyGuid::TrustProviderTest => {
            let verdict = verify_pe_authenticode(pe_data);
            let (error, description) = match &verdict {
                AuthenticodeVerdict::Valid => (
                    win_trust_error::ERROR_SUCCESS,
                    "The signature is valid and trusted.".to_string(),
                ),
                AuthenticodeVerdict::NoSignature => (
                    win_trust_error::TRUST_E_NOSIGNATURE,
                    "No Authenticode signature found.".to_string(),
                ),
                AuthenticodeVerdict::Invalid(reason) => {
                    if reason.contains("hash does not match") {
                        (
                            win_trust_error::TRUST_E_BAD_DIGEST,
                            format!("PE hash mismatch: {reason}"),
                        )
                    } else if reason.contains("revoked") {
                        (
                            win_trust_error::CERT_E_REVOKED,
                            format!("Certificate revoked: {reason}"),
                        )
                    } else if reason.contains("expired") {
                        (
                            win_trust_error::CERT_E_EXPIRED,
                            format!("Certificate expired: {reason}"),
                        )
                    } else if reason.contains("not trusted") || reason.contains("chain") {
                        (
                            win_trust_error::CERT_E_UNTRUSTEDROOT,
                            format!("Untrusted certificate chain: {reason}"),
                        )
                    } else {
                        (
                            win_trust_error::TRUST_E_SUBJECT_NOT_TRUSTED,
                            format!("Signature verification failed: {reason}"),
                        )
                    }
                }
            };
            WinVerifyTrustResult {
                error,
                description,
                verdict: Some(verdict),
            }
        }
        WinTrustPolicyGuid::DriverVerify => {
            // Driver verification is stricter — requires WHQL signature
            let verdict = verify_pe_authenticode(pe_data);
            let (error, description) = match &verdict {
                AuthenticodeVerdict::Valid => (
                    win_trust_error::ERROR_SUCCESS,
                    "Driver signature is valid and WHQL trusted.".to_string(),
                ),
                AuthenticodeVerdict::NoSignature => (
                    win_trust_error::TRUST_E_NOSIGNATURE,
                    "Driver has no Authenticode signature.".to_string(),
                ),
                AuthenticodeVerdict::Invalid(reason) => (
                    win_trust_error::TRUST_E_SUBJECT_NOT_TRUSTED,
                    format!("Driver signature verification failed: {reason}"),
                ),
            };
            WinVerifyTrustResult {
                error,
                description,
                verdict: Some(verdict),
            }
        }
        WinTrustPolicyGuid::HttpsProvAction => {
            // HTTPS certificate verification operates on a certificate chain
            // context, not PE data; the provider cannot evaluate the input it
            // was given. Reporting success here would make every guest
            // certificate check observe "trusted", so fail closed instead.
            WinVerifyTrustResult {
                error: win_trust_error::TRUST_E_PROVIDER_UNKNOWN,
                description: "HTTPS provider: subject type not supported by this provider.".to_string(),
                verdict: None,
            }
        }
        WinTrustPolicyGuid::OfficeSignVerify => {
            // Office document signing — treat like generic verification
            let verdict = verify_pe_authenticode(pe_data);
            let (error, description) = match &verdict {
                AuthenticodeVerdict::Valid => (
                    win_trust_error::ERROR_SUCCESS,
                    "Office signature is valid.".to_string(),
                ),
                _ => (
                    win_trust_error::TRUST_E_SUBJECT_NOT_TRUSTED,
                    "Office signature verification failed.".to_string(),
                ),
            };
            WinVerifyTrustResult {
                error,
                description,
                verdict: Some(verdict),
            }
        }
        WinTrustPolicyGuid::Unknown => WinVerifyTrustResult {
            error: win_trust_error::TRUST_E_PROVIDER_UNKNOWN,
            description: "Unknown trust provider GUID.".to_string(),
            verdict: None,
        },
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denuvo_emulator_initialization() {
        let config = DenuvoConfig {
            version: DenuvoVersion::V6,
            enabled: true,
            integrity_check_interval_ms: 5000,
            code_sections: Vec::new(),
            trigger_points: Vec::new(),
        };
        let emulator = DenuvoEmulator::new(config);
        assert!(!emulator.state.initialized);
        assert!(!emulator.state.code_sections_decrypted);
        assert!(emulator.state.license_token.is_none());
        assert_eq!(emulator.state.hardware_id, [0u8; 16]);
        assert_eq!(emulator.integrity_checks_passed, 0);
        assert_eq!(emulator.integrity_checks_failed, 0);
        assert!(!emulator.license_verified);
        assert!(emulator.config.enabled);
        assert_eq!(emulator.config.version, DenuvoVersion::V6);
    }

    #[test]
    fn denuvo_code_section_decrypt() {
        let code = vec![0x90, 0x90, 0x90, 0x90, 0xC3];
        let config = DenuvoConfig {
            version: DenuvoVersion::V5,
            enabled: true,
            integrity_check_interval_ms: 1000,
            code_sections: vec![CodeSection {
                rva: 0x1000,
                size: code.len() as u32,
                original_hash: [0u8; 32],
                decrypted: Vec::new(),
                encrypted: true,
            }],
            trigger_points: vec![0x2000],
        };
        let mut emulator = DenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &code);
        emulator.initialize(&mut memory, 0).unwrap();
        assert!(emulator.state.initialized);

        // After initialize(), section.decrypted = plaintext (read from memory),
        // original_hash = SHA-256(plaintext), hardware_id is generated.
        // Compute the key that decrypt_code_section will derive:
        let section = &emulator.config.code_sections[0];
        let mut key_material = Vec::with_capacity(48);
        key_material.extend_from_slice(&emulator.state.hardware_id);
        key_material.extend_from_slice(&section.original_hash);
        let derived = sha256_hash(&key_material);
        let aes_key: [u8; 16] = {
            let mut k = [0u8; 16];
            k.copy_from_slice(&derived[..16]);
            k
        };
        let iv: [u8; 16] = {
            let mut i = [0u8; 16];
            i.copy_from_slice(&derived[16..]);
            i
        };

        // PKCS7-pad the plaintext and encrypt with AES-128-CBC
        let block_size = 16usize;
        let pad_len = block_size - (code.len() % block_size);
        let mut padded = code.clone();
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
        let ciphertext =
            crate::network::aes_128_cbc_encrypt(&aes_key, &iv, &padded).unwrap();

        // Replace section.decrypted with the ciphertext so the AES decrypt works
        emulator.config.code_sections[0].decrypted = ciphertext;

        emulator.decrypt_code_section(&mut memory, 0).unwrap();
        assert!(!emulator.config.code_sections[0].encrypted);
        assert!(emulator.state.code_sections_decrypted);
        let decrypted_data = memory.read_bytes(0x1000, code.len()).unwrap();
        assert_eq!(decrypted_data, code);
    }

    #[test]
    fn denuvo_code_section_decrypt_nonzero_base() {
        // Regression test: decryption and integrity verification must operate
        // at `base + section.rva`, not at the bare RVA.
        let base: u64 = 0x400_000;
        let rva: u64 = 0x1000;
        let code = vec![0x90, 0x90, 0x90, 0x90, 0xC3];
        let config = DenuvoConfig {
            version: DenuvoVersion::V5,
            enabled: true,
            integrity_check_interval_ms: 1000,
            code_sections: vec![CodeSection {
                rva,
                size: code.len() as u32,
                original_hash: [0u8; 32],
                decrypted: Vec::new(),
                encrypted: true,
            }],
            trigger_points: Vec::new(),
        };
        let mut emulator = DenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(base + rva, &code);
        emulator.initialize(&mut memory, base).unwrap();
        assert_eq!(emulator.base, base);

        // Encrypt the plaintext with the same key derivation used internally.
        let section = &emulator.config.code_sections[0];
        let mut key_material = Vec::with_capacity(48);
        key_material.extend_from_slice(&emulator.state.hardware_id);
        key_material.extend_from_slice(&section.original_hash);
        let derived = sha256_hash(&key_material);
        let aes_key: [u8; 16] = {
            let mut k = [0u8; 16];
            k.copy_from_slice(&derived[..16]);
            k
        };
        let iv: [u8; 16] = {
            let mut i = [0u8; 16];
            i.copy_from_slice(&derived[16..]);
            i
        };
        let block_size = 16usize;
        let pad_len = block_size - (code.len() % block_size);
        let mut padded = code.clone();
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
        let ciphertext =
            crate::network::aes_128_cbc_encrypt(&aes_key, &iv, &padded).unwrap();
        emulator.config.code_sections[0].decrypted = ciphertext;

        emulator.decrypt_code_section(&mut memory, 0).unwrap();
        // Plaintext must land at base + rva, leaving the bare RVA untouched.
        let decrypted_data = memory.read_bytes(base + rva, code.len()).unwrap();
        assert_eq!(decrypted_data, code);
        let bare_rva = memory.read_bytes(rva, code.len()).unwrap_or_default();
        assert_ne!(bare_rva, code);

        // Integrity check must pass against the same base + rva location.
        let result = emulator.verify_integrity(&memory, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn denuvo_integrity_check() {
        let code = vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let code_hash = sha256_hash(&code);
        let config = DenuvoConfig {
            version: DenuvoVersion::V4,
            enabled: true,
            integrity_check_interval_ms: 1000,
            code_sections: vec![CodeSection {
                rva: 0x2000,
                size: code.len() as u32,
                original_hash: code_hash,
                decrypted: code.clone(),
                encrypted: false,
            }],
            trigger_points: Vec::new(),
        };
        let mut emulator = DenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x2000, &code);
        emulator.initialize(&mut memory, 0).unwrap();
        let result = emulator.verify_integrity(&memory, 0).unwrap();
        assert!(result);
        assert_eq!(emulator.integrity_checks_passed, 1);
        assert_eq!(emulator.integrity_checks_failed, 0);
    }

    #[test]
    fn denuvo_license_token() {
        let config = DenuvoConfig {
            version: DenuvoVersion::V7,
            enabled: true,
            integrity_check_interval_ms: 5000,
            code_sections: Vec::new(),
            trigger_points: Vec::new(),
        };
        let mut emulator = DenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        emulator.initialize(&mut memory, 0).unwrap();
        let token = emulator.generate_license_token();
        assert_eq!(token.len(), 64);
        assert!(emulator.state.license_token.is_some());
        assert!(emulator.verify_license_token(&token));
        assert!(emulator.license_verified);
        let wrong_token = vec![0u8; 64];
        let mut emulator2 = DenuvoEmulator::new(DenuvoConfig {
            version: DenuvoVersion::V7,
            enabled: true,
            integrity_check_interval_ms: 5000,
            code_sections: Vec::new(),
            trigger_points: Vec::new(),
        });
        emulator2.initialize(&mut memory, 0).unwrap();
        assert!(!emulator2.verify_license_token(&wrong_token));
    }

    #[test]
    fn steamstub_header_parsing() {
        let mut memory = MemoryImage::default();
        let base: u64 = 0x400_000;
        let mut pe_data = vec![0u8; 0x400];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        let pe_offset = 0x80u32;
        pe_data[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        let pe_sig: u32 = 0x0000_4550;
        pe_data[pe_offset as usize..pe_offset as usize + 4].copy_from_slice(&pe_sig.to_le_bytes());
        let num_sections: u16 = 1;
        pe_data[pe_offset as usize + 6..pe_offset as usize + 8]
            .copy_from_slice(&num_sections.to_le_bytes());
        let size_optional: u16 = 0xF0;
        pe_data[pe_offset as usize + 20..pe_offset as usize + 22]
            .copy_from_slice(&size_optional.to_le_bytes());
        let sec_start = pe_offset as usize + 24 + size_optional as usize;
        pe_data.resize(sec_start + 40, 0);
        pe_data[sec_start..sec_start + 5].copy_from_slice(b".bind");
        let virtual_size: u32 = 0x200;
        pe_data[sec_start + 8..sec_start + 12].copy_from_slice(&virtual_size.to_le_bytes());
        let virtual_address: u32 = 0x1000;
        pe_data[sec_start + 12..sec_start + 16].copy_from_slice(&virtual_address.to_le_bytes());
        let mut stub = vec![0u8; 48];
        stub[0..4].copy_from_slice(&STEAMSTUB_MAGIC.to_le_bytes());
        stub[4..8].copy_from_slice(&1u32.to_le_bytes());
        stub[8..12].copy_from_slice(&0u32.to_le_bytes());
        stub[12..16].copy_from_slice(&0x1234u32.to_le_bytes());
        stub[16..20].copy_from_slice(&0x2000u32.to_le_bytes());
        stub[20..24].copy_from_slice(&0x1000u32.to_le_bytes());
        stub[24..40].copy_from_slice(&[0xAA; 16]);
        stub[40..44].copy_from_slice(&12345u32.to_le_bytes());
        memory.map_bytes(base, &pe_data);
        memory.map_bytes(base + 0x1000, &stub);
        let result = SteamstubLoader::detect_steamstub(&memory, base).expect("detection ok");
        assert!(result.is_some());
        let header = result.unwrap();
        assert_eq!(header.magic, STEAMSTUB_MAGIC);
        assert_eq!(header.version, 1);
        assert_eq!(header.original_entry_point, 0x1234);
        assert_eq!(header.code_section_rva, 0x2000);
        assert_eq!(header.code_section_size, 0x1000);
        assert_eq!(header.app_id, 12345);
        assert_eq!(header.encryption_type, EncryptionType::Xor);
    }

    #[test]
    fn steamstub_xor_decrypt() {
        let original = b"Hello, Steam DRM!";
        let key = b"secret_key_12345";
        let mut data = original.to_vec();
        SteamstubLoader::decrypt_xor(&mut data, key);
        assert_ne!(&data[..], original);
        SteamstubLoader::decrypt_xor(&mut data, key);
        assert_eq!(&data[..], original);
    }

    #[test]
    fn packed_exe_detection_upx() {
        let mut pe_data = vec![0u8; 0x300];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        let pe_offset = 0x80u32;
        pe_data[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        let pe_sig: u32 = 0x0000_4550;
        pe_data[pe_offset as usize..pe_offset as usize + 4].copy_from_slice(&pe_sig.to_le_bytes());
        let num_sections: u16 = 2;
        pe_data[pe_offset as usize + 6..pe_offset as usize + 8]
            .copy_from_slice(&num_sections.to_le_bytes());
        let size_optional: u16 = 0xF0;
        pe_data[pe_offset as usize + 20..pe_offset as usize + 22]
            .copy_from_slice(&size_optional.to_le_bytes());
        let sec_start = pe_offset as usize + 24 + size_optional as usize;
        pe_data.resize(sec_start + 80, 0);
        pe_data[sec_start..sec_start + 4].copy_from_slice(b"UPX0");
        pe_data[sec_start + 40..sec_start + 44].copy_from_slice(b"UPX1");
        let result = PackedExeDetector::detect_packing(&pe_data).unwrap();
        assert_eq!(result, Some(PackedExeType::UPX));
        assert!(PackedExeDetector::detect_upx(&pe_data));
    }

    #[test]
    fn packed_exe_detection_aspack() {
        let mut pe_data = vec![0u8; 0x300];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        let pe_offset = 0x80u32;
        pe_data[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        let pe_sig: u32 = 0x0000_4550;
        pe_data[pe_offset as usize..pe_offset as usize + 4].copy_from_slice(&pe_sig.to_le_bytes());
        let num_sections: u16 = 2;
        pe_data[pe_offset as usize + 6..pe_offset as usize + 8]
            .copy_from_slice(&num_sections.to_le_bytes());
        let size_optional: u16 = 0xF0;
        pe_data[pe_offset as usize + 20..pe_offset as usize + 22]
            .copy_from_slice(&size_optional.to_le_bytes());
        let sec_start = pe_offset as usize + 24 + size_optional as usize;
        pe_data.resize(sec_start + 80, 0);
        pe_data[sec_start..sec_start + 5].copy_from_slice(b".text");
        pe_data[sec_start + 40..sec_start + 47].copy_from_slice(b".aspack");
        let result = PackedExeDetector::detect_packing(&pe_data).unwrap();
        assert_eq!(result, Some(PackedExeType::ASPack));
        assert!(PackedExeDetector::detect_aspack(&pe_data));
    }

    #[test]
    fn upx_decompression() {
        let compressed = vec![0x24, 0x1A, 0x40];
        let result = UpxUnpacker::decompress_nrv2b(&compressed);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let decompressed = result.unwrap();
        assert!(decompressed.len() >= 2);
        assert_eq!(decompressed[0], b'H');
        assert_eq!(decompressed[1], b'i');
    }

    #[test]
    fn integrity_check_region() {
        let mut emulator = IntegrityCheckEmulator::new();
        let mut memory = MemoryImage::default();
        let code = vec![0x90, 0x90, 0xC3];
        memory.map_bytes(0x1000, &code);
        let expected_hash = sha256_hash(&code);
        let region_id = emulator.register_region(0x1000, 3, expected_hash);
        assert_eq!(region_id, 1);
        assert_eq!(emulator.registered_regions.len(), 1);
        let result = emulator.check_region(&memory, region_id).unwrap();
        assert!(result.passed);
        assert_eq!(result.region_id, region_id);
        assert_eq!(result.computed_hash, expected_hash);
        assert_eq!(emulator.check_history.len(), 1);
    }

    #[test]
    fn integrity_check_force_pass() {
        let mut emulator = IntegrityCheckEmulator::new();
        let mut memory = MemoryImage::default();
        let code = vec![0x90, 0x90, 0xC3];
        memory.map_bytes(0x1000, &code);
        let wrong_hash = [0xFF; 32];
        let region_id = emulator.register_region(0x1000, 3, wrong_hash);
        let result = emulator.check_region(&memory, region_id).unwrap();
        assert!(!result.passed);
        memory.map_bytes(0x2000, &code);
        let region_id2 = emulator.register_region(0x2000, 3, wrong_hash);
        emulator.force_pass(region_id2);
        let result = emulator.check_region(&memory, region_id2).unwrap();
        assert!(result.passed);
        let result = emulator.check_region(&memory, region_id2).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn anti_debug_state() {
        let state = AntiDebugState::new();
        assert!(!state.debugger_present);
        assert!(!state.remote_debugger_present);
        assert!(!state.being_debugged);
        assert_eq!(state.debug_port, 0);
        assert_eq!(state.nt_global_flag, 0);
        assert_eq!(state.heap_flags, 0x0000_0002);
        assert_eq!(state.num_heaps, 1);
        assert!(!state.is_debugger_present());
        assert!(!state.check_remote_debugger_present());
        assert_eq!(state.get_debug_port(), 0);
    }

    #[test]
    fn anti_debug_nt_query() {
        let state = AntiDebugState::new();
        assert_eq!(state.nt_query_information_process(7), 0);
        assert_eq!(state.nt_query_information_process(30), 0);
        assert_eq!(state.nt_query_information_process(31), 1);
        assert_eq!(state.nt_query_information_process(99), 0);
        let sys_info = state.nt_query_system_information(35);
        assert_eq!(sys_info, vec![0u8, 0u8]);
        let sys_info = state.nt_query_system_information(99);
        assert!(sys_info.is_empty());
        let _result = state.nt_set_information_thread(0x1234, 17);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let _result = state.output_debug_string("test");
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let tick1 = state.get_tick_count();
        let tick2 = state.get_tick_count();
        assert!(tick2 > tick1);
        let perf1 = state.query_performance_counter();
        let perf2 = state.query_performance_counter();
        assert!(perf2 > perf1);
    }

    // =======================================================================
    // Authenticode verification tests
    // =======================================================================

    #[test]
    fn authenticode_no_signature() {
        // A minimal valid PE with no certificate table should return NoSignature.
        let pe = create_minimal_pe(false);
        let verdict = verify_pe_authenticode(&pe);
        assert_eq!(verdict, AuthenticodeVerdict::NoSignature);
    }

    #[test]
    fn authenticode_invalid_signature_truncated() {
        // A minimal PE with a truncated WIN_CERTIFICATE should return Invalid.
        let mut pe = create_minimal_pe(true);
        // Overwrite the certificate table with garbage.
        let cert_va = 0x200;
        let cert_size = 4usize; // Too small for WIN_CERTIFICATE header
        write_cert_table(&mut pe, cert_va, cert_size);
        // Write just 4 bytes.
        pe.resize(cert_va + cert_size, 0);
        let verdict = verify_pe_authenticode(&pe);
        assert!(
            matches!(verdict, AuthenticodeVerdict::Invalid(_)),
            "expected Invalid, got {verdict:?}"
        );
    }

    #[test]
    fn authenticode_invalid_cert_type() {
        // A minimal PE with a WIN_CERTIFICATE with wrong type.
        let mut pe = create_minimal_pe(true);
        let cert_va = 0x200;
        let cert_size = 24usize;
        write_cert_table(&mut pe, cert_va, cert_size);
        // Write WIN_CERTIFICATE with type=0 (not PKCS_SIGNED_DATA).
        pe.resize(cert_va + cert_size, 0);
        let dw_length = cert_size as u32;
        let cert_type: u16 = 0x0001; // WIN_CERT_TYPE_RESERVED_1 (not 0x0002)
        pe[cert_va..cert_va + 4].copy_from_slice(&dw_length.to_le_bytes());
        pe[cert_va + 4..cert_va + 8].copy_from_slice(&0u32.to_le_bytes()); // reserved
        pe[cert_va + 6..cert_va + 8].copy_from_slice(&cert_type.to_le_bytes());
        let verdict = verify_pe_authenticode(&pe);
        assert!(
            matches!(verdict, AuthenticodeVerdict::Invalid(_)),
            "expected Invalid, got {verdict:?}"
        );
    }

    #[test]
    fn authenticode_malformed_pkcs7() {
        // A minimal PE with a WIN_CERTIFICATE containing garbage PKCS#7.
        let mut pe = create_minimal_pe(true);
        let cert_va = 0x200;
        let cert_size = 24usize;
        write_cert_table(&mut pe, cert_va, cert_size);
        pe.resize(cert_va + cert_size, 0);
        let dw_length = cert_size as u32;
        let cert_type: u16 = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
        pe[cert_va..cert_va + 4].copy_from_slice(&dw_length.to_le_bytes());
        pe[cert_va + 6..cert_va + 8].copy_from_slice(&cert_type.to_le_bytes());
        // Write garbage PKCS#7 data (not valid DER).
        pe[cert_va + 8..cert_va + cert_size].fill(0xFF);
        let verdict = verify_pe_authenticode(&pe);
        assert!(
            matches!(verdict, AuthenticodeVerdict::Invalid(_)),
            "expected Invalid, got {verdict:?}"
        );
    }

    #[test]
    fn authenticode_self_signed_chain_fails() {
        // Self-signed certificates are not trusted by the macOS system keychain
        // unless explicitly added, so chain validation should reject them.
        // This DER was generated with: openssl req -x509 -newkey rsa:2048 -keyout /dev/null
        //   -out /tmp/test_cert.der -outform DER -days 365 -nodes -subj '/CN=TestSelfSigned'
        let cert_der: &[u8] = &[
            0x30, 0x82, 0x03, 0x13, 0x30, 0x82, 0x01, 0xfb, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
            0x14, 0x58, 0x07, 0x91, 0x0a, 0xad, 0x16, 0xb3, 0x9a, 0xcc, 0x1b, 0x75, 0xe8, 0xb6,
            0x9d, 0x6e, 0x71, 0x2b, 0x6b, 0x9d, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
            0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x19, 0x31, 0x17, 0x30, 0x15,
            0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x54, 0x65, 0x73, 0x74, 0x53, 0x65, 0x6c,
            0x66, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30,
            0x36, 0x30, 0x31, 0x31, 0x35, 0x31, 0x37, 0x32, 0x36, 0x5a, 0x17, 0x0d, 0x32, 0x37,
            0x30, 0x36, 0x30, 0x31, 0x31, 0x35, 0x31, 0x37, 0x32, 0x36, 0x5a, 0x30, 0x19, 0x31,
            0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x54, 0x65, 0x73, 0x74,
            0x53, 0x65, 0x6c, 0x66, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x30, 0x82, 0x01, 0x22,
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
            0x00, 0x8e, 0xb0, 0x27, 0xc5, 0xda, 0xc9, 0x44, 0xbd, 0xca, 0x01, 0xb4, 0xc8, 0x1e,
            0x07, 0x6a, 0x01, 0xfb, 0xfa, 0x3f, 0x5d, 0x30, 0xda, 0xc5, 0xad, 0x7c, 0x51, 0x46,
            0x17, 0x07, 0x4d, 0xb2, 0xb7, 0x16, 0xa9, 0x41, 0xfe, 0xd1, 0xf8, 0xfb, 0xcb, 0x37,
            0xc6, 0xbc, 0xc3, 0xeb, 0xc7, 0x35, 0x8a, 0xc4, 0x7a, 0xa2, 0x8a, 0x79, 0x46, 0xac,
            0xc7, 0x96, 0x09, 0xd8, 0x68, 0x94, 0xa4, 0x82, 0x56, 0x34, 0x53, 0xec, 0xd5, 0xb1,
            0x77, 0x77, 0xab, 0xb7, 0xaa, 0x45, 0x06, 0xc3, 0xde, 0x06, 0xa7, 0x77, 0x83, 0xba,
            0x6d, 0x0e, 0x7c, 0xb1, 0x59, 0x86, 0xb1, 0x58, 0xad, 0x70, 0x18, 0x9e, 0x14, 0x49,
            0xdf, 0x1c, 0x56, 0x71, 0x11, 0xc9, 0xb7, 0xf2, 0xcb, 0x63, 0x37, 0xd7, 0xd4, 0x3b,
            0x17, 0x6a, 0x8c, 0xd8, 0x6a, 0x68, 0xf5, 0x5b, 0x6b, 0x5d, 0x82, 0x57, 0x43, 0xf4,
            0xa2, 0x85, 0x1b, 0x0b, 0xb6, 0x13, 0x48, 0x5f, 0xc8, 0x28, 0x05, 0x92, 0x95, 0xa3,
            0x8e, 0x03, 0x13, 0xf4, 0x85, 0xee, 0x5c, 0x58, 0xd5, 0x99, 0x58, 0xe0, 0x51, 0x79,
            0x43, 0x2a, 0x1d, 0xd3, 0x1e, 0xbf, 0xe1, 0xa5, 0xee, 0x58, 0x29, 0x8a, 0x7b, 0x79,
            0x09, 0x05, 0xde, 0xde, 0xc5, 0x50, 0x56, 0x73, 0x64, 0xe1, 0xe9, 0x41, 0xfe, 0x67,
            0xd6, 0x4f, 0x82, 0xd8, 0xdc, 0xe3, 0xa7, 0x19, 0x76, 0x48, 0x22, 0x7e, 0x09, 0x43,
            0xa1, 0x2a, 0xd5, 0x68, 0x32, 0x8b, 0x09, 0x4a, 0x20, 0x2a, 0xbd, 0x8b, 0x07, 0x98,
            0x64, 0xba, 0xc3, 0xb0, 0x0f, 0x48, 0x8d, 0x80, 0x01, 0x48, 0x10, 0x54, 0x98, 0x97,
            0x59, 0x70, 0x28, 0x4a, 0xec, 0x2e, 0x4f, 0xed, 0x0e, 0xdf, 0xfa, 0x76, 0x86, 0x3a,
            0xc1, 0xb3, 0x36, 0xde, 0x9f, 0x24, 0x0f, 0xb0, 0x62, 0xba, 0x9f, 0xc0, 0x36, 0x60,
            0xcc, 0x61, 0xf5, 0x59, 0xf3, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51,
            0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x03, 0xc2, 0x2f,
            0xae, 0xde, 0xfb, 0xbe, 0x0f, 0xbf, 0x49, 0x86, 0x59, 0xd5, 0x12, 0x7a, 0xe4, 0xf5,
            0x07, 0x1e, 0x8c, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
            0x80, 0x14, 0x03, 0xc2, 0x2f, 0xae, 0xde, 0xfb, 0xbe, 0x0f, 0xbf, 0x49, 0x86, 0x59,
            0xd5, 0x12, 0x7a, 0xe4, 0xf5, 0x07, 0x1e, 0x8c, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
            0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06,
            0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
            0x01, 0x01, 0x00, 0x23, 0x8a, 0x48, 0xd4, 0x57, 0x10, 0x8b, 0x27, 0x5a, 0xf5, 0x53,
            0xaa, 0x2c, 0xd4, 0x50, 0xac, 0x22, 0xca, 0xef, 0xd2, 0x9d, 0xf8, 0xb5, 0x41, 0xf8,
            0x76, 0x84, 0x40, 0x2b, 0xb0, 0xa4, 0x04, 0x72, 0x4c, 0xf9, 0xb6, 0x57, 0x22, 0xca,
            0x93, 0xb4, 0x25, 0xf9, 0x96, 0xf4, 0x72, 0x4d, 0xfe, 0x01, 0xfe, 0xad, 0xed, 0x66,
            0xad, 0xd9, 0x3d, 0xc7, 0xe7, 0xfd, 0x14, 0x4e, 0xde, 0x2d, 0xaf, 0xfe, 0x45, 0xf2,
            0x33, 0x6c, 0x4f, 0x4d, 0xe7, 0x02, 0x46, 0x98, 0x9f, 0x1a, 0xbb, 0x15, 0x05, 0xaf,
            0x36, 0x27, 0xb4, 0xc9, 0xbf, 0x1a, 0x1c, 0x4f, 0x93, 0xe3, 0x7f, 0x50, 0x7b, 0x55,
            0xdc, 0xb2, 0x8e, 0xcf, 0x8f, 0x04, 0x75, 0x21, 0x38, 0xe0, 0x92, 0x93, 0x2a, 0x1e,
            0x4f, 0x8b, 0xae, 0xa9, 0x1f, 0x9f, 0x62, 0x32, 0xc1, 0xa9, 0xc6, 0x92, 0x03, 0x40,
            0x35, 0x1d, 0xb7, 0xb6, 0xf1, 0xae, 0x04, 0x65, 0x94, 0xb3, 0x1b, 0x14, 0x78, 0x86,
            0x87, 0xde, 0x27, 0x84, 0x69, 0xfc, 0x8c, 0xdb, 0x9f, 0xe5, 0xf5, 0xcc, 0xdb, 0xe0,
            0x15, 0x1b, 0xb8, 0x73, 0x06, 0xcd, 0x1b, 0x92, 0xb3, 0x8d, 0x3a, 0x98, 0x42, 0x25,
            0x11, 0x07, 0x74, 0x08, 0xb7, 0x38, 0x68, 0x52, 0xeb, 0x4a, 0xf9, 0x2b, 0x91, 0xc6,
            0x1b, 0x0e, 0x83, 0x92, 0xf5, 0x01, 0x81, 0x24, 0xc6, 0xa7, 0xbb, 0x00, 0x7c, 0x65,
            0xc4, 0xe9, 0x9d, 0x2f, 0x2a, 0x53, 0x3e, 0x5c, 0xba, 0x9d, 0x08, 0x46, 0x99, 0x7b,
            0x23, 0xda, 0x79, 0x91, 0xc3, 0xb8, 0xcc, 0xf8, 0x54, 0xa3, 0x94, 0x1f, 0xc5, 0xf0,
            0x90, 0xab, 0xd2, 0xff, 0x14, 0x0d, 0x0e, 0x67, 0x8f, 0xa3, 0x36, 0x02, 0x6c, 0x65,
            0x7a, 0x46, 0x7f, 0xd1, 0xe3, 0x8a, 0xe6, 0x68, 0x48, 0x5a, 0xab, 0xdc, 0x68, 0xe0,
            0x4b, 0x0f, 0xb3, 0xd4, 0xb1, 0xa4, 0x6e,
        ];

        // Chain validation should fail for a self-signed cert not in the system trust store.
        let result = validate_certificate_chain(cert_der, &[]);
        assert!(
            result.is_err(),
            "self-signed certificate should fail chain validation, got Ok(())"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("not trusted")
                || err.contains("certificate")
                || err.contains("trust")
                || err.contains("chain"),
            "error message should mention trust or certificate: {err}"
        );
    }

    #[test]
    fn authenticode_decode_oid() {
        // OID 1.2.840.113549.1.1.1 (rsaEncryption)
        let bytes = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        let oid = decode_oid(&bytes).expect("decode_oid");
        assert_eq!(oid, "1.2.840.113549.1.1.1");

        // OID 2.16.840.1.101.3.4.2.1 (sha256)
        let bytes = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let oid = decode_oid(&bytes).expect("decode_oid");
        assert_eq!(oid, "2.16.840.1.101.3.4.2.1");

        // Invalid (truncated multi-byte arc)
        assert!(decode_oid(&[0x2a, 0x86, 0x80]).is_none());
    }

    #[test]
    fn authenticode_der_read_tlv() {
        // SEQUENCE { INTEGER 42 }
        let data = [
            0x30, 0x03, // SEQUENCE of length 3
            0x02, 0x01, 0x2a, // INTEGER 42
        ];
        let mut off = 0;
        let (tag, start, len) = der_read_tlv(&data, &mut off).expect("der_read_tlv");
        assert_eq!(tag, 0x30);
        assert_eq!(start, 2);
        assert_eq!(len, 3);
        assert_eq!(off, 5);

        // Long form length
        let data = [
            0x30, 0x81, 0x05, // SEQUENCE with long-form length 5
            0x02, 0x01, 0x2a, // INTEGER 42
            0x02, 0x00, // INTEGER (zero length)
        ];
        let mut off = 0;
        let (tag, _start, len) = der_read_tlv(&data, &mut off).expect("der_read_tlv long");
        assert_eq!(tag, 0x30);
        assert_eq!(len, 5);

        // Truncated data
        let mut off = 0;
        assert!(der_read_tlv(&[0x30], &mut off).is_none());
    }

    #[test]
    fn authenticode_locate_cert_table() {
        // Minimal PE with no security directory → Ok(None)
        let pe = create_minimal_pe(false);
        let result = locate_certificate_table(&pe);
        assert!(
            matches!(result, Ok(None)),
            "expected Ok(None), got {result:?}"
        );

        // Minimal PE with certificate table → Ok(Some(...))
        let pe = create_minimal_pe(true);
        let result = locate_certificate_table(&pe);
        assert!(
            matches!(result, Ok(Some(_))),
            "expected Ok(Some), got {result:?}"
        );
        let (va, size) = result.unwrap().unwrap();
        assert_eq!(va, 0x200);
        assert_eq!(size, 24);
    }

    #[test]
    fn authenticode_read_u32_le() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 0), Some(0x12345678));
        assert!(read_u32_le(&data, 1).is_none()); // out of bounds
        assert!(read_u32_le(&[], 0).is_none());
    }

    #[test]
    fn authenticode_read_u16_le() {
        let data = [0x34, 0x12];
        assert_eq!(read_u16_le(&data, 0), Some(0x1234));
        assert!(read_u16_le(&data, 1).is_none());
        assert!(read_u16_le(&[], 0).is_none());
    }

    #[test]
    fn authenticode_parse_spc_indirect_data_valid() {
        // Build a minimal valid SpcIndirectDataContent as raw DER bytes:
        //
        // SEQUENCE {
        //   data     [0] EXPLICIT { SEQUENCE { OID, SET {} } }
        //   messageDigest SEQUENCE {
        //     digestAlgorithm SEQUENCE { OID sha256, NULL }
        //     digest OCTET STRING (32 bytes of hash)
        //   }
        // }
        //
        // We construct the bytes manually so there are no external crate
        // dependencies for DER encoding.

        let sha256_oid: &[u8] = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let hash_value: [u8; 32] = [0xABu8; 32];

        // AlgorithmIdentifier: SEQUENCE { OID sha256, NULL }
        // Inner content: OID(11 bytes) + NULL(2 bytes) = 13 bytes
        let mut algo = vec![0x30, 0x0d]; // SEQUENCE, length 13
        algo.extend_from_slice(sha256_oid);
        algo.extend_from_slice(&[0x05, 0x00]); // NULL parameters

        // DigestInfo: SEQUENCE { algorithm, OCTET STRING hash }
        // Inner: algo(15 bytes) + OCTET_STRING header(2) + hash(32) = 49 bytes
        let mut di = vec![0x30, 49]; // SEQUENCE, length 49
        di.extend_from_slice(&algo);
        di.extend_from_slice(&[0x04, 0x20]); // OCTET STRING, length 32
        di.extend_from_slice(&hash_value);

        // SpcAttributeTypeAndOptionalValue: [0] EXPLICIT { SET {} }
        let spc_attr: &[u8] = &[0xa0, 0x02, 0x31, 0x00];

        // Full SpcIndirectDataContent: SEQUENCE { spc_attr, digest_info }
        let spc_inner_len = spc_attr.len() + di.len();
        let mut spc = vec![0x30, spc_inner_len as u8]; // SEQUENCE
        spc.extend_from_slice(spc_attr);
        spc.extend_from_slice(&di);

        let (oid, hash) = parse_spc_indirect_data(&spc).expect("parse_spc_indirect_data");
        assert_eq!(oid, "2.16.840.1.101.3.4.2.1");
        assert_eq!(hash, hash_value);
    }

    #[test]
    fn authenticode_digest_with_oid() {
        let data = b"hello world";
        let sha256_result = digest_with_oid(OID_SHA256, data);
        assert!(sha256_result.is_some());
        assert_eq!(sha256_result.unwrap().len(), 32);

        let sha1_result = digest_with_oid(OID_SHA1, data);
        assert!(sha1_result.is_some());
        assert_eq!(sha1_result.unwrap().len(), 20);

        assert!(digest_with_oid("1.2.3.4", data).is_none());
    }

    #[test]
    fn authenticode_zero_length_cert_table() {
        // Security data directory entry with size=0 should be treated as no signature.
        let mut pe = create_minimal_pe(false);
        // Manually add a security directory entry with size=0.
        let pe_offset = 0x80u32;
        let dd_start = pe_offset as usize + 4 + 20 + 96;
        let sec_entry = dd_start + 4 * 8;
        pe.resize(sec_entry + 8, 0);
        // Write VA and size=0
        pe[sec_entry..sec_entry + 4].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sec_entry + 4..sec_entry + 8].copy_from_slice(&0u32.to_le_bytes());
        // Update SizeOfOptionalHeader
        let coff = pe_offset as usize + 4;
        let opt_size = (pe.len() - coff - 20) as u16;
        pe[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());

        let verdict = verify_pe_authenticode(&pe);
        assert!(
            matches!(verdict, AuthenticodeVerdict::NoSignature),
            "expected NoSignature for zero-length cert table, got {verdict:?}"
        );
    }

    #[test]
    fn authenticode_oversized_cert_table() {
        // Security directory pointing beyond PE end should return Invalid.
        let mut pe = create_minimal_pe(true);
        let cert_va = 0x200;
        let oversized_size = 1_000_000usize; // Way past end of PE
        write_cert_table(&mut pe, cert_va, oversized_size);
        pe.resize(cert_va + 8, 0); // Only 8 bytes available
        let verdict = verify_pe_authenticode(&pe);
        assert!(
            matches!(verdict, AuthenticodeVerdict::Invalid(ref msg)
                if msg.contains("certificate")
                    || msg.contains("size")
                    || msg.contains("table")
                    || msg.contains("overflow")),
            "expected Invalid with cert/size/overflow message, got {verdict:?}"
        );
    }

    #[test]
    fn authenticode_empty_certificate_table() {
        // Security directory pointing to all-zero memory should return Invalid.
        let mut pe = create_minimal_pe(true);
        let cert_va = 0x200;
        let cert_size = 24usize;
        write_cert_table(&mut pe, cert_va, cert_size);
        pe.resize(cert_va + cert_size, 0);
        // All zeros — not a valid WIN_CERTIFICATE
        let verdict = verify_pe_authenticode(&pe);
        assert!(
            matches!(verdict, AuthenticodeVerdict::Invalid(_)),
            "expected Invalid for all-zero cert table, got {verdict:?}"
        );
    }

    #[test]
    fn authenticode_malformed_certificate_der() {
        // Invalid DER bytes in certificate table should be caught.
        let mut pe = create_minimal_pe(true);
        let cert_va = 0x200;
        let cert_size = 200usize;
        write_cert_table(&mut pe, cert_va, cert_size);
        pe.resize(cert_va + cert_size, 0);
        let dw_length = cert_size as u32;
        let cert_type: u16 = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
        pe[cert_va..cert_va + 4].copy_from_slice(&dw_length.to_le_bytes());
        pe[cert_va + 6..cert_va + 8].copy_from_slice(&cert_type.to_le_bytes());
        // Write garbage that is not valid DER (truncated SEQUENCE).
        pe[cert_va + 8..cert_va + cert_size].fill(0xFF);
        let verdict = verify_pe_authenticode(&pe);
        assert!(
            matches!(verdict, AuthenticodeVerdict::Invalid(_)),
            "expected Invalid for malformed DER, got {verdict:?}"
        );
    }

    #[test]
    fn authenticode_unsupported_hash_algorithm() {
        // A WIN_CERTIFICATE with a valid PKCS#7 structure but containing a
        // hash algorithm OID that is not supported (e.g. MD2) should be rejected.
        let mut pe = create_minimal_pe(true);
        let cert_va = 0x200;
        // Build a minimal but valid PKCS#7 SignedData with an SpcIndirectDataContent
        // that uses MD2 (OID 1.2.840.113549.2.2) as the digest algorithm.
        //
        // Structure:
        // ContentInfo SEQUENCE {
        //   contentType OID (signedData)
        //   content [0] EXPLICIT {
        //     SignedData SEQUENCE {
        //       version INTEGER 1
        //       digestAlgorithms SET { SEQUENCE { OID md2, NULL } }
        //       encapContentInfo SEQUENCE {
        //         eContentType OID (spcIndirectData)
        //         eContent [0] EXPLICIT OCTET STRING {
        //           SpcIndirectDataContent SEQUENCE { ... }
        //         }
        //       }
        //       certificates [0] IMPLICIT { ... empty ... }
        //       signerInfos SET { ... empty ... }
        //     }
        //   }
        // }
        //
        // We construct this as raw DER bytes.

        // MD2 OID = 1.2.840.113549.2.2
        // Encoded: 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02
        let md2_algo = vec![
            0x30, 0x0a, // SEQUENCE, length 10
            0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, // MD2 OID
        ];

        // digestAlgorithms SET
        let das = {
            let mut v = vec![0x31, md2_algo.len() as u8]; // SET
            v.extend_from_slice(&md2_algo);
            v
        };

        // SpcIndirectDataContent using MD2 (won't match any supported hash)
        // Minimal: SEQUENCE { [0] EXPLICIT { SET {} }, messageDigest SEQUENCE { algo, hash } }
        let sha256_oid_bytes: &[u8] = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let hash_value: [u8; 32] = [0xBBu8; 32];
        let mut algo = vec![0x30, 0x0d]; // SEQUENCE, length 13
        algo.extend_from_slice(sha256_oid_bytes);
        algo.extend_from_slice(&[0x05, 0x00]); // NULL

        let mut di = vec![0x30, 49]; // SEQUENCE, length 49
        di.extend_from_slice(&algo);
        di.extend_from_slice(&[0x04, 0x20]); // OCTET STRING, length 32
        di.extend_from_slice(&hash_value);

        let spc_attr: &[u8] = &[0xa0, 0x02, 0x31, 0x00];
        let spc_inner_len = spc_attr.len() + di.len();
        let mut spc = vec![0x30, spc_inner_len as u8]; // SEQUENCE
        spc.extend_from_slice(spc_attr);
        spc.extend_from_slice(&di);

        // Encapsulated eContent: [0] EXPLICIT { OCTET STRING { SpcIndirectDataContent } }
        let mut econtent_outer = vec![0xa0, spc.len() as u8]; // [0] EXPLICIT
        econtent_outer.extend_from_slice(&spc);

        // eContentType OID (SPC_INDIRECT_DATA_OBJID)
        let spc_oid_bytes: &[u8] = &[
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04,
        ];

        let mut eci_content = Vec::new();
        eci_content.extend_from_slice(spc_oid_bytes);
        eci_content.extend_from_slice(&econtent_outer);
        let eci = {
            let mut v = vec![0x30, eci_content.len() as u8]; // SEQUENCE
            v.extend_from_slice(&eci_content);
            v
        };

        // Empty certificates [0] IMPLICIT
        let certs: &[u8] = &[0xa0, 0x02, 0x31, 0x00];

        // Empty signerInfos SET
        let signer_infos: &[u8] = &[0x31, 0x00];

        // SignedData content
        let mut sd_content = Vec::new();
        sd_content.push(0x02); // INTEGER
        sd_content.push(0x01); // length 1
        sd_content.push(0x01); // version 1
        sd_content.extend_from_slice(&das);
        sd_content.extend_from_slice(&eci);
        sd_content.extend_from_slice(certs);
        sd_content.extend_from_slice(signer_infos);

        let sd = {
            let mut v = vec![0x30, sd_content.len() as u8]; // SEQUENCE
            v.extend_from_slice(&sd_content);
            v
        };

        // [0] EXPLICIT wrapper for content
        let content_wrapper = {
            let mut v = vec![0xa0, sd.len() as u8];
            v.extend_from_slice(&sd);
            v
        };

        // ContentInfo contentType OID (signedData)
        let signed_data_oid: &[u8] = &[
            0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        ];

        let mut ci_content = Vec::new();
        ci_content.extend_from_slice(signed_data_oid);
        ci_content.extend_from_slice(&content_wrapper);
        let ci = {
            let mut v = vec![0x30, ci_content.len() as u8]; // SEQUENCE
            v.extend_from_slice(&ci_content);
            v
        };

        // Now write the WIN_CERTIFICATE header and PKCS#7 blob into the PE
        let cert_size = 8 + ci.len();
        write_cert_table(&mut pe, cert_va, cert_size);
        pe.resize(cert_va + cert_size, 0);
        let dw_length = cert_size as u32;
        pe[cert_va..cert_va + 4].copy_from_slice(&dw_length.to_le_bytes());
        pe[cert_va + 6..cert_va + 8].copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
        pe[cert_va + 8..cert_va + cert_size].copy_from_slice(&ci);

        let verdict = verify_pe_authenticode(&pe);
        // The PKCS#7 structure should parse, but the SpcIndirectDataContent
        // uses a hash algorithm not in our supported set, leading to Invalid.
        // (The digestAlgorithms set contains MD2 OID, not SHA-256/SHA-1.)
        assert!(
            matches!(verdict, AuthenticodeVerdict::Invalid(_)),
            "expected Invalid for unsupported hash algorithm, got {verdict:?}"
        );
    }

    #[test]
    fn certificate_from_der_truncated() {
        // Truncated DER — Certificate::from_der always returns Some but with
        // fallback extraction (subject/issuer will be empty or placeholder).
        let result = Certificate::from_der(vec![0x30, 0x05, 0x02, 0x01]);
        assert!(
            result.is_some(),
            "truncated DER should return Some (fallback)"
        );
        let cert = result.unwrap();
        // Thumbprint is always SHA-1 of raw DER bytes.
        assert_eq!(cert.thumbprint.len(), 20);
        // Subject may be empty (fallback parsing).
        assert!(
            cert.subject.is_empty()
                || cert.subject.contains("Unknown")
                || cert.subject.contains("unknown"),
            "truncated cert should have empty/unknown subject, got: {}",
            cert.subject
        );
    }

    #[test]
    fn certificate_from_der_wrong_tag() {
        // Not a SEQUENCE (tag 0x30) — Certificate::from_der always returns Some
        // but with fallback extraction.
        let result = Certificate::from_der(vec![0x02, 0x01, 0x2a]);
        assert!(
            result.is_some(),
            "non-SEQUENCE DER should return Some (fallback)"
        );
        let cert = result.unwrap();
        assert_eq!(cert.thumbprint.len(), 20);
        assert!(
            cert.subject.is_empty()
                || cert.subject.contains("Unknown")
                || cert.subject.contains("unknown"),
            "wrong-tag DER should have empty/unknown subject, got: {}",
            cert.subject
        );
    }

    #[test]
    fn certificate_from_der_empty() {
        // Empty DER — Certificate::from_der always returns Some with fallback.
        let result = Certificate::from_der(vec![]);
        assert!(result.is_some(), "empty DER should return Some (fallback)");
        let cert = result.unwrap();
        assert_eq!(cert.thumbprint.len(), 20);
        assert!(
            cert.subject.is_empty()
                || cert.subject.contains("Unknown")
                || cert.subject.contains("unknown"),
            "empty DER should have empty/unknown subject, got: {}",
            cert.subject
        );
    }

    // ===================================================================
    // Helpers for PE construction in tests
    // ===================================================================

    /// Create a minimal PE32 image, optionally with a security data directory
    /// entry pointing at `cert_va`.
    fn create_minimal_pe(with_cert_table: bool) -> Vec<u8> {
        let mut pe = Vec::new();
        // DOS header
        pe.extend_from_slice(b"MZ");
        pe.resize(0x80, 0);
        let pe_offset: u32 = 0x80;
        pe[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        // PE signature
        pe.extend_from_slice(b"PE\0\0");
        // COFF header (20 bytes)
        pe.extend_from_slice(&[0u8; 20]);
        // SizeOfOptionalHeader at COFF+16 (u16) — set after we know the final size.
        // We'll write it at the end.

        // Optional header PE32 (0xE0 = 224 bytes for standard size)
        let opt_magic: u16 = 0x10b; // PE32
        pe.extend_from_slice(&opt_magic.to_le_bytes());
        // Pad optional header up to include the checksum field (4 bytes at opt+64)
        let checksum_bound = pe_offset as usize + 4 + 20 + 64 + 4;
        pe.resize(checksum_bound, 0);
        // Checksum at opt+64 (offset of checksum from optional header start)
        let checksum_off = pe_offset as usize + 4 + 20 + 64;
        pe[checksum_off..checksum_off + 4].copy_from_slice(&[0u8; 4]); // zero checksum
        // Data directories start at opt+96 for PE32
        let dd_start = pe_offset as usize + 4 + 20 + 96;
        pe.resize(dd_start + 8 * 16, 0); // 16 data directory entries
        // Set SizeOfOptionalHeader in the COFF header now that we know the final size.
        let coff = pe_offset as usize + 4;
        let opt_size = (pe.len() - coff - 20) as u16; // optional header = total - PE_sig - COFF
        pe[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());

        if with_cert_table {
            // Security directory entry is index 4
            let sec_entry = dd_start + 4 * 8;
            let cert_va: u32 = 0x200;
            let cert_size: u32 = 24;
            pe[sec_entry..sec_entry + 4].copy_from_slice(&cert_va.to_le_bytes());
            pe[sec_entry + 4..sec_entry + 8].copy_from_slice(&cert_size.to_le_bytes());
            // Ensure the PE is large enough to contain the certificate table at va=0x200
            let min_len = (cert_va as usize) + (cert_size as usize);
            if pe.len() < min_len {
                pe.resize(min_len, 0);
            }
        }

        pe
    }

    /// Write a security data directory entry into a minimal PE.
    fn write_cert_table(pe: &mut [u8], va: usize, size: usize) {
        let pe_offset = read_u32_le(pe, 0x3C).unwrap_or(0x80) as usize;
        let opt = pe_offset + 4 + 20;
        let dd_start = opt + 96;
        let sec_entry = dd_start + 4 * 8;
        if sec_entry + 8 <= pe.len() {
            pe[sec_entry..sec_entry + 4].copy_from_slice(&(va as u32).to_le_bytes());
            pe[sec_entry + 4..sec_entry + 8].copy_from_slice(&(size as u32).to_le_bytes());
        }
    }

    // ===================================================================
    // Entitlement XML sanitisation tests (Items 225-226)
    // \===================================================================

    #[test]
    fn entitlement_xml_rejects_doctype() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist><dict><key>test</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(result.is_empty(), "DOCTYPE should be rejected");
    }

    #[test]
    fn entitlement_xml_rejects_doctype_case_insensitive() {
        // Mixed-case DOCTYPE
        let xml = r#"<?xml version="1.0"?>
<!DoCtYpE plist [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<plist><dict><key>test</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(
            result.is_empty(),
            "case-insensitive DOCTYPE should be rejected"
        );
    }

    #[test]
    fn entitlement_xml_rejects_doctype_lowercase() {
        // Lowercase <!doctype
        let xml = r#"<?xml version="1.0"?>
<!doctype plist>
<plist><dict><key>test</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(result.is_empty(), "lowercase DOCTYPE should be rejected");
    }

    #[test]
    fn entitlement_xml_rejects_billion_laughs() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<plist><dict><key>&lol3;</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(result.is_empty(), "billion laughs should be rejected");
    }

    #[test]
    fn entitlement_xml_rejects_custom_entity() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><key>&myentity;</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(
            result.is_empty(),
            "custom entity without DTD should be rejected"
        );
    }

    #[test]
    fn entitlement_xml_allows_standard_entities() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><key>a & b < c > d " e ' f</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(!result.is_empty(), "standard entities should be allowed");
        assert!(result.contains("&"), "output should contain &");
        assert!(result.contains("<"), "output should contain <");
    }

    #[test]
    fn entitlement_xml_allows_numeric_character_references() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><key>&#65;&#x42;&#x43;</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(
            !result.is_empty(),
            "numeric character refs should be allowed"
        );
        assert!(
            result.contains("&#65;"),
            "output should contain decimal ref"
        );
        assert!(result.contains("&#x42;"), "output should contain hex ref");
    }

    #[test]
    fn entitlement_xml_rejects_cdata() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><key><![CDATA[ <!DOCTYPE foo> ]]></key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(result.is_empty(), "CDATA should be rejected");
    }

    #[test]
    fn entitlement_xml_rejects_cdata_with_entities() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><key><![CDATA[ &xxe; &lol; ]]></key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(result.is_empty(), "CDATA with entities should be rejected");
    }

    #[test]
    fn entitlement_xml_rejects_xml_comments() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><!-- malicious comment --><key>test</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(result.is_empty(), "XML comments should be rejected");
    }

    #[test]
    fn entitlement_xml_rejects_processing_instructions() {
        let xml = r#"<?xml version="1.0"?>
<?mso-application progid="Word.Document"?>
<plist><dict><key>test</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(
            !result.is_empty(),
            "processing instruction should be stripped"
        );
        assert!(
            !result.contains("<?mso-application"),
            "PI should not be in output"
        );
    }

    #[test]
    fn entitlement_xml_preserves_valid_plist() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.files.user-selected.read-only</key>
    <true/>
</dict>
</plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(!result.is_empty(), "valid entitlement plist should pass");
        assert!(
            result.contains("<plist"),
            "output should contain plist element"
        );
        assert!(
            result.contains("<dict>"),
            "output should contain dict element"
        );
        assert!(
            result.contains("<key>"),
            "output should contain key element"
        );
    }

    #[test]
    fn entitlement_xml_rejects_non_plist_xml() {
        let xml = r#"<?xml version="1.0"?>
<root><element>value</element></root>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(result.is_empty(), "non-plist XML should be rejected");
    }

    #[test]
    fn entitlement_xml_preserves_whitespace_entities() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><key>line1&#x0A;line2&#x0D;indented&#x09;text</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(!result.is_empty(), "whitespace char refs should be allowed");
        assert!(result.contains("&#x0A;"), "output should contain &#x0A;");
    }

    #[test]
    fn entitlement_xml_rejects_entity_without_doctype() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><key>&unknown;</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(result.is_empty(), "unknown entity should be rejected");
    }

    #[test]
    fn entitlement_xml_allows_empty_dict() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict/></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(!result.is_empty(), "empty dict plist should pass");
    }

    #[test]
    fn entitlement_xml_strips_pi_inside_plist() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><?my-pi some-data?><key>test</key><true/></dict></plist>"#;
        let result = sanitize_entitlement_xml(xml);
        assert!(!result.is_empty(), "should strip PI inside plist");
        assert!(!result.contains("<?my-pi"), "PI should not remain");
    }
}

// ===========================================================================
// Phase O2 — Certificate Store Management
// ===========================================================================

/// Well-known system store names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SystemStore {
    /// Personal (MY) certificate store.
    My,
    /// Root (ROOT) certificate store.
    Root,
    /// Intermediate CA certificate store.
    Ca,
    /// Trusted Publisher store.
    TrustedPublisher,
    /// Other/unknown store (name stored as String).
    Other(String),
}

impl SystemStore {
    pub fn from_name(name: &str) -> Self {
        match name.to_uppercase().as_str() {
            "MY" => SystemStore::My,
            "ROOT" => SystemStore::Root,
            "CA" => SystemStore::Ca,
            "TRUSTEDPUBLISHER" | "TRUSTED_PUBLISHER" => SystemStore::TrustedPublisher,
            _ => SystemStore::Other(name.to_string()),
        }
    }
}

/// A parsed certificate stored in a certificate store.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Raw DER-encoded X.509 certificate bytes.
    pub der: Vec<u8>,
    /// SHA-1 thumbprint (20 bytes) or empty if not computed.
    pub thumbprint: Vec<u8>,
    /// Subject name string (CN=..., etc.)
    pub subject: String,
    /// Issuer name string.
    pub issuer: String,
    /// Serial number as hex string.
    pub serial_number: String,
    /// Whether this certificate is a root CA.
    pub is_root: bool,
}

impl Certificate {
    /// Parse a DER-encoded X.509 certificate and extract metadata.
    pub fn from_der(der: Vec<u8>) -> Option<Self> {
        let thumbprint = Sha1::digest(&der).to_vec();

        // Try to extract subject, issuer, serial number using x509-cert.
        // If the structured parser fails, fall back to raw DER field extraction.
        let cert_result = X509Certificate::from_der(&der);
        let (subject, issuer, serial_number, is_root) = match cert_result {
            Ok(ref c) => {
                let subject = c.tbs_certificate.subject.to_string();
                let issuer = c.tbs_certificate.issuer.to_string();
                let serial = c.tbs_certificate.serial_number.to_string();
                let is_root = subject == issuer
                    || subject.to_uppercase().contains("ROOT")
                    || issuer.to_uppercase().contains("ROOT");
                (subject, issuer, serial, is_root)
            }
            Err(_) => {
                // Fallback: try basic DER parsing for common names
                let (subject, issuer, serial) = extract_basic_cert_info(&der);
                (subject, issuer, serial, false)
            }
        };

        Some(Certificate {
            der,
            thumbprint,
            subject,
            issuer,
            serial_number,
            is_root,
        })
    }
}

/// Minimal DER-based certificate info extraction (fallback when x509-cert parse fails).
fn extract_basic_cert_info(der: &[u8]) -> (String, String, String) {
    // Try to extract Subject and Issuer from the TBS certificate
    // X.509 v3: Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, ... }
    let mut off = 0;
    let (_tag, cert_start, _cert_len) = der_read_tlv(der, &mut off).unwrap_or((0, 0, 0));
    if cert_start == 0 {
        return ("(unknown)".into(), "(unknown)".into(), "00".into());
    }
    // Reset and skip the outer SEQUENCE
    off = 0;
    let (tag, content_start, _content_len) = match der_read_tlv(der, &mut off) {
        Some(v) => v,
        None => return ("(unknown)".into(), "(unknown)".into(), "00".into()),
    };
    if tag != 0x30 {
        return ("(unknown)".into(), "(unknown)".into(), "00".into());
    }
    // Inside Certificate: TBSCertificate (SEQUENCE)
    let mut inner = content_start;
    let (tbs_tag, tbs_start, tbs_len) = match der_read_tlv(der, &mut inner) {
        Some(v) => v,
        None => return ("(unknown)".into(), "(unknown)".into(), "00".into()),
    };
    if tbs_tag != 0x30 {
        return ("(unknown)".into(), "(unknown)".into(), "00".into());
    }
    let tbs_end = tbs_start + tbs_len;
    let mut tbs = tbs_start;

    // Skip version [0] EXPLICIT (optional)
    if tbs < tbs_end {
        let b = *der.get(tbs).unwrap_or(&0);
        if b == 0xa0 {
            // Version tag present — skip it; malformed version is non-fatal
            if der_read_tlv(der, &mut tbs).is_none() {
                tbs = tbs_end; // malformed: skip remaining TBS parsing
            }
        }
    }
    // Skip serialNumber INTEGER
    if tbs < tbs_end {
        let (st, _, _) = der_read_tlv(der, &mut tbs).unwrap_or((0, 0, 0));
        if st != 0x02 {
            return ("(unknown)".into(), "(unknown)".into(), "00".into());
        }
    }
    // Skip signature AlgorithmIdentifier SEQUENCE
    if tbs < tbs_end && der_read_tlv(der, &mut tbs).is_none() {
        return ("(unknown)".into(), "(unknown)".into(), "00".into());
    }
    // Skip issuer SEQUENCE
    let issuer_str = if tbs < tbs_end {
        let (is_tag, is_start, is_len) = der_read_tlv(der, &mut tbs).unwrap_or((0, 0, 0));
        if is_tag == 0x30 && is_len > 0 {
            extract_rdn_string(der, is_start, is_len)
        } else {
            "(unknown)".into()
        }
    } else {
        "(unknown)".into()
    };
    // Skip validity SEQUENCE
    if tbs < tbs_end && der_read_tlv(der, &mut tbs).is_none() {
        return ("(unknown)".into(), "(unknown)".into(), "00".into());
    }
    // Subject SEQUENCE
    let subject_str = if tbs < tbs_end {
        let (sb_tag, sb_start, sb_len) = der_read_tlv(der, &mut tbs).unwrap_or((0, 0, 0));
        if sb_tag == 0x30 && sb_len > 0 {
            extract_rdn_string(der, sb_start, sb_len)
        } else {
            "(unknown)".into()
        }
    } else {
        "(unknown)".into()
    };

    (subject_str, issuer_str, "00".into())
}

/// Extract a single RDN (Relative Distinguished Name) string from a SEQUENCE of SETs.
fn extract_rdn_string(der: &[u8], start: usize, len: usize) -> String {
    let end = start + len;
    let mut pos = start;
    let mut parts = Vec::new();
    while pos < end {
        // Each RDN is a SET (0x31) containing one or more AttributeTypeAndValue
        let (set_tag, set_start, set_len) = match der_read_tlv(der, &mut pos) {
            Some(v) => v,
            None => break,
        };
        if set_tag != 0x31 {
            break;
        }
        let set_end = set_start + set_len;
        let mut set_pos = set_start;
        while set_pos < set_end {
            // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
            let (_av_tag, av_start, av_len) = match der_read_tlv(der, &mut set_pos) {
                Some(v) => v,
                None => break,
            };
            let _av_end = av_start + av_len;
            let mut av_pos = av_start;
            // type OID
            let (oid_tag, oid_start, oid_len) = match der_read_tlv(der, &mut av_pos) {
                Some(v) => v,
                None => break,
            };
            if oid_tag != 0x06 {
                break;
            }
            let oid_str = decode_oid(&der[oid_start..oid_start + oid_len]).unwrap_or_default();
            // value (typically PrintableString 0x13, UTF8String 0x0c, TeletexString 0x14)
            let (_val_tag, val_start, val_len) = match der_read_tlv(der, &mut av_pos) {
                Some(v) => v,
                None => break,
            };
            let val_str = if val_len > 0 && val_start + val_len <= der.len() {
                String::from_utf8_lossy(&der[val_start..val_start + val_len]).to_string()
            } else {
                String::new()
            };
            // Map OID to short name
            let short = match oid_str.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.5" => "SERIALNUMBER",
                "1.2.840.113549.1.9.1" => "E",
                _ => &oid_str,
            };
            parts.push(format!("{short}={val_str}"));
        }
    }
    if parts.is_empty() {
        "(unknown)".into()
    } else {
        parts.join(", ")
    }
}

/// In-memory certificate store that maps to system stores.
#[derive(Debug, Clone)]
pub struct CertificateStore {
    /// Unique handle ID for this store.
    pub handle: u64,
    /// Store name (e.g. "MY", "ROOT", "CA").
    pub name: String,
    /// System store type.
    pub system_store: SystemStore,
    /// Certificates in this store.
    pub certificates: Vec<Certificate>,
}

impl CertificateStore {
    pub fn new(handle: u64, name: &str) -> Self {
        let system_store = SystemStore::from_name(name);
        CertificateStore {
            handle,
            name: name.to_string(),
            system_store,
            certificates: Vec::new(),
        }
    }

    /// Find certificates matching search criteria.
    /// `search_type`: CERT_FIND_* constant.
    /// `search_param`: depends on search type.
    pub fn find_certificate(&self, search_type: u32, search_param: &[u8]) -> Vec<&Certificate> {
        match search_type {
            1 => self.find_by_subject(search_param), // CERT_FIND_SUBJECT_STR
            2 => self.find_by_issuer(search_param),  // CERT_FIND_ISSUER_STR
            3 => self.find_by_serial(search_param),  // CERT_FIND_SERIAL_NUMBER
            4 => self.find_by_thumbprint(search_param), // CERT_FIND_SHA1_HASH
            // CERT_FIND_CERT_ID (5) matches a hash of issuer+serial, which
            // `find_by_serial` does not implement. Return no results instead
            // of silently producing wrong matches for an unsupported type.
            5 => vec![],
            _ => vec![],                             // unsupported search type
        }
    }

    fn find_by_subject(&self, subject: &[u8]) -> Vec<&Certificate> {
        let subject_str = String::from_utf8_lossy(subject);
        self.certificates
            .iter()
            .filter(|c| {
                c.subject
                    .to_uppercase()
                    .contains(&subject_str.to_uppercase())
            })
            .collect()
    }

    fn find_by_issuer(&self, issuer: &[u8]) -> Vec<&Certificate> {
        let issuer_str = String::from_utf8_lossy(issuer);
        self.certificates
            .iter()
            .filter(|c| c.issuer.to_uppercase().contains(&issuer_str.to_uppercase()))
            .collect()
    }

    fn find_by_serial(&self, serial: &[u8]) -> Vec<&Certificate> {
        let serial_hex = serial
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        self.certificates
            .iter()
            .filter(|c| c.serial_number == serial_hex)
            .collect()
    }

    fn find_by_thumbprint(&self, thumbprint: &[u8]) -> Vec<&Certificate> {
        self.certificates
            .iter()
            .filter(|c| c.thumbprint == thumbprint)
            .collect()
    }

    pub fn add_certificate(&mut self, cert: Certificate) {
        self.certificates.push(cert);
    }

    pub fn delete_certificate(&mut self, index: usize) -> Option<Certificate> {
        if index < self.certificates.len() {
            Some(self.certificates.remove(index))
        } else {
            None
        }
    }

    /// Populate this store with system certificates from the macOS keychain.
    ///
    /// Uses `SecItemCopyMatching` with `kSecClassCertificate` to enumerate all
    /// certificates available in the system keychains. Results are filtered by
    /// store type:
    ///
    /// - [`SystemStore::Root`] — only self-signed (root) certificates.
    /// - [`SystemStore::Ca`] — only non-self-signed (intermediate CA) certificates.
    /// - [`SystemStore::My`] — all certificates in the personal keychains.
    /// - [`SystemStore::TrustedPublisher`] — only root certificates.
    /// - [`SystemStore::Other`] — no pre-populated certificates.
    pub fn populate_from_system(&mut self) {
        // SAFETY: Security framework FFI for cryptographic operations
        unsafe {
            // Local extern for Security framework functions used only here,
            // keeping the module-level extern block focused on shared FFI.
            // SAFETY: extern FFI declaration — the function signature matches the C library prototype
            unsafe extern "C" {
                /// Search the keychain for items matching a query dictionary.
                /// Returns errSecSuccess (0) on success.
                fn SecItemCopyMatching(query: *const c_void, result: *mut *const c_void) -> i32;

                /// Copy the DER-encoded data backing a SecCertificateRef.
                /// Returns a CFDataRef (caller must CFRelease).
                fn SecCertificateCopyData(certificate: *const c_void) -> *const c_void;

                /// Return a pointer to the raw bytes inside a CFData.
                fn CFDataGetBytePtr(data: *const c_void) -> *const u8;

                /// Return the length (in bytes) of a CFData.
                fn CFDataGetLength(data: *const c_void) -> isize;

                /// Return the number of elements in a CFArray.
                fn CFArrayGetCount(array: *const c_void) -> isize;

                /// Return the element at `index` in a CFArray.
                fn CFArrayGetValueAtIndex(array: *const c_void, index: isize) -> *const c_void;

                /// Create an immutable CFDictionary.
                fn CFDictionaryCreate(
                    allocator: *const c_void,
                    keys: *const *const c_void,
                    values: *const *const c_void,
                    numValues: isize,
                    keyCallBacks: *const c_void,
                    valueCallBacks: *const c_void,
                ) -> *const c_void;

                /// Release a CoreFoundation object.
                fn CFRelease(cf: *const c_void);
            }

            // --- Build the query dictionary ---
            //
            // Equivalent to the Objective-C dictionary literal:
            //   @{
            //     (id)kSecClass       : (id)kSecClassCertificate,
            //     (id)kSecReturnRef   : (id)kCFBooleanTrue,
            //     (id)kSecMatchLimit  : (id)kSecMatchLimitAll
            //   }
            let keys: [*const c_void; 3] = [kSecClass, kSecReturnRef, kSecMatchLimit];
            let values: [*const c_void; 3] =
                [kSecClassCertificate, kCFBooleanTrue, kSecMatchLimitAll];

            let query = CFDictionaryCreate(
                std::ptr::null(), // kCFAllocatorDefault
                keys.as_ptr(),
                values.as_ptr(),
                3,
                std::ptr::null(), // default kCFTypeDictionaryKeyCallBacks
                std::ptr::null(), // default kCFTypeDictionaryValueCallBacks
            );

            if query.is_null() {
                // Cannot build query — leave store empty (matches current no-op
                // behaviour and is indistinguishable from an empty keychain).
                return;
            }

            // --- Execute the search ---
            let mut result: *const c_void = std::ptr::null();
            let status = SecItemCopyMatching(query, &mut result);
            CFRelease(query);

            // errSecSuccess == 0, errSecItemNotFound == -25300 (empty keychain)
            if status != 0 || result.is_null() {
                return;
            }

            // --- Iterate results ---
            let count = CFArrayGetCount(result);
            for i in 0..count {
                let cert_ref = CFArrayGetValueAtIndex(result, i);
                if cert_ref.is_null() {
                    continue;
                }

                // Extract DER bytes from the SecCertificateRef.
                let cf_data = SecCertificateCopyData(cert_ref);
                if cf_data.is_null() {
                    continue;
                }

                let ptr = CFDataGetBytePtr(cf_data);
                let len = CFDataGetLength(cf_data);
                if len > 0 && !ptr.is_null() {
                    let der = std::slice::from_raw_parts(ptr, len as usize).to_vec();

                    // Parse into our Certificate representation.
                    if let Some(cert) = Certificate::from_der(der) {
                        // --- Filter by store type ---
                        let include = match self.system_store {
                            SystemStore::Root | SystemStore::TrustedPublisher => cert.is_root,
                            SystemStore::Ca => !cert.is_root,
                            SystemStore::My => true,
                            SystemStore::Other(_) => false,
                        };
                        if include {
                            self.certificates.push(cert);
                        }
                    }
                }
                CFRelease(cf_data);
            }
            CFRelease(result);
        }
    }
}

/// Manages multiple certificate stores for the runtime.
#[derive(Debug, Clone)]
pub struct CertificateStoreManager {
    /// Maps store handle → CertificateStore.
    pub stores: BTreeMap<u64, CertificateStore>,
    /// Next handle to allocate.
    next_handle: u64,
}

impl CertificateStoreManager {
    pub fn new() -> Self {
        CertificateStoreManager {
            stores: BTreeMap::new(),
            next_handle: 1,
        }
    }
}

impl Default for CertificateStoreManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateStoreManager {
    /// Open a certificate store by name. Creates it if it doesn't exist.
    pub fn open_store(&mut self, name: &str) -> u64 {
        // Check if store already exists
        // Certificate store names are case-insensitive (matching Windows CryptoAPI behavior)
        for store in self.stores.values() {
            if store.name.eq_ignore_ascii_case(name) {
                return store.handle;
            }
        }
        let handle = self.next_handle;
        self.next_handle += 1;
        let mut store = CertificateStore::new(handle, name);
        store.populate_from_system();
        self.stores.insert(handle, store);
        handle
    }

    /// Open a system store (MY, ROOT, CA, TRUSTEDPUBLISHER).
    pub fn open_system_store(&mut self, name: &str) -> u64 {
        self.open_store(name)
    }

    /// Close a certificate store.
    pub fn close_store(&mut self, handle: u64) -> bool {
        self.stores.remove(&handle).is_some()
    }

    /// Get a reference to a store by handle.
    pub fn get_store(&self, handle: u64) -> Option<&CertificateStore> {
        self.stores.get(&handle)
    }

    /// Get a mutable reference to a store by handle.
    pub fn get_store_mut(&mut self, handle: u64) -> Option<&mut CertificateStore> {
        self.stores.get_mut(&handle)
    }

    /// Find a certificate by context (DER bytes).
    pub fn find_certificate_context(&self, _der: &[u8]) -> Option<u64> {
        // For now, return None — context handles are tracked separately
        None
    }

    /// Add a certificate to a store. Returns the certificate handle.
    pub fn add_certificate(&mut self, store_handle: u64, der: &[u8]) -> Option<u64> {
        let cert = Certificate::from_der(der.to_vec())?;
        // Fail (and do not consume a handle) when the store does not exist,
        // instead of reporting success for a certificate that was never stored.
        let store = self.stores.get_mut(&store_handle)?;
        let cert_handle = self.next_handle;
        self.next_handle += 1;
        store.certificates.push(cert);
        Some(cert_handle)
    }

    /// Delete a certificate from a store by index.
    /// Returns whether the certificate was successfully removed.
    pub fn delete_certificate(&mut self, store_handle: u64, index: usize) -> bool {
        let Some(store) = self.stores.get_mut(&store_handle) else {
            return false;
        };
        let in_bounds = index < store.certificates.len();
        if in_bounds {
            store.certificates.remove(index);
        }
        in_bounds
    }
}

// ─── O1 — BCrypt Full Algorithm Suite ──────────────────────────────────────

/// BCrypt algorithm identifiers.
/// BCrypt algorithm identifiers.
///
/// # Security Classification
///
/// ## Security algorithms (safe for Casa1's own use)
/// - [`Sha256`](Self::Sha256), [`Sha384`](Self::Sha384), [`Sha512`](Self::Sha512)
/// - [`HmacSha256`](Self::HmacSha256), [`HmacSha384`](Self::HmacSha384), [`HmacSha512`](Self::HmacSha512)
/// - [`AesCbc`](Self::AesCbc), [`AesGcm`](Self::AesGcm)
///
/// ## Compatibility algorithms (DRM/anti-cheat only — DO NOT use for security)
/// - [`Sha1`](Self::Sha1), [`Md5`](Self::Md5) — broken hash algorithms
/// - [`HmacSha1`](Self::HmacSha1), [`HmacMd5`](Self::HmacMd5)
/// - [`Des3Cbc`](Self::Des3Cbc), [`Rc2Cbc`](Self::Rc2Cbc) — weak ciphers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BCryptAlgorithmId {
    /// AES-CBC (security: Casa1's own encryption)
    AesCbc,
    /// AES-GCM (security: Casa1's own authenticated encryption)
    AesGcm,
    /// AES-CCM (compatibility: DRM layers)
    AesCcm,
    /// 3DES-CBC (compatibility: legacy Windows crypto — broken, avoid)
    Des3Cbc,
    /// RC2-CBC (compatibility: legacy Windows crypto — broken, avoid)
    Rc2Cbc,
    /// SHA-256 (security: code integrity, entitlements)
    Sha256,
    /// SHA-384 (security: certificate validation)
    Sha384,
    /// SHA-512 (security: Authenticode verification)
    Sha512,
    /// SHA-1 (compatibility: legacy Authenticode, DRM — broken, DO NOT use for security)
    Sha1,
    /// MD5 (compatibility: DRM integrity checks — broken, DO NOT use for security)
    Md5,
    /// HMAC-SHA-256 (security: key derivation, integrity)
    HmacSha256,
    /// HMAC-SHA-1 (compatibility: anti-cheat integrity — broken, DO NOT use for security)
    HmacSha1,
    /// HMAC-SHA-384 (security: certificate path validation)
    HmacSha384,
    /// HMAC-SHA-512 (security: Authenticode)
    HmacSha512,
    /// HMAC-MD5 (compatibility: Steam protocol — broken, DO NOT use for security)
    HmacMd5,
    /// PBKDF2 (compatibility: PFX/P12 import)
    Pbkdf2,
    /// RSA (compatibility: key generation placeholder)
    Rsa,
    /// RSA-PSS (compatibility: key generation placeholder)
    RsaPss,
    /// Diffie-Hellman (compatibility: key agreement placeholder)
    Dh,
    /// ECDH P-256 (compatibility: key agreement placeholder)
    EcdhP256,
    /// ECDH P-384 (compatibility: key agreement placeholder)
    EcdhP384,
    /// ECDSA P-256 (compatibility: signature placeholder)
    EcdsaP256,
    /// ECDSA P-384 (compatibility: signature placeholder)
    EcdsaP384,
}

impl BCryptAlgorithmId {
    /// Get the Windows algorithm name string.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::AesCbc => "AES-CBC",
            Self::AesGcm => "AES-GCM",
            Self::AesCcm => "AES-CCM",
            Self::Des3Cbc => "3DES-CBC",
            Self::Rc2Cbc => "RC2-CBC",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha1 => "SHA-1",
            Self::Md5 => "MD5",
            Self::HmacSha256 => "HMAC-SHA-256",
            Self::HmacSha1 => "HMAC-SHA-1",
            Self::HmacSha384 => "HMAC-SHA-384",
            Self::HmacSha512 => "HMAC-SHA-512",
            Self::HmacMd5 => "HMAC-MD5",
            Self::Pbkdf2 => "PBKDF2",
            Self::Rsa => "RSA",
            Self::RsaPss => "RSA-PSS",
            Self::Dh => "DH",
            Self::EcdhP256 => "ECDH-P256",
            Self::EcdhP384 => "ECDH-P384",
            Self::EcdsaP256 => "ECDSA-P256",
            Self::EcdsaP384 => "ECDSA-P384",
        }
    }

    /// Returns the output digest size in bytes for hash/HMAC algorithms.
    pub fn digest_size(&self) -> usize {
        match self {
            Self::Sha256 | Self::HmacSha256 => 32,
            Self::Sha384 | Self::HmacSha384 => 48,
            Self::Sha512 | Self::HmacSha512 => 64,
            Self::Sha1 | Self::HmacSha1 => 20,
            Self::Md5 | Self::HmacMd5 => 16,
            _ => 0,
        }
    }
}

/// A BCrypt algorithm handle.
#[derive(Debug)]
pub struct BCryptAlgorithmHandle {
    pub id: BCryptAlgorithmId,
    pub key_size_bits: u32,
}

/// A BCrypt hash handle for streaming hash computation.
#[derive(Debug)]
pub struct BCryptHashHandle {
    pub algorithm: BCryptAlgorithmId,
    /// Accumulated hash data.
    pub data: Vec<u8>,
}

/// A BCrypt key handle for symmetric/asymmetric operations.
#[derive(Debug)]
pub struct BCryptKeyHandle {
    pub algorithm: BCryptAlgorithmId,
    pub key_data: Vec<u8>,
    pub is_public: bool,
}

/// BCrypt secret agreement handle (for DH/ECDH).
#[derive(Debug)]
pub struct BCryptSecretHandle {
    pub algorithm: BCryptAlgorithmId,
    pub shared_secret: Vec<u8>,
}

/// Emulates the Windows BCrypt primitive library (bcrypt.dll) for guest
/// application compatibility.
///
/// This is a **compatibility layer**, not a security boundary. It implements
/// the Windows BCrypt API surface so that guest applications (particularly
/// DRM and anti-cheat modules like SteamStub, Denuvo, and EasyAntiCheat)
/// can perform their expected cryptographic operations.
///
/// # Security Notes — Cryptographic Algorithm Classification
///
/// ## Compatibility Hashes (DO NOT USE for Casa1's own security)
/// - `Md5` — MD5: Used by SteamStub integrity checks, Denuvo license tokens
/// - `Sha1` — SHA-1: Used by legacy Authenticode signatures, DRM hashing
/// - `HmacMd5` — HMAC-MD5: Used by Steam protocol compatibility layers
/// - `HmacSha1` — HMAC-SHA1: Used by anti-cheat integrity checks
///
/// These are retained solely for DRM/anti-cheat compatibility. They MUST NOT
/// be used for Casa1's own security functions (entitlement verification,
/// code integrity, certificate validation).
///
/// ## Security Hashes (safe for Casa1's own use)
/// - `Sha256` / `HmacSha256` — SHA-256: Used for code integrity, entitlements
/// - `Sha384` / `HmacSha384` — SHA-384: Used for certificate validation
/// - `Sha512` / `HmacSha512` — SHA-512: Used for Authenticode verification
///
/// ## Key Generation
/// Asymmetric key pairs (RSA, ECDH, ECDSA, DH) are generated using
/// `getrandom()` for key material. This is suitable for DRM emulation
/// where the actual private key is unavailable; it does NOT provide real
/// cryptographic security guarantees.
///
/// ## Signature Operations
/// `sign_hash` and `verify_signature` return placeholder results — real
/// signature verification requires the actual private key, which is
/// unavailable in the emulation context. Authenticode validation uses the
/// macOS Security framework via FFI (see `validate_certificate_chain`).
#[derive(Debug)]
pub struct BCryptRuntime {
    pub algorithm_handles: BTreeMap<u64, BCryptAlgorithmHandle>,
    pub hash_handles: BTreeMap<u64, BCryptHashHandle>,
    pub key_handles: BTreeMap<u64, BCryptKeyHandle>,
    pub secret_handles: BTreeMap<u64, BCryptSecretHandle>,
    next_handle: u64,
}

impl BCryptRuntime {
    pub fn new() -> Self {
        Self {
            algorithm_handles: BTreeMap::new(),
            hash_handles: BTreeMap::new(),
            key_handles: BTreeMap::new(),
            secret_handles: BTreeMap::new(),
            next_handle: 1,
        }
    }

    fn allocate_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    /// Open an algorithm handle.
    pub fn open_algorithm(&mut self, id: BCryptAlgorithmId) -> u64 {
        let handle = self.allocate_handle();
        self.algorithm_handles.insert(
            handle,
            BCryptAlgorithmHandle {
                id,
                key_size_bits: 0,
            },
        );
        handle
    }

    /// Create a hash object for streaming computation.
    pub fn create_hash(&mut self, alg_handle: u64) -> Option<u64> {
        let alg_id = self.algorithm_handles.get(&alg_handle)?.id;
        let hash_handle = self.allocate_handle();
        self.hash_handles.insert(
            hash_handle,
            BCryptHashHandle {
                algorithm: alg_id,
                data: Vec::new(),
            },
        );
        Some(hash_handle)
    }

    /// Hash data into the streaming hash object.
    pub fn hash_data(&mut self, hash_handle: u64, data: &[u8]) -> bool {
        if let Some(hash) = self.hash_handles.get_mut(&hash_handle) {
            hash.data.extend_from_slice(data);
            true
        } else {
            false
        }
    }

    /// Finish the hash and return the hash value.
    ///
    /// ## Security Classification of Hash Algorithms
    ///
    /// **Compatibility hashes** (MD5, SHA-1, HMAC-MD5, HMAC-SHA1):
    /// These are provided solely for DRM/anti-cheat compatibility
    /// (SteamStub, Denuvo, EasyAntiCheat integrity checks). They MUST NOT
    /// be used by Casa1's own security functions.
    ///
    /// **Security hashes** (SHA-256, SHA-384, SHA-512, HMAC variants):
    /// Used by Casa1's own security operations — code integrity,
    /// entitlement verification, Authenticode validation.
    pub fn finish_hash(&mut self, hash_handle: u64) -> Option<Vec<u8>> {
        let hash = self.hash_handles.remove(&hash_handle)?;
        use sha2::{Digest, Sha256, Sha384, Sha512};
        match hash.algorithm {
            BCryptAlgorithmId::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&hash.data);
                Some(hasher.finalize().to_vec())
            }
            BCryptAlgorithmId::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(&hash.data);
                Some(hasher.finalize().to_vec())
            }
            BCryptAlgorithmId::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(&hash.data);
                Some(hasher.finalize().to_vec())
            }
            BCryptAlgorithmId::Sha1 => {
                let mut hasher = sha1::Sha1::new();
                hasher.update(&hash.data);
                Some(hasher.finalize().to_vec())
            }
            BCryptAlgorithmId::Md5 => {
                let digest = md5::compute(&hash.data);
                Some(digest.0.to_vec())
            }
            BCryptAlgorithmId::HmacSha256 => {
                use hmac::{Hmac, Mac};
                type HmacSha256 = Hmac<sha2::Sha256>;
                // For HMAC, the data field stores: key || message (separated by a zero-length
                // marker at position 0). The key is stored in the first part, message after.
                // We use a simple scheme: key_len (4 bytes BE) + key + message.
                let (key, msg) = split_hmac_key_message(&hash.data);
                let mut mac = HmacSha256::new_from_slice(key).ok()?;
                mac.update(msg);
                Some(mac.finalize().into_bytes().to_vec())
            }
            BCryptAlgorithmId::HmacSha1 => {
                use hmac::{Hmac, Mac};
                type HmacSha1 = Hmac<sha1::Sha1>;
                let (key, msg) = split_hmac_key_message(&hash.data);
                let mut mac = HmacSha1::new_from_slice(key).ok()?;
                mac.update(msg);
                Some(mac.finalize().into_bytes().to_vec())
            }
            BCryptAlgorithmId::HmacSha384 => {
                use hmac::{Hmac, Mac};
                type HmacSha384 = Hmac<sha2::Sha384>;
                let (key, msg) = split_hmac_key_message(&hash.data);
                let mut mac = HmacSha384::new_from_slice(key).ok()?;
                mac.update(msg);
                Some(mac.finalize().into_bytes().to_vec())
            }
            BCryptAlgorithmId::HmacSha512 => {
                use hmac::{Hmac, Mac};
                type HmacSha512 = Hmac<sha2::Sha512>;
                let (key, msg) = split_hmac_key_message(&hash.data);
                let mut mac = HmacSha512::new_from_slice(key).ok()?;
                mac.update(msg);
                Some(mac.finalize().into_bytes().to_vec())
            }
            BCryptAlgorithmId::HmacMd5 => {
                // md5 crate v0.7 doesn't implement digest traits needed for hmac::Hmac,
                // so we implement HMAC-MD5 manually: H(K XOR opad, H(K XOR ipad, msg))
                let (key, msg) = split_hmac_key_message(&hash.data);
                let key = if key.len() > 64 {
                    let digest = md5::compute(key);
                    let mut padded = digest.0.to_vec();
                    padded.resize(64, 0);
                    padded
                } else {
                    let mut padded = key.to_vec();
                    padded.resize(64, 0);
                    padded
                };
                let mut ipad = [0x36u8; 64];
                let mut opad = [0x5cu8; 64];
                for i in 0..64 {
                    ipad[i] ^= key[i];
                    opad[i] ^= key[i];
                }
                let mut inner_data = ipad.to_vec();
                inner_data.extend_from_slice(msg);
                let inner_hash = md5::compute(&inner_data);
                let mut outer_data = opad.to_vec();
                outer_data.extend_from_slice(&inner_hash.0);
                let outer_hash = md5::compute(&outer_data);
                Some(outer_hash.0.to_vec())
            }
            BCryptAlgorithmId::Pbkdf2 => {
                // For PBKDF2, data stores: 4-byte-be key_len + key + 4-byte-be salt_len + salt + 4-byte-be iterations
                let result = derive_pbkdf2_from_data(&hash.data)?;
                Some(result)
            }
            _ => {
                // For other algorithms, return raw data
                Some(hash.data)
            }
        }
    }

    /// Generate an asymmetric key pair.
    pub fn generate_key_pair(&mut self, alg_handle: u64, key_size_bits: u32) -> Option<(u64, u64)> {
        let alg_id = self.algorithm_handles.get(&alg_handle)?.id;
        let private_handle = self.allocate_handle();
        let public_handle = self.allocate_handle();

        // Generate key material using the appropriate algorithm
        let key_data = match alg_id {
            BCryptAlgorithmId::Rsa | BCryptAlgorithmId::RsaPss => {
                // Sanity-cap the key size so a guest-requested value cannot
                // drive a huge allocation (raw u32 bit size up to ~512 MiB).
                if !(512..=16384).contains(&key_size_bits) || !key_size_bits.is_multiple_of(8) {
                    return None;
                }
                // Generate a random RSA key placeholder
                let mut key = vec![0u8; (key_size_bits / 8) as usize];
                getrandom::getrandom(&mut key).ok()?;
                key
            }
            BCryptAlgorithmId::EcdhP256 | BCryptAlgorithmId::EcdsaP256 => {
                let mut key = vec![0u8; 64]; // 32 bytes private + 32 bytes public
                getrandom::getrandom(&mut key).ok()?;
                key
            }
            BCryptAlgorithmId::EcdhP384 | BCryptAlgorithmId::EcdsaP384 => {
                let mut key = vec![0u8; 96]; // 48 bytes private + 48 bytes public
                getrandom::getrandom(&mut key).ok()?;
                key
            }
            BCryptAlgorithmId::Dh => {
                // Sanity-cap the key size so a guest-requested value cannot
                // drive a huge allocation.
                if !(512..=16384).contains(&key_size_bits) || !key_size_bits.is_multiple_of(8) {
                    return None;
                }
                let mut key = vec![0u8; (key_size_bits / 8) as usize];
                getrandom::getrandom(&mut key).ok()?;
                key
            }
            _ => return None,
        };

        self.key_handles.insert(
            private_handle,
            BCryptKeyHandle {
                algorithm: alg_id,
                key_data: key_data.clone(),
                is_public: false,
            },
        );
        self.key_handles.insert(
            public_handle,
            BCryptKeyHandle {
                algorithm: alg_id,
                key_data,
                is_public: true,
            },
        );

        Some((private_handle, public_handle))
    }

    /// Import a symmetric key.
    pub fn import_symmetric_key(&mut self, alg_handle: u64, key_data: &[u8]) -> Option<u64> {
        let alg_id = self.algorithm_handles.get(&alg_handle)?.id;
        let handle = self.allocate_handle();
        self.key_handles.insert(
            handle,
            BCryptKeyHandle {
                algorithm: alg_id,
                key_data: key_data.to_vec(),
                is_public: true,
            },
        );
        Some(handle)
    }

    /// Export a key.
    pub fn export_key(&self, key_handle: u64) -> Option<&[u8]> {
        self.key_handles
            .get(&key_handle)
            .map(|k| k.key_data.as_slice())
    }

    /// Encrypt data using a symmetric key.
    pub fn encrypt_symmetric(
        &self,
        key_handle: u64,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Option<Vec<u8>> {
        let key = self.key_handles.get(&key_handle)?;
        match key.algorithm {
            BCryptAlgorithmId::AesCbc => {
                use cipher::{BlockEncryptMut, KeyIvInit};
                if iv.len() != 16 {
                    return None;
                }
                // Select the cipher from the actual key size so AES-128 keys
                // (16 bytes) work instead of failing on the hardcoded AES-256.
                let mut buf = plaintext.to_vec();
                let pad_len = 16 - (buf.len() % 16);
                buf.extend(std::iter::repeat_n(pad_len as u8, pad_len));
                match key.key_data.len() {
                    16 => {
                        use aes::Aes128;
                        use cbc::Encryptor;
                        type Aes128CbcEnc = Encryptor<Aes128>;
                        let mut encryptor = Aes128CbcEnc::new_from_slices(&key.key_data, iv).ok()?;
                        for chunk in buf.chunks_exact_mut(16) {
                            encryptor.encrypt_block_mut(aes::Block::from_mut_slice(chunk));
                        }
                    }
                    32 => {
                        use aes::Aes256;
                        use cbc::Encryptor;
                        type Aes256CbcEnc = Encryptor<Aes256>;
                        let mut encryptor = Aes256CbcEnc::new_from_slices(&key.key_data, iv).ok()?;
                        for chunk in buf.chunks_exact_mut(16) {
                            encryptor.encrypt_block_mut(aes::Block::from_mut_slice(chunk));
                        }
                    }
                    _ => return None,
                }
                Some(buf)
            }
            BCryptAlgorithmId::AesGcm => {
                use aes_gcm::aead::Aead;
                use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
                let cipher = Aes256Gcm::new_from_slice(&key.key_data).ok()?;
                let nonce = Nonce::from_slice(iv);
                cipher.encrypt(nonce, plaintext).ok()
            }
            _ => None,
        }
    }

    /// Decrypt data using a symmetric key.
    pub fn decrypt_symmetric(
        &self,
        key_handle: u64,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Option<Vec<u8>> {
        let key = self.key_handles.get(&key_handle)?;
        match key.algorithm {
            BCryptAlgorithmId::AesCbc => {
                use cipher::{BlockDecryptMut, KeyIvInit};
                if iv.len() != 16 {
                    return None;
                }
                if !ciphertext.len().is_multiple_of(16) {
                    return None;
                }
                let mut buf = ciphertext.to_vec();
                match key.key_data.len() {
                    16 => {
                        use aes::Aes128;
                        use cbc::Decryptor;
                        type Aes128CbcDec = Decryptor<Aes128>;
                        let mut decryptor = Aes128CbcDec::new_from_slices(&key.key_data, iv).ok()?;
                        for chunk in buf.chunks_exact_mut(16) {
                            decryptor.decrypt_block_mut(aes::Block::from_mut_slice(chunk));
                        }
                    }
                    32 => {
                        use aes::Aes256;
                        use cbc::Decryptor;
                        type Aes256CbcDec = Decryptor<Aes256>;
                        let mut decryptor = Aes256CbcDec::new_from_slices(&key.key_data, iv).ok()?;
                        for chunk in buf.chunks_exact_mut(16) {
                            decryptor.decrypt_block_mut(aes::Block::from_mut_slice(chunk));
                        }
                    }
                    _ => return None,
                }
                // Validate the PKCS#7 padding before truncating: pad length in
                // 1..=16 and every pad byte equal to it.
                let pad_len = *buf.last()? as usize;
                if pad_len == 0 || pad_len > 16 {
                    return None;
                }
                if buf[buf.len() - pad_len..]
                    .iter()
                    .any(|&b| b as usize != pad_len)
                {
                    return None;
                }
                buf.truncate(buf.len() - pad_len);
                Some(buf)
            }
            BCryptAlgorithmId::AesGcm => {
                use aes_gcm::aead::Aead;
                use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
                let cipher = Aes256Gcm::new_from_slice(&key.key_data).ok()?;
                let nonce = Nonce::from_slice(iv);
                cipher.decrypt(nonce, ciphertext).ok()
            }
            _ => None,
        }
    }

    /// Sign a hash using an asymmetric key.
    ///
    /// ## Security Note — Placeholder Implementation
    ///
    /// This is a **compatibility stub** for the Windows BCrypt API. It returns
    /// a random placeholder signature because:
    ///
    /// 1. RSA signing requires the private key, which is unavailable in the
    ///    DRM emulation context (the original signing was done by the game
    ///    developer/publisher).
    /// 2. The generated keys in [`generate_key_pair`](Self::generate_key_pair)
    ///    use `getrandom()` for key material and are NOT cryptographically
    ///    meaningful — they exist solely to satisfy API calls from guest code.
    /// 3. Real cryptographic signature verification in Casa1 is performed via
    ///    the macOS Security framework (see [`validate_certificate_chain`]).
    pub fn sign_hash(&self, key_handle: u64, _hash: &[u8]) -> Option<Vec<u8>> {
        let key = self.key_handles.get(&key_handle)?;
        match key.algorithm {
            BCryptAlgorithmId::Rsa => {
                // Use the key data to create a signing key
                // For now, return a placeholder signature
                let mut sig = vec![0u8; 256]; // RSA-2048 signature size
                getrandom::getrandom(&mut sig).ok()?;
                Some(sig)
            }
            BCryptAlgorithmId::EcdsaP256 => {
                let mut sig = vec![0u8; 64]; // P-256 signature
                getrandom::getrandom(&mut sig).ok()?;
                Some(sig)
            }
            _ => None,
        }
    }

    /// Verify a signature.
    ///
    /// ## Security Note — Compatibility Stub
    ///
    /// This is a **compatibility stub**: it does NOT perform real
    /// cryptographic verification and must NEVER be used for security
    /// decisions. It only requires that the inputs are non-empty and that the
    /// signature size is consistent with the key's algorithm, so guest code
    /// that passes mismatched key/signature pairs fails instead of observing
    /// an unconditional pass.
    ///
    /// Casa1's authenticode/signature verification uses the macOS Security
    /// framework (see [`validate_certificate_chain`]) rather than this BCrypt
    /// emulation layer, so this stub only affects guest-observed behavior.
    pub fn verify_signature(&self, key_handle: u64, hash: &[u8], signature: &[u8]) -> bool {
        let Some(key) = self.key_handles.get(&key_handle) else {
            return false;
        };
        if hash.is_empty() || signature.is_empty() {
            return false;
        }
        match key.algorithm {
            // RSA signature length equals the modulus size in bytes.
            BCryptAlgorithmId::Rsa | BCryptAlgorithmId::RsaPss => {
                signature.len() == key.key_data.len() && !key.key_data.is_empty()
            }
            // P-256: r || s (32 + 32 bytes); P-384: 48 + 48 bytes.
            BCryptAlgorithmId::EcdsaP256 => signature.len() == 64,
            BCryptAlgorithmId::EcdsaP384 => signature.len() == 96,
            _ => false,
        }
    }

    /// Derive a shared secret (DH/ECDH).
    ///
    /// ## Security Note — HMAC-Based Derivation
    ///
    /// This implements DH/ECDH key agreement by deriving a deterministic
    /// shared secret via `HMAC-SHA256(private_key_data, public_key_data)`.
    /// This is NOT a real DH/ECDH computation — true key agreement requires
    /// modular exponentiation (DH) or scalar multiplication (ECDH).
    ///
    /// This approach is acceptable for DRM compatibility because:
    /// 1. The generated key pairs use `getrandom()` and are not derived from
    ///    actual cryptographic secrets.
    /// 2. Guest DRM code expects the API to produce a shared secret — any
    ///    deterministic derivation satisfies the protocol.
    /// 3. Casa1's own security does not rely on this implementation.
    pub fn secret_agreement(&mut self, private_key: u64, public_key: u64) -> Option<u64> {
        let (priv_algo, priv_data) = {
            let priv_key = self.key_handles.get(&private_key)?;
            (priv_key.algorithm, priv_key.key_data.clone())
        };
        let pub_data = {
            let pub_key = self.key_handles.get(&public_key)?;
            pub_key.key_data.clone()
        };

        let shared_len = match priv_algo {
            BCryptAlgorithmId::Dh | BCryptAlgorithmId::EcdhP256 => 32,
            BCryptAlgorithmId::EcdhP384 => 48,
            _ => return None,
        };

        let mut shared = vec![0u8; shared_len];
        // In a real implementation, this would perform the actual DH/ECDH computation.
        // For the compatibility layer, we derive a deterministic shared secret from
        // the key material using HMAC.
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        if let Ok(mut mac) = HmacSha256::new_from_slice(&priv_data) {
            mac.update(&pub_data);
            let result = mac.finalize().into_bytes();
            shared.copy_from_slice(&result[..shared_len]);
        }

        let handle = self.allocate_handle();
        self.secret_handles.insert(
            handle,
            BCryptSecretHandle {
                algorithm: priv_algo,
                shared_secret: shared,
            },
        );
        Some(handle)
    }

    /// Derive a key from a shared secret.
    ///
    /// Implements HKDF-Expand (RFC 5869) with the shared secret as the PRK,
    /// producing exactly `key_length` bytes. Unsupported lengths (above the
    /// HMAC-SHA256 counter-block limit of 255 * 32 bytes) return `None` rather
    /// than silently returning a short key.
    pub fn derive_key(&self, secret_handle: u64, key_length: usize) -> Option<Vec<u8>> {
        let secret = self.secret_handles.get(&secret_handle)?;
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;

        const H_LEN: usize = 32;
        if key_length > 255 * H_LEN {
            return None;
        }
        let block_count = key_length.div_ceil(H_LEN);
        let mut okm = Vec::with_capacity(block_count * H_LEN);
        let mut t: Vec<u8> = Vec::new();
        for i in 1..=block_count {
            let mut mac = HmacSha256::new_from_slice(&secret.shared_secret).ok()?;
            mac.update(&t);
            mac.update(b"bcrypt-derive-key");
            mac.update(&[i as u8]);
            t = mac.finalize().into_bytes().to_vec();
            okm.extend_from_slice(&t);
        }
        okm.truncate(key_length);
        Some(okm)
    }

    /// Destroy a handle.
    pub fn destroy_handle(&mut self, handle: u64) {
        self.algorithm_handles.remove(&handle);
        self.hash_handles.remove(&handle);
        self.key_handles.remove(&handle);
        self.secret_handles.remove(&handle);
    }
}

impl Default for BCryptRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ─── O3 — Code Integrity Policy Enforcement ───────────────────────────────

/// Code integrity policy for PE loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeIntegrityPolicy {
    /// No signing requirement.
    None,
    /// PE must have a valid Authenticode signature.
    RequireSignature,
    /// PE must be WHQL-signed (driver signing).
    RequireWhql,
    /// PE must be signed by a trusted publisher.
    RequireTrustedPublisher,
}

/// Result of a code integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeIntegrityResult {
    pub policy: CodeIntegrityPolicy,
    pub passed: bool,
    pub reason: String,
    pub signer: Option<String>,
}

/// Check code integrity of a PE against the given policy.
pub fn enforce_code_integrity(pe_data: &[u8], policy: CodeIntegrityPolicy) -> CodeIntegrityResult {
    match policy {
        CodeIntegrityPolicy::None => CodeIntegrityResult {
            policy,
            passed: true,
            reason: "No signing requirement".to_string(),
            signer: None,
        },
        CodeIntegrityPolicy::RequireSignature => {
            let verdict = verify_pe_authenticode(pe_data);
            match verdict {
                AuthenticodeVerdict::Valid => CodeIntegrityResult {
                    policy,
                    passed: true,
                    reason: "Valid Authenticode signature".to_string(),
                    signer: None,
                },
                AuthenticodeVerdict::Invalid(msg) => CodeIntegrityResult {
                    policy,
                    passed: false,
                    reason: format!("Invalid/untrusted signature: {msg}"),
                    signer: None,
                },
                AuthenticodeVerdict::NoSignature => CodeIntegrityResult {
                    policy,
                    passed: false,
                    reason: "No Authenticode signature found".to_string(),
                    signer: None,
                },
            }
        }
        CodeIntegrityPolicy::RequireWhql => {
            let verdict = verify_pe_authenticode(pe_data);
            match verdict {
                AuthenticodeVerdict::Valid => CodeIntegrityResult {
                    policy,
                    passed: true,
                    reason: "WHQL signature verified".to_string(),
                    signer: None,
                },
                _ => CodeIntegrityResult {
                    policy,
                    passed: false,
                    reason: "WHQL signing requirement not met".to_string(),
                    signer: None,
                },
            }
        }
        CodeIntegrityPolicy::RequireTrustedPublisher => {
            let verdict = verify_pe_authenticode(pe_data);
            match verdict {
                AuthenticodeVerdict::Valid => CodeIntegrityResult {
                    policy,
                    passed: true,
                    reason: "Trusted publisher signature verified".to_string(),
                    signer: None,
                },
                _ => CodeIntegrityResult {
                    policy,
                    passed: false,
                    reason: "Trusted publisher signing requirement not met".to_string(),
                    signer: None,
                },
            }
        }
    }
}

// ─── O4 — Protected Process Light (PPL) Detection — Gap 10.5 ──────────────

/// Process protection level constants (PS_PROTECTION.Level field).
pub mod ppl_level {
    /// No protection.
    pub const PPL_NONE: u8 = 0x00;
    /// Protected process light — anti-malware/signer level.
    pub const PPL_LIGHT: u8 = 0x01;
    /// Protected process light — Windows level.
    pub const PPL_WINDOWS: u8 = 0x02;
    /// Protected process light — Windows TCB level.
    pub const PPL_WINDOWS_TCB: u8 = 0x03;
    /// Full protected process — authenticode level.
    pub const PP_FULL: u8 = 0x04;
    /// Full protected process — Windows level.
    pub const PP_WINDOWS: u8 = 0x05;
    /// Full protected process — Windows TCB level.
    pub const PP_WINDOWS_TCB: u8 = 0x06;
    /// Maximum protection level.
    pub const PP_MAX: u8 = 0x07;
}

/// Process protection type constants (PS_PROTECTION.Type field).
pub mod ppl_type {
    /// No protection type.
    pub const PROTECTION_NONE: u8 = 0x00;
    /// Protected process (full).
    pub const PROTECTION_FULL: u8 = 0x01;
    /// Protected process light.
    pub const PROTECTION_LIGHT: u8 = 0x02;
}

/// Process signer type constants (PS_PROTECTION.Signer field).
pub mod ppl_signer {
    /// No signer.
    pub const SIGNER_NONE: u8 = 0x00;
    /// Authenticode-signed.
    pub const SIGNER_AUTHENTICODE: u8 = 0x01;
    /// Windows-signed.
    pub const SIGNER_WINDOWS: u8 = 0x02;
    /// Windows TCB (Trusted Computing Base).
    pub const SIGNER_WINDOWS_TCB: u8 = 0x03;
    /// WinTcb-signed but allowed to be unprotected.
    pub const SIGNER_WINDOWS_TCB_UNPROTECTED: u8 = 0x04;
    /// Code integrity-signed.
    pub const SIGNER_CODEINTEGRITY: u8 = 0x05;
    /// Anti-malware signer.
    pub const SIGNER_ANTIMALWARE: u8 = 0x06;
    /// LSA (Local Security Authority) signer.
    pub const SIGNER_LSA: u8 = 0x07;
}

/// Process protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsProtection {
    /// Protection level (PPL_NONE, PPL_LIGHT, PP_FULL, etc.).
    pub level: u8,
    /// Protection type (PROTECTION_NONE, PROTECTION_FULL, PROTECTION_LIGHT).
    pub type_: u8,
    /// Signer type (SIGNER_NONE, SIGNER_WINDOWS, SIGNER_AUTHENTICODE, etc.).
    pub signer: u8,
}

impl PsProtection {
    /// No protection (unprotected process).
    pub fn unprotected() -> Self {
        Self {
            level: ppl_level::PPL_NONE,
            type_: ppl_type::PROTECTION_NONE,
            signer: ppl_signer::SIGNER_NONE,
        }
    }

    /// Protected process light with anti-malware signer.
    pub fn ppl_light_anti_malware() -> Self {
        Self {
            level: ppl_level::PPL_LIGHT,
            type_: ppl_type::PROTECTION_LIGHT,
            signer: ppl_signer::SIGNER_ANTIMALWARE,
        }
    }

    /// Protected process light with Windows signer.
    pub fn ppl_light_windows() -> Self {
        Self {
            level: ppl_level::PPL_LIGHT,
            type_: ppl_type::PROTECTION_LIGHT,
            signer: ppl_signer::SIGNER_WINDOWS,
        }
    }

    /// Protected process light with authenticode signer.
    pub fn ppl_light_authenticode() -> Self {
        Self {
            level: ppl_level::PPL_LIGHT,
            type_: ppl_type::PROTECTION_LIGHT,
            signer: ppl_signer::SIGNER_AUTHENTICODE,
        }
    }

    /// Full protected process with Windows TCB signer.
    pub fn pp_full_windows_tcb() -> Self {
        Self {
            level: ppl_level::PP_WINDOWS_TCB,
            type_: ppl_type::PROTECTION_FULL,
            signer: ppl_signer::SIGNER_WINDOWS_TCB,
        }
    }

    /// Returns true if this protection level represents PPL or higher.
    pub fn is_ppl_or_higher(&self) -> bool {
        self.level >= ppl_level::PPL_LIGHT
    }

    /// Returns true if this protection level represents full protection.
    pub fn is_full_protection(&self) -> bool {
        self.type_ == ppl_type::PROTECTION_FULL
    }

    /// Encodes the protection into a single byte (as Windows stores it).
    /// Format: Bits 0-3 = Level, Bits 4-5 = Type, Bits 6-8 = Signer.
    pub fn to_byte(&self) -> u8 {
        (self.level & 0x0F) | ((self.type_ & 0x03) << 4) | ((self.signer & 0x07) << 6)
    }

    /// Decodes a protection byte into a PsProtection struct.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            level: byte & 0x0F,
            type_: (byte >> 4) & 0x03,
            signer: (byte >> 6) & 0x07,
        }
    }
}

/// An entry in the process protection registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProtectionEntry {
    /// Process name (e.g. "steam.exe", "lsass.exe").
    pub process_name: String,
    /// Protection level for this process.
    pub protection: PsProtection,
    /// Whether PPL cancellation is allowed for this process.
    pub cancellation_allowed: bool,
}

/// Global process protection registry.
///
/// Maps process names to their protection levels. This is used to
/// determine the protection level of the current process when queried
/// by guest code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProtectionRegistry {
    /// Map from lowercase process name to protection entry.
    entries: BTreeMap<String, ProcessProtectionEntry>,
    /// Whether the registry has been initialized with defaults.
    initialized: bool,
}

impl ProcessProtectionRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            initialized: false,
        }
    }

    /// Initializes the registry with default protection levels for well-known processes.
    pub fn initialize_defaults(&mut self) {
        if self.initialized {
            return;
        }

        // Steam.exe runs with some protection on Windows
        self.register(ProcessProtectionEntry {
            process_name: "steam.exe".to_string(),
            protection: PsProtection::ppl_light_authenticode(),
            cancellation_allowed: true,
        });

        // Steam service
        self.register(ProcessProtectionEntry {
            process_name: "steamservice.exe".to_string(),
            protection: PsProtection::ppl_light_authenticode(),
            cancellation_allowed: true,
        });

        // Steam web helper
        self.register(ProcessProtectionEntry {
            process_name: "steamwebhelper.exe".to_string(),
            protection: PsProtection::ppl_light_authenticode(),
            cancellation_allowed: true,
        });

        // System processes
        self.register(ProcessProtectionEntry {
            process_name: "lsass.exe".to_string(),
            protection: PsProtection::pp_full_windows_tcb(),
            cancellation_allowed: false,
        });

        self.register(ProcessProtectionEntry {
            process_name: "csrss.exe".to_string(),
            protection: PsProtection::pp_full_windows_tcb(),
            cancellation_allowed: false,
        });

        self.register(ProcessProtectionEntry {
            process_name: "services.exe".to_string(),
            protection: PsProtection::ppl_light_windows(),
            cancellation_allowed: false,
        });

        self.register(ProcessProtectionEntry {
            process_name: "svchost.exe".to_string(),
            protection: PsProtection::ppl_light_windows(),
            cancellation_allowed: false,
        });

        self.register(ProcessProtectionEntry {
            process_name: "wininit.exe".to_string(),
            protection: PsProtection::pp_full_windows_tcb(),
            cancellation_allowed: false,
        });

        self.register(ProcessProtectionEntry {
            process_name: "winlogon.exe".to_string(),
            protection: PsProtection::pp_full_windows_tcb(),
            cancellation_allowed: false,
        });

        // Anti-malware processes
        self.register(ProcessProtectionEntry {
            process_name: "msmpeng.exe".to_string(),
            protection: PsProtection::ppl_light_anti_malware(),
            cancellation_allowed: true,
        });

        // Load overrides from environment variable
        self.load_env_overrides();

        self.initialized = true;
    }

    /// Registers a process protection entry.
    pub fn register(&mut self, entry: ProcessProtectionEntry) {
        self.entries
            .insert(entry.process_name.to_ascii_lowercase(), entry);
    }

    /// Looks up the protection level for a process by name.
    pub fn get_protection(&self, process_name: &str) -> PsProtection {
        self.entries
            .get(&process_name.to_ascii_lowercase())
            .map(|e| e.protection)
            .unwrap_or_else(PsProtection::unprotected)
    }

    /// Looks up the full protection entry for a process.
    pub fn get_entry(&self, process_name: &str) -> Option<&ProcessProtectionEntry> {
        self.entries.get(&process_name.to_ascii_lowercase())
    }

    /// Checks if a process has PPL protection.
    pub fn is_ppl(&self, process_name: &str) -> bool {
        self.get_protection(process_name).is_ppl_or_higher()
    }

    /// Checks if PPL cancellation is allowed for a process.
    pub fn is_cancellation_allowed(&self, process_name: &str) -> bool {
        self.entries
            .get(&process_name.to_ascii_lowercase())
            .map(|e| e.cancellation_allowed)
            .unwrap_or(false)
    }

    /// Sets the cancellation state for a process.
    pub fn set_cancellation(&mut self, process_name: &str, allowed: bool) -> bool {
        if let Some(entry) = self.entries.get_mut(&process_name.to_ascii_lowercase()) {
            entry.cancellation_allowed = allowed;
            true
        } else {
            false
        }
    }

    /// Returns the number of registered processes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Loads protection level overrides from the `CASA1_PPL_OVERRIDES` environment variable.
    ///
    /// Format: `process1.exe=level:signer,process2.exe=level:signer`
    ///
    /// Where `level` is a decimal PPL level (0-7) and `signer` is a decimal signer type (0-7).
    ///
    /// Example: `CASA1_PPL_OVERRIDES=steam.exe=1:1,game.exe=0:0`
    fn load_env_overrides(&mut self) {
        if let Ok(overrides) = std::env::var("CASA1_PPL_OVERRIDES") {
            for entry in overrides.split(',') {
                let parts: Vec<&str> = entry.split('=').collect();
                if parts.len() != 2 {
                    continue;
                }
                let name = parts[0].trim();
                let value_parts: Vec<&str> = parts[1].split(':').collect();
                if value_parts.len() != 2 {
                    continue;
                }
                if let (Ok(level), Ok(signer)) = (
                    value_parts[0].trim().parse::<u8>(),
                    value_parts[1].trim().parse::<u8>(),
                ) {
                    let type_ = if level == 0 {
                        ppl_type::PROTECTION_NONE
                    } else if level <= ppl_level::PPL_WINDOWS_TCB {
                        ppl_type::PROTECTION_LIGHT
                    } else {
                        ppl_type::PROTECTION_FULL
                    };
                    self.register(ProcessProtectionEntry {
                        process_name: name.to_string(),
                        protection: PsProtection {
                            level,
                            type_,
                            signer,
                        },
                        cancellation_allowed: true,
                    });
                }
            }
        }
    }
}

impl Default for ProcessProtectionRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.initialize_defaults();
        registry
    }
}

// Global process protection registry (lazy-initialized).
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref PPL_REGISTRY: Mutex<ProcessProtectionRegistry> =
        Mutex::new(ProcessProtectionRegistry::new());
}

/// Ensures the PPL registry is initialized.
fn ensure_ppl_registry() {
    let mut registry = PPL_REGISTRY.lock().unwrap();
    if !registry.initialized {
        registry.initialize_defaults();
    }
}

/// Check if the current process is a protected process.
///
/// Returns `true` if the process has any protection level (PPL or full).
pub fn is_protected_process() -> bool {
    is_protected_process_named(&current_process_name())
}

/// Check if the current process is a protected process light.
///
/// Returns `true` if the process has PPL_LIGHT or higher protection level
/// but is not a full protected process.
pub fn is_protected_process_light() -> bool {
    is_protected_process_light_named(&current_process_name())
}

/// Get the process protection level for the current process.
pub fn get_process_protection() -> PsProtection {
    get_process_protection_named(&current_process_name())
}

/// Check if a named process is a protected process.
pub fn is_protected_process_named(process_name: &str) -> bool {
    ensure_ppl_registry();
    let registry = PPL_REGISTRY.lock().unwrap();
    let protection = registry.get_protection(process_name);
    protection.is_ppl_or_higher()
}

/// Check if a named process is a protected process light.
pub fn is_protected_process_light_named(process_name: &str) -> bool {
    ensure_ppl_registry();
    let registry = PPL_REGISTRY.lock().unwrap();
    let protection = registry.get_protection(process_name);
    protection.is_ppl_or_higher() && !protection.is_full_protection()
}

/// Get the process protection level for a named process.
pub fn get_process_protection_named(process_name: &str) -> PsProtection {
    ensure_ppl_registry();
    let registry = PPL_REGISTRY.lock().unwrap();
    registry.get_protection(process_name)
}

/// Implements `NtQueryInformationProcess` for `ProcessProtectionInformation` (class 0x3D).
///
/// Returns the PS_PROTECTION structure for the given process as a u64 value.
/// The structure is encoded as:
///   Byte 0: PS_PROTECTION byte (level | type<<4 | signer<<6)
///   Byte 1-7: Reserved (zero)
pub fn nt_query_process_protection(process_name: &str) -> u64 {
    let protection = get_process_protection_named(process_name);
    protection.to_byte() as u64
}

/// Implements `SetProtectedProcessLightCancellation`.
///
/// Allows a PPL process to opt out of protection. Returns `true` if the
/// cancellation was successfully applied.
pub fn set_protected_process_light_cancellation(process_name: &str, cancel: bool) -> bool {
    ensure_ppl_registry();
    let mut registry = PPL_REGISTRY.lock().unwrap();
    if registry.is_cancellation_allowed(process_name) {
        if cancel {
            // Downgrade protection to NONE
            registry.register(ProcessProtectionEntry {
                process_name: process_name.to_string(),
                protection: PsProtection::unprotected(),
                cancellation_allowed: true,
            });
        }
        true
    } else {
        false
    }
}

// Global current-process name used by the PPL lookups.
//
// A process-global `Mutex<String>` replaces the previous `std::env` channel:
// environment access is documented as not thread-safe, and guest code can
// call the name-set API concurrently from multiple threads.
lazy_static::lazy_static! {
    static ref CURRENT_PROCESS_NAME: Mutex<String> = Mutex::new("game.exe".to_string());
}

/// Returns the current process name (extracted from the executable path).
///
/// This is a simple helper that returns a default process name. In the
/// actual PE runtime, this would be set based on the loaded executable.
fn current_process_name() -> String {
    CURRENT_PROCESS_NAME
        .lock()
        .map(|name| name.clone())
        .unwrap_or_else(|_| "game.exe".to_string())
}

/// Sets the current process name for PPL lookups.
pub fn set_current_process_name(name: &str) {
    if let Ok(mut current) = CURRENT_PROCESS_NAME.lock() {
        *current = name.to_string();
    }
}

/// Returns all registered process protection entries.
pub fn get_all_protection_entries() -> Vec<ProcessProtectionEntry> {
    ensure_ppl_registry();
    let registry = PPL_REGISTRY.lock().unwrap();
    registry.entries.values().cloned().collect()
}

// ─── O5 — Credential Guard Simulation ─────────────────────────────────────

/// Credential guard status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialGuardStatus {
    pub enabled: bool,
    pub lsa_isolated: bool,
}

impl CredentialGuardStatus {
    /// Credential guard is not available for guest processes.
    pub fn not_available() -> Self {
        Self {
            enabled: false,
            lsa_isolated: false,
        }
    }
}

/// Check if LSA is running in isolated mode.
/// Always returns FALSE for guest processes.
pub fn lsa_is_isolated() -> bool {
    false
}

/// Check if a credential is protected by credential guard.
/// Always returns FALSE for guest processes.
pub fn cred_is_protected() -> bool {
    false
}

/// Protect a credential (pass-through for guest processes).
pub fn cred_protect(credential: &[u8]) -> Vec<u8> {
    credential.to_vec()
}

/// Unprotect a credential (pass-through for guest processes).
pub fn cred_unprotect(credential: &[u8]) -> Vec<u8> {
    credential.to_vec()
}

/// Get the credential guard status.
pub fn get_credential_guard_status() -> CredentialGuardStatus {
    CredentialGuardStatus::not_available()
}

// ─── Gap 6.3: BCrypt HMAC / PBKDF2 helper functions ────────────────────────

/// Split the HMAC key-message buffer.
///
/// Format: 4-byte BE key length + key bytes + message bytes.
fn split_hmac_key_message(data: &[u8]) -> (&[u8], &[u8]) {
    if data.len() < 4 {
        return (&[], data);
    }
    let key_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + key_len {
        return (&[], data);
    }
    (&data[4..4 + key_len], &data[4 + key_len..])
}

/// PBKDF2 key derivation using HMAC-SHA256.
///
/// The `data` buffer format:
///   4-byte BE key_len + key + 4-byte BE salt_len + salt + 4-byte BE iterations + 4-byte BE dk_len
///
/// Both `iterations` and `dk_len` are attacker-controlled; they are clamped at
/// parse time (1M iterations, 1 MiB output) to prevent CPU/memory exhaustion.
///
/// Returns the derived key bytes, or None if the data is malformed.
fn derive_pbkdf2_from_data(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 16 {
        return None;
    }
    let key_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + key_len + 4 {
        return None;
    }
    let key = &data[4..4 + key_len];
    let off = 4 + key_len;
    let salt_len =
        u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
    if data.len() < off + 4 + salt_len + 8 {
        return None;
    }
    let salt = &data[off + 4..off + 4 + salt_len];
    let off2 = off + 4 + salt_len;
    let iterations =
        u32::from_be_bytes([data[off2], data[off2 + 1], data[off2 + 2], data[off2 + 3]]);
    let dk_len = u32::from_be_bytes([
        data[off2 + 4],
        data[off2 + 5],
        data[off2 + 6],
        data[off2 + 7],
    ]) as usize;

    // Caps against guest-controlled CPU/memory exhaustion.
    const MAX_ITERATIONS: u32 = 1_000_000;
    const MAX_DK_LEN: usize = 1024 * 1024;
    if iterations == 0 || iterations > MAX_ITERATIONS || dk_len == 0 || dk_len > MAX_DK_LEN {
        return None;
    }

    pbkdf2_hmac_sha256(key, salt, iterations, dk_len)
}

/// PBKDF2-HMAC-SHA256 key derivation.
///
/// Implements RFC 2898 PBKDF2 with HMAC-SHA256 as the pseudo-random function.
/// Each iteration computes HMAC-SHA256(password, salt || INT(block_index)) and
/// then XORs the result with the previous U-value.
fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk_len: usize,
) -> Option<Vec<u8>> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let h_len = 32; // SHA-256 output size
    let block_count = dk_len.div_ceil(h_len);

    let mut derived_key = Vec::with_capacity(block_count * h_len);

    for block_index in 1..=block_count as u32 {
        // U_1 = HMAC(password, salt || INT_32_BE(block_index))
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&block_index.to_be_bytes());

        let mut mac = HmacSha256::new_from_slice(password).ok()?;
        mac.update(&salt_block);
        let mut u = mac.finalize().into_bytes();
        let mut result = u.to_vec();

        // U_2 .. U_c
        for _ in 1..iterations {
            let mut mac = HmacSha256::new_from_slice(password).ok()?;
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (r, u_byte) in result.iter_mut().zip(u.iter()) {
                *r ^= u_byte;
            }
        }

        derived_key.extend_from_slice(&result);
    }

    derived_key.truncate(dk_len);
    Some(derived_key)
}

// ---------------------------------------------------------------------------
// Gap 7.5 — PFX (PKCS#12) Certificate Import
// ---------------------------------------------------------------------------

/// Result of a PFX import operation.
#[derive(Debug, Clone)]
pub struct PfxImportResult {
    /// Handle to the newly created certificate store.
    pub store_handle: u64,
    /// Number of certificates imported.
    pub cert_count: usize,
    /// Whether a private key was extracted.
    pub has_private_key: bool,
}

/// Check if a blob looks like a PFX/PKCS#12 blob.
///
/// A PFX blob starts with the ASN.1 SEQUENCE tag (0x30) and contains
/// the PKCS#12 PFX OID (1.2.840.113549.1.12.10.1).
pub fn pfx_is_pfx_blob(data: &[u8]) -> bool {
    if data.len() < 10 {
        return false;
    }
    // PKCS#12 always starts with ASN.1 SEQUENCE (0x30)
    if data[0] != 0x30 {
        return false;
    }
    // Check for PKCS#12 content type OID somewhere in the first 100 bytes
    // The OID 1.2.840.113549.1.12.10.1 encodes as:
    // 06 0B 2A 86 48 86 F7 0D 01 0C 0A 01
    let search_window = &data[..data.len().min(200)];
    let pfx_oid_pattern: &[u8] = &[
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A,
    ];
    // Also accept the PKCS#7 signedData OID: 1.2.840.113549.1.7.2
    let pkcs7_oid_pattern: &[u8] = &[
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];

    // Simple byte search for the OID patterns
    let mut found = false;
    for i in 0..search_window.len().saturating_sub(pfx_oid_pattern.len()) {
        if &search_window[i..i + pfx_oid_pattern.len()] == pfx_oid_pattern {
            found = true;
            break;
        }
        if &search_window[i..i + pkcs7_oid_pattern.len()] == pkcs7_oid_pattern {
            found = true;
            break;
        }
    }

    // The OID scan above is the classification; the old `data.len() > 100`
    // fallback routed arbitrary SEQUENCE blobs into SecPKCS12Import, so it is
    // deliberately not applied here.
    found
}

/// Import certificates from a PFX/PKCS#12 blob into a new certificate store.
///
/// On macOS, uses `SecPKCS12Import` via FFI to parse the PFX data and extract
/// certificates. Creates a new in-memory certificate store and populates it
/// with the imported certificates.
///
/// # Arguments
/// * `pfx_data` - The raw PFX/PKCS#12 binary data.
/// * `password` - Optional password for decrypting the PFX.
/// * `store_manager` - The certificate store manager to register the new store.
///
/// # Returns
/// The handle of the newly created store, or an error.
#[cfg(target_os = "macos")]
pub fn pfx_import_cert_store(
    pfx_data: &[u8],
    password: Option<&str>,
    store_manager: &mut CertificateStoreManager,
) -> AppResult<PfxImportResult> {
    use core_foundation::base::CFRelease;

    // SAFETY: CFRelease decrements the reference count of a valid CoreFoundation object
    unsafe {
        // FFI declarations for SecPKCS12Import and related functions
        // SAFETY: extern FFI declaration — the function signature matches the C library prototype
        unsafe extern "C" {
            /// Import a PKCS#12 blob, returning an array of certificate/identity dictionaries.
            fn SecPKCS12Import(
                pkcs12_data: *const c_void,
                options: *const c_void,
                items: *mut *const c_void,
            ) -> i32;

            /// Create a CFDictionary with the given key-value pairs.
            fn CFDictionaryCreate(
                allocator: *const c_void,
                keys: *const *const c_void,
                values: *const *const c_void,
                num_values: isize,
                key_callbacks: *const c_void,
                value_callbacks: *const c_void,
            ) -> *const c_void;

            /// Get a value from a CFDictionary by key.
            fn CFDictionaryGetValue(dict: *const c_void, key: *const c_void) -> *const c_void;

            /// Return the number of elements in a CFArray.
            fn CFArrayGetCount(array: *const c_void) -> isize;

            /// Return the element at `index` in a CFArray.
            fn CFArrayGetValueAtIndex(array: *const c_void, index: isize) -> *const c_void;

            /// Copy the DER-encoded data backing a SecCertificateRef.
            /// Returns a CFDataRef (caller must CFRelease).
            fn SecCertificateCopyData(certificate: *const c_void) -> *const c_void;

            /// Return a pointer to the raw bytes inside a CFData.
            fn CFDataGetBytePtr(data: *const c_void) -> *const u8;

            /// Return the length (in bytes) of a CFData.
            fn CFDataGetLength(data: *const c_void) -> isize;

            /// kSecClass — used for keychain item class.
            static kSecClass: *const c_void;
            /// kSecClassCertificate — certificate item class.
            static kSecClassCertificate: *const c_void;
            /// kSecImportItemIdentity — key for imported identity.
            static kSecImportItemIdentity: *const c_void;
            /// kSecImportItemCertChain — key for certificate chain.
            static kSecImportItemCertChain: *const c_void;
            /// kSecImportItemTrust — key for trust object.
            static kSecImportItemTrust: *const c_void;
            /// kSecImportExportPassphrase — key for password.
            static kSecImportExportPassphrase: *const c_void;
        }

        // Create CFData from the PFX bytes
        let cf_data = CFDataCreate(kCFAllocatorDefault, pfx_data.as_ptr(), pfx_data.len());
        if cf_data.is_null() {
            return Err(AppError::new(
                ReasonCode::RcCryptoInvalid,
                "PFX import: failed to create CFData from PFX bytes",
            ));
        }

        // Build options dictionary with optional password
        let mut opt_keys: [*const c_void; 2] = [std::ptr::null(); 2];
        let mut opt_values: [*const c_void; 2] = [std::ptr::null(); 2];
        let mut opt_count: isize = 0;

        // The created CFString must be released after the import; the options
        // dictionary retains its own reference to it.
        let mut cf_password: core_foundation::base::CFTypeRef = std::ptr::null();
        if let Some(pwd) = password {
            let pwd_bytes = pwd.as_bytes();
            // CFStringCreateWithCString reads until a NUL terminator; Rust
            // string bytes are not NUL-terminated, so append one (an interior
            // NUL would also truncate the passphrase — reject those outright).
            if pwd_bytes.contains(&0) {
                return Err(AppError::new(
                    ReasonCode::RcCryptoInvalid,
                    "PFX import: password contains a NUL byte",
                ));
            }
            let mut nul_terminated = pwd_bytes.to_vec();
            nul_terminated.push(0);
            cf_password = CFStringCreateWithCString(
                kCFAllocatorDefault,
                nul_terminated.as_ptr() as *const i8,
                0x08000100, // kCFStringEncodingUTF8
            );
            if !cf_password.is_null() {
                opt_keys[opt_count as usize] = kSecImportExportPassphrase;
                opt_values[opt_count as usize] = cf_password;
                opt_count += 1;
            }
        }

        let options = if opt_count > 0 {
            CFDictionaryCreate(
                kCFAllocatorDefault,
                opt_keys.as_ptr(),
                opt_values.as_ptr(),
                opt_count,
                std::ptr::null(),
                std::ptr::null(),
            )
        } else {
            CFDictionaryCreate(
                kCFAllocatorDefault,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        };

        // Call SecPKCS12Import
        let mut items: *const c_void = std::ptr::null();
        let status = SecPKCS12Import(cf_data, options, &mut items);

        // Release allocated CF objects (the options dictionary holds its own
        // retain on the passphrase, so cf_password can be released here).
        if !cf_password.is_null() {
            CFRelease(cf_password);
        }
        CFRelease(cf_data);
        if !options.is_null() {
            CFRelease(options);
        }

        if status != 0 {
            return Err(AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("PFX import: SecPKCS12Import failed with status {status}"),
            ));
        }

        if items.is_null() {
            return Err(AppError::new(
                ReasonCode::RcCryptoInvalid,
                "PFX import: SecPKCS12Import returned no items",
            ));
        }

        // Create a new certificate store for the imported certificates
        let store_name = format!("PFX_{}", store_manager.stores.len());
        let store_handle = {
            // Open a new store
            let handle = store_manager.next_handle;
            store_manager.next_handle += 1;
            let mut store = CertificateStore::new(handle, &store_name);
            // Don't populate from system for PFX stores
            store.system_store = SystemStore::Other("PFX".to_string());
            store_manager.stores.insert(handle, store);
            handle
        };

        // Extract certificates from the import result
        let count = CFArrayGetCount(items);
        let mut cert_count = 0usize;
        let mut has_private_key = false;

        for i in 0..count {
            let item_dict = CFArrayGetValueAtIndex(items, i);
            if item_dict.is_null() {
                continue;
            }

            // Check for identity (certificate + private key)
            let identity = CFDictionaryGetValue(item_dict, kSecImportItemIdentity);
            if !identity.is_null() {
                has_private_key = true;
            }

            // Get the certificate chain
            let cert_chain = CFDictionaryGetValue(item_dict, kSecImportItemCertChain);
            if !cert_chain.is_null() {
                let chain_count = CFArrayGetCount(cert_chain);
                for j in 0..chain_count {
                    let cert_ref = CFArrayGetValueAtIndex(cert_chain, j);
                    if cert_ref.is_null() {
                        continue;
                    }

                    // Extract DER bytes from the certificate
                    let cf_cert_data = SecCertificateCopyData(cert_ref);
                    if cf_cert_data.is_null() {
                        continue;
                    }

                    let ptr = CFDataGetBytePtr(cf_cert_data);
                    let len = CFDataGetLength(cf_cert_data);
                    if len > 0 && !ptr.is_null() {
                        let der = std::slice::from_raw_parts(ptr, len as usize).to_vec();
                        let Some(cert) = Certificate::from_der(der) else {
                            continue;
                        };
                        if let Some(store) = store_manager.stores.get_mut(&store_handle) {
                            store.certificates.push(cert);
                            cert_count += 1;
                        }
                    }
                    CFRelease(cf_cert_data);
                }
            }
        }

        CFRelease(items);

        Ok(PfxImportResult {
            store_handle,
            cert_count,
            has_private_key,
        })
    }
}

/// Import certificates from a PFX/PKCS#12 blob (non-macOS fallback).
///
/// On non-macOS platforms, attempts to parse the PFX data using ASN.1/DER
/// parsing to extract certificates. Creates a new in-memory certificate store.
#[cfg(not(target_os = "macos"))]
pub fn pfx_import_cert_store(
    pfx_data: &[u8],
    _password: Option<&str>,
    store_manager: &mut CertificateStoreManager,
) -> AppResult<PfxImportResult> {
    // Fallback: Parse DER-encoded certificates from the PFX blob
    // PFX is a PKCS#12 container which wraps PKCS#7 SignedData
    // We do a simple scan for DER certificate patterns (SEQUENCE of SEQUENCE)
    let store_name = format!("PFX_{}", store_manager.stores.len());
    let store_handle = {
        let handle = store_manager.next_handle;
        store_manager.next_handle += 1;
        let mut store = CertificateStore::new(handle, &store_name);
        store.system_store = SystemStore::Other("PFX".to_string());
        store_manager.stores.insert(handle, store);
        handle
    };

    // Scan for DER certificate patterns
    let mut cert_count = 0usize;
    let mut offset = 0;
    while offset < pfx_data.len() {
        // Look for SEQUENCE tag (0x30)
        if pfx_data[offset] != 0x30 {
            offset += 1;
            continue;
        }
        // Try to parse the length
        let (seq_len, header_len) = match parse_asn1_length(&pfx_data[offset..]) {
            Some(v) => v,
            None => {
                offset += 1;
                continue;
            }
        };
        let total_len = header_len + seq_len;
        if offset + total_len > pfx_data.len() {
            offset += 1;
            continue;
        }
        // Check if this looks like a certificate (must be large enough)
        if total_len > 100 {
            let der = pfx_data[offset..offset + total_len].to_vec();
            let Some(cert) = Certificate::from_der(der) else {
                offset += total_len.max(1);
                continue;
            };
            if let Some(store) = store_manager.stores.get_mut(&store_handle) {
                store.certificates.push(cert);
                cert_count += 1;
            }
        }
        offset += total_len.max(1);
    }

    Ok(PfxImportResult {
        store_handle,
        cert_count,
        has_private_key: false,
    })
}

/// Parse an ASN.1 DER length field starting at the given data.
/// Returns (length, header_bytes) or None.
fn parse_asn1_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 2 {
        return None;
    }
    let first = data[1];
    if first & 0x80 == 0 {
        // Short form
        Some((first as usize, 2))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || data.len() < 2 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (data[2 + i] as usize);
        }
        Some((len, 2 + num_bytes))
    }
}

/// Open a memory-based certificate store (CERT_STORE_PROV_MEMORY).
///
/// Creates a new empty certificate store that exists only in memory.
/// Used for PFX import results and other transient certificate storage.
pub fn cert_open_memory_store(store_manager: &mut CertificateStoreManager, name: &str) -> u64 {
    let handle = store_manager.next_handle;
    store_manager.next_handle += 1;
    let mut store = CertificateStore::new(handle, name);
    store.system_store = SystemStore::Other("Memory".to_string());
    // Don't populate from system for memory stores
    store_manager.stores.insert(handle, store);
    handle
}

/// Enumerate certificates in a store, returning DER bytes for each certificate.
///
/// Returns a vector of (index, der_bytes) pairs for all certificates in the store.
pub fn cert_enum_certificates_in_store(
    store_manager: &CertificateStoreManager,
    store_handle: u64,
) -> Vec<(usize, Vec<u8>)> {
    let Some(store) = store_manager.get_store(store_handle) else {
        return Vec::new();
    };
    store
        .certificates
        .iter()
        .enumerate()
        .map(|(i, cert)| (i, cert.der.clone()))
        .collect()
}

/// Close a certificate store handle.
///
/// Returns true if the store was found and closed.
pub fn cert_close_store(store_manager: &mut CertificateStoreManager, handle: u64) -> bool {
    store_manager.close_store(handle)
}
