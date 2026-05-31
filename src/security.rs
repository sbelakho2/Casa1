use crate::canonical::GuestException;
use crate::cpu::MemoryImage;
use crate::error::{AppError, AppResult};
use crate::ge::NetworkProfile;
use crate::reason::ReasonCode;
use crate::util;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
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
        // Derive a deterministic key from hardware_id + original_hash
        let mut key_material = Vec::with_capacity(48);
        key_material.extend_from_slice(&self.state.hardware_id);
        key_material.extend_from_slice(&section.original_hash);
        let key = sha256_hash(&key_material);

        let abs_addr = section.rva;
        let mut data = section.decrypted.clone();
        // XOR decrypt with derived key (cycling key bytes)
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }
        memory.map_bytes(abs_addr, &data);
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
        let abs_addr = section.rva;
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
    pub fn check_trigger_point(
        &mut self,
        memory: &mut MemoryImage,
        rva: u64,
    ) -> AppResult<bool> {
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
    fn generate_hardware_id() -> [u8; 16] {
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
    pub fn detect_steamstub(
        memory: &MemoryImage,
        base: u64,
    ) -> AppResult<Option<SteamstubHeader>> {
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
            if name.starts_with(".bind") || name.starts_with(".stub") {
                // Found a Steamstub section; read the header from its raw data
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
        if let Ok(magic) = memory.read_u32(last_section_end) {
            if magic == STEAMSTUB_MAGIC {
                return Self::parse_header_at(memory, last_section_end, 64);
            }
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
        // Determine encryption type from flags
        let encryption_type = match flags & 0xFF {
            0 => EncryptionType::Xor,
            1 => EncryptionType::Aes128,
            2 => EncryptionType::Aes256,
            other => EncryptionType::Custom(other),
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
            EncryptionType::Custom(_) => {
                return Err(AppError::new(
                    ReasonCode::RcDrmDecryptFailed,
                    "custom steamstub encryption not supported",
                ));
            }
        }
        memory.map_bytes(abs_addr, &data);
        // Fix up the entry point: write original_entry_point at PE + 0x28 (AddressOfEntryPoint)
        let e_lfanew = memory.read_u32(base + 0x3C)?;
        let pe_offset = base + e_lfanew as u64;
        memory.map_bytes(
            pe_offset + 40,
            &header.original_entry_point.to_le_bytes(),
        );
        self.decrypted_text = Some(data);
        self.loaded = true;
        Ok(())
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
    /// # Errors
    /// Returns an error if the data length is not a multiple of the AES block
    /// size (16 bytes) or the key length is invalid.
    pub fn decrypt_aes(data: &mut [u8], key: &[u8], iv: &[u8]) -> AppResult<()> {
        if data.len() % 16 != 0 {
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
                    AppError::new(ReasonCode::RcDrmDecryptFailed, "AES-128-CBC decryption failed")
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
                    AppError::new(ReasonCode::RcDrmDecryptFailed, "AES-256-CBC decryption failed")
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
        let mut mac =
            HmacSha256::new_from_slice(ticket).expect("HMAC accepts any key length");
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
        sections.iter().any(|name| name == ".aspack" || name == ".adata")
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
            name == ".themida"
                || name == ".winlice"
                || name == ".vmp0"
                || name == ".vmp1"
        })
    }

    /// Reads section names from a PE file's raw bytes.
    fn read_section_names(pe_data: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        if pe_data.len() < 64 {
            return names;
        }
        let e_lfanew = u32::from_le_bytes([
            pe_data[0x3C],
            pe_data[0x3D],
            pe_data[0x3E],
            pe_data[0x3F],
        ]) as usize;
        if pe_data.len() < e_lfanew + 6 {
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
        let e_lfanew = u32::from_le_bytes([
            pe_data[0x3C],
            pe_data[0x3D],
            pe_data[0x3E],
            pe_data[0x3F],
        ]) as usize;
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

        /// Read one bit from the bit-stream. Returns `None` at end-of-stream.
        let read_bit = |data: &[u8], pos: &mut usize| -> Option<u8> {
            let byte_idx = *pos / 8;
            let bit_idx = 7 - (*pos % 8);
            if byte_idx >= data.len() {
                return None;
            }
            *pos += 1;
            Some((data[byte_idx] >> bit_idx) & 1)
        };

        /// Read `n` bits from the bit-stream (MSB first).
        let read_bits = |data: &[u8], pos: &mut usize, n: usize| -> Option<u32> {
            let mut val = 0u32;
            for _ in 0..n {
                val = (val << 1) | read_bit(data, pos)? as u32;
            }
            Some(val)
        };

        /// Decode a gamma2-encoded integer from the bit stream.
        /// Gamma2 encoding: read bits in pairs (flag, value).
        /// While flag == 1, shift (value) into result; a flag of 0 terminates.
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
        let uncompressed_size = u64::from_le_bytes(
            data[5..13]
                .try_into()
                .map_err(|_| AppError::new(ReasonCode::RcDrmDecryptFailed, "LZMA header parse error"))?,
        );

        let max_size = if uncompressed_size == u64::MAX {
            16 * 1024 * 1024
        } else {
            uncompressed_size as usize
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
            *prob += ((2048 - *prob) >> 5) as u16;
            self.normalize();
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob -= (*prob >> 5);
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
            // Matched literal: use match byte as context
            let match_byte = if pos > self.rep0 as usize && (self.rep0 as usize) < pos {
                output[pos - 1 - self.rep0 as usize]
            } else {
                0
            };
            let mut match_byte = match_byte as u32;
            let mut i = 0;
            while i < 8 {
                let match_bit = (match_byte >> 7) & 1;
                match_byte <<= 1;
                let bit = self.rc.decode_bit(&mut self.literal[lit_index][symbol as usize]);
                symbol = (symbol << 1) | bit;
                if match_bit != bit {
                    // Rest of bits decoded normally
                    while symbol < 0x100 {
                        symbol = (symbol << 1) | self.rc.decode_bit(&mut self.literal[lit_index][symbol as usize]);
                    }
                    break;
                }
                i += 1;
            }
        } else {
            // Normal literal
            while symbol < 0x100 {
                symbol = (symbol << 1) | self.rc.decode_bit(&mut self.literal[lit_index][symbol as usize]);
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
                symbol = (symbol << 1) | rc.decode_bit(&mut len_codec.low[pos_state][symbol]) as usize;
            }
            symbol - 1 + LZMA_MATCH_MIN_LEN
        } else if rc.decode_bit(&mut len_codec.choice2[0]) == 0 {
            // Mid length: 3 bits + 8
            let mut symbol = 1usize;
            for _ in 0..3 {
                symbol = (symbol << 1) | rc.decode_bit(&mut len_codec.mid[pos_state][symbol]) as usize;
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
    fn decode_pos_slot(rc: &mut RangeCoder, pos_slot: &mut [u16; 64], len_state: usize) -> u32 {
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
            dist += rc.decode_direct_bits(num_direct_bits - LZMA_NUM_ALIGN_BITS) << LZMA_NUM_ALIGN_BITS;
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
            if self.rc.decode_bit(&mut self.is_match[self.state][pos_state]) == 0 {
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
                    if self.rc.decode_bit(&mut self.is_rep0_long[self.state][pos_state]) == 0 {
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
                    let temp = self.rep1;
                    self.rep1 = self.rep0;
                    self.rep0 = temp;
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
        let e_lfanew = u32::from_le_bytes([
            pe_data[0x3C],
            pe_data[0x3D],
            pe_data[0x3E],
            pe_data[0x3F],
        ]) as usize;
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
            output[e_lfanew + 40..e_lfanew + 44]
                .copy_from_slice(&original_entry.to_le_bytes());
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
                        output.push(output[start]);
                        output.push(output[start + 1]);
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

    /// Silently succeeds for `ThreadHideFromDebugger` requests.
    pub fn nt_set_information_thread(&self, _thread_handle: u64, info_class: u32) -> AppResult<()> {
        // Match on the info class for documentation purposes; all cases succeed.
        match info_class {
            THREAD_HIDE_FROM_DEBUGGER => { /* silently hide from debugger */ }
            _ => { /* other thread info classes: no-op */ }
        }
        Ok(())
    }

    /// Silently consumes debug output strings.
    pub fn output_debug_string(&self, _message: &str) -> AppResult<()> {
        Ok(())
    }

    /// Returns a monotonically increasing tick count.
    pub fn get_tick_count(&self) -> u32 {
        let prev = TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
        (prev + 30_000) as u32
    }

    /// Returns a monotonically increasing performance counter value.
    pub fn query_performance_counter(&self) -> u64 {
        let prev = PERF_COUNTER.fetch_add(1, Ordering::Relaxed);
        prev * 100 + 1_000_000
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticodeVerdict {
    /// The PE carries an embedded PKCS#7 signature whose signer certificate
    /// cryptographically signs the file's Authenticode hash.
    ///
    /// Scope note: this proves *integrity* (the file matches what the embedded
    /// signer signed) and *signer binding* (the signature verifies against the
    /// public key in the embedded signer certificate). It deliberately does
    /// **not** validate the signer certificate chain up to a trusted Windows
    /// root authority, because the emulator does not ship the Windows root
    /// certificate store. Callers that need full trust-chain validation must
    /// supply their own root store.
    Valid,
    /// The PE has no attribute certificate table (it is unsigned). This maps to
    /// the Win32 `TRUST_E_NOSIGNATURE` status.
    NoSignature,
    /// A signature is present but failed verification: tampered file, malformed
    /// structure, unsupported algorithm, or signature mismatch. This maps to the
    /// Win32 `TRUST_E_BAD_DIGEST` / `TRUST_E_NOSIGNATURE` failure family.
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

fn read_u16_le(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
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
        _ => None,
    }
}

/// Verify the embedded Authenticode signature on a PE image.
///
/// See [`AuthenticodeVerdict`] for the precise meaning and scope of each result.
pub fn verify_pe_authenticode(pe_data: &[u8]) -> AuthenticodeVerdict {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::{SignedData, SignerIdentifier};
    use der::asn1::OctetString;
    use der::{Decode, Encode};
    use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

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
    // The value octets of SpcIndirectDataContent (tag/length stripped) are what
    // the messageDigest signed attribute is computed over.
    let econtent_value = {
        let mut off = 0;
        match der_read_tlv(&econtent_full, &mut off) {
            Some((0x30, start, len)) => econtent_full[start..start + len].to_vec(),
            _ => return AuthenticodeVerdict::Invalid("eContent is not a SEQUENCE".into()),
        }
    };

    // Extract the PE hash claimed by the signature and verify it against the file.
    let (pe_hash_oid, claimed_pe_hash) = match parse_spc_indirect_data(&econtent_full) {
        Some(v) => v,
        None => return AuthenticodeVerdict::Invalid("malformed SpcIndirectData".into()),
    };
    let computed_pe_hash = match compute_authenticode_hash(pe_data, &pe_hash_oid) {
        Some(h) => h,
        None => {
            return AuthenticodeVerdict::Invalid(format!(
                "unsupported PE hash algorithm {pe_hash_oid}"
            ))
        }
    };
    if computed_pe_hash != claimed_pe_hash {
        return AuthenticodeVerdict::Invalid("PE hash does not match signature".into());
    }

    // Verify the signer's signature over the signed attributes (or eContent).
    let signer = match signed_data.signer_infos.0.iter().next() {
        Some(s) => s,
        None => return AuthenticodeVerdict::Invalid("no SignerInfo".into()),
    };
    let digest_oid = signer.digest_alg.oid.to_string();

    // Locate the signer's certificate by issuer + serial number.
    let signer_cert = {
        let ias = match &signer.sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => ias,
            SignerIdentifier::SubjectKeyIdentifier(_) => {
                return AuthenticodeVerdict::Invalid(
                    "subjectKeyIdentifier signer id is unsupported".into(),
                )
            }
        };
        let certs = match signed_data.certificates.as_ref() {
            Some(c) => c,
            None => return AuthenticodeVerdict::Invalid("no certificates in signature".into()),
        };
        let mut found = None;
        for choice in certs.0.iter() {
            if let CertificateChoices::Certificate(cert) = choice {
                if cert.tbs_certificate.issuer == ias.issuer
                    && cert.tbs_certificate.serial_number == ias.serial_number
                {
                    found = Some(cert.clone());
                    break;
                }
            }
        }
        match found {
            Some(c) => c,
            None => return AuthenticodeVerdict::Invalid("signer certificate not found".into()),
        }
    };

    // Extract the signer's RSA public key.
    let spki_der = match signer_cert.tbs_certificate.subject_public_key_info.to_der() {
        Ok(d) => d,
        Err(e) => return AuthenticodeVerdict::Invalid(format!("bad SubjectPublicKeyInfo: {e}")),
    };
    let public_key = match RsaPublicKey::from_public_key_der(&spki_der) {
        Ok(k) => k,
        Err(_) => {
            return AuthenticodeVerdict::Invalid(
                "signer key is not RSA or could not be parsed".into(),
            )
        }
    };

    // Determine the message that was actually signed.
    let message = match signer.signed_attrs.as_ref() {
        Some(attrs) => {
            // The messageDigest signed attribute must equal the hash of eContent.
            let mut message_digest: Option<Vec<u8>> = None;
            for attr in attrs.iter() {
                if attr.oid.to_string() == OID_MESSAGE_DIGEST {
                    if let Some(value) = attr.values.iter().next() {
                        if let Ok(octets) = value.decode_as::<OctetString>() {
                            message_digest = Some(octets.as_bytes().to_vec());
                        }
                    }
                }
            }
            let message_digest = match message_digest {
                Some(d) => d,
                None => {
                    return AuthenticodeVerdict::Invalid(
                        "missing messageDigest signed attribute".into(),
                    )
                }
            };
            let expected = match digest_with_oid(&digest_oid, &econtent_value) {
                Some(d) => d,
                None => {
                    return AuthenticodeVerdict::Invalid(format!(
                        "unsupported signed-attribute digest {digest_oid}"
                    ))
                }
            };
            if message_digest != expected {
                return AuthenticodeVerdict::Invalid(
                    "messageDigest attribute does not match eContent".into(),
                );
            }
            // The signature is over the DER SET encoding of the signed attributes.
            match attrs.to_der() {
                Ok(d) => d,
                Err(e) => {
                    return AuthenticodeVerdict::Invalid(format!(
                        "signed attributes re-encode failed: {e}"
                    ))
                }
            }
        }
        None => econtent_value,
    };

    // Verify the RSA PKCS#1 v1.5 signature over `message`.
    let signature = match RsaSignature::try_from(signer.signature.as_bytes()) {
        Ok(s) => s,
        Err(_) => return AuthenticodeVerdict::Invalid("malformed signature value".into()),
    };
    let verify_result = match digest_oid.as_str() {
        OID_SHA256 => VerifyingKey::<Sha256>::new(public_key).verify(&message, &signature),
        OID_SHA1 => VerifyingKey::<sha1::Sha1>::new(public_key).verify(&message, &signature),
        other => {
            return AuthenticodeVerdict::Invalid(format!("unsupported signature digest {other}"))
        }
    };
    match verify_result {
        Ok(()) => AuthenticodeVerdict::Valid,
        Err(_) => AuthenticodeVerdict::Invalid("signature verification failed".into()),
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
        let code_hash = sha256_hash(&code);
        let config = DenuvoConfig {
            version: DenuvoVersion::V5,
            enabled: true,
            integrity_check_interval_ms: 1000,
            code_sections: vec![CodeSection {
                rva: 0x1000,
                size: code.len() as u32,
                original_hash: code_hash,
                decrypted: code.clone(),
                encrypted: true,
            }],
            trigger_points: vec![0x2000],
        };
        let mut emulator = DenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &code);
        emulator.initialize(&mut memory, 0).unwrap();
        assert!(emulator.state.initialized);
        emulator.decrypt_code_section(&mut memory, 0).unwrap();
        assert!(!emulator.config.code_sections[0].encrypted);
        assert!(emulator.state.code_sections_decrypted);
        let decrypted_data = memory.read_bytes(0x1000, 5).unwrap();
        assert_ne!(decrypted_data, code);
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
        pe_data[pe_offset as usize + 6..pe_offset as usize + 8].copy_from_slice(&num_sections.to_le_bytes());
        let size_optional: u16 = 0xF0;
        pe_data[pe_offset as usize + 20..pe_offset as usize + 22].copy_from_slice(&size_optional.to_le_bytes());
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
        pe_data[pe_offset as usize + 6..pe_offset as usize + 8].copy_from_slice(&num_sections.to_le_bytes());
        let size_optional: u16 = 0xF0;
        pe_data[pe_offset as usize + 20..pe_offset as usize + 22].copy_from_slice(&size_optional.to_le_bytes());
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
        pe_data[pe_offset as usize + 6..pe_offset as usize + 8].copy_from_slice(&num_sections.to_le_bytes());
        let size_optional: u16 = 0xF0;
        pe_data[pe_offset as usize + 20..pe_offset as usize + 22].copy_from_slice(&size_optional.to_le_bytes());
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
        let mut compressed = Vec::new();
        compressed.push(0x24);
        compressed.push(0x1A);
        compressed.push(0x40);
        let result = UpxUnpacker::decompress_nrv2b(&compressed);
        assert!(result.is_ok());
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
        assert!(state.nt_set_information_thread(0x1234, 17).is_ok());
        assert!(state.output_debug_string("test").is_ok());
        let tick1 = state.get_tick_count();
        let tick2 = state.get_tick_count();
        assert!(tick2 > tick1);
        let perf1 = state.query_performance_counter();
        let perf2 = state.query_performance_counter();
        assert!(perf2 > perf1);
    }
}
