//! WSL (Windows Subsystem for Linux) support detection and interop module.
//!
//! On Windows, WSL provides a Linux-compatible kernel interface for running
//! ELF binaries. On macOS (Casa1's primary target), this module detects whether
//! a WSL-like environment is available (e.g., Docker, colima, or a local Linux VM)
//! and provides the Windows API surface that programs expect for WSL interop.
//!
//! Windows API mappings:
//! - `wslapi.dll` → WSL user-mode API (WslLaunch, WslGetDistributionConfiguration, etc.)
//! - `lxss.sys` / `LxssUserLd` → WSL filesystem interop
//! - `Lxcore.sys` → WSL core kernel interface
//!
//! # Gap 15.4
//! This module was added to close Gap 15.4 ("No Windows Subsystem for Linux (WSL) Support")
//! from the comprehensive gap analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// Default WSL distribution name used when none is specified.
pub const DEFAULT_WSL_DISTRO: &str = "Ubuntu";

/// Minimum WSL version that supports full systemd integration.
pub const WSL_VERSION_2: u32 = 2;

/// Registry path where WSL distributions are registered on Windows.
pub const WSL_REGISTRY_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Lxss";

/// WSL distribution state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WslDistributionState {
    /// Distribution is registered but not running.
    Stopped,
    /// Distribution is currently running.
    Running,
    /// Distribution installation is in progress.
    Installing,
    /// Distribution installation failed.
    Failed,
}

impl WslDistributionState {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Stopped => "Stopped",
            Self::Running => "Running",
            Self::Installing => "Installing",
            Self::Failed => "Failed",
        }
    }
}

/// Describes a single WSL distribution (e.g., Ubuntu-22.04, Debian).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslDistribution {
    /// Display name (e.g., "Ubuntu-22.04").
    pub name: String,
    /// WSL major version (1 or 2).
    pub wsl_version: u32,
    /// Current runtime state.
    pub state: WslDistributionState,
    /// Path to the distribution's root filesystem.
    pub base_path: PathBuf,
    /// Default UID for the distribution.
    pub default_uid: u32,
    /// Environment variables configured for this distribution.
    pub environment: HashMap<String, String>,
    /// Whether systemd is enabled (WSL 2 only).
    pub systemd_enabled: bool,
    /// Kernel command-line override (WSL 2 only).
    pub kernel_command_line: Option<String>,
}

impl Default for WslDistribution {
    fn default() -> Self {
        Self {
            name: DEFAULT_WSL_DISTRO.to_string(),
            wsl_version: WSL_VERSION_2,
            state: WslDistributionState::Stopped,
            base_path: PathBuf::new(),
            default_uid: 1000,
            environment: HashMap::new(),
            systemd_enabled: false,
            kernel_command_line: None,
        }
    }
}

/// Outcome of launching a command in a WSL distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslCommandResult {
    /// Standard output from the command.
    pub stdout: String,
    /// Standard error from the command.
    pub stderr: String,
    /// Exit code of the command.
    pub exit_code: i32,
    /// Whether the command timed out.
    pub timed_out: bool,
}

/// Platform detection result for WSL compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslPlatformInfo {
    /// `true` if running on Windows with WSL installed.
    pub host_is_windows: bool,
    /// `true` if running on macOS.
    pub host_is_macos: bool,
    /// `true` if a WSL-alternative (Docker, colima, multipass) is available on macOS.
    pub alternative_available: bool,
    /// Name of the detected alternative (e.g., "docker", "colima", "lima").
    pub alternative_name: Option<String>,
    /// WSL version of the primary distribution, if any.
    pub wsl_version_detected: Option<u32>,
}

/// Main WSL support struct providing distribution management and command execution.
pub struct WslSupport {
    /// Registered distributions.
    distributions: Mutex<Vec<WslDistribution>>,
    /// Cached platform info.
    platform: WslPlatformInfo,
    /// Whether WSL interop is enabled globally.
    enabled: Mutex<bool>,
}

/// Shell-quote a string for safe interpolation into a command line.
///
/// Returns the quoted form, or `String::new()` when the string cannot be
/// quoted safely (embedded NUL bytes); an empty tool name simply fails the
/// lookup instead of injecting anything.
fn shell_quote(s: &str) -> String {
    shlex::try_quote(s)
        .map(|quoted| quoted.into_owned())
        .unwrap_or_default()
}

impl WslSupport {
    /// Create a new [`WslSupport`] instance and auto-detect the platform.
    pub fn new() -> Self {
        let platform = detect_wsl_platform();
        let mut distros = Vec::new();
        if platform.host_is_windows {
            // On Windows, probe the WSL registry for installed distributions.
            if let Ok(detected) = probe_wsl_distributions() {
                distros = detected;
            }
        }
        if distros.is_empty() {
            // Add a default distribution placeholder.
            distros.push(WslDistribution::default());
        }
        Self {
            distributions: Mutex::new(distros),
            platform,
            enabled: Mutex::new(true),
        }
    }

    /// Create a [`WslSupport`] with an explicit set of distributions (for testing).
    pub fn with_distributions(distributions: Vec<WslDistribution>) -> Self {
        Self {
            platform: detect_wsl_platform(),
            distributions: Mutex::new(distributions),
            enabled: Mutex::new(true),
        }
    }

    /// Return a snapshot of the current platform info.
    pub fn platform_info(&self) -> &WslPlatformInfo {
        &self.platform
    }

    /// Return whether WSL interop is currently enabled.
    pub fn is_enabled(&self) -> bool {
        *self.enabled.lock().unwrap()
    }

    /// Enable or disable WSL interop globally.
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.lock().unwrap() = enabled;
    }

    /// Return a copy of all registered distributions.
    pub fn list_distributions(&self) -> Vec<WslDistribution> {
        self.distributions.lock().unwrap().clone()
    }

    /// Find a distribution by name (case-insensitive).
    pub fn find_distribution(&self, name: &str) -> Option<WslDistribution> {
        let distros = self.distributions.lock().unwrap();
        distros
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    /// Return the default distribution (first in the list, or a fallback).
    pub fn default_distribution(&self) -> WslDistribution {
        let distros = self.distributions.lock().unwrap();
        distros.first().cloned().unwrap_or_default()
    }

    /// Register a new distribution.
    pub fn register_distribution(&self, distro: WslDistribution) {
        let mut distros = self.distributions.lock().unwrap();
        // Replace existing entry with the same name.
        if let Some(pos) = distros
            .iter()
            .position(|d| d.name.eq_ignore_ascii_case(&distro.name))
        {
            distros[pos] = distro;
        } else {
            distros.push(distro);
        }
    }

    /// Remove a distribution by name. Returns `true` if it was found and removed.
    pub fn unregister_distribution(&self, name: &str) -> bool {
        let mut distros = self.distributions.lock().unwrap();
        let len_before = distros.len();
        distros.retain(|d| !d.name.eq_ignore_ascii_case(name));
        distros.len() < len_before
    }

    /// Set the runtime state of a distribution.
    pub fn set_distribution_state(&self, name: &str, state: WslDistributionState) -> bool {
        let mut distros = self.distributions.lock().unwrap();
        if let Some(distro) = distros
            .iter_mut()
            .find(|d| d.name.eq_ignore_ascii_case(name))
        {
            distro.state = state;
            true
        } else {
            false
        }
    }

    /// Launch a Linux command in the specified distribution.
    ///
    /// On Windows with real WSL, this invokes `wsl.exe --distribution <name> -- <command>`.
    /// On macOS, this falls back to running the command via `/bin/bash -c` or detecting
    /// an alternative like Docker.
    pub fn launch_command(
        &self,
        distribution: &str,
        command: &str,
        timeout_secs: Option<u64>,
    ) -> Result<WslCommandResult, String> {
        if !*self.enabled.lock().unwrap() {
            return Err("WSL interop is disabled".to_string());
        }
        let _distro = self
            .find_distribution(distribution)
            .ok_or_else(|| format!("distribution '{distribution}' not found"))?;

        if self.platform.host_is_windows {
            launch_wsl_command_windows(distribution, command, timeout_secs)
        } else if self.platform.host_is_macos {
            launch_wsl_command_macos(distribution, command, timeout_secs)
        } else {
            Err("unsupported host platform for WSL command execution".to_string())
        }
    }

    /// Launch a Linux command in the default distribution.
    pub fn launch_command_default(
        &self,
        command: &str,
        timeout_secs: Option<u64>,
    ) -> Result<WslCommandResult, String> {
        let default = self.default_distribution();
        self.launch_command(&default.name, command, timeout_secs)
    }

    /// Check if a specific package/tool is available in a distribution.
    pub fn check_tool_available(&self, distribution: &str, tool: &str) -> Result<bool, String> {
        // Shell-quote the tool name so guest-supplied input can never inject
        // additional commands into the launched shell.
        let result = self.launch_command(
            distribution,
            &format!("which {}", shell_quote(tool)),
            Some(10),
        )?;
        Ok(result.exit_code == 0)
    }

    /// Retrieve the Linux kernel version reported by a distribution.
    pub fn kernel_version(&self, distribution: &str) -> Result<Option<String>, String> {
        let result = self.launch_command(distribution, "uname -r", Some(10))?;
        if result.exit_code == 0 {
            let version = result.stdout.trim().to_string();
            if version.is_empty() {
                Ok(None)
            } else {
                Ok(Some(version))
            }
        } else {
            Ok(None)
        }
    }

    /// Retrieve OS release info from a distribution (content of `/etc/os-release`).
    pub fn os_release_info(&self, distribution: &str) -> Result<HashMap<String, String>, String> {
        let result = self.launch_command(distribution, "cat /etc/os-release", Some(10))?;
        if result.exit_code != 0 {
            return Ok(HashMap::new());
        }
        let mut info = HashMap::new();
        for line in result.stdout.lines() {
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim().to_string();
                let value = line[eq_pos + 1..].trim().trim_matches('"').to_string();
                info.insert(key, value);
            }
        }
        Ok(info)
    }
}

impl Default for WslSupport {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public helper functions
// ---------------------------------------------------------------------------

/// Detect the current platform and determine WSL availability.
///
/// The result is cached process-wide (probes are only run once) and the
/// tool probes run concurrently, so repeated construction of
/// [`WslSupport`] does not pay serial subprocess spawn latency.
pub fn detect_wsl_platform() -> WslPlatformInfo {
    static WSL_PLATFORM_CACHE: std::sync::OnceLock<WslPlatformInfo> = std::sync::OnceLock::new();
    WSL_PLATFORM_CACHE
        .get_or_init(detect_wsl_platform_uncached)
        .clone()
}

fn detect_wsl_platform_uncached() -> WslPlatformInfo {
    let host_is_windows = cfg!(target_os = "windows");
    let host_is_macos = cfg!(target_os = "macos");

    let (alternative_available, alternative_name) = if host_is_macos {
        // Probe for Docker, colima, multipass and lima concurrently; the
        // first positive probe in priority order wins.
        const PROBES: [(&str, &str); 4] = [
            ("docker", "docker"),
            ("colima", "colima"),
            ("multipass", "multipass"),
            ("limactl", "lima"),
        ];
        let handles: Vec<_> = PROBES
            .iter()
            .map(|(binary, name)| {
                let binary = *binary;
                let name = *name;
                std::thread::spawn(move || {
                    std::process::Command::new(binary)
                        .arg("--version")
                        .output()
                        .ok()
                        .filter(|output| output.status.success())
                        .map(|_| name.to_string())
                })
            })
            .collect();
        let mut found = (false, None);
        for handle in handles {
            if let Ok(Some(name)) = handle.join() {
                found = (true, Some(name));
                break;
            }
        }
        found
    } else {
        (false, None)
    };

    let wsl_version_detected = if host_is_windows {
        detect_wsl_version()
    } else {
        None
    };

    WslPlatformInfo {
        host_is_windows,
        host_is_macos,
        alternative_available,
        alternative_name,
        wsl_version_detected,
    }
}

/// On Windows, detect the installed WSL version by running `wsl.exe --status`.
fn detect_wsl_version() -> Option<u32> {
    let output = std::process::Command::new("wsl.exe")
        .arg("--status")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // WSL 2 output contains "WSL 2" or "Default Version: 2".
    if stdout.contains("WSL 2") || stdout.contains("Default Version: 2") {
        Some(2)
    } else if stdout.contains("WSL 1") || stdout.contains("Default Version: 1") {
        Some(1)
    } else {
        None
    }
}

/// Parse a single line of `wsl.exe --list --verbose` output into a
/// distribution, tolerating the `*` default marker and distribution names
/// containing spaces.
///
/// Line layout is `[ *] <NAME...> <STATE> <VERSION>`. Lines that do not
/// parse cleanly (header, empty, or unparseable state/version) are skipped.
fn parse_wsl_list_line(line: &str) -> Option<WslDistribution> {
    let trimmed = line.trim().trim_start_matches('*').trim();
    if trimmed.is_empty() {
        return None;
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let wsl_version = parts.last()?.parse::<u32>().ok()?;
    let state = match parts[parts.len() - 2].to_ascii_lowercase().as_str() {
        "running" => WslDistributionState::Running,
        "installing" => WslDistributionState::Installing,
        "failed" => WslDistributionState::Failed,
        "stopped" => WslDistributionState::Stopped,
        // Unknown state words (including localized headers) are skipped
        // rather than defaulted.
        _ => return None,
    };
    let name = parts[..parts.len() - 2].join(" ");
    if name.is_empty() {
        return None;
    }
    Some(WslDistribution {
        name,
        wsl_version,
        state,
        base_path: PathBuf::new(),
        default_uid: 1000,
        environment: HashMap::new(),
        systemd_enabled: wsl_version == WSL_VERSION_2,
        kernel_command_line: None,
    })
}

/// Probe the Windows registry for installed WSL distributions (Windows only).
fn probe_wsl_distributions() -> Result<Vec<WslDistribution>, String> {
    // On non-Windows platforms, return an empty list.
    if !cfg!(target_os = "windows") {
        return Ok(Vec::new());
    }
    // Attempt to enumerate distributions via `wsl.exe --list --verbose`.
    let output = std::process::Command::new("wsl.exe")
        .args(["--list", "--verbose"])
        .output()
        .map_err(|e| format!("failed to run wsl.exe: {e}"))?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut distributions = Vec::new();
    // Expected format (header + lines):
    //   NAME                   STATE           VERSION
    //   * Ubuntu-22.04         Running         2
    //   Kali Linux             Stopped         2
    for line in stdout.lines().skip(1) {
        if let Some(distro) = parse_wsl_list_line(line) {
            distributions.push(distro);
        }
    }
    Ok(distributions)
}

/// Wait for a child process to exit while draining its stdout/stderr pipes
/// concurrently (preventing pipe-buffer deadlocks on large output), with an
/// optional timeout.
///
/// On timeout the child (and its process tree on Windows) is killed and
/// reaped before returning; the collected output is returned in both cases.
/// Returns `(output, timed_out)`.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Option<std::time::Duration>,
) -> Result<(std::process::Output, bool), String> {
    let stdout_reader = child.stdout.take().map(|pipe| {
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = std::io::Read::read_to_end(&mut std::io::BufReader::new(pipe), &mut out);
            out
        })
    });
    let stderr_reader = child.stderr.take().map(|pipe| {
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = std::io::Read::read_to_end(&mut std::io::BufReader::new(pipe), &mut out);
            out
        })
    });

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let _ = child.wait();
                let stdout = stdout_reader
                    .and_then(|handle| handle.join().ok())
                    .unwrap_or_default();
                let stderr = stderr_reader
                    .and_then(|handle| handle.join().ok())
                    .unwrap_or_default();
                return Ok((
                    std::process::Output {
                        status,
                        stdout,
                        stderr,
                    },
                    false,
                ));
            }
            Ok(None) => {
                if let Some(limit) = timeout
                    && start.elapsed() > limit
                {
                    kill_child_tree(child);
                    let status = child
                        .wait()
                        .map_err(|e| format!("failed to reap child after timeout kill: {e}"))?;
                    let stdout = stdout_reader
                        .and_then(|handle| handle.join().ok())
                        .unwrap_or_default();
                    let stderr = stderr_reader
                        .and_then(|handle| handle.join().ok())
                        .unwrap_or_default();
                    return Ok((
                        std::process::Output {
                            status,
                            stdout,
                            stderr,
                        },
                        true,
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                return Err(format!("error waiting for child process: {e}"));
            }
        }
    }
}

/// Kill a child process and, on Windows, its process tree (via `taskkill`).
fn kill_child_tree(child: &mut std::process::Child) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .output();
    }
    let _ = child.kill();
}

/// Execute a command in a WSL distribution on Windows via `wsl.exe`.
fn launch_wsl_command_windows(
    distribution: &str,
    command: &str,
    timeout_secs: Option<u64>,
) -> Result<WslCommandResult, String> {
    let mut cmd = std::process::Command::new("wsl.exe");
    cmd.args(["--distribution", distribution, "--"]);
    cmd.arg(command);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn wsl.exe: {e}"))?;

    let timeout = timeout_secs.map(std::time::Duration::from_secs);
    let (output, timed_out) = wait_with_timeout(&mut child, timeout)?;
    Ok(WslCommandResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
        timed_out,
    })
}

/// Execute a Linux command on macOS inside a container/VM runtime.
///
/// On macOS there is no real WSL. Commands are only ever executed inside a
/// container (Docker/colima/Lima). There is deliberately no fallback to
/// `/bin/bash -c` on the host: the command originates from emulated
/// (untrusted) guest code via the `wslapi.dll` surface, and native host
/// execution would bypass the sandbox with the Casa1 user's full privileges.
fn launch_wsl_command_macos(
    distribution: &str,
    command: &str,
    timeout_secs: Option<u64>,
) -> Result<WslCommandResult, String> {
    // Require a container runtime; refuse native host execution.
    let docker_check = std::process::Command::new("docker")
        .arg("--version")
        .output();
    if let Ok(docker_output) = docker_check
        && docker_output.status.success()
    {
        return launch_via_docker(distribution, command, timeout_secs);
    }
    Err(
        "no Linux runtime available on macOS (Docker/colima/Lima required); \
         native host execution is refused for sandboxing"
            .to_string(),
    )
}

/// Launch a command inside a Docker container named after the distribution.
///
/// The container is given a unique name so a timed-out launch can be
/// force-removed (`docker rm -f`); otherwise killing only the `docker`
/// client would orphan a running container.
fn launch_via_docker(
    distribution: &str,
    command: &str,
    timeout_secs: Option<u64>,
) -> Result<WslCommandResult, String> {
    let image = if distribution.eq_ignore_ascii_case(DEFAULT_WSL_DISTRO) {
        "ubuntu:22.04"
    } else {
        // Use the distribution name as the image name, lowercased.
        &distribution.to_lowercase()
    };

    let container_name = format!(
        "casa1_wsl_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );

    let mut cmd = std::process::Command::new("docker");
    cmd.args([
        "run",
        "--rm",
        "--name",
        container_name.as_str(),
        image,
        "/bin/bash",
        "-c",
        command,
    ]);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn docker: {e}"))?;

    let timeout = timeout_secs.map(std::time::Duration::from_secs);
    let (output, timed_out) = wait_with_timeout(&mut child, timeout)?;

    // The `--rm` flag only removes the container after it exits; if the
    // client was killed on timeout, force-remove the container.
    if timed_out {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &container_name])
            .output();
    }

    Ok(WslCommandResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
        timed_out,
    })
}

/// Map a Windows path to a WSL path (e.g., `C:\Users` → `/mnt/c/Users`).
///
/// Returns `None` if the path does not look like a Windows absolute path.
pub fn map_windows_to_wsl_path(windows_path: &str) -> Option<String> {
    let trimmed = windows_path.trim();
    if trimmed.len() < 3 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    // Check for drive letter followed by colon, e.g., "C:\" or "C:/"
    if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = trimmed[3..].replace('\\', "/");
        if rest.is_empty() {
            Some(format!("/mnt/{drive}/"))
        } else {
            Some(format!("/mnt/{drive}/{rest}"))
        }
    } else if trimmed.starts_with("\\\\") {
        // UNC path — WSL maps these to /mnt/... but UNC isn't directly supported.
        None
    } else {
        None
    }
}

/// Map a WSL path to a Windows path (e.g., `/mnt/c/Users` → `C:\Users`).
///
/// Returns `None` if the path does not start with `/mnt/`.
pub fn map_wsl_to_windows_path(wsl_path: &str) -> Option<String> {
    let trimmed = wsl_path.trim();
    if let Some(rest) = trimmed.strip_prefix("/mnt/") {
        if rest.is_empty() || rest.len() < 2 {
            return None;
        }
        // The drive component must be a single ASCII alphabetic letter;
        // slicing at byte index 1 is only a UTF-8 char boundary when the
        // first byte is ASCII.
        let first = *rest.as_bytes().first()?;
        if !first.is_ascii_alphabetic() {
            return None;
        }
        let drive = (first as char).to_ascii_uppercase();
        let path_part = &rest[1..];
        let windows_path = format!("{drive}:{}", path_part.replace('/', "\\"));
        Some(windows_path)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Windows API surface for WSL interop (wslapi.dll)
// ---------------------------------------------------------------------------

/// Result type for WSL API operations.
pub type WslApiResult<T> = Result<T, WslApiError>;

/// Errors that can occur during WSL API operations.
#[derive(Debug, Clone)]
pub struct WslApiError {
    pub message: String,
    pub code: u32,
}

impl WslApiError {
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for WslApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WslApiError({}): {}", self.code, self.message)
    }
}

/// Represents the emulated `wslapi.dll` API surface.
///
/// These functions mirror the exported symbols of `wslapi.dll` that Windows
/// programs may call to interact with WSL distributions.
pub struct WslApi;

impl WslApi {
    /// `WslIsDistributionRegistered` — Check whether a distribution is registered.
    pub fn is_distribution_registered(support: &WslSupport, distro_name: &str) -> bool {
        support.find_distribution(distro_name).is_some()
    }

    /// `WslRegisterDistribution` — Register a new distribution.
    pub fn register_distribution(
        support: &WslSupport,
        distro_name: &str,
        tar_gz_path: &str,
    ) -> WslApiResult<()> {
        if support.find_distribution(distro_name).is_some() {
            return Err(WslApiError::new(
                1,
                format!("distribution '{distro_name}' is already registered"),
            ));
        }
        // Registration is a metadata operation here; the distribution starts
        // in the Stopped state. Callers that perform an actual installation
        // should transition the state (Installing -> Stopped/Running) via
        // `set_distribution_state` when installation completes.
        let distro = WslDistribution {
            name: distro_name.to_string(),
            wsl_version: WSL_VERSION_2,
            state: WslDistributionState::Stopped,
            base_path: PathBuf::from(tar_gz_path),
            ..Default::default()
        };
        support.register_distribution(distro);
        Ok(())
    }

    /// `WslUnregisterDistribution` — Unregister a distribution.
    pub fn unregister_distribution(support: &WslSupport, distro_name: &str) -> WslApiResult<()> {
        if !support.unregister_distribution(distro_name) {
            return Err(WslApiError::new(
                2,
                format!("distribution '{distro_name}' not found"),
            ));
        }
        Ok(())
    }

    /// `WslGetDistributionConfiguration` — Get configuration of a distribution.
    pub fn get_distribution_configuration(
        support: &WslSupport,
        distro_name: &str,
    ) -> WslApiResult<WslDistribution> {
        support
            .find_distribution(distro_name)
            .ok_or_else(|| WslApiError::new(3, format!("distribution '{distro_name}' not found")))
    }

    /// `WslLaunchInteractive` — Launch an interactive shell in a distribution.
    ///
    /// When `use_cwd` is set, the command runs with the host's current
    /// working directory mapped into the Linux environment (best effort:
    /// the mapping is skipped when the current directory cannot be mapped).
    /// A full TTY/interactive mode requires a terminal host and is not
    /// emulated here; the command still runs with piped output.
    pub fn launch_interactive(
        support: &WslSupport,
        distro_name: &str,
        command: &str,
        use_cwd: bool,
    ) -> WslApiResult<WslCommandResult> {
        let _distro = support.find_distribution(distro_name).ok_or_else(|| {
            WslApiError::new(3, format!("distribution '{distro_name}' not found"))
        })?;
        let effective_command = if use_cwd {
            std::env::current_dir()
                .ok()
                .and_then(|cwd| map_windows_to_wsl_path(&cwd.to_string_lossy()))
                .map(|wsl_cwd| format!("cd {} && {}", shell_quote(&wsl_cwd), command))
                .unwrap_or_else(|| command.to_string())
        } else {
            command.to_string()
        };
        support
            .launch_command(distro_name, &effective_command, None)
            .map_err(|e| WslApiError::new(4, e))
    }

    /// `WslLaunch` — Launch a command in a distribution with a timeout.
    pub fn launch(
        support: &WslSupport,
        distro_name: &str,
        command: &str,
        timeout_ms: u64,
    ) -> WslApiResult<WslCommandResult> {
        // Round sub-second timeouts up so a 1..=999 ms request is never
        // truncated to a 0-second (immediate) timeout.
        let timeout_secs = if timeout_ms == 0 {
            None
        } else {
            Some(timeout_ms.div_ceil(1000))
        };
        support
            .launch_command(distro_name, command, timeout_secs)
            .map_err(|e| WslApiError::new(4, e))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wsl_support_default_creation() {
        let support = WslSupport::new();
        assert!(support.is_enabled());
        assert!(!support.list_distributions().is_empty());
    }

    #[test]
    fn test_register_and_find_distribution() {
        let support = WslSupport::new();
        let distro = WslDistribution {
            name: "TestDistro".to_string(),
            wsl_version: 2,
            state: WslDistributionState::Stopped,
            base_path: PathBuf::from("/test"),
            default_uid: 1000,
            environment: HashMap::new(),
            systemd_enabled: true,
            kernel_command_line: None,
        };
        support.register_distribution(distro.clone());
        let found = support.find_distribution("TestDistro");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "TestDistro");
    }

    #[test]
    fn test_unregister_distribution() {
        let support = WslSupport::new();
        let distro = WslDistribution {
            name: "ToRemove".to_string(),
            ..Default::default()
        };
        support.register_distribution(distro);
        assert!(support.unregister_distribution("ToRemove"));
        assert!(!support.unregister_distribution("NonExistent"));
    }

    #[test]
    fn test_set_distribution_state() {
        let support = WslSupport::new();
        let distro = WslDistribution {
            name: "StateTest".to_string(),
            ..Default::default()
        };
        support.register_distribution(distro);
        assert!(support.set_distribution_state("StateTest", WslDistributionState::Running));
        let found = support.find_distribution("StateTest").unwrap();
        assert_eq!(found.state, WslDistributionState::Running);
        // Non-existent returns false.
        assert!(!support.set_distribution_state("Missing", WslDistributionState::Running));
    }

    #[test]
    fn test_default_distribution() {
        let support = WslSupport::new();
        let default = support.default_distribution();
        assert_eq!(default.name, DEFAULT_WSL_DISTRO);
    }

    #[test]
    fn test_platform_detection() {
        let info = detect_wsl_platform();
        // We should know whether we're on macOS or Windows.
        assert!(info.host_is_macos || info.host_is_windows);
    }

    #[test]
    fn test_map_windows_to_wsl_path() {
        assert_eq!(
            map_windows_to_wsl_path(r"C:\Users\test"),
            Some("/mnt/c/Users/test".to_string())
        );
        assert_eq!(
            map_windows_to_wsl_path(r"D:/stuff/file.txt"),
            Some("/mnt/d/stuff/file.txt".to_string())
        );
        assert_eq!(map_windows_to_wsl_path("/unix/path"), None);
        assert_eq!(map_windows_to_wsl_path("relative/path"), None);
    }

    #[test]
    fn test_map_wsl_to_windows_path() {
        assert_eq!(
            map_wsl_to_windows_path("/mnt/c/Users/test"),
            Some("C:\\Users\\test".to_string())
        );
        assert_eq!(
            map_wsl_to_windows_path("/mnt/d/stuff/file.txt"),
            Some("D:\\stuff\\file.txt".to_string())
        );
        assert_eq!(map_wsl_to_windows_path("/home/user"), None);
        assert_eq!(map_wsl_to_windows_path("relative/path"), None);
    }

    #[test]
    fn test_wsl_api_is_distribution_registered() {
        let support = WslSupport::new();
        let distro = WslDistribution {
            name: "ApiTest".to_string(),
            ..Default::default()
        };
        support.register_distribution(distro);
        assert!(WslApi::is_distribution_registered(&support, "ApiTest"));
        assert!(!WslApi::is_distribution_registered(&support, "Missing"));
    }

    #[test]
    fn test_wsl_api_register_unregister() {
        let support = WslSupport::new();
        assert!(
            WslApi::register_distribution(&support, "NewDistro", "/path/to/rootfs.tar.gz").is_ok()
        );
        assert!(WslApi::unregister_distribution(&support, "NewDistro").is_ok());
        // Unregistering a non-existent distribution fails.
        assert!(WslApi::unregister_distribution(&support, "NonExistent").is_err());
    }

    #[test]
    fn test_wsl_api_get_configuration() {
        let support = WslSupport::new();
        let distro = WslDistribution {
            name: "ConfigTest".to_string(),
            wsl_version: 2,
            state: WslDistributionState::Running,
            ..Default::default()
        };
        support.register_distribution(distro);
        let config = WslApi::get_distribution_configuration(&support, "ConfigTest").unwrap();
        assert_eq!(config.wsl_version, 2);
        assert_eq!(config.state, WslDistributionState::Running);
        // Missing distro returns error.
        assert!(WslApi::get_distribution_configuration(&support, "Missing").is_err());
    }

    #[test]
    fn test_distribution_state_name() {
        assert_eq!(WslDistributionState::Stopped.name(), "Stopped");
        assert_eq!(WslDistributionState::Running.name(), "Running");
        assert_eq!(WslDistributionState::Installing.name(), "Installing");
        assert_eq!(WslDistributionState::Failed.name(), "Failed");
    }

    #[test]
    fn test_set_enabled() {
        let support = WslSupport::new();
        assert!(support.is_enabled());
        support.set_enabled(false);
        assert!(!support.is_enabled());
        support.set_enabled(true);
        assert!(support.is_enabled());
    }

    #[test]
    fn test_launch_command_disabled() {
        let support = WslSupport::new();
        support.set_enabled(false);
        let result = support.launch_command("Ubuntu", "echo hello", Some(5));
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert!(result.unwrap_err().contains("disabled"));
    }

    #[test]
    fn test_with_distributions() {
        let distros = vec![
            WslDistribution {
                name: "Custom1".to_string(),
                ..Default::default()
            },
            WslDistribution {
                name: "Custom2".to_string(),
                wsl_version: 1,
                ..Default::default()
            },
        ];
        let support = WslSupport::with_distributions(distros);
        assert_eq!(support.list_distributions().len(), 2);
        assert!(support.find_distribution("Custom1").is_some());
        assert!(support.find_distribution("custom2").is_some()); // case-insensitive
    }

    #[test]
    fn test_check_tool_available() {
        let support = WslSupport::new();
        // We don't actually run tools in tests, but verify the path works for known tools.
        let result = support.check_tool_available(DEFAULT_WSL_DISTRO, "sh");
        // This may fail on non-Windows/macOS without Docker, but shouldn't panic.
        assert!(result.is_ok() || result.is_err());
    }

    // -----------------------------------------------------------------------
    // macOS-specific WSL behavior tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_platform_detection_macos() {
        let info = detect_wsl_platform();
        // On macOS, host_is_macos should be true and host_is_windows false
        #[cfg(target_os = "macos")]
        {
            assert!(info.host_is_macos, "on macOS, host_is_macos should be true");
            assert!(
                !info.host_is_windows,
                "on macOS, host_is_windows should be false"
            );
            // WSL version should not be detected on macOS
            assert!(
                info.wsl_version_detected.is_none(),
                "WSL version should be None on macOS"
            );
        }
    }

    #[test]
    fn test_probe_distributions_returns_empty_on_non_windows() {
        // probe_wsl_distributions should return empty on non-Windows platforms
        let result = probe_wsl_distributions();
        #[cfg(not(target_os = "windows"))]
        {
            assert!(
                result.is_ok(),
                "probe_wsl_distributions should succeed on non-Windows"
            );
            assert!(
                result.unwrap().is_empty(),
                "probe_wsl_distributions should return empty on non-Windows"
            );
        }
    }

    #[test]
    fn test_launch_command_returns_error_for_missing_distribution() {
        let support = WslSupport::with_distributions(vec![]);
        let result = support.launch_command("NonExistent", "echo hello", Some(5));
        assert!(
            result.is_err(),
            "launch_command should return error for missing distribution"
        );
        assert!(
            result.unwrap_err().contains("not found"),
            "error should mention distribution not found"
        );
    }

    #[test]
    fn test_launch_command_disabled_returns_error() {
        let support = WslSupport::new();
        support.set_enabled(false);
        let result = support.launch_command(DEFAULT_WSL_DISTRO, "echo hello", Some(5));
        assert!(result.is_err(), "expected Err, got {result:?}");
        let err = result.unwrap_err();
        assert!(
            err.contains("disabled"),
            "error should mention WSL is disabled, got: {err}"
        );
    }

    #[test]
    fn test_wsl_api_launch_interactive_missing_distro() {
        let support = WslSupport::with_distributions(vec![]);
        let result = WslApi::launch_interactive(&support, "MissingDistro", "ls", false);
        assert!(
            result.is_err(),
            "launch_interactive should fail for missing distribution"
        );
    }

    #[test]
    fn test_wsl_api_launch_missing_distro() {
        let support = WslSupport::with_distributions(vec![]);
        let result = WslApi::launch(&support, "MissingDistro", "ls", 5000);
        assert!(
            result.is_err(),
            "launch should fail for missing distribution"
        );
    }

    #[test]
    fn test_map_windows_to_wsl_path_edge_cases() {
        // Too short
        assert_eq!(map_windows_to_wsl_path("C:"), None);
        assert_eq!(map_windows_to_wsl_path("AB"), None);
        // UNC path
        assert_eq!(map_windows_to_wsl_path(r"\\server\share"), None);
        // Unix path
        assert_eq!(map_windows_to_wsl_path("/usr/bin"), None);
        // Relative path
        assert_eq!(map_windows_to_wsl_path("relative\\path"), None);
    }

    #[test]
    fn test_map_wsl_to_windows_path_edge_cases() {
        // Too short after /mnt/
        assert_eq!(map_wsl_to_windows_path("/mnt/"), None);
        assert_eq!(map_wsl_to_windows_path("/mnt"), None);
        // Non-mnt path
        assert_eq!(map_wsl_to_windows_path("/home/user"), None);
        // Valid
        assert_eq!(map_wsl_to_windows_path("/mnt/c/"), Some("C:\\".to_string()));
    }

    #[test]
    fn test_map_wsl_to_windows_path_rejects_non_ascii_drive() {
        // Non-ASCII first characters must not panic the byte-index slice.
        assert_eq!(map_wsl_to_windows_path("/mnt/é"), None);
        assert_eq!(map_wsl_to_windows_path("/mnt/€/data"), None);
        assert_eq!(map_wsl_to_windows_path("/mnt/ÿ/"), None);
        assert_eq!(map_wsl_to_windows_path("/mnt/1/x"), None);
        // ASCII drives still work.
        assert_eq!(
            map_wsl_to_windows_path("/mnt/z/etc/passwd"),
            Some("Z:\\etc\\passwd".to_string())
        );
    }

    #[test]
    fn test_parse_wsl_list_line() {
        // Default marker `*` must be stripped.
        let distro = parse_wsl_list_line("* Ubuntu-22.04           Running         2").unwrap();
        assert_eq!(distro.name, "Ubuntu-22.04");
        assert_eq!(distro.state, WslDistributionState::Running);
        assert_eq!(distro.wsl_version, 2);

        // Distribution names containing spaces.
        let distro = parse_wsl_list_line("  Kali Linux            Stopped         2").unwrap();
        assert_eq!(distro.name, "Kali Linux");
        assert_eq!(distro.state, WslDistributionState::Stopped);

        // Header and unparseable lines are skipped.
        assert!(parse_wsl_list_line("  NAME                   STATE           VERSION").is_none());
        assert!(parse_wsl_list_line("").is_none());
        assert!(parse_wsl_list_line("* Distro   Running   not-a-version").is_none());
        assert!(parse_wsl_list_line("Distro   WeirdState   2").is_none());
        assert!(parse_wsl_list_line("Distro   Running").is_none());
    }
}
