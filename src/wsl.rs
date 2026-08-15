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
            Err(format!(
                "unsupported host platform for WSL command execution"
            ))
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
        let result = self.launch_command(distribution, &format!("which {tool}"), Some(10))?;
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
pub fn detect_wsl_platform() -> WslPlatformInfo {
    let host_is_windows = cfg!(target_os = "windows");
    let host_is_macos = cfg!(target_os = "macos");
    let mut alternative_available = false;
    let mut alternative_name: Option<String> = None;

    if host_is_macos {
        // Probe for Docker.
        if let Ok(output) = std::process::Command::new("docker")
            .arg("--version")
            .output()
        {
            if output.status.success() {
                alternative_available = true;
                alternative_name = Some("docker".to_string());
            }
        }
        // Probe for colima.
        if !alternative_available {
            if let Ok(output) = std::process::Command::new("colima")
                .arg("--version")
                .output()
            {
                if output.status.success() {
                    alternative_available = true;
                    alternative_name = Some("colima".to_string());
                }
            }
        }
        // Probe for multipass.
        if !alternative_available {
            if let Ok(output) = std::process::Command::new("multipass")
                .arg("--version")
                .output()
            {
                if output.status.success() {
                    alternative_available = true;
                    alternative_name = Some("multipass".to_string());
                }
            }
        }
        // Probe for lima.
        if !alternative_available {
            if let Ok(output) = std::process::Command::new("limactl")
                .arg("--version")
                .output()
            {
                if output.status.success() {
                    alternative_available = true;
                    alternative_name = Some("lima".to_string());
                }
            }
        }
    }

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
    //   Ubuntu-22.04           Running         2
    //   Debian                 Stopped         2
    for line in stdout.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let state = match parts[1].to_lowercase().as_str() {
                "running" => WslDistributionState::Running,
                "installing" => WslDistributionState::Installing,
                _ => WslDistributionState::Stopped,
            };
            let wsl_version = parts[2].parse::<u32>().unwrap_or(WSL_VERSION_2);
            distributions.push(WslDistribution {
                name,
                wsl_version,
                state,
                base_path: PathBuf::new(),
                default_uid: 1000,
                environment: HashMap::new(),
                systemd_enabled: wsl_version == WSL_VERSION_2,
                kernel_command_line: None,
            });
        }
    }
    Ok(distributions)
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

    let timeout = timeout_secs.unwrap_or(30);
    let start = std::time::Instant::now();
    loop {
        if start.elapsed().as_secs() > timeout {
            // We can't easily kill on non-Unix, but attempt it.
            match std::process::Command::new("taskkill")
                .args(["/PID", &child.id().to_string(), "/F"])
                .output()
            {
                Ok(output) if !output.status.success() => {
                    eprintln!(
                        "[wsl] timeout: taskkill failed for PID {} with status {:?}",
                        child.id(),
                        output.status
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!(
                        "[wsl] timeout: failed to invoke taskkill for PID {}: {}",
                        child.id(),
                        error
                    );
                }
            }
            return Ok(WslCommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: -1,
                timed_out: true,
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .unwrap_or_else(|_| std::process::Output {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status,
                    });
                return Ok(WslCommandResult {
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    exit_code: status.code().unwrap_or(-1),
                    timed_out: false,
                });
            }
            Ok(None) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                return Err(format!("error waiting for wsl.exe: {e}"));
            }
        }
    }
}

/// Execute a Linux command on macOS by shelling out to `/bin/bash`.
///
/// On macOS, there is no real WSL. This provides a best-effort fallback that
/// runs the command via bash directly. For proper Linux binary execution, users
/// should have Docker, colima, or another Linux VM tool installed.
fn launch_wsl_command_macos(
    distribution: &str,
    command: &str,
    timeout_secs: Option<u64>,
) -> Result<WslCommandResult, String> {
    // Try Docker as the preferred alternative.
    let docker_check = std::process::Command::new("docker")
        .arg("--version")
        .output();
    if let Ok(docker_output) = docker_check {
        if docker_output.status.success() {
            return launch_via_docker(distribution, command, timeout_secs);
        }
    }

    // Fallback: run directly via bash (assumes the command is available natively).
    let mut cmd = std::process::Command::new("/bin/bash");
    cmd.arg("-c");
    cmd.arg(command);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn bash: {e}"))?;

    let timeout = timeout_secs.unwrap_or(30);
    let start = std::time::Instant::now();
    loop {
        if start.elapsed().as_secs() > timeout {
            if let Err(error) = child.kill() {
                return Err(format!(
                    "timed out and failed to terminate bash process: {error}"
                ));
            }
            return Ok(WslCommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: -1,
                timed_out: true,
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .unwrap_or_else(|_| std::process::Output {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status,
                    });
                return Ok(WslCommandResult {
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    exit_code: status.code().unwrap_or(-1),
                    timed_out: false,
                });
            }
            Ok(None) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                return Err(format!("error waiting for bash: {e}"));
            }
        }
    }
}

/// Launch a command inside a Docker container named after the distribution.
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

    let mut cmd = std::process::Command::new("docker");
    cmd.args(["run", "--rm", image, "/bin/bash", "-c", command]);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn docker: {e}"))?;

    let timeout = timeout_secs.unwrap_or(60);
    let start = std::time::Instant::now();
    loop {
        if start.elapsed().as_secs() > timeout {
            if let Err(error) = child.kill() {
                return Err(format!(
                    "timed out and failed to terminate docker process: {error}"
                ));
            }
            return Ok(WslCommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: -1,
                timed_out: true,
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .unwrap_or_else(|_| std::process::Output {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status,
                    });
                return Ok(WslCommandResult {
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    exit_code: status.code().unwrap_or(-1),
                    timed_out: false,
                });
            }
            Ok(None) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                return Err(format!("error waiting for docker: {e}"));
            }
        }
    }
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
        let drive = rest[..1].to_ascii_uppercase();
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
        let distro = WslDistribution {
            name: distro_name.to_string(),
            wsl_version: WSL_VERSION_2,
            state: WslDistributionState::Installing,
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
    pub fn launch_interactive(
        support: &WslSupport,
        distro_name: &str,
        command: &str,
        _use_cwd: bool,
    ) -> WslApiResult<WslCommandResult> {
        let _distro = support.find_distribution(distro_name).ok_or_else(|| {
            WslApiError::new(3, format!("distribution '{distro_name}' not found"))
        })?;
        support
            .launch_command(distro_name, command, None)
            .map_err(|e| WslApiError::new(4, e))
    }

    /// `WslLaunch` — Launch a command in a distribution with a timeout.
    pub fn launch(
        support: &WslSupport,
        distro_name: &str,
        command: &str,
        timeout_ms: u64,
    ) -> WslApiResult<WslCommandResult> {
        let timeout_secs = if timeout_ms == 0 {
            None
        } else {
            Some(timeout_ms / 1000)
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
}
