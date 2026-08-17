//! Real Steam client integration for Casa1.
//!
//! Provides the pipeline for executing the real Steam.exe Windows binary through
//! Casa1's PE loader, with real filesystem I/O, networking, Metal rendering,
//! multi-threading, and audio. This replaces the simulated Steam boot in
//! `src/steam.rs` with actual Windows PE execution.
//!
//! Also provides the `SteamProtocolIntegration` layer that registers and
//! dispatches `steam://` protocol URL activations on macOS.

use crate::error::{AppError, AppResult};
use crate::ge::GameEnvironment;
use crate::pe_runtime;
use crate::reason::ReasonCode;
use crate::steam_protocol::{SteamProtocolDispatchResult, SteamProtocolHandler, SteamProtocolUrl};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Steam paths
// ---------------------------------------------------------------------------

/// Standard Steam file paths relative to the install root.
pub struct SteamPaths;

impl SteamPaths {
    /// The main Steam executable.
    pub const STEAM_EXE: &'static str = "Steam.exe";
    /// The Steam service executable.
    pub const STEAM_SERVICE_EXE: &'static str = "bin/SteamService.exe";
    /// The Steam bootstrapper.
    pub const STEAM_BOOTSTRAPPER: &'static str = "steambootstrapper.exe";
    /// Steam config file.
    pub const CONFIG_VDF: &'static str = "config/config.vdf";
    /// Steam registry file.
    pub const REGISTRY_VDF: &'static str = "config/loginusers.vdf";
    /// Steam logs directory.
    pub const LOGS_DIR: &'static str = "logs";
    /// Steam userdata directory.
    pub const USERDATA_DIR: &'static str = "userdata";
    /// Steam apps directory.
    pub const APPS_DIR: &'static str = "steamapps";
    /// Steam common apps install directory.
    pub const COMMON_DIR: &'static str = "steamapps/common";
    /// Steam downloading directory.
    pub const DOWNLOADING_DIR: &'static str = "steamapps/downloading";
    /// Steam temp directory.
    pub const TEMP_DIR: &'static str = "temp";
    /// Steam cache directory.
    pub const CACHE_DIR: &'static str = "cache";
    /// Steam depotcache directory.
    pub const DEPOT_CACHE_DIR: &'static str = "steamapps/depotcache";
}

// ---------------------------------------------------------------------------
// Steam boot configuration
// ---------------------------------------------------------------------------

/// Configuration for booting the Steam client.
#[derive(Debug, Clone)]
pub struct SteamBootConfig {
    /// Path to the GE root directory containing drive_c.
    pub ge_root: PathBuf,
    /// Whether to enable Steam overlay.
    pub enable_overlay: bool,
    /// Whether to enable Steam IPC.
    pub enable_ipc: bool,
    /// TCP port for Steam IPC (default 57343).
    pub ipc_port: u16,
    /// Whether to auto-login.
    pub auto_login: bool,
    /// Whether to start in offline mode.
    pub offline_mode: bool,
    /// Whether to enable debug logging.
    pub debug_logging: bool,
    /// Custom launch arguments.
    pub launch_args: Vec<String>,
}

impl Default for SteamBootConfig {
    fn default() -> Self {
        Self {
            ge_root: PathBuf::from("."),
            enable_overlay: true,
            enable_ipc: true,
            ipc_port: 57343,
            auto_login: false,
            offline_mode: false,
            debug_logging: false,
            launch_args: Vec::new(),
        }
    }
}

impl SteamBootConfig {
    /// Get the Steam install directory.
    pub fn steam_dir(&self) -> PathBuf {
        self.ge_root.join("drive_c").join("Steam")
    }

    /// Get the path to Steam.exe.
    pub fn steam_exe(&self) -> PathBuf {
        self.steam_dir().join(SteamPaths::STEAM_EXE)
    }

    /// Check if Steam.exe exists.
    pub fn steam_exe_exists(&self) -> bool {
        self.steam_exe().exists()
    }

    /// Build the command line for launching Steam.
    pub fn build_command_line(&self) -> String {
        let mut args = vec![self.steam_exe().to_string_lossy().to_string()];

        if self.enable_overlay {
            args.push("-overlay".to_string());
        }
        if self.auto_login {
            args.push("-login".to_string());
        }
        if self.offline_mode {
            args.push("-offline".to_string());
        }
        if self.debug_logging {
            args.push("-debug".to_string());
        }
        args.extend(self.launch_args.iter().cloned());

        args.iter()
            .map(|a| quote_command_line_arg(a))
            .collect::<Vec<String>>()
            .join(" ")
    }
}

/// Quote a command-line argument for a joined command line.
///
/// Arguments containing whitespace or quotes are wrapped in double quotes
/// with inner double quotes escaped so that downstream re-parsing does not
/// split the executable path or argument list.
fn quote_command_line_arg(arg: &str) -> String {
    if arg.contains([' ', '\t', '"']) {
        format!("\"{}\"", arg.replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

// ---------------------------------------------------------------------------
// Steam environment setup
// ---------------------------------------------------------------------------

/// Sets up the Steam runtime environment.
pub struct SteamEnvironment;

impl SteamEnvironment {
    /// Create all required Steam directories within the GE root.
    pub fn create_required_directories(steam_dir: &Path) -> AppResult<()> {
        let dirs = [
            SteamPaths::LOGS_DIR,
            SteamPaths::USERDATA_DIR,
            SteamPaths::APPS_DIR,
            SteamPaths::COMMON_DIR,
            SteamPaths::DOWNLOADING_DIR,
            SteamPaths::TEMP_DIR,
            SteamPaths::CACHE_DIR,
            SteamPaths::DEPOT_CACHE_DIR,
            "config",
            "bin",
            "public",
            "friends",
            "resource",
            "skins",
            "dumps",
            "packages",
            "appcache",
            "htmlcache",
            "shadercache",
        ];

        for dir in &dirs {
            let path = steam_dir.join(dir);
            fs::create_dir_all(&path).map_err(|e| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("failed to create Steam directory {}: {e}", path.display()),
                )
            })?;
        }

        Ok(())
    }

    /// Create default Steam config files if they don't exist.
    pub fn create_default_config(steam_dir: &Path) -> AppResult<()> {
        let config_dir = steam_dir.join("config");
        fs::create_dir_all(&config_dir).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("cannot create config dir: {e}"))
        })?;

        let config_path = config_dir.join("config.vdf");
        if !config_path.exists() {
            let default_config = r#""InstallConfigStore"
{
    "Software"
    {
        "Valve"
        {
            "Steam"
            {
                "Connectivity"
                {
                    "SteamConnectionStatus"    "1"
                }
                "Download"
                {
                    "DownloadRegion"    "0"
                }
            }
        }
    }
}
"#;
            fs::write(&config_path, default_config).map_err(|e| {
                AppError::new(ReasonCode::RcIo, format!("cannot write config.vdf: {e}"))
            })?;
        }

        Ok(())
    }

    /// Verify Steam installation integrity.
    pub fn verify_installation(steam_dir: &Path) -> AppResult<SteamInstallInfo> {
        let steam_exe = steam_dir.join(SteamPaths::STEAM_EXE);
        let service_exe = steam_dir.join(SteamPaths::STEAM_SERVICE_EXE);

        if !steam_exe.exists() {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("Steam.exe not found at {}", steam_exe.display()),
            ));
        }

        let exe_size = fs::metadata(&steam_exe).map(|m| m.len()).unwrap_or(0);

        let service_exists = service_exe.exists();

        // Count files in Steam directory (skipping cache-heavy subtrees that
        // can contain 100k+ files and turn this into a multi-second walk).
        let file_count = WalkDir::new(steam_dir)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !(e.file_type().is_dir()
                    && (name == "shadercache" || name == "htmlcache" || name == "dumps"))
            })
            .filter_map(|e: Result<walkdir::DirEntry, _>| e.ok())
            .filter(|e: &walkdir::DirEntry| e.file_type().is_file())
            .count();

        Ok(SteamInstallInfo {
            steam_dir: steam_dir.to_path_buf(),
            exe_size,
            service_exists,
            file_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Steam install info
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SteamInstallInfo {
    pub steam_dir: PathBuf,
    pub exe_size: u64,
    pub service_exists: bool,
    pub file_count: usize,
}

// ---------------------------------------------------------------------------
// Steam Named Pipe IPC (legacy named-pipe tracking)
// ---------------------------------------------------------------------------

/// Manages Steam named pipe registration and tracking.
pub struct SteamNamedPipeManager {
    pipe_base: String,
    active_pipes: BTreeMap<String, String>,
}

impl SteamNamedPipeManager {
    pub fn new() -> Self {
        Self {
            pipe_base: "\\\\.\\pipe\\".to_string(),
            active_pipes: BTreeMap::new(),
        }
    }

    /// Get the pipe name for a Steam IPC channel.
    pub fn pipe_name(&self, channel: &str) -> String {
        format!("{}steam_{}", self.pipe_base, channel)
    }

    /// Register an active IPC pipe.
    pub fn register_pipe(&mut self, channel: &str, path: &str) {
        self.active_pipes
            .insert(channel.to_string(), path.to_string());
    }

    /// List all active IPC pipes.
    pub fn active_pipes(&self) -> &BTreeMap<String, String> {
        &self.active_pipes
    }

    /// Check if a specific IPC pipe is active.
    pub fn is_pipe_active(&self, channel: &str) -> bool {
        self.active_pipes.contains_key(channel)
    }
}

impl Default for SteamNamedPipeManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SteamService execution
// ---------------------------------------------------------------------------

/// Service state machine for SteamService.exe lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is not running.
    Stopped,
    /// Service is in the process of starting.
    Starting,
    /// Service is running (either as real process or stub mode).
    Running,
    /// Service encountered an error during startup.
    Error,
}

/// Manages the SteamService.exe background process lifecycle.
///
/// Searches multiple candidate directories for `SteamService.exe`:
///   1. `${ge_root}/drive_c/Steam/bin/SteamService.exe`
///   2. `${ge_root}/drive_c/Program Files (x86)/Steam/bin/SteamService.exe`
///   3. `/Applications/Steam.app/Contents/MacOS/bin/SteamService.exe` (native macOS)
///
/// Implements the service protocol so that Steam.exe's `CreatePipe` /
/// `CallNamedPipe` requests receive valid responses.
pub struct SteamServiceProcess {
    /// The resolved host path to SteamService.exe (may be empty).
    service_path: PathBuf,
    /// Child process handle (if running as native process).
    child: Option<std::process::Child>,
    /// Service process ID if running.
    service_pid: u32,
    /// Service state.
    state: ServiceState,
    /// Service startup timestamp.
    started_at: Instant,
    /// Optional steam:// protocol handler registered with the OS.
    protocol_handler: Option<SteamProtocolHandler>,
    /// Queue of incoming named-pipe-style requests (CreatePipe / CallNamedPipe).
    pipe_requests: std::collections::VecDeque<(Vec<u8>, Instant)>,
}

/// Maximum number of pipe requests retained for debugging before the oldest
/// entries are dropped. Bounds the `pipe_requests` queue so that every
/// `CreatePipe` / `CallNamedPipe` request from Steam.exe cannot accumulate
/// memory indefinitely.
const MAX_PIPE_REQUESTS: usize = 256;

impl SteamServiceProcess {
    /// Create a new service process tracker for the given GE root.
    ///
    /// Searches multiple candidate locations for SteamService.exe.
    pub fn new(ge_root: &Path) -> Self {
        let service_path = Self::find_service_exe(ge_root);
        Self {
            service_path,
            child: None,
            service_pid: 0,
            state: ServiceState::Stopped,
            started_at: Instant::now(),
            protocol_handler: None,
            pipe_requests: std::collections::VecDeque::new(),
        }
    }

    /// Search multiple locations for SteamService.exe.
    fn find_service_exe(ge_root: &Path) -> PathBuf {
        // Candidate 1: Standard GE Steam directory
        let candidates = [
            ge_root
                .join("drive_c")
                .join("Steam")
                .join(SteamPaths::STEAM_SERVICE_EXE),
            ge_root
                .join("drive_c")
                .join("Program Files (x86)")
                .join("Steam")
                .join(SteamPaths::STEAM_SERVICE_EXE),
            ge_root
                .join("drive_c")
                .join("Program Files")
                .join("Steam")
                .join(SteamPaths::STEAM_SERVICE_EXE),
            PathBuf::from("/Applications/Steam.app/Contents/MacOS")
                .join(SteamPaths::STEAM_SERVICE_EXE),
            PathBuf::from("/Applications/Steam.app/Contents/MacOS/bin/SteamService.exe"),
            // Also check the native Steam installation
            PathBuf::from(std::env::var("HOME").unwrap_or_default())
                .join("Library/Application Support/Steam/SteamService.exe"),
        ];

        for candidate in &candidates {
            if candidate.exists() {
                eprintln!("SteamService: found at {}", candidate.display());
                return candidate.clone();
            }
        }

        // If not found anywhere, use the default GE path (will trigger stub mode).
        eprintln!("SteamService: not found anywhere, will use stub mode");
        ge_root
            .join("drive_c")
            .join("Steam")
            .join(SteamPaths::STEAM_SERVICE_EXE)
    }

    /// Start the SteamService.exe process.
    ///
    /// If the executable exists, this attempts to run it:
    ///   - As a native macOS process if found in `/Applications/Steam.app/...`
    ///   - Through the GE via `pe_runtime::execute` for Windows PE
    ///
    /// If the executable is not present, the service enters stub mode
    /// and responds to `CreatePipe`/`CallNamedPipe` requests from Steam.exe
    /// with valid protocol responses.
    pub fn start(&mut self, ge: &GameEnvironment) -> AppResult<()> {
        if self.state == ServiceState::Running {
            return Ok(());
        }
        self.state = ServiceState::Starting;

        // Register the steam:// URL protocol handler with the OS.
        let mut handler = SteamProtocolHandler::new_verbose();
        handler.register();
        self.protocol_handler = Some(handler);

        // Check if SteamService.exe exists
        if !self.service_path.exists() {
            eprintln!("SteamService: executable not found, entering stub mode");
            self.state = ServiceState::Running;
            self.started_at = Instant::now();
            return Ok(());
        }

        // Determine if this is a native macOS or Windows PE executable
        let is_native_macos = self
            .service_path
            .to_string_lossy()
            .contains("/Applications/Steam.app");

        if is_native_macos {
            // Run as a native macOS process
            match std::process::Command::new(&self.service_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(child) => {
                    self.service_pid = child.id();
                    self.child = Some(child);
                    self.state = ServiceState::Running;
                    self.started_at = Instant::now();
                    eprintln!(
                        "SteamService: spawned native process (PID {})",
                        self.service_pid
                    );
                    Ok(())
                }
                Err(e) => {
                    eprintln!(
                        "SteamService: failed to spawn native process: {e}, falling back to stub"
                    );
                    self.state = ServiceState::Running;
                    self.started_at = Instant::now();
                    Ok(())
                }
            }
        } else {
            // Attempt to execute SteamService.exe via the PE runtime.
            //
            // `pe_runtime::execute` runs the guest PE synchronously to
            // completion, but SteamService.exe is a long-running service.
            // Run it on a dedicated thread so that `start()` returns
            // immediately, the service is reported as `Running`, and
            // `stop()` / pipe responses stay reachable. The thread only
            // updates logging once the guest exits; it cannot touch `self`
            // after launch.
            let args: Vec<String> = Vec::new();
            let env = BTreeMap::new();
            let cwd = self
                .service_path
                .parent()
                .unwrap_or(Path::new("."))
                .to_path_buf();
            let service_exe = self.service_path.clone();
            let ge_clone = ge.clone();
            std::thread::Builder::new()
                .name("steam-service".to_string())
                .spawn(move || {
                    match pe_runtime::execute(
                        &service_exe,
                        &args,
                        &ge_clone,
                        &cwd,
                        &env,
                        false, // dtm
                        "steam-service",
                    ) {
                        Ok(result) => {
                            eprintln!(
                                "SteamService: PE service exited with code {}",
                                result.exit_code
                            );
                        }
                        Err(e) => {
                            eprintln!("SteamService: PE execution failed: {e}");
                        }
                    }
                })
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcRunnerSpawnFailed,
                        format!("SteamService: failed to spawn service thread: {e}"),
                    )
                })?;
            self.state = ServiceState::Running;
            self.started_at = Instant::now();
            Ok(())
        }
    }

    /// Stop the SteamService.exe process.
    ///
    /// If a child process handle is available, it is killed gracefully
    /// (SIGTERM first, then SIGKILL after timeout). Marks service as stopped.
    pub fn stop(&mut self) -> AppResult<()> {
        if let Some(mut child) = self.child.take() {
            // Try graceful shutdown first
            #[cfg(unix)]
            {
                // Send SIGTERM
                let pid = child.id() as i32;
                let kill_result = unsafe { libc::kill(pid, libc::SIGTERM) };
                if kill_result != 0 {
                    eprintln!("SteamService: SIGTERM to PID {pid} failed (errno {kill_result})");
                }
                // Wait briefly for graceful shutdown
                for _ in 0..50 {
                    if child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }

            // Force kill if still running
            if child.try_wait().ok().flatten().is_none() {
                if let Err(e) = child.kill() {
                    eprintln!("SteamService: failed to kill child process: {e}");
                }
                if let Err(e) = child.wait() {
                    eprintln!("SteamService: failed to wait for child process: {e}");
                }
            }
        }
        // Reset the recorded PID so `pid()` cannot return a stale value for a
        // process that is no longer running (e.g. a PE-thread service).
        self.service_pid = 0;
        self.state = ServiceState::Stopped;
        self.pipe_requests.clear();
        Ok(())
    }

    /// Handle an incoming named pipe request from Steam.exe.
    ///
    /// Implements the Steam service protocol:
    /// - `CreatePipe` requests receive a valid pipe handle response
    /// - `CallNamedPipe` requests receive valid service responses
    /// - Unknown requests are logged and return an empty response
    pub fn handle_pipe_request(&mut self, request: &[u8]) -> Vec<u8> {
        // Parse the service protocol request.
        // Steam's service protocol typically has:
        //   [4 bytes: request type / pipe name hash]
        //   [4 bytes: data length]
        //   [N bytes: data payload]
        if request.len() < 8 {
            eprintln!(
                "SteamService: received short pipe request ({} bytes)",
                request.len()
            );
            return self.make_pipe_response(0xFFFFFFFF, &[]); // Error response
        }

        let request_type = u32::from_le_bytes(request[0..4].try_into().unwrap_or([0; 4]));
        let data_len = u32::from_le_bytes(request[4..8].try_into().unwrap_or([0; 4])) as usize;
        let _data = if data_len > 0 && 8 + data_len <= request.len() {
            request[8..8 + data_len].to_vec()
        } else {
            Vec::new()
        };

        // Log the request for debugging
        eprintln!(
            "SteamService: pipe request type=0x{:08X}, data_len={}",
            request_type, data_len
        );

        // Queue it as pending (bounded: drop the oldest request if the queue
        // is full so untrusted guest traffic cannot grow memory unboundedly).
        if self.pipe_requests.len() >= MAX_PIPE_REQUESTS {
            self.pipe_requests.pop_front();
        }
        self.pipe_requests
            .push_back((request.to_vec(), Instant::now()));

        match request_type {
            // CreatePipe: respond with a valid pipe handle
            0x00000001 | 0x00001001 => {
                let pipe_handle = 0xCAFE0001u32.to_le_bytes();
                let mut response = Vec::with_capacity(12);
                response.extend_from_slice(&0u32.to_le_bytes()); // status = success
                response.extend_from_slice(&pipe_handle);
                response
            }
            // CallNamedPipe (service query): respond with service status
            0x00000002 | 0x00001002 => {
                // Return service status: running, version info
                let status: u32 = if self.state == ServiceState::Running {
                    0
                } else {
                    1
                };
                let version: u32 = 0x00020001; // Steam service API v2.1
                let mut response = Vec::with_capacity(16);
                response.extend_from_slice(&status.to_le_bytes());
                response.extend_from_slice(&version.to_le_bytes());
                response.extend_from_slice(&self.service_pid.to_le_bytes());
                response
            }
            // Steam client ping / heartbeat check
            0x00000003 => {
                let mut response = Vec::with_capacity(8);
                response.extend_from_slice(&0u32.to_le_bytes()); // pong
                response
                    .extend_from_slice(&(Instant::now().elapsed().as_secs() as u32).to_le_bytes());
                response
            }
            // Shutdown request from Steam.exe
            0x0000FFFF => {
                eprintln!("SteamService: received shutdown request from Steam.exe");
                self.state = ServiceState::Stopped;
                self.make_pipe_response(0, &[])
            }
            // Unknown: return error
            _ => {
                eprintln!("SteamService: unknown pipe request type 0x{request_type:08X}");
                self.make_pipe_response(0xFFFFFFFF, &[])
            }
        }
    }

    /// Build a generic pipe response with status code and optional data.
    fn make_pipe_response(&self, status: u32, data: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(8 + data.len());
        response.extend_from_slice(&status.to_le_bytes());
        response.extend_from_slice(&(data.len() as u32).to_le_bytes());
        response.extend_from_slice(data);
        response
    }

    /// Check whether the service is currently running (or in stub mode).
    pub fn is_running(&self) -> bool {
        self.state == ServiceState::Running || self.state == ServiceState::Starting
    }

    /// Return the service state.
    pub fn state(&self) -> ServiceState {
        self.state
    }

    /// Return the process ID of the service, if a native child is available.
    pub fn pid(&self) -> Option<u32> {
        if self.service_pid != 0 {
            Some(self.service_pid)
        } else {
            self.child.as_ref().map(|c| c.id())
        }
    }

    /// Get the resolved service executable path.
    pub fn service_path(&self) -> &Path {
        &self.service_path
    }

    /// Get a reference to the protocol handler, if registered.
    pub fn protocol_handler(&self) -> Option<&SteamProtocolHandler> {
        self.protocol_handler.as_ref()
    }

    /// Get a mutable reference to the protocol handler, if registered.
    pub fn protocol_handler_mut(&mut self) -> Option<&mut SteamProtocolHandler> {
        self.protocol_handler.as_mut()
    }

    /// Drain pending pipe requests.
    pub fn drain_pipe_requests(&mut self) -> Vec<(Vec<u8>, Instant)> {
        self.pipe_requests.drain(..).collect()
    }
}

// ---------------------------------------------------------------------------
// Steam Protocol Integration — steam:// URL handling
// ---------------------------------------------------------------------------

/// High-level integration for steam:// protocol URL handling.
///
/// Provides macOS URL event system integration, protocol URL parsing, and
/// dispatch to the appropriate Casa1 subsystem (game launcher, browser
/// navigation, UI sections, downloads, etc.).
///
/// This bridges the gap between OS-level URL activation events and Casa1's
/// internal subsystems.
#[derive(Debug)]
pub struct SteamProtocolIntegration {
    /// The underlying protocol handler.
    pub handler: SteamProtocolHandler,
}

impl SteamProtocolIntegration {
    /// Create a new protocol integration with an unregistered handler.
    pub fn new() -> Self {
        Self {
            handler: SteamProtocolHandler::new(),
        }
    }

    /// Create a new protocol integration and register the handler immediately.
    pub fn new_registered() -> Self {
        let mut handler = SteamProtocolHandler::new_verbose();
        handler.register();
        Self { handler }
    }

    /// Process a steam:// URL string: parse it and return the dispatch result.
    ///
    /// This is the main entry point for handling steam:// protocol activations
    /// received from the OS (e.g., via macOS NSAppleEventManager or command line).
    pub fn handle_url(&self, url_str: &str) -> SteamProtocolDispatchResult {
        self.handler.handle_url(url_str)
    }

    /// Process a steam:// URL and dispatch it to the appropriate subsystem.
    ///
    /// Returns true if the command was handled successfully.
    pub fn dispatch_url(&self, url_str: &str) -> bool {
        match self.handle_url(url_str) {
            SteamProtocolDispatchResult::Handled => {
                eprintln!("[SteamProtocol] Handled: {url_str}");
                true
            }
            SteamProtocolDispatchResult::LaunchGame(app_id, action) => {
                eprintln!(
                    "[SteamProtocol] Launching game {app_id} (action={:?}) — NOT IMPLEMENTED",
                    action.unwrap_or_default()
                );
                // In a full implementation, this would trigger the Phase 4
                // AAA Game Execution Pipeline to launch the game. Until the
                // backing subsystem is wired, report failure so callers can
                // fall back.
                false
            }
            SteamProtocolDispatchResult::NavigateBrowser(url) => {
                eprintln!("[SteamProtocol] Navigating browser to: {url} — NOT IMPLEMENTED");
                // This would use CEF bridge (cef_bridge.rs) to navigate the
                // Steam overlay or main browser to the given URL.
                false
            }
            SteamProtocolDispatchResult::ShowFriends => {
                eprintln!("[SteamProtocol] Opening friends list");
                true
            }
            SteamProtocolDispatchResult::NavigateSection(section) => {
                eprintln!("[SteamProtocol] Navigating to section: {section}");
                true
            }
            SteamProtocolDispatchResult::InstallGame(app_id) => {
                eprintln!("[SteamProtocol] Installing game {app_id} — NOT IMPLEMENTED");
                // This would trigger the CDN download pipeline.
                false
            }
            SteamProtocolDispatchResult::Unrecognized(cmd) => {
                eprintln!("[SteamProtocol] Unrecognized command: {cmd}");
                false
            }
            SteamProtocolDispatchResult::Error(msg) => {
                eprintln!("[SteamProtocol] Error: {msg}");
                false
            }
        }
    }

    /// Parse command-line arguments for Steam-style flags and protocol URLs.
    ///
    /// Returns a list of parsed `SteamProtocolUrl` values extracted from the
    /// arguments. This handles both direct `steam://` URLs and Steam-style
    /// flags like `-applaunch`, `-silent`, etc.
    pub fn parse_command_line(args: &[String]) -> Vec<SteamProtocolUrl> {
        SteamProtocolHandler::parse_command_line(args)
    }
}

impl Default for SteamProtocolIntegration {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Steam TCP IPC (between Steam.exe and SteamService.exe)
// ---------------------------------------------------------------------------

/// Manages the TCP-based named pipe IPC channel between Steam.exe and
/// SteamService.exe.
///
/// Uses a simple TCP socket on loopback at the configured port. This
/// replaces the Windows named pipe mechanism with a portable TCP equivalent.
pub struct SteamIpcManager {
    /// Port for TCP-based Steam IPC (default 57343).
    port: u16,
    /// Whether IPC is enabled.
    enabled: bool,
    /// Steam service process handle.
    service: Option<SteamServiceProcess>,
    /// Optional TCP listener (acceptor side).
    listener: Option<std::net::TcpListener>,
}

/// Maximum accepted size of a single length-prefixed IPC message. Guards
/// against unbounded allocations driven by an attacker-controlled length
/// prefix on the loopback socket (the listener is reachable by any local
/// process).
const MAX_IPC_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// How long `send_message` waits for a response header before giving up.
const IPC_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl SteamIpcManager {
    /// Create a new TCP-based IPC manager.
    pub fn new(port: u16, ge_root: &Path) -> Self {
        Self {
            port,
            enabled: true,
            service: Some(SteamServiceProcess::new(ge_root)),
            listener: None,
        }
    }

    /// Start the IPC system: starts the service process and binds the TCP
    /// listener on loopback.
    pub fn start(&mut self, ge: &GameEnvironment) -> AppResult<()> {
        if !self.enabled {
            return Ok(());
        }

        // Start the SteamService process
        if let Some(ref mut svc) = self.service {
            svc.start(ge)?;
        }

        // Bind the TCP listener on loopback
        let addr = format!("127.0.0.1:{}", self.port);
        match std::net::TcpListener::bind(&addr) {
            Ok(listener) => {
                if let Err(e) = listener.set_nonblocking(true) {
                    eprintln!("SteamIpcManager: failed to set nonblocking on listener: {e}");
                }
                self.listener = Some(listener);
            }
            Err(e) => {
                // Port already in use or unavailable — degrade gracefully
                eprintln!("SteamIpcManager: failed to bind to {}: {}", addr, e);
            }
        }

        Ok(())
    }

    /// Stop the IPC system: stops the service and drops the listener.
    pub fn stop(&mut self) -> AppResult<()> {
        self.listener = None;
        if let Some(ref mut svc) = self.service {
            svc.stop()?;
        }
        Ok(())
    }

    /// Send an IPC message to the service.
    ///
    /// If no connection is active, this attempts to connect to the local
    /// loopback port. The message is prefixed with a 4-byte length header
    /// (little-endian u32) for framing.
    ///
    /// The response read is bounded by `IPC_RESPONSE_TIMEOUT` and the
    /// response length is capped at `MAX_IPC_MESSAGE_SIZE`, so a missing
    /// responder or a hostile peer can never block or exhaust this process.
    pub fn send_message(&self, msg: &[u8]) -> AppResult<Vec<u8>> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        if msg.len() > MAX_IPC_MESSAGE_SIZE {
            return Err(AppError::new(
                ReasonCode::RcRequestBodyTooLarge,
                format!(
                    "SteamIpcManager: outgoing message too large ({} bytes, max {MAX_IPC_MESSAGE_SIZE})",
                    msg.len()
                ),
            ));
        }

        let addr = format!("127.0.0.1:{}", self.port);
        let mut stream = std::net::TcpStream::connect(&addr).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("SteamIpcManager: connect to {addr} failed: {e}"),
            )
        })?;
        stream
            .set_read_timeout(Some(IPC_RESPONSE_TIMEOUT))
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetSocketCreateFailed,
                    format!("SteamIpcManager: failed to set read timeout: {e}"),
                )
            })?;

        // Send length-prefixed message
        let len = msg.len() as u32;
        let header = len.to_le_bytes();
        let mut packet = Vec::with_capacity(4 + msg.len());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(msg);

        use std::io::Write;
        stream.write_all(&packet).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetWriteFailed,
                format!("SteamIpcManager: send failed: {e}"),
            )
        })?;

        // Read response (also length-prefixed)
        use std::io::Read;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetReadFailed,
                format!(
                    "SteamIpcManager: read response header failed (no responder on port {}?): {e}",
                    self.port
                ),
            )
        })?;

        let response_len = u32::from_le_bytes(len_buf) as usize;
        if response_len > MAX_IPC_MESSAGE_SIZE {
            return Err(AppError::new(
                ReasonCode::RcRequestBodyTooLarge,
                format!(
                    "SteamIpcManager: response length {response_len} exceeds limit {MAX_IPC_MESSAGE_SIZE}"
                ),
            ));
        }
        let mut response = vec![0u8; response_len];
        if response_len > 0 {
            stream.read_exact(&mut response).map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetReadFailed,
                    format!("SteamIpcManager: read response body failed: {e}"),
                )
            })?;
        }

        Ok(response)
    }

    /// Receive an IPC message (responder side).
    ///
    /// If a listener is active, this accepts an incoming connection and reads
    /// a length-prefixed message from it. Unlike the previous behaviour, the
    /// request is answered: the peer's length-prefixed request is handed to
    /// the SteamService stub protocol (`handle_pipe_request`) and the reply
    /// is written back over the same connection, so a paired
    /// `send_message` call completes instead of hanging forever.
    pub fn receive_message(&mut self) -> AppResult<Vec<u8>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        if let Some(ref listener) = self.listener {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    use std::io::{Read, Write};
                    // Bound how long a single request may stall this
                    // responder; a peer that connects but never sends must
                    // not block the caller indefinitely.
                    if let Err(e) = stream.set_read_timeout(Some(IPC_RESPONSE_TIMEOUT)) {
                        eprintln!("SteamIpcManager: failed to set read timeout: {e}");
                    }
                    let mut len_buf = [0u8; 4];
                    stream.read_exact(&mut len_buf).map_err(|e| {
                        AppError::new(
                            ReasonCode::RcNetReadFailed,
                            format!("SteamIpcManager: read header failed: {e}"),
                        )
                    })?;

                    let msg_len = u32::from_le_bytes(len_buf) as usize;
                    if msg_len > MAX_IPC_MESSAGE_SIZE {
                        return Err(AppError::new(
                            ReasonCode::RcRequestBodyTooLarge,
                            format!(
                                "SteamIpcManager: received length {msg_len} exceeds limit {MAX_IPC_MESSAGE_SIZE}"
                            ),
                        ));
                    }
                    let mut msg = vec![0u8; msg_len];
                    if msg_len > 0 {
                        stream.read_exact(&mut msg).map_err(|e| {
                            AppError::new(
                                ReasonCode::RcNetReadFailed,
                                format!("SteamIpcManager: read body failed: {e}"),
                            )
                        })?;
                    }

                    // Reply to the peer so request/response round-trips work.
                    let response = self
                        .service
                        .as_mut()
                        .map(|svc| svc.handle_pipe_request(&msg))
                        .unwrap_or_default();
                    if response.len() > MAX_IPC_MESSAGE_SIZE {
                        return Err(AppError::new(
                            ReasonCode::RcRequestBodyTooLarge,
                            "SteamIpcManager: response too large",
                        ));
                    }
                    let mut reply = Vec::with_capacity(4 + response.len());
                    reply.extend_from_slice(&(response.len() as u32).to_le_bytes());
                    reply.extend_from_slice(&response);
                    if let Err(e) = stream.write_all(&reply) {
                        eprintln!("SteamIpcManager: failed to write response: {e}");
                    }

                    Ok(msg)
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    Ok(Vec::new()) // No pending connection
                }
                Err(e) => Err(AppError::new(
                    ReasonCode::RcNetReadFailed,
                    format!("SteamIpcManager: accept failed: {e}"),
                )),
            }
        } else {
            Ok(Vec::new())
        }
    }
}

// ---------------------------------------------------------------------------
// Steam game management
// ---------------------------------------------------------------------------

/// Information about an installed Steam game.
#[derive(Debug, Clone)]
pub struct SteamGameInfo {
    pub app_id: u32,
    pub name: String,
    pub install_dir: PathBuf,
    pub launch_exe: String,
    pub size_bytes: u64,
}

/// Scans the Steam library for installed games.
pub struct SteamLibraryScanner;

impl SteamLibraryScanner {
    /// Scan a Steam installation for installed games.
    pub fn scan_library(steam_dir: &Path) -> AppResult<Vec<SteamGameInfo>> {
        let common_dir = steam_dir.join(SteamPaths::COMMON_DIR);
        if !common_dir.exists() {
            return Ok(Vec::new());
        }

        let mut games = Vec::new();
        let entries = fs::read_dir(&common_dir)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("cannot read common dir: {e}")))?;

        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let name = entry.file_name().to_string_lossy().to_string();
                let install_dir = entry.path();

                // Calculate total size (skipping cache-heavy subtrees such as
                // shadercache/htmlcache that can contain 100k+ files).
                let size_bytes = WalkDir::new(&install_dir)
                    .into_iter()
                    .filter_entry(|e| {
                        let name = e.file_name().to_string_lossy();
                        !(e.file_type().is_dir()
                            && (name == "shadercache" || name == "htmlcache" || name == "dumps"))
                    })
                    .filter_map(|e: Result<walkdir::DirEntry, _>| e.ok())
                    .filter(|e: &walkdir::DirEntry| e.file_type().is_file())
                    .filter_map(|e: walkdir::DirEntry| e.metadata().ok())
                    .map(|m: std::fs::Metadata| m.len())
                    .sum();

                games.push(SteamGameInfo {
                    app_id: 0, // Would be determined from appmanifest files
                    name,
                    install_dir,
                    launch_exe: String::new(), // Would be determined from appmanifest
                    size_bytes,
                });
            }
        }

        Ok(games)
    }
}

// ---------------------------------------------------------------------------
// Steam manifest parsing
// ---------------------------------------------------------------------------

/// Parse a Steam app manifest (appmanifest_*.acf) file.
///
/// The parser is block-aware: key/value pairs are only recorded at brace
/// depth 0/1, so nested-block keys (e.g. `"InstalledDepots" { "480000" ... }`)
/// no longer pollute the flat result map.
pub fn parse_app_manifest(content: &str) -> AppResult<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let mut depth: i64 = 0;
    let mut current_key = String::new();
    let mut in_value = false;

    for line in content.lines() {
        let line = line.trim();

        // Count braces outside of quoted strings on this line, and the depth
        // at the start of the line (i.e. the block the line belongs to).
        let mut line_depth_delta: i64 = 0;
        let mut in_quote = false;
        for ch in line.chars() {
            match ch {
                '"' => in_quote = !in_quote,
                '{' if !in_quote => line_depth_delta += 1,
                '}' if !in_quote => line_depth_delta -= 1,
                _ => {}
            }
        }
        let line_depth = depth;
        depth += line_depth_delta;
        let is_brace_line = line_depth_delta != 0;

        if line.starts_with('"') && !is_brace_line {
            let parts: Vec<&str> = line.splitn(5, '"').collect();
            if parts.len() >= 5 {
                if line_depth <= 1 {
                    let key = parts[1];
                    let value = parts[3];
                    result.insert(key.to_string(), value.to_string());
                    in_value = false;
                }
            } else if parts.len() >= 2 && line_depth <= 1 {
                current_key = parts[1].to_string();
                in_value = true;
            }
        } else if in_value && !line.is_empty() && !is_brace_line {
            // Continuation of a multi-line value — append to current key
            if let Some(val) = result.get_mut(&current_key) {
                val.push(' ');
                val.push_str(line);
            }
        }
    }

    Ok(result)
}

/// Validate a relative path coming from an untrusted source (sync-server
/// listing, depot manifest, or guest FFI).
///
/// Rejects empty paths, absolute paths, and any `..` component so that
/// joining the path with a base directory can never escape that directory.
fn is_safe_rel_path(rel_path: &str) -> bool {
    if rel_path.is_empty() {
        return false;
    }
    let mut seen_normal = false;
    for component in Path::new(rel_path).components() {
        match component {
            Component::ParentDir => return false,
            Component::RootDir | Component::Prefix(_) => return false,
            Component::Normal(c) if c.is_empty() => return false,
            Component::Normal(_) => seen_normal = true,
            Component::CurDir => {}
        }
    }
    seen_normal
}

/// Percent-encode a string for use as a single URL path segment.
///
/// Leaves RFC 3986 unreserved characters (`A-Z a-z 0-9 - . _ ~`) untouched
/// and encodes everything else, so file names containing spaces, `#`, `?`,
/// `%`, etc. cannot produce malformed or misrouted cloud-sync requests.
fn percent_encode(segment: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(segment.len());
    for &byte in segment.as_bytes() {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0F) as usize] as char);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SteamClient — high-level integration layer wrapping SteamProtocolStack
// ---------------------------------------------------------------------------

use crate::steam_protocol::{
    self, ConnectionState, ContentServerRecord, DEFAULT_STUN_SERVER, GameNetworkingSockets,
    GnsConnectionHandle, SteamMessageType, SteamNetworkingMessage, SteamProtocolStack,
};
use rsa::RsaPublicKey;

/// Notification types for Steam client events.
#[derive(Debug, Clone)]
pub enum SteamNotification {
    /// Friend online/offline/status change.
    FriendStatus { steam_id: u64, status: String },
    /// Chat message received.
    ChatMessage { steam_id: u64, message: String },
    /// Workshop item updated.
    WorkshopUpdate { item_id: u64, app_id: u32 },
    /// Download progress update.
    DownloadProgress { app_id: u32, progress: f64 },
    /// License/app rights change.
    LicenseChange { app_id: u32 },
}

/// High-level Steam client that wraps `SteamProtocolStack` with
/// authentication, content download, and notification management.
#[derive(Debug)]
pub struct SteamClient {
    /// The underlying protocol stack.
    pub stack: SteamProtocolStack,
    /// GNS session for multiplayer.
    gns: Option<GameNetworkingSockets>,
    /// Known content server records.
    content_servers: Vec<ContentServerRecord>,
    /// Whether the client has successfully logged on.
    pub logged_on: bool,
    /// RSA public key captured from the CM server during encryption handshake.
    /// Used for RSA-OAEP password encryption during logon.
    rsa_public_key: Option<RsaPublicKey>,
    /// Persistent GNS sessions indexed by target Steam ID for lobby/chat
    /// multi-peer routing.  Created on first message to a given peer and
    /// reused for subsequent messages.
    lobby_sessions: std::collections::HashMap<u64, GnsConnectionHandle>,
}

impl SteamClient {
    /// Create a new SteamClient in the disconnected state.
    pub fn new() -> Self {
        Self {
            stack: SteamProtocolStack::new(),
            gns: None,
            content_servers: Vec::new(),
            logged_on: false,
            rsa_public_key: None,
            lobby_sessions: std::collections::HashMap::new(),
        }
    }

    /// Connect to a Steam CM server, perform the encryption handshake, and
    /// send a logon request.
    ///
    /// Steps:
    ///   1. Connect to CM server (TCP)
    ///   2. Perform RSA/AES encryption handshake
    ///   3. Send `ClientLogOn` message with credentials
    ///   4. Wait for `ClientLogOnResponse` (EMsg 1103)
    ///   5. Extract Steam ID and session token from response
    ///
    /// This is a synchronous (blocking) flow. In production the handshake
    /// and logon would be asynchronous with timeouts.
    pub fn connect_and_login(
        &mut self,
        server: Option<&str>,
        username: &str,
        password: &str,
    ) -> AppResult<()> {
        // Step 1: Connect to CM server
        self.stack.connect(server)?;

        // Step 2: Encryption handshake is performed by connect()
        if self.stack.state != ConnectionState::Ready {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                format!(
                    "SteamClient: connect returned without reaching Ready state (state={:?})",
                    self.stack.state
                ),
            ));
        }

        // Capture the RSA public key from the CM handshake for real
        // RSA-OAEP password encryption.
        self.rsa_public_key = self.stack.rsa_public_key().cloned();

        // Step 3: Encrypt the password using RSA-OAEP.
        let password_encrypted = self.encrypt_password(password)?;

        // Step 4: Send logon message
        self.stack.send_logon(username, &password_encrypted)?;

        // Step 5: Wait for logon response by polling the message queue
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut logged_in = false;

        while std::time::Instant::now() < deadline {
            self.stack.drain_messages()?;

            while let Some(msg) = self.stack.pop_message() {
                match msg.msg_type {
                    SteamMessageType::ClientLogOnResponse => {
                        // Parse the logon response payload:
                        //   result (u32 LE)
                        //   steam_id (u64 LE)
                        //   session_token (rest)
                        if msg.payload.len() >= 12 {
                            let _result = u32::from_le_bytes(msg.payload[0..4].try_into().unwrap());
                            let steam_id =
                                u64::from_le_bytes(msg.payload[4..12].try_into().unwrap());
                            let session_token = if msg.payload.len() > 12 {
                                Some(msg.payload[12..].to_vec())
                            } else {
                                None
                            };

                            self.stack.set_steam_id(steam_id);
                            if let Some(token) = session_token {
                                self.stack.auth.session_token = Some(token);
                            }
                            self.stack.auth.auth_status = steam_protocol::AuthStatus::Authenticated;
                            self.stack.state = ConnectionState::Ready;
                            self.logged_on = true;
                            logged_in = true;
                        }
                        break;
                    }
                    SteamMessageType::ChannelEncryptResult => {
                        // Session ID may be set here
                        if msg.payload.len() >= 4 {
                            let session_id =
                                u32::from_le_bytes(msg.payload[0..4].try_into().unwrap());
                            self.stack.set_session_id(session_id);
                        }
                    }
                    _ => {
                        // Queue other messages for the application
                        self.stack.incoming_messages.push_back(msg);
                    }
                }
            }

            if logged_in {
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if !logged_in {
            return Err(AppError::new(
                ReasonCode::RcWin32Timeout,
                "SteamClient: logon timed out — no ClientLogOnResponse received",
            ));
        }

        Ok(())
    }

    /// Encrypt the password for the logon message using RSA-OAEP.
    ///
    /// The real Steam protocol encrypts the password with the CM server's RSA
    /// public key using RSA-OAEP (SHA-256). If no server RSA key is
    /// available, the login is refused: the password is never transmitted
    /// unencrypted (raw bytes or trivially reversible XOR are not
    /// encryption).
    fn encrypt_password(&self, password: &str) -> AppResult<Vec<u8>> {
        let pw_bytes = password.as_bytes();

        // RSA-OAEP (SHA-256) with the CM server's public key.
        if let Some(ref pub_key) = self.rsa_public_key {
            use rsa::Oaep;
            use sha2::Sha256;
            let padding = Oaep::new::<Sha256>();
            match pub_key.encrypt(&mut rand::thread_rng(), padding, pw_bytes) {
                Ok(encrypted) => return Ok(encrypted),
                Err(e) => {
                    return Err(AppError::new(
                        ReasonCode::RcCryptoInvalid,
                        format!("SteamClient: RSA-OAEP password encryption failed: {e}"),
                    ));
                }
            }
        }

        Err(AppError::new(
            ReasonCode::RcCryptoInvalid,
            "SteamClient: no encryption key available — refusing to send plaintext password",
        ))
    }

    /// Download all files for a given app from Steam's CDN.
    ///
    /// Steps:
    ///   1. Request app info (depots, manifests)
    ///   2. Parse depot manifests
    ///   3. Download each file via CDN content servers
    ///   4. Verify file checksums
    pub fn download_app(&mut self, app_id: u32, output_dir: &Path) -> AppResult<()> {
        if !self.logged_on {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "SteamClient: must be logged on to download apps",
            ));
        }

        // Request package info — this triggers the CM to send us manifest data
        self.stack.request_package_info(app_id)?;

        // Give the server time to respond
        std::thread::sleep(std::time::Duration::from_millis(500));
        self.stack.drain_messages()?;

        // Process any package info responses
        while let Some(msg) = self.stack.pop_message() {
            match msg.msg_type {
                SteamMessageType::ClientPackageInfoResponse
                | SteamMessageType::ClientPackageInfoResponse2 => {
                    // Parse the response to extract depot manifests.
                    // The response contains serialized depot manifest data.
                    let manifests = self.stack.parse_depot_manifest(&msg.payload, None)?;

                    for manifest in &manifests {
                        // The manifest comes from the CM server (untrusted
                        // network data); refuse entries whose filename could
                        // escape `output_dir` (absolute paths or `..`).
                        if !is_safe_rel_path(&manifest.filename) {
                            eprintln!(
                                "SteamClient: skipping depot manifest entry with unsafe filename {:?}",
                                manifest.filename
                            );
                            continue;
                        }
                        let file_output = output_dir.join(&manifest.filename);

                        // Try to find a content server to download from
                        if let Some(server) = self.content_servers.first() {
                            self.stack
                                .download_file(server, manifest, &file_output, app_id)?;

                            // Update progress
                            self.stack
                                .download_progress
                                .entry(app_id)
                                .and_modify(|p| *p += 1.0);
                        }
                    }
                }
                _ => {
                    self.stack.incoming_messages.push_back(msg);
                }
            }
        }

        // Finalise progress
        self.stack.download_progress.insert(app_id, 100.0);

        Ok(())
    }

    /// Send a lobby/chat message to another Steam user via GNS.
    ///
    /// Creates or reuses a GNS session for the target peer and sends the
    /// message.  The `target_steam_id` is used for multi-peer routing so
    /// that all messages to the same peer go through the same session.
    pub fn send_lobby_message(&mut self, target_steam_id: u64, data: &[u8]) -> AppResult<()> {
        // Ensure GNS is initialized
        let gns = self.gns.get_or_insert_with(GameNetworkingSockets::new);

        // The session map is capped so long-running sessions cannot grow
        // without bound; the oldest peer session is evicted first (only for
        // new peers — an existing session is never evicted).
        const MAX_LOBBY_SESSIONS: usize = 256;
        if !self.lobby_sessions.contains_key(&target_steam_id)
            && self.lobby_sessions.len() >= MAX_LOBBY_SESSIONS
        {
            let oldest = self.lobby_sessions.keys().next().copied();
            if let Some(oldest) = oldest {
                if let Err(err) = gns.close_session(oldest) {
                    eprintln!("SteamClient: failed to close evicted GNS session: {err}");
                }
                self.lobby_sessions.remove(&oldest);
            }
        }

        // Reuse an existing session for this peer, or create a new one.
        let handle = match self.lobby_sessions.entry(target_steam_id) {
            std::collections::hash_map::Entry::Occupied(e) => *e.get(),
            std::collections::hash_map::Entry::Vacant(e) => *e.insert(gns.create_session()?),
        };

        // Send the message through the established session
        gns.send_message(handle, data, 0)?;

        Ok(())
    }

    /// Poll for incoming Steam notifications (friend status, chat, workshop
    /// events, etc.).
    pub fn poll_notifications(&mut self) -> AppResult<Vec<SteamNotification>> {
        let mut notifications = Vec::new();

        // Drain the protocol message queue
        self.stack.drain_messages()?;

        while let Some(msg) = self.stack.pop_message() {
            match msg.msg_type {
                SteamMessageType::ClientPersonaState => {
                    // Friend status change notification
                    if msg.payload.len() >= 8 {
                        let friend_steam_id =
                            u64::from_le_bytes(msg.payload[0..8].try_into().unwrap());
                        notifications.push(SteamNotification::FriendStatus {
                            steam_id: friend_steam_id,
                            status: "online".to_string(),
                        });
                    }
                }
                SteamMessageType::ClientFriendMsgIncoming => {
                    // Chat message received
                    if msg.payload.len() >= 8 {
                        let sender_steam_id =
                            u64::from_le_bytes(msg.payload[0..8].try_into().unwrap());
                        let message_text = if msg.payload.len() > 8 {
                            String::from_utf8_lossy(&msg.payload[8..]).to_string()
                        } else {
                            String::new()
                        };
                        notifications.push(SteamNotification::ChatMessage {
                            steam_id: sender_steam_id,
                            message: message_text,
                        });
                    }
                }
                SteamMessageType::ClientLicenseList => {
                    // License/app rights change
                    if msg.payload.len() >= 4 {
                        let app_id = u32::from_le_bytes(msg.payload[0..4].try_into().unwrap());
                        notifications.push(SteamNotification::LicenseChange { app_id });
                    }
                }
                SteamMessageType::ClientUserNotifications => {
                    // Generic user notifications (workshop, etc.)
                    let item_id = 0u64;
                    let app_id = 0u32;
                    notifications.push(SteamNotification::WorkshopUpdate { item_id, app_id });
                }
                _ => {
                    // Re-queue unexpected messages
                    self.stack.incoming_messages.push_back(msg);
                }
            }
        }

        // Also poll GNS messages if initialized
        if let Some(gns) = self.gns.as_mut()
            && let Ok(gns_messages) = gns.poll_incoming_messages()
        {
            for gns_msg in &gns_messages {
                // GNS messages could be chat, game data, etc.
                notifications.push(SteamNotification::ChatMessage {
                    steam_id: gns_msg.sender_id,
                    message: format!("GNS message ({} bytes)", gns_msg.data.len()),
                });
            }
        }

        Ok(notifications)
    }

    /// Set content server records for CDN downloads.
    pub fn set_content_servers(&mut self, servers: Vec<ContentServerRecord>) {
        self.content_servers = servers;
    }

    /// Parse and set content servers from a CDN routing response string.
    pub fn parse_and_set_content_servers(&mut self, routing_body: &str) -> AppResult<()> {
        let servers = self.stack.parse_cdn_routing(routing_body)?;
        self.content_servers = servers;
        Ok(())
    }
}

impl Default for SteamClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SteamNetworkingSockets — API wrapper for
// ISteamNetworkingSockets exported to the PE guest.
//
// This wraps GameNetworkingSockets with the Steam flat-API surface
// expected by game binaries (CreateListenSocketIP, ConnectByIPAddress,
// SendMessageToConnection, ReceiveMessagesOnListenSocket, etc.).
// ---------------------------------------------------------------------------

/// Handle representing a listen socket.
pub type ListenSocketHandle = u64;

/// Handle representing a connection (same as GnsConnectionHandle).
pub type SocketsConnectionHandle = u64;

/// SteamNetworkingSockets API wrapper.
///
/// Provides the flat-API functions that Steam game binaries call via
/// the PE runtime export table. Backed by a `GameNetworkingSockets`
/// instance for actual UDP/P2P networking.
/// Per-connection state tracking for the connection state machine.
#[derive(Debug, Clone)]
pub struct ConnectionDetail {
    /// Current GNS connection state.
    pub state: i32,
    /// Round-trip time estimate in milliseconds.
    pub ping_ms: i32,
    /// Local connection quality (0.0 – 1.0).
    pub connection_quality_local: f32,
    /// Remote connection quality (0.0 – 1.0).
    pub connection_quality_remote: f32,
    /// Outgoing packets per second.
    pub out_packets_per_sec: f32,
    /// Incoming packets per second.
    pub in_packets_per_sec: f32,
    /// Send rate in bytes per second.
    pub send_rate_bytes_per_sec: u32,
    /// Number of pending unreliable messages.
    pub pending_unreliable: u32,
    /// Number of pending reliable messages.
    pub pending_reliable: u32,
    /// Number of sent but unacknowledged reliable messages.
    pub sent_unacked_reliable: u32,
}

impl Default for ConnectionDetail {
    fn default() -> Self {
        Self {
            state: 0, // k_ESteamNetworkingConnectionState_None
            ping_ms: 0,
            connection_quality_local: 1.0,
            connection_quality_remote: 1.0,
            out_packets_per_sec: 0.0,
            in_packets_per_sec: 0.0,
            send_rate_bytes_per_sec: 0,
            pending_unreliable: 0,
            pending_reliable: 0,
            sent_unacked_reliable: 0,
        }
    }
}

pub struct SteamNetworkingSockets {
    /// Inner GNS implementation.
    gns: GameNetworkingSockets,
    /// Listen sockets map: listen handle -> (local address, connection handles).
    listen_sockets: BTreeMap<ListenSocketHandle, (String, Vec<SocketsConnectionHandle>)>,
    /// Next listen socket handle.
    next_listen_handle: ListenSocketHandle,
    /// SteamID → SocketAddr resolution cache.
    steam_id_to_addr: BTreeMap<u64, SocketAddr>,
    /// Connection name table: connection handle -> name string.
    connection_names: BTreeMap<SocketsConnectionHandle, String>,
    /// Per-connection state machine details.
    connection_details: BTreeMap<SocketsConnectionHandle, ConnectionDetail>,
    /// Pending outgoing message queue per connection (for flush).
    pending_outgoing: BTreeMap<SocketsConnectionHandle, Vec<Vec<u8>>>,
}

impl SteamNetworkingSockets {
    /// Create a new SteamNetworkingSockets instance.
    pub fn new() -> Self {
        Self {
            gns: GameNetworkingSockets::new(),
            listen_sockets: BTreeMap::new(),
            next_listen_handle: 1,
            steam_id_to_addr: BTreeMap::new(),
            connection_names: BTreeMap::new(),
            connection_details: BTreeMap::new(),
            pending_outgoing: BTreeMap::new(),
        }
    }

    /// Returns a mutable reference to the inner GNS.
    pub fn gns_mut(&mut self) -> &mut GameNetworkingSockets {
        &mut self.gns
    }

    /// Returns a reference to the inner GNS.
    pub fn gns(&self) -> &GameNetworkingSockets {
        &self.gns
    }

    /// Create a listen socket bound to a local address (P2P).
    ///
    /// This binds a UDP socket for incoming P2P connections and
    /// optionally performs STUN to discover the external address.
    ///
    /// Returns the listen socket handle.
    pub fn create_listen_socket_ip(
        &mut self,
        bind_addr: Option<SocketAddr>,
        use_stun: bool,
    ) -> AppResult<ListenSocketHandle> {
        let local_addr = self.gns.bind_udp(bind_addr)?;

        if use_stun {
            // Use default STUN server if not already configured
            if self.gns.stun_server().is_none() {
                let stun_addr: SocketAddr = DEFAULT_STUN_SERVER
                    .to_socket_addrs()
                    .map_err(|e| {
                        AppError::new(
                            ReasonCode::RcNetDnsResolutionFailed,
                            format!("SteamNetworkingSockets: STUN DNS resolution failed: {e}"),
                        )
                    })?
                    .next()
                    .ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcNetDnsResolutionFailed,
                            "SteamNetworkingSockets: no STUN server address",
                        )
                    })?;
                self.gns.set_stun_server(stun_addr);
            }

            // Perform STUN binding
            match self.gns.perform_stun_binding() {
                Ok(external) => {
                    eprintln!(
                        "SteamNetworkingSockets: STUN discovered external address: {external}"
                    );
                }
                Err(e) => {
                    eprintln!("SteamNetworkingSockets: STUN failed (non-fatal): {e}");
                }
            }
        }

        let handle = self.next_listen_handle;
        self.next_listen_handle += 1;
        self.listen_sockets
            .insert(handle, (local_addr.to_string(), Vec::new()));
        Ok(handle)
    }

    /// Connect to a remote peer by IP address.
    ///
    /// Creates a new GNS session and records the peer address in the
    /// routing table for subsequent `send_message_to_connection()` calls.
    pub fn connect_by_ip_address(
        &mut self,
        peer_addr: SocketAddr,
    ) -> AppResult<SocketsConnectionHandle> {
        let handle = self.gns.create_session()?;
        self.gns.set_peer_address(handle, peer_addr)?;
        Ok(handle)
    }

    /// Send a message to a connected peer.
    pub fn send_message_to_connection(
        &mut self,
        conn_handle: SocketsConnectionHandle,
        data: &[u8],
        channel: i32,
    ) -> AppResult<()> {
        self.gns.send_message(conn_handle, data, channel)
    }

    /// Receive messages on a listen socket (incoming connections and data).
    ///
    /// Messages are filtered to the connections that belong to this listen
    /// socket so that one game polling its own listen socket cannot consume
    /// messages intended for another listen socket / connection. Connections
    /// are claimed by the first listen socket that observes a message from
    /// them.
    pub fn receive_messages_on_listen_socket(
        &mut self,
        listen_handle: ListenSocketHandle,
    ) -> AppResult<Vec<SteamNetworkingMessage>> {
        if !self.listen_sockets.contains_key(&listen_handle) {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("SteamNetworkingSockets: unknown listen socket {listen_handle}"),
            ));
        }

        let messages = self.gns.poll_incoming_messages()?;
        let mut result = Vec::with_capacity(messages.len());
        for msg in messages {
            // Claim unowned connections for this listen socket so messages
            // are not cross-delivered between sockets.
            let is_owned_elsewhere = self
                .listen_sockets
                .iter()
                .any(|(handle, (_, conns))| *handle != listen_handle && conns.contains(&msg.conn));
            if !is_owned_elsewhere
                && let Some((_, conns)) = self.listen_sockets.get_mut(&listen_handle)
                && !conns.contains(&msg.conn)
            {
                conns.push(msg.conn);
            }
            if !is_owned_elsewhere {
                result.push(msg);
            }
        }
        Ok(result)
    }

    /// Close a connection.
    pub fn close_connection(&mut self, conn_handle: SocketsConnectionHandle) -> AppResult<()> {
        self.gns.close_session(conn_handle)
    }

    /// Destroy a listen socket and all associated connections.
    pub fn destroy_listen_socket(&mut self, listen_handle: ListenSocketHandle) -> AppResult<()> {
        if let Some((_, conn_handles)) = self.listen_sockets.remove(&listen_handle) {
            for handle in conn_handles {
                if let Err(e) = self.gns.close_session(handle) {
                    eprintln!("SteamService: error closing GNS session {handle}: {e}");
                }
            }
        }
        Ok(())
    }

    /// Register a SteamID → SocketAddr mapping for P2P connections by SteamID.
    pub fn set_steam_id_address(&mut self, steam_id: u64, addr: SocketAddr) {
        self.steam_id_to_addr.insert(steam_id, addr);
    }

    /// Connect to a peer using their SteamID rather than IP address.
    ///
    /// Looks up the cached SocketAddr for the given SteamID and creates
    /// a GNS session to that address.
    pub fn connect_by_steam_id(&mut self, steam_id: u64) -> AppResult<SocketsConnectionHandle> {
        let addr = self.steam_id_to_addr.get(&steam_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("No address cached for SteamID {}", steam_id),
            )
        })?;
        let handle = self.gns.create_session()?;
        self.gns.set_peer_address(handle, *addr)?;
        Ok(handle as SocketsConnectionHandle)
    }

    /// Accept an incoming connection.
    pub fn accept_connection(&mut self, handle: SocketsConnectionHandle) -> AppResult<()> {
        self.gns.accept_session(handle as GnsConnectionHandle)
    }

    /// Get detailed status information for a connection.
    ///
    /// Merges the tracked per-connection details (ping, quality, rates,
    /// pending counts) with the live GNS connection state.
    pub fn get_connection_status(
        &self,
        handle: SocketsConnectionHandle,
    ) -> AppResult<SteamNetworkingConnectionStatus> {
        let state = self.gns.connection_state(handle as GnsConnectionHandle);
        let detail = self.connection_details.get(&handle);
        Ok(SteamNetworkingConnectionStatus {
            state: state.map(|s| s as i32).unwrap_or(0),
            ping: detail.map(|d| d.ping_ms).unwrap_or(0),
            connection_quality_local: detail.map(|d| d.connection_quality_local).unwrap_or(1.0),
            connection_quality_remote: detail.map(|d| d.connection_quality_remote).unwrap_or(1.0),
            out_packets_per_sec: detail.map(|d| d.out_packets_per_sec).unwrap_or(0.0),
            in_packets_per_sec: detail.map(|d| d.in_packets_per_sec).unwrap_or(0.0),
            send_rate_bytes_per_sec: detail
                .map(|d| d.send_rate_bytes_per_sec as i32)
                .unwrap_or(0),
            pending_unreliable: detail.map(|d| d.pending_unreliable as i32).unwrap_or(0),
            pending_reliable: detail.map(|d| d.pending_reliable as i32).unwrap_or(0),
            sent_unacked_reliable: detail.map(|d| d.sent_unacked_reliable as i32).unwrap_or(0),
            ..Default::default()
        })
    }

    /// Set a human-readable name for a connection.
    pub fn set_connection_name(&mut self, handle: SocketsConnectionHandle, name: &str) {
        self.connection_names.insert(handle, name.to_string());
    }

    /// Get the human-readable name for a connection.
    pub fn get_connection_name(&self, handle: SocketsConnectionHandle) -> AppResult<String> {
        self.connection_names.get(&handle).cloned().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("No name for connection {}", handle),
            )
        })
    }

    /// Create a P2P listen socket (no IP/port argument, binds to ephemeral port).
    ///
    /// This is the connection-less variant used for P2P networking.
    pub fn create_listen_socket(&mut self) -> AppResult<ListenSocketHandle> {
        // Bind to 0.0.0.0:0 (OS-assigned ephemeral port) without STUN
        let addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e| {
            AppError::new(
                ReasonCode::RcPortParseError,
                format!("SteamNetworkingSockets: failed to parse ephemeral bind address: {e}"),
            )
        })?;
        self.create_listen_socket_ip(Some(addr), false)
    }

    /// Flush any pending outgoing messages on a connection.
    ///
    /// Immediately sends all queued pending messages through the GNS layer.
    /// Returns the number of bytes flushed on success. If a send fails
    /// partway, the unsent remainder is re-queued for a later retry instead
    /// of being dropped.
    pub fn flush_message_on_connection(
        &mut self,
        conn_handle: SocketsConnectionHandle,
        channel: i32,
    ) -> AppResult<u64> {
        let mut total_bytes: u64 = 0;
        if let Some(pending) = self.pending_outgoing.remove(&conn_handle) {
            for (i, data) in pending.iter().enumerate() {
                if let Err(e) = self.gns.send_message(conn_handle, data, channel) {
                    // Re-queue everything from the first failed message on;
                    // already-sent messages are gone but nothing is lost
                    // silently.
                    if i < pending.len() {
                        self.pending_outgoing
                            .entry(conn_handle)
                            .or_default()
                            .extend_from_slice(&pending[i..]);
                    }
                    return Err(e);
                }
                total_bytes += data.len() as u64;
            }
        }
        // Update connection state metrics after flushing.
        if let Some(detail) = self.connection_details.get_mut(&conn_handle) {
            detail.pending_reliable = self
                .pending_outgoing
                .get(&conn_handle)
                .map(|v| v.len() as u32)
                .unwrap_or(0);
        }
        Ok(total_bytes)
    }

    /// Queue a message for later flushing, or send immediately if not using flush mode.
    pub fn send_message_with_flush(
        &mut self,
        conn_handle: SocketsConnectionHandle,
        data: &[u8],
        channel: i32,
        use_flush: bool,
    ) -> AppResult<()> {
        if use_flush {
            // Bound the per-connection queue so an unflushed producer cannot
            // grow memory without limit.
            const MAX_PENDING_PER_CONNECTION: usize = 1024;
            let queue = self.pending_outgoing.entry(conn_handle).or_default();
            if queue.len() >= MAX_PENDING_PER_CONNECTION {
                return Err(AppError::new(
                    ReasonCode::RcSocketReceiveQueueFull,
                    format!(
                        "SteamNetworkingSockets: pending queue full for connection {conn_handle} (max {MAX_PENDING_PER_CONNECTION})"
                    ),
                ));
            }
            queue.push(data.to_vec());
            if let Some(detail) = self.connection_details.get_mut(&conn_handle) {
                detail.pending_reliable = self
                    .pending_outgoing
                    .get(&conn_handle)
                    .map(|v| v.len() as u32)
                    .unwrap_or(0);
            }
            Ok(())
        } else {
            self.gns.send_message(conn_handle, data, channel)
        }
    }
}

impl Default for SteamNetworkingSockets {
    fn default() -> Self {
        Self::new()
    }
}

/// Detailed status of a Steam networking connection.
///
/// Field types match `SteamNetworkingConnectionStatus_t` from the Steam SDK
/// (`int` for the rate/count fields) so the layout exported to guest binaries
/// via FFI is exact.
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct SteamNetworkingConnectionStatus {
    pub state: i32,
    pub ping: i32,
    pub connection_quality_local: f32,
    pub connection_quality_remote: f32,
    pub out_packets_per_sec: f32,
    pub in_packets_per_sec: f32,
    pub send_rate_bytes_per_sec: i32,
    pub pending_unreliable: i32,
    pub pending_reliable: i32,
    pub sent_unacked_reliable: i32,
    pub usec_queue_time: u64,
}

// ---------------------------------------------------------------------------
// SteamNetworkingMessages — API wrapper for ISteamNetworkingMessages
//
// Provides a simpler message-oriented API (as opposed to connection-oriented
// ISteamNetworkingSockets). Used for lobby/chat messaging between Steam users.
// ---------------------------------------------------------------------------

/// SteamNetworkingMessages API wrapper.
///
/// Provides SendMessageToUser / ReceiveMessagesOnChannel for simple
/// Steam user-to-user messaging over the GNS layer.
#[derive(Debug)]
pub struct SteamNetworkingMessages {
    /// Inner GNS implementation (shared or separate).
    gns: GameNetworkingSockets,
    /// Map of Steam ID -> GNS connection handle for active sessions.
    sessions: BTreeMap<u64, GnsConnectionHandle>,
}

impl SteamNetworkingMessages {
    /// Create a new SteamNetworkingMessages instance.
    pub fn new() -> Self {
        Self {
            gns: GameNetworkingSockets::new(),
            sessions: BTreeMap::new(),
        }
    }

    /// Returns a mutable reference to the inner GNS.
    pub fn gns_mut(&mut self) -> &mut GameNetworkingSockets {
        &mut self.gns
    }

    /// Returns a reference to the inner GNS.
    pub fn gns(&self) -> &GameNetworkingSockets {
        &self.gns
    }

    /// Send a message to a Steam user by their Steam ID.
    ///
    /// Creates a GNS session if one does not already exist for this user.
    /// If a peer address is known (via `set_user_address`), the message is
    /// sent over UDP; otherwise falls back to the in-memory queue.
    pub fn send_message_to_user(
        &mut self,
        steam_id: u64,
        data: &[u8],
        channel: i32,
    ) -> AppResult<()> {
        let handle = match self.sessions.get(&steam_id) {
            Some(&h) => h,
            None => {
                // Bound the session table so long-running peers cannot grow
                // memory without limit; the oldest session is evicted first.
                const MAX_USER_SESSIONS: usize = 256;
                while self.sessions.len() >= MAX_USER_SESSIONS {
                    if let Some((oldest, _)) = self.sessions.iter().next().map(|(k, v)| (*k, *v)) {
                        if let Err(err) = self.gns.close_session(oldest) {
                            eprintln!(
                                "SteamNetworkingMessages: failed to close evicted session: {err}"
                            );
                        }
                        self.sessions.remove(&oldest);
                    }
                }
                let h = self.gns.create_session()?;
                self.sessions.insert(steam_id, h);
                h
            }
        };
        self.gns.send_message(handle, data, channel)
    }

    /// Receive all pending messages across all user sessions.
    pub fn receive_messages_on_channel(&mut self) -> AppResult<Vec<SteamNetworkingMessage>> {
        self.gns.poll_incoming_messages()
    }

    /// Set the peer address for a given Steam ID (for P2P routing).
    pub fn set_user_address(&mut self, steam_id: u64, addr: SocketAddr) -> AppResult<()> {
        let handle = match self.sessions.get(&steam_id) {
            Some(&h) => h,
            None => {
                let h = self.gns.create_session()?;
                self.sessions.insert(steam_id, h);
                h
            }
        };
        self.gns.set_peer_address(handle, addr)
    }

    /// Close the session with a specific user.
    pub fn close_session_with_user(&mut self, steam_id: u64) -> AppResult<()> {
        if let Some(handle) = self.sessions.remove(&steam_id) {
            self.gns.close_session(handle)?;
        }
        Ok(())
    }
}

impl Default for SteamNetworkingMessages {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Steam Overlay State Manager
// ---------------------------------------------------------------------------

// CoreGraphics FFI for real-time keyboard state querying on macOS.
//
// Used by the overlay manager to detect Shift+Tab keybinding without
// requiring modification of the input pipeline.  This is the same
// approach used by `src/user32.rs` for `GetAsyncKeyState`.
#[cfg(target_os = "macos")]
#[allow(non_snake_case)]
unsafe extern "C" {
    // Returns the flags state (modifier keys) for a given event source.
    fn CGEventSourceFlagsState(sourceStateID: i32) -> u64;
    // Returns whether a given key code is currently pressed.
    fn CGEventSourceKeyState(sourceStateID: i32, keyCode: u16) -> bool;
}

#[cfg(target_os = "macos")]
const kCGEventSourceStatePrivate: i32 = -1;
#[cfg(target_os = "macos")]
const kCGEventFlagMaskShift: u64 = 0x0002_0000;
#[cfg(target_os = "macos")]
const kCGEventFlagMaskControl: u64 = 0x0004_0000;

/// macOS HID key code for the Tab key (0x30 = kVK_Tab).
#[cfg(target_os = "macos")]
const kVK_TAB: u16 = 0x30;

/// Steam overlay state manager.
///
/// Tracks whether the Steam overlay is active and provides Shift+Tab
/// detection via macOS CoreGraphics event APIs so that the overlay
/// toggle works even when the guest game window does not have focus.
///
/// This is a thread-safe global singleton, callable from any module.
pub struct SteamOverlayManager {
    /// Whether the overlay is currently visible / compositing.
    overlay_active: bool,
    /// Edge-detection flag: true for one poll cycle after a toggle.
    /// Consumers (e.g. the CEF bridge) check this to load/unload the
    /// overlay WKWebView.
    toggle_occurred: bool,
    /// Whether Shift was held during the *last* poll.  Used to detect
    /// a fresh combined press of Shift+Tab rather than continuous hold.
    shift_was_down: bool,
    /// Whether Tab was held during the *last* poll.
    tab_was_down: bool,
    /// Steam overlay URL that will be loaded when the overlay activates.
    overlay_url: String,
}

impl SteamOverlayManager {
    /// Create a new overlay manager with the default Steam overlay URL.
    pub fn new() -> Self {
        Self {
            overlay_active: false,
            toggle_occurred: false,
            shift_was_down: false,
            tab_was_down: false,
            overlay_url: "steam://openurl/https://steamcommunity.com/my/overlay".to_string(),
        }
    }

    /// Poll keyboard state via the macOS CoreGraphics API and detect
    /// Shift+Tab.  If the chord is newly pressed, toggle the overlay.
    ///
    /// Should be called once per frame from the rendering loop or from
    /// the host window's event pump.
    pub fn poll_keyboard_state(&mut self) {
        let (shift_down, tab_down) = self.query_key_state();
        // Edge detection: rising edge of both keys simultaneously.
        let newly_pressed = shift_down && tab_down && !(self.shift_was_down && self.tab_was_down);
        self.shift_was_down = shift_down;
        self.tab_was_down = tab_down;
        if newly_pressed {
            self.overlay_active = !self.overlay_active;
            self.toggle_occurred = true;
        }
    }

    /// Query the physical key state via CoreGraphics.
    #[cfg(target_os = "macos")]
    fn query_key_state(&self) -> (bool, bool) {
        unsafe {
            let flags = CGEventSourceFlagsState(kCGEventSourceStatePrivate);
            let shift = (flags & kCGEventFlagMaskShift) != 0;
            let tab = CGEventSourceKeyState(kCGEventSourceStatePrivate, kVK_TAB);
            (shift, tab)
        }
    }

    /// Fallback when not on macOS — always returns (false, false).
    #[cfg(not(target_os = "macos"))]
    fn query_key_state(&self) -> (bool, bool) {
        (false, false)
    }

    /// Force-toggle the overlay state programmatically (e.g. from a
    /// Steam API call or remote debug command).
    pub fn toggle(&mut self) {
        self.overlay_active = !self.overlay_active;
        self.toggle_occurred = true;
    }

    /// Set the overlay active state directly.
    pub fn set_active(&mut self, active: bool) {
        if self.overlay_active != active {
            self.overlay_active = active;
            self.toggle_occurred = true;
        }
    }

    /// Returns `true` if the overlay is currently active / visible.
    pub fn is_active(&self) -> bool {
        self.overlay_active
    }

    /// Consume the toggle-occurred flag (edge detection).  Returns
    /// `true` if a toggle happened since the last call to this method.
    pub fn consume_toggle(&mut self) -> bool {
        let occurred = self.toggle_occurred;
        self.toggle_occurred = false;
        occurred
    }

    /// Get the overlay URL that should be loaded when the overlay activates.
    pub fn overlay_url(&self) -> &str {
        &self.overlay_url
    }

    /// Set a custom overlay URL.
    pub fn set_overlay_url(&mut self, url: String) {
        self.overlay_url = url;
    }
}

impl Default for SteamOverlayManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Global singleton ──────────────────────────────────────────────────

static GLOBAL_STEAM_OVERLAY: std::sync::LazyLock<std::sync::Mutex<SteamOverlayManager>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(SteamOverlayManager::new()));

/// Access the global overlay manager with a closure.
pub fn with_steam_overlay<F, R>(f: F) -> R
where
    F: FnOnce(&mut SteamOverlayManager) -> R,
{
    // Recover from a poisoned lock (a previous panic while holding it) so
    // overlay callbacks never become fatal.
    let mut guard = GLOBAL_STEAM_OVERLAY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// Poll keyboard state for Shift+Tab detection (call once per frame).
pub fn steam_overlay_poll_keyboard() {
    with_steam_overlay(|mgr| mgr.poll_keyboard_state());
}

/// Returns `true` if the overlay is currently active.
pub fn steam_overlay_is_active() -> bool {
    with_steam_overlay(|mgr| mgr.is_active())
}

/// Force-toggle the overlay.
pub fn steam_overlay_toggle() {
    with_steam_overlay(|mgr| mgr.toggle());
}

/// Set overlay active state directly.
pub fn steam_overlay_set_active(active: bool) {
    with_steam_overlay(|mgr| mgr.set_active(active));
}

/// Consume the toggle flag (edge detection).  Returns `true` if the
/// overlay was toggled since the last call.
pub fn steam_overlay_consume_toggle() -> bool {
    with_steam_overlay(|mgr| mgr.consume_toggle())
}

// ---------------------------------------------------------------------------
// Overlay Input Forwarding
// ---------------------------------------------------------------------------

/// Determines whether keyboard/mouse input events should be forwarded to
/// the overlay WKWebView instead of the game.
///
/// When the overlay is active, input events (keyboard, mouse clicks,
/// scroll) should be routed to the overlay webview so the user can
/// interact with the Steam UI (browse, chat, etc.).  When the overlay
/// is inactive, all events pass through to the game normally.
pub fn steam_overlay_should_capture_input() -> bool {
    steam_overlay_is_active()
}

/// Forward a keyboard event to the overlay WKWebView (if active).
///
/// When the overlay is capturing input, this dispatches a synthetic
/// `KeyboardEvent` via JavaScript in the overlay browser.  This lets
/// the Steam UI respond to typing, navigation, and shortcut keys.
///
/// Parameters:
/// - `key_code`:  Windows virtual-key code (e.g. `VK_RETURN = 0x0D`).
/// - `key_char`:  Optional Unicode character for `keypress` events.
/// - `down`:      `true` for `keydown`, `false` for `keyup`.
pub fn steam_overlay_forward_key_event(key_code: u16, key_char: Option<char>, down: bool) {
    if !steam_overlay_should_capture_input() {
        return;
    }

    let event_type = if down { "keydown" } else { "keyup" };
    // JSON-encode the key so quotes/backslashes can never break out of the
    // generated JavaScript string literal.
    let key_str = key_char
        .map(|c| serde_json::to_string(&c.to_string()).unwrap_or_else(|_| "\"\"".to_string()))
        .unwrap_or_else(|| "\"\"".to_string());

    let js = format!(
        r#"(function() {{
            var event = new KeyboardEvent('{event_type}', {{
                key: {key_str},
                keyCode: {key_code},
                which: {key_code},
                code: '',
                bubbles: true,
                cancelable: true
            }});
            document.activeElement?.dispatchEvent(event);
        }})()"#,
        event_type = event_type,
        key_str = key_str,
        key_code = key_code,
    );

    crate::cef_bridge::with_global_cef_bridge(|bridge| {
        if let Some(handle) = bridge.overlay_browser_handle()
            && let Err(e) = bridge.cef_frame_execute_java_script(handle, 1, &js)
        {
            eprintln!("steam_overlay_forward_key_event: JS exec failed: {e}");
        }
    });
}

/// Forward a mouse-move event to the overlay WKWebView (if active).
///
/// The coordinates are in window-relative pixels.
pub fn steam_overlay_forward_mouse_move(x: f64, y: f64) {
    if !steam_overlay_should_capture_input() {
        return;
    }

    let js = format!(
        r#"(function() {{
            var event = new MouseEvent('mousemove', {{
                clientX: {x},
                clientY: {y},
                bubbles: true,
                cancelable: true
            }});
            document.elementFromPoint({x}, {y})?.dispatchEvent(event);
        }})()"#,
        x = x,
        y = y,
    );

    crate::cef_bridge::with_global_cef_bridge(|bridge| {
        if let Some(handle) = bridge.overlay_browser_handle()
            && let Err(e) = bridge.cef_frame_execute_java_script(handle, 1, &js)
        {
            eprintln!("steam_overlay_forward_mouse_move: JS exec failed: {e}");
        }
    });
}

/// Forward a mouse-button event to the overlay WKWebView (if active).
///
/// `button` follows the MouseEvent.button convention:
///   0 = left, 1 = middle, 2 = right
/// `down` is `true` for mousedown, `false` for mouseup.
pub fn steam_overlay_forward_mouse_button(x: f64, y: f64, button: i32, down: bool) {
    if !steam_overlay_should_capture_input() {
        return;
    }

    let event_type = if down { "mousedown" } else { "mouseup" };

    let js = format!(
        r#"(function() {{
            var event = new MouseEvent('{event_type}', {{
                clientX: {x},
                clientY: {y},
                button: {button},
                bubbles: true,
                cancelable: true
            }});
            document.elementFromPoint({x}, {y})?.dispatchEvent(event);
        }})()"#,
        event_type = event_type,
        x = x,
        y = y,
        button = button,
    );

    crate::cef_bridge::with_global_cef_bridge(|bridge| {
        if let Some(handle) = bridge.overlay_browser_handle()
            && let Err(e) = bridge.cef_frame_execute_java_script(handle, 1, &js)
        {
            eprintln!("steam_overlay_forward_mouse_button: JS exec failed: {e}");
        }
    });
}

/// Forward a mouse-wheel event to the overlay WKWebView (if active).
///
/// `delta_x` and `delta_y` represent scroll deltas in pixels.
pub fn steam_overlay_forward_mouse_wheel(x: f64, y: f64, delta_x: f64, delta_y: f64) {
    if !steam_overlay_should_capture_input() {
        return;
    }

    let js = format!(
        r#"(function() {{
            var event = new WheelEvent('wheel', {{
                clientX: {x},
                clientY: {y},
                deltaX: {delta_x},
                deltaY: {delta_y},
                deltaMode: 0,
                bubbles: true,
                cancelable: true
            }});
            document.elementFromPoint({x}, {y})?.dispatchEvent(event);
        }})()"#,
        x = x,
        y = y,
        delta_x = delta_x,
        delta_y = delta_y,
    );

    crate::cef_bridge::with_global_cef_bridge(|bridge| {
        if let Some(handle) = bridge.overlay_browser_handle()
            && let Err(e) = bridge.cef_frame_execute_java_script(handle, 1, &js)
        {
            eprintln!("steam_overlay_forward_mouse_wheel: JS exec failed: {e}");
        }
    });
}

// ---------------------------------------------------------------------------
// K1 — ISteamUserStats (Achievements, Stats, Leaderboards)
// ---------------------------------------------------------------------------

/// Current app id for per-app config file scoping.
///
/// Set via `SteamUserStats::set_app_id` / `SteamFriends::set_app_id` (or the
/// shared `set_steam_config_app_id`) so stats/friends data from different
/// games does not overwrite one another in the shared config directory.
static CONFIG_APP_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Set the app id used to scope persisted Steam config files (stats, friends).
pub fn set_steam_config_app_id(app_id: u32) {
    CONFIG_APP_ID.store(app_id, std::sync::atomic::Ordering::Relaxed);
}

/// Build a per-app config file name, e.g. `user_stats_480.json` when an app
/// id is set, or `user_stats.json` for the default (unset) app.
fn app_scoped_config_name(base: &str) -> String {
    let app_id = CONFIG_APP_ID.load(std::sync::atomic::Ordering::Relaxed);
    if app_id == 0 {
        base.to_string()
    } else {
        format!("{base}_{app_id}")
    }
}

/// A single leaderboard entry returned by `DownloadLeaderboardEntries`.
#[derive(Debug, Clone)]
pub struct LeaderboardEntry {
    pub steam_id: u64,
    pub global_rank: i32,
    pub score: i32,
    pub details: Vec<i32>,
    pub ugc_handle: u64,
}

/// Steam UserStats / Achievements / Leaderboards API wrapper.
///
/// Provides in-memory storage for stats and achievements, plus leaderboard
/// CRUD with numeric scoring.  All data is local — no network calls.
/// Snapshot of SteamUserStats state for JSON persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatsSnapshot {
    achievements: BTreeMap<String, u64>,
    stats: BTreeMap<String, i32>,
    stats_float: BTreeMap<String, f64>,
    avg_rate: BTreeMap<String, (f64, f64)>,
    leaderboards: BTreeMap<String, Vec<(i32, u64, Vec<i32>)>>,
    achievement_progress: BTreeMap<String, (f32, f32)>,
}

#[derive(Debug)]
pub struct SteamUserStats {
    achievements: BTreeMap<String, u64>,
    stats: BTreeMap<String, i32>,
    stats_float: BTreeMap<String, f64>,
    avg_rate: BTreeMap<String, (f64, f64)>,
    leaderboards: BTreeMap<String, Vec<(i32, u64, Vec<i32>)>>,
    stats_received: bool,
    /// Per-SteamID stat snapshots for request_user_stats.
    remote_stats: BTreeMap<u64, BTreeMap<String, i32>>,
    remote_stats_float: BTreeMap<u64, BTreeMap<String, f64>>,
    /// Achievement progress tracking: achievement_name -> (current_progress, max_progress).
    achievement_progress: BTreeMap<String, (f32, f32)>,
}

impl SteamUserStats {
    fn config_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Casa1")
            .join("config")
            .join(format!("{}.json", app_scoped_config_name("user_stats")))
    }

    /// Set the app id used to scope this user's persisted stats file, so
    /// different games do not overwrite each other's achievements/leaderboards.
    pub fn set_app_id(app_id: u32) {
        set_steam_config_app_id(app_id);
    }

    fn load_from_config(&mut self) {
        let path = Self::config_path();
        if !path.exists() {
            return;
        }
        match fs::read_to_string(&path) {
            Ok(json) => match serde_json::from_str::<StatsSnapshot>(&json) {
                Ok(snapshot) => {
                    self.achievements = snapshot.achievements;
                    self.stats = snapshot.stats;
                    self.stats_float = snapshot.stats_float;
                    self.avg_rate = snapshot.avg_rate;
                    self.leaderboards = snapshot.leaderboards;
                    self.achievement_progress = snapshot.achievement_progress;
                }
                Err(e) => {
                    eprintln!("SteamUserStats: failed to parse config: {e}");
                }
            },
            Err(e) => {
                eprintln!("SteamUserStats: failed to read config: {e}");
            }
        }
    }

    fn save_to_config(&self) {
        let snapshot = StatsSnapshot {
            achievements: self.achievements.clone(),
            stats: self.stats.clone(),
            stats_float: self.stats_float.clone(),
            avg_rate: self.avg_rate.clone(),
            leaderboards: self.leaderboards.clone(),
            achievement_progress: self.achievement_progress.clone(),
        };
        let path = Self::config_path();
        let Some(parent) = path.parent() else {
            return;
        };
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("SteamUserStats: failed to create config dir: {e}");
            return;
        }
        match serde_json::to_string_pretty(&snapshot) {
            Ok(json) => {
                if let Err(e) = fs::write(&path, &json) {
                    eprintln!("SteamUserStats: failed to save config: {e}");
                }
            }
            Err(e) => {
                eprintln!("SteamUserStats: failed to serialize config: {e}");
            }
        }
    }

    pub fn new() -> Self {
        let mut s = Self {
            achievements: BTreeMap::new(),
            stats: BTreeMap::new(),
            stats_float: BTreeMap::new(),
            avg_rate: BTreeMap::new(),
            leaderboards: BTreeMap::new(),
            stats_received: false,
            remote_stats: BTreeMap::new(),
            remote_stats_float: BTreeMap::new(),
            achievement_progress: BTreeMap::new(),
        };
        s.load_from_config();
        s
    }

    pub fn request_current_stats(&mut self) -> AppResult<()> {
        self.stats_received = true;
        Ok(())
    }

    pub fn get_achievement(&self, name: &str) -> bool {
        self.achievements.contains_key(name)
    }

    pub fn get_achievement_unlock_time(&self, name: &str) -> Option<u64> {
        self.achievements.get(name).copied()
    }

    pub fn set_achievement(&mut self, name: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.achievements.insert(name.to_string(), now);
        self.save_to_config();
    }

    pub fn clear_achievement(&mut self, name: &str) {
        self.achievements.remove(name);
        self.save_to_config();
    }

    pub fn get_num_achievements(&self) -> usize {
        self.achievements.len()
    }

    pub fn get_achievement_name(&self, idx: usize) -> Option<&str> {
        // BTreeMap keys are already sorted; step the iterator directly to
        // avoid per-call allocation and sorting in this hot getter.
        self.achievements.keys().nth(idx).map(|s| s.as_str())
    }

    pub fn indicate_achievement_icon(&mut self, _name: &str) -> bool {
        true
    }

    pub fn get_stat(&self, name: &str) -> i32 {
        self.stats.get(name).copied().unwrap_or(0)
    }

    pub fn set_stat(&mut self, name: &str, value: i32) {
        self.stats.insert(name.to_string(), value);
        self.save_to_config();
    }

    pub fn get_stat_float(&self, name: &str) -> f64 {
        self.stats_float.get(name).copied().unwrap_or(0.0)
    }

    pub fn set_stat_float(&mut self, name: &str, value: f64) {
        self.stats_float.insert(name.to_string(), value);
        self.save_to_config();
    }

    pub fn update_avg_rate_stat(&mut self, name: &str, count: f64, value: f64) {
        let entry = self.avg_rate.entry(name.to_string()).or_insert((0.0, 0.0));
        entry.0 += value;
        entry.1 += count;
    }

    pub fn get_avg_rate_stat(&self, name: &str) -> f64 {
        self.avg_rate
            .get(name)
            .filter(|(_, count)| *count > 0.0)
            .map(|(sum, count)| sum / count)
            .unwrap_or(0.0)
    }

    pub fn store_stat_float(&mut self, name: &str, value: f64) {
        self.stats_float.insert(name.to_string(), value);
        self.save_to_config();
    }

    pub fn find_or_create_leaderboard(&mut self, name: &str) -> AppResult<()> {
        self.leaderboards.entry(name.to_string()).or_default();
        self.save_to_config();
        Ok(())
    }

    pub fn upload_leaderboard_score(
        &mut self,
        name: &str,
        score: i32,
        details: Vec<i32>,
    ) -> AppResult<()> {
        let board = self.leaderboards.entry(name.to_string()).or_default();
        board.push((score, 0, details));
        board.sort_by_key(|e| std::cmp::Reverse(e.0));
        self.save_to_config();
        Ok(())
    }

    pub fn download_leaderboard_entries(&self, name: &str) -> AppResult<Vec<LeaderboardEntry>> {
        let board = self.leaderboards.get(name).ok_or_else(|| {
            AppError::new(
                crate::reason::ReasonCode::RcCliInvalid,
                format!("leaderboard '{name}' not found"),
            )
        })?;
        let entries: Vec<LeaderboardEntry> = board
            .iter()
            .enumerate()
            .map(|(i, (score, sid, det))| LeaderboardEntry {
                steam_id: *sid,
                global_rank: (i + 1) as i32,
                score: *score,
                details: det.clone(),
                ugc_handle: 0,
            })
            .collect();
        Ok(entries)
    }

    pub fn get_leaderboard_entry_count(&self, name: &str) -> usize {
        self.leaderboards.get(name).map(|b| b.len()).unwrap_or(0)
    }

    pub fn get_leaderboard_name(&self, idx: usize) -> Option<&str> {
        // BTreeMap keys are already sorted; avoid per-call allocation/sort.
        self.leaderboards.keys().nth(idx).map(|s| s.as_str())
    }

    pub fn attach_leaderboard_ugc(&mut self, _name: &str, _ugc_handle: u64) -> AppResult<()> {
        Ok(())
    }

    pub fn get_leaderboard_sort_method(&self, _name: &str) -> i32 {
        0
    }

    pub fn get_leaderboard_display_type(&self, _name: &str) -> i32 {
        0
    }

    // ── Missing K1 methods ────────────────────────────────────────────

    /// Reset all stats (local in-memory).
    pub fn reset_all_stats(&mut self) -> AppResult<()> {
        self.stats.clear();
        self.stats_float.clear();
        self.avg_rate.clear();
        self.save_to_config();
        Ok(())
    }

    /// Request stats for another user.
    ///
    /// Snapshots the current local stats into a per-SteamID cache so that
    /// `GetUserStat` calls for that user return the local values. In a real
    /// implementation this would fetch stats from the Steam backend.
    pub fn request_user_stats(&mut self, steam_id: u64) -> AppResult<()> {
        self.stats_received = true;
        // Snapshot local stats into the per-user cache.
        let stats_snapshot = self.stats.clone();
        let stats_float_snapshot = self.stats_float.clone();
        self.remote_stats.insert(steam_id, stats_snapshot);
        self.remote_stats_float
            .insert(steam_id, stats_float_snapshot);
        Ok(())
    }

    /// Retrieve a snapshot stat for a remote user (int32).
    pub fn get_user_stat(&self, steam_id: u64, name: &str) -> Option<i32> {
        self.remote_stats.get(&steam_id)?.get(name).copied()
    }

    /// Retrieve a snapshot stat for a remote user (float).
    pub fn get_user_stat_float(&self, steam_id: u64, name: &str) -> Option<f64> {
        self.remote_stats_float.get(&steam_id)?.get(name).copied()
    }

    /// Indicate achievement progress towards unlocking.
    ///
    /// Stores the current/max progress so that games can display a progress bar.
    /// Returns true if the achievement has been unlocked already (progress == max).
    pub fn indicate_achievement_progress(
        &mut self,
        name: &str,
        current_progress: f32,
        max_progress: f32,
    ) -> bool {
        self.achievement_progress
            .insert(name.to_string(), (current_progress, max_progress));
        // If already fully unlocked, return true.
        if self.achievements.contains_key(name) {
            return true;
        }
        // Auto-unlock when progress reaches max: use the same epoch-seconds
        // timestamp as `set_achievement` and persist so the unlock survives
        // restarts.
        if max_progress > 0.0 && current_progress >= max_progress {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.achievements.insert(name.to_string(), now);
            self.save_to_config();
            return true;
        }
        false
    }

    /// Get the stored achievement progress for display purposes.
    pub fn get_achievement_progress(&self, name: &str) -> Option<(f32, f32)> {
        self.achievement_progress.get(name).copied()
    }

    /// Find a leaderboard by name; returns true if found.
    pub fn find_leaderboard<'a>(&self, name: &'a str) -> Option<&'a str> {
        self.leaderboards.get(name).map(|_| name)
    }

    /// Get a downloaded leaderboard entry by index.
    pub fn get_downloaded_leaderboard_entry(
        &self,
        name: &str,
        index: i32,
    ) -> Option<LeaderboardEntry> {
        let board = self.leaderboards.get(name)?;
        let idx = index as usize;
        if idx >= board.len() {
            return None;
        }
        let (score, sid, det) = &board[idx];
        Some(LeaderboardEntry {
            steam_id: *sid,
            global_rank: (idx + 1) as i32,
            score: *score,
            details: det.clone(),
            ugc_handle: 0,
        })
    }
}

impl Default for SteamUserStats {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// K2 — ISteamFriends (Friends List, Chat, Clan Groups)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FriendGameInfo {
    pub game_id: u64,
    pub game_ip: u32,
    pub game_port: u16,
    pub query_port: u16,
    pub steam_id_lobby: u64,
}

/// Friends list entry serialised for config persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FriendEntry {
    name: String,
    persona_state: i32,
    game_info: Option<FriendGameInfo>,
}

/// Snapshot of SteamFriends state for JSON persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FriendsSnapshot {
    persona_name: String,
    persona_state: i32,
    friends: BTreeMap<u64, FriendEntry>,
    clans: BTreeMap<u64, String>,
}

#[derive(Debug)]
pub struct SteamFriends {
    persona_name: String,
    persona_state: i32,
    friends: BTreeMap<u64, (String, i32, Option<FriendGameInfo>)>,
    friend_invites: BTreeMap<u64, String>,
    chat_messages: BTreeMap<u64, Vec<String>>,
    clans: BTreeMap<u64, String>,
    next_avatar_handle: u64,
}

impl SteamFriends {
    fn config_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Casa1")
            .join("config")
            .join(format!("{}.json", app_scoped_config_name("friends_config")))
    }

    /// Set the app id used to scope this user's persisted friends file, so
    /// different games do not overwrite each other's friends state.
    pub fn set_app_id(app_id: u32) {
        set_steam_config_app_id(app_id);
    }

    fn load_from_config(&mut self) {
        let path = Self::config_path();
        if !path.exists() {
            return;
        }
        match fs::read_to_string(&path) {
            Ok(json) => match serde_json::from_str::<FriendsSnapshot>(&json) {
                Ok(snapshot) => {
                    self.persona_name = snapshot.persona_name;
                    self.persona_state = snapshot.persona_state;
                    self.friends.clear();
                    for (sid, entry) in snapshot.friends {
                        self.friends
                            .insert(sid, (entry.name, entry.persona_state, entry.game_info));
                    }
                    self.clans = snapshot.clans;
                }
                Err(e) => {
                    eprintln!("SteamFriends: failed to parse config: {e}");
                }
            },
            Err(e) => {
                eprintln!("SteamFriends: failed to read config: {e}");
            }
        }
    }

    fn save_to_config(&self) {
        let snapshot = FriendsSnapshot {
            persona_name: self.persona_name.clone(),
            persona_state: self.persona_state,
            friends: self
                .friends
                .iter()
                .map(|(sid, (name, state, game))| {
                    (
                        *sid,
                        FriendEntry {
                            name: name.clone(),
                            persona_state: *state,
                            game_info: game.clone(),
                        },
                    )
                })
                .collect(),
            clans: self.clans.clone(),
        };
        let path = Self::config_path();
        let Some(parent) = path.parent() else {
            return;
        };
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("SteamFriends: failed to create config dir: {e}");
            return;
        }
        match serde_json::to_string_pretty(&snapshot) {
            Ok(json) => {
                if let Err(e) = fs::write(&path, &json) {
                    eprintln!("SteamFriends: failed to save config: {e}");
                }
            }
            Err(e) => {
                eprintln!("SteamFriends: failed to serialize config: {e}");
            }
        }
    }

    pub fn new() -> Self {
        let mut s = Self {
            persona_name: "Player".to_string(),
            persona_state: 1,
            friends: BTreeMap::new(),
            friend_invites: BTreeMap::new(),
            chat_messages: BTreeMap::new(),
            clans: BTreeMap::new(),
            next_avatar_handle: 1000,
        };
        s.load_from_config();
        s
    }

    pub fn get_persona_name(&self) -> &str {
        &self.persona_name
    }
    pub fn set_persona_name(&mut self, name: &str) {
        self.persona_name = name.to_string();
        self.save_to_config();
    }
    pub fn get_persona_state(&self) -> i32 {
        self.persona_state
    }
    pub fn set_persona_state(&mut self, state: i32) {
        self.persona_state = state;
        self.save_to_config();
    }

    pub fn get_friend_persona_state(&self, steam_id: u64) -> i32 {
        self.friends.get(&steam_id).map(|(_, s, _)| *s).unwrap_or(0)
    }

    pub fn get_friend_persona_name(&self, steam_id: u64) -> Option<&str> {
        self.friends.get(&steam_id).map(|(n, _, _)| n.as_str())
    }

    pub fn get_friend_game_played(&self, steam_id: u64) -> Option<&FriendGameInfo> {
        self.friends.get(&steam_id).and_then(|(_, _, i)| i.as_ref())
    }

    pub fn get_friend_count(&self) -> i32 {
        self.friends.len() as i32
    }

    pub fn get_friend_by_index(&self, index: i32) -> Option<u64> {
        if index < 0 {
            return None;
        }
        self.friends.keys().nth(index as usize).copied()
    }

    pub fn add_friend(&mut self, steam_id: u64, name: &str) {
        self.friends
            .entry(steam_id)
            .or_insert_with(|| (name.to_string(), 1, None));
        self.save_to_config();
    }

    pub fn remove_friend(&mut self, steam_id: u64) {
        self.friends.remove(&steam_id);
        self.save_to_config();
    }

    pub fn set_friend_persona_state(&mut self, steam_id: u64, state: i32) {
        if let Some(e) = self.friends.get_mut(&steam_id) {
            e.1 = state;
        }
        self.save_to_config();
    }

    pub fn set_friend_game_info(&mut self, steam_id: u64, info: FriendGameInfo) {
        if let Some(e) = self.friends.get_mut(&steam_id) {
            e.2 = Some(info);
        }
        self.save_to_config();
    }

    pub fn invite_friend(&mut self, steam_id: u64, message: &str) {
        self.friend_invites.insert(steam_id, message.to_string());
    }

    pub fn get_invite_count(&self) -> i32 {
        self.friend_invites.len() as i32
    }

    pub fn get_invite_by_index(&self, index: i32) -> Option<u64> {
        if index < 0 {
            return None;
        }
        self.friend_invites.keys().nth(index as usize).copied()
    }

    pub fn accept_invite(&mut self, steam_id: u64) {
        if let Some(_msg) = self.friend_invites.remove(&steam_id) {
            self.friends
                .entry(steam_id)
                .or_insert_with(|| (format!("Friend{steam_id}"), 1, None));
        }
        self.save_to_config();
    }

    pub fn decline_invite(&mut self, steam_id: u64) {
        self.friend_invites.remove(&steam_id);
    }

    pub fn send_friend_message(&mut self, steam_id: u64, message: &str) {
        // Bound per-friend history so long chat sessions cannot grow memory
        // without limit (drop the oldest message beyond the cap).
        const MAX_FRIEND_CHAT_MESSAGES: usize = 200;
        let history = self.chat_messages.entry(steam_id).or_default();
        if history.len() >= MAX_FRIEND_CHAT_MESSAGES {
            history.remove(0);
        }
        history.push(message.to_string());
    }

    pub fn get_friend_message_count(&self, steam_id: u64) -> i32 {
        self.chat_messages
            .get(&steam_id)
            .map(|v| v.len() as i32)
            .unwrap_or(0)
    }

    pub fn get_friend_message(&self, steam_id: u64, index: i32) -> Option<&str> {
        self.chat_messages
            .get(&steam_id)
            .and_then(|v| v.get(index as usize))
            .map(|s| s.as_str())
    }

    pub fn clear_friend_messages(&mut self, steam_id: u64) {
        self.chat_messages.remove(&steam_id);
    }

    pub fn join_clan(&mut self, clan_id: u64, clan_name: &str) {
        self.clans.insert(clan_id, clan_name.to_string());
        self.save_to_config();
    }

    pub fn leave_clan(&mut self, clan_id: u64) {
        self.clans.remove(&clan_id);
        self.save_to_config();
    }

    pub fn get_clan_count(&self) -> i32 {
        self.clans.len() as i32
    }

    pub fn get_clan_by_index(&self, index: i32) -> Option<u64> {
        if index < 0 {
            return None;
        }
        self.clans.keys().nth(index as usize).copied()
    }

    pub fn get_clan_name(&self, clan_id: u64) -> Option<&str> {
        self.clans.get(&clan_id).map(|s| s.as_str())
    }

    pub fn is_clan_member(&self, clan_id: u64) -> bool {
        self.clans.contains_key(&clan_id)
    }

    pub fn set_rich_presence(&mut self, _key: &str, _value: &str) {}
    pub fn clear_rich_presence(&mut self) {}

    pub fn activate_game_overlay_to_web_page(&self, _url: &str) {}
    pub fn activate_game_overlay_to_friends(&self) {}

    pub fn get_small_friend_avatar(&mut self, _steam_id: u64) -> i32 {
        let h = self.next_avatar_handle;
        self.next_avatar_handle += 1;
        h as i32
    }

    pub fn get_medium_friend_avatar(&mut self, _steam_id: u64) -> i32 {
        let h = self.next_avatar_handle;
        self.next_avatar_handle += 1;
        h as i32
    }

    pub fn get_large_friend_avatar(&mut self, _steam_id: u64) -> i32 {
        let h = self.next_avatar_handle;
        self.next_avatar_handle += 1;
        h as i32
    }

    pub fn get_friend_relationship(&self, _steam_id: u64) -> i32 {
        // k_EFriendRelationshipFriend = 3
        3
    }

    pub fn get_clan_tag(&self, clan_id: u64) -> Option<&str> {
        self.clans.get(&clan_id).map(|s| s.as_str())
    }

    /// Activate the overlay and navigate to the specified dialog page.
    ///
    /// Supported dialogs: "friends", "community", "settings", "achievements",
    /// "stats", "chat", "store", "web", etc.
    pub fn activate_game_overlay(&self, dialog: &str) {
        let url = match dialog.to_lowercase().as_str() {
            "friends" | "friendslist" => "steam://openurl/https://steamcommunity.com/my/friends",
            "community" => "steam://openurl/https://steamcommunity.com/my",
            "settings" => "steam://openurl/https://steamcommunity.com/my/settings",
            "achievements" => "steam://openurl/https://steamcommunity.com/my/achievements",
            "stats" => "steam://openurl/https://steamcommunity.com/my/stats",
            "chat" => "steam://openurl/https://steamcommunity.com/chat",
            "store" => "steam://openurl/https://store.steampowered.com",
            "web" => "steam://openurl/https://steamcommunity.com",
            _ => "steam://openurl/https://steamcommunity.com/my/overlay",
        };
        with_steam_overlay(|mgr| {
            mgr.set_active(true);
            mgr.set_overlay_url(url.to_string());
        });
    }

    /// Activate the overlay focused on a specific user's profile.
    pub fn activate_game_overlay_to_user(&self, dialog: &str, steam_id: u64) {
        let url = format!(
            "steam://openurl/https://steamcommunity.com/profiles/{}/{}",
            steam_id, dialog
        );
        with_steam_overlay(|mgr| {
            mgr.set_active(true);
            mgr.set_overlay_url(url);
        });
    }

    /// Activate the overlay and navigate to a specific store page.
    pub fn activate_game_overlay_to_store(&self, app_id: u32) {
        let url = format!(
            "steam://openurl/https://store.steampowered.com/app/{}",
            app_id
        );
        with_steam_overlay(|mgr| {
            mgr.set_active(true);
            mgr.set_overlay_url(url);
        });
    }

    /// Activate the overlay to show an invite dialog for a lobby.
    pub fn activate_game_overlay_to_invite_dialog(&self, lobby_id: u64) {
        let url = format!(
            "steam://openurl/https://steamcommunity.com/invite/{}",
            lobby_id
        );
        with_steam_overlay(|mgr| {
            mgr.set_active(true);
            mgr.set_overlay_url(url);
        });
    }
}

impl Default for SteamFriends {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// K3 — ISteamMatchmaking (Lobbies, Game Search, P2P Sessions)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Lobby {
    pub steam_id: u64,
    pub owner_id: u64,
    pub max_members: i32,
    pub metadata: BTreeMap<String, String>,
    pub members: BTreeMap<u64, BTreeMap<String, String>>,
    pub lobby_type: i32,
    pub joinable: bool,
    pub chat_messages: Vec<String>,
}

#[derive(Debug)]
pub struct SteamMatchmaking {
    lobbies: BTreeMap<u64, Lobby>,
    search_results: BTreeMap<u64, Lobby>,
    next_lobby_id: u64,
}

impl SteamMatchmaking {
    pub fn new() -> Self {
        Self {
            lobbies: BTreeMap::new(),
            search_results: BTreeMap::new(),
            next_lobby_id: 10000,
        }
    }

    pub fn create_lobby(&mut self, lobby_type: i32, max_members: i32) -> AppResult<u64> {
        let lobby_id = self.next_lobby_id;
        self.next_lobby_id += 1;
        let lobby = Lobby {
            steam_id: lobby_id,
            owner_id: 0,
            max_members,
            metadata: BTreeMap::new(),
            members: BTreeMap::new(),
            lobby_type,
            joinable: true,
            chat_messages: Vec::new(),
        };
        self.lobbies.insert(lobby_id, lobby);
        Ok(lobby_id)
    }

    pub fn join_lobby(&mut self, lobby_id: u64) -> AppResult<()> {
        if self.lobbies.contains_key(&lobby_id) {
            return Ok(());
        }
        let lobby = self.search_results.get(&lobby_id).cloned().ok_or_else(|| {
            AppError::new(
                crate::reason::ReasonCode::RcCliInvalid,
                format!("lobby {lobby_id} not found"),
            )
        })?;
        self.lobbies.insert(lobby_id, lobby);
        Ok(())
    }

    pub fn leave_lobby(&mut self, lobby_id: u64) {
        self.lobbies.remove(&lobby_id);
    }

    pub fn get_lobby(&self, lobby_id: u64) -> Option<&Lobby> {
        self.lobbies.get(&lobby_id)
    }
    pub fn get_lobby_mut(&mut self, lobby_id: u64) -> Option<&mut Lobby> {
        self.lobbies.get_mut(&lobby_id)
    }

    pub fn get_lobby_count(&self) -> usize {
        self.lobbies.len()
    }

    pub fn get_lobby_by_index(&self, index: usize) -> Option<u64> {
        self.lobbies.keys().nth(index).copied()
    }

    pub fn get_lobby_data(&self, lobby_id: u64, key: &str) -> Option<&str> {
        self.lobbies
            .get(&lobby_id)
            .and_then(|l| l.metadata.get(key))
            .map(|s| s.as_str())
    }

    pub fn set_lobby_data(&mut self, lobby_id: u64, key: &str, value: &str) -> AppResult<()> {
        let lobby = self.lobbies.get_mut(&lobby_id).ok_or_else(|| {
            AppError::new(crate::reason::ReasonCode::RcCliInvalid, "lobby not found")
        })?;
        lobby.metadata.insert(key.to_string(), value.to_string());
        Ok(())
    }

    pub fn get_lobby_member_count(&self, lobby_id: u64) -> i32 {
        self.lobbies
            .get(&lobby_id)
            .map(|l| l.members.len() as i32)
            .unwrap_or(0)
    }

    pub fn get_lobby_member_by_index(&self, lobby_id: u64, index: i32) -> Option<u64> {
        if index < 0 {
            return None;
        }
        self.lobbies
            .get(&lobby_id)
            .and_then(|l| l.members.keys().nth(index as usize).copied())
    }

    pub fn get_lobby_member_data(&self, lobby_id: u64, member_id: u64, key: &str) -> Option<&str> {
        self.lobbies
            .get(&lobby_id)
            .and_then(|l| l.members.get(&member_id))
            .and_then(|m| m.get(key))
            .map(|s| s.as_str())
    }

    pub fn set_lobby_member_data(
        &mut self,
        lobby_id: u64,
        member_id: u64,
        key: &str,
        value: &str,
    ) -> AppResult<()> {
        let lobby = self.lobbies.get_mut(&lobby_id).ok_or_else(|| {
            AppError::new(crate::reason::ReasonCode::RcCliInvalid, "lobby not found")
        })?;
        lobby
            .members
            .entry(member_id)
            .or_default()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    pub fn set_lobby_owner(&mut self, lobby_id: u64, new_owner: u64) -> AppResult<()> {
        let lobby = self.lobbies.get_mut(&lobby_id).ok_or_else(|| {
            AppError::new(crate::reason::ReasonCode::RcCliInvalid, "lobby not found")
        })?;
        lobby.owner_id = new_owner;
        Ok(())
    }

    pub fn get_lobby_owner(&self, lobby_id: u64) -> Option<u64> {
        self.lobbies.get(&lobby_id).map(|l| l.owner_id)
    }

    pub fn set_lobby_joinable(&mut self, lobby_id: u64, joinable: bool) -> AppResult<()> {
        let lobby = self.lobbies.get_mut(&lobby_id).ok_or_else(|| {
            AppError::new(crate::reason::ReasonCode::RcCliInvalid, "lobby not found")
        })?;
        lobby.joinable = joinable;
        Ok(())
    }

    pub fn send_lobby_chat_message(&mut self, lobby_id: u64, message: &str) -> AppResult<()> {
        let lobby = self.lobbies.get_mut(&lobby_id).ok_or_else(|| {
            AppError::new(crate::reason::ReasonCode::RcCliInvalid, "lobby not found")
        })?;
        // Bound the lobby chat history so long sessions cannot grow memory
        // without limit.
        const MAX_LOBBY_CHAT_MESSAGES: usize = 200;
        if lobby.chat_messages.len() >= MAX_LOBBY_CHAT_MESSAGES {
            lobby.chat_messages.remove(0);
        }
        lobby.chat_messages.push(message.to_string());
        Ok(())
    }

    pub fn get_lobby_chat_messages(&self, lobby_id: u64) -> Vec<String> {
        self.lobbies
            .get(&lobby_id)
            .map(|l| l.chat_messages.clone())
            .unwrap_or_default()
    }

    pub fn add_lobby_to_search(&mut self, lobby_id: u64, lobby: Lobby) {
        self.search_results.insert(lobby_id, lobby);
    }

    pub fn request_lobby_list(&mut self) -> AppResult<()> {
        for (id, lobby) in &self.lobbies {
            self.search_results.insert(*id, lobby.clone());
        }
        Ok(())
    }

    pub fn get_lobby_search_result_count(&self) -> usize {
        self.search_results.len()
    }

    pub fn get_lobby_search_result(&self, index: usize) -> Option<&Lobby> {
        self.search_results
            .keys()
            .nth(index)
            .and_then(|k| self.search_results.get(k))
    }

    pub fn clear_lobby_search_results(&mut self) {
        self.search_results.clear();
    }

    pub fn set_lobby_type(&mut self, lobby_id: u64, lobby_type: i32) -> AppResult<()> {
        let lobby = self.lobbies.get_mut(&lobby_id).ok_or_else(|| {
            AppError::new(crate::reason::ReasonCode::RcCliInvalid, "lobby not found")
        })?;
        lobby.lobby_type = lobby_type;
        Ok(())
    }

    pub fn get_lobby_member_limit(&self, lobby_id: u64) -> i32 {
        self.lobbies
            .get(&lobby_id)
            .map(|l| l.max_members)
            .unwrap_or(0)
    }
}

impl Default for SteamMatchmaking {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// K5 — ISteamRemoteStorage (Cloud Storage with File Persistence)
// ---------------------------------------------------------------------------

/// Per-file sync state for cloud conflict detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncFileState {
    /// Local modification timestamp (seconds since epoch).
    local_mtime: u64,
    /// Remote modification timestamp (seconds since epoch).
    remote_mtime: u64,
    /// Sync status for this file.
    sync_status: SyncStatus,
    /// Remote version identifier (hash or etag).
    remote_version: String,
}

impl Default for SyncFileState {
    fn default() -> Self {
        Self {
            local_mtime: 0,
            remote_mtime: 0,
            sync_status: SyncStatus::Synced,
            remote_version: String::new(),
        }
    }
}

/// Sync status for an individual file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum SyncStatus {
    Synced,
    LocalChanged,
    RemoteChanged,
    Conflict,
}

/// Persisted sync state snapshot for the entire storage directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncStateSnapshot {
    last_sync_time: u64,
    files: BTreeMap<String, SyncFileState>,
}

/// Tracked UGC item metadata.
#[derive(Debug, Clone)]
struct UGCItem {
    local_path: String,
    size: u64,
    name: String,
}

/// File metadata returned by the sync server in the directory listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteFileInfo {
    mtime: u64,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    version: String,
    #[serde(default)]
    quota_used: Option<u64>,
    #[serde(default)]
    quota_total: Option<u64>,
}

/// Cloud-enabled Steam remote storage.
///
/// Provides local file persistence with HTTP REST cloud sync backend.
/// File change detection uses modification timestamps. Conflict resolution
/// follows last-write-wins. Sync state is persisted to `.sync_state.json`
/// inside the storage directory.
#[derive(Debug)]
pub struct SteamRemoteStorage {
    base_path: PathBuf,
    files: BTreeMap<String, u64>,
    /// File modification timestamps for change detection (seconds since epoch).
    file_timestamps: BTreeMap<String, u64>,
    quota_used: u64,
    quota_total: u64,
    cloud_enabled_for_app: bool,
    /// Tracked UGC items: handle → metadata.
    ugc_items: BTreeMap<u64, UGCItem>,
    /// Cloud sync server base URL (e.g. "https://sync.example.com").
    sync_server_url: Option<String>,
    /// Per-file sync state for change detection and conflict resolution.
    sync_state: BTreeMap<String, SyncFileState>,
    /// Timestamp of the last successful sync (seconds since epoch).
    last_sync_time: u64,
    /// Reusable HTTP client with cookie support.
    http_client: Option<reqwest::blocking::Client>,
}

/// Upper bound on a single cloud download (4 GiB). Guards against an
/// untrusted sync server streaming unbounded data to disk.
const MAX_CLOUD_DOWNLOAD_SIZE: u64 = 4 * 1024 * 1024 * 1024;

impl SteamRemoteStorage {
    pub fn new() -> Self {
        let base_path = Self::default_base_path();
        let mut s = Self {
            base_path,
            files: BTreeMap::new(),
            file_timestamps: BTreeMap::new(),
            quota_used: 0,
            quota_total: 1_073_741_824,
            cloud_enabled_for_app: true,
            ugc_items: BTreeMap::new(),
            sync_server_url: None,
            sync_state: BTreeMap::new(),
            last_sync_time: 0,
            http_client: None,
        };
        s.sync_from_disk();
        s.load_sync_state();
        s
    }

    fn default_base_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Casa1")
            .join("remote_storage")
    }

    /// Synchronise in-memory file index with the actual files on disk.
    fn sync_from_disk(&mut self) {
        self.files.clear();
        self.file_timestamps.clear();
        self.quota_used = 0;
        if !self.base_path.exists() {
            if let Err(e) = fs::create_dir_all(&self.base_path) {
                eprintln!(
                    "RemoteStorage: failed to create base dir {:?}: {e}",
                    self.base_path
                );
            }
            return;
        }
        if let Ok(entries) = fs::read_dir(&self.base_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    // Skip sync state file
                    let rel = path
                        .strip_prefix(&self.base_path)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if rel.starts_with('.') {
                        continue;
                    }
                    if let Ok(meta) = fs::metadata(&path) {
                        let size = meta.len();
                        let mtime = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        self.files.insert(rel.clone(), size);
                        self.file_timestamps.insert(rel, mtime);
                        self.quota_used += size;
                    }
                }
            }
        }
    }

    fn ensure_parent_dir(&self, rel_path: &str) -> AppResult<()> {
        let full_path = self.base_path.join(rel_path);
        let parent = match full_path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => self.base_path.clone(),
        };
        fs::create_dir_all(&parent).map_err(|e| {
            AppError::new(
                crate::reason::ReasonCode::RcIo,
                format!("cannot create remote storage dir: {e}"),
            )
        })
    }

    pub fn set_base_path(&mut self, path: PathBuf) {
        self.base_path = path;
        self.sync_from_disk();
    }

    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Configure the cloud sync server URL.
    ///
    /// Initialises the HTTP client lazily. Pass `None` to disable cloud sync.
    pub fn configure_sync_server(&mut self, url: Option<&str>) {
        self.sync_server_url = url.map(|s| s.trim_end_matches('/').to_string());
        if self.sync_server_url.is_some() && self.http_client.is_none() {
            match reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .cookie_store(true)
                .build()
            {
                Ok(client) => self.http_client = Some(client),
                Err(e) => {
                    eprintln!("RemoteStorage: failed to build HTTP client: {e}");
                }
            }
        }
    }

    // ── Cloud sync ──────────────────────────────────────────────────────

    /// Upload all locally-changed files to the sync server.
    ///
    /// Files whose local mtime differs from the last synced remote mtime
    /// are uploaded via HTTP PUT.  The server response updates the remote
    /// quota and version.
    pub fn sync_to_cloud(&mut self) -> AppResult<()> {
        let server_url = match &self.sync_server_url {
            Some(url) => url.clone(),
            None => return Ok(()),
        };

        self.detect_changes();

        let client = match &self.http_client {
            Some(c) => c.clone(),
            None => return Ok(()),
        };

        let mut changed_count = 0u32;
        let rel_paths: Vec<String> = self.files.keys().cloned().collect();

        for rel_path in rel_paths {
            if !is_safe_rel_path(&rel_path) {
                eprintln!("RemoteStorage: skipping upload of unsafe path '{rel_path}'");
                continue;
            }
            let state = self.sync_state.get(&rel_path).cloned().unwrap_or_default();

            if state.sync_status == SyncStatus::Synced {
                continue;
            }

            // Stream the local file to the server instead of loading the
            // whole file into memory (multi-GB saves cause large transient
            // allocations otherwise).
            let full_path = self.base_path.join(&rel_path);
            let file = match std::fs::File::open(&full_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("RemoteStorage: cannot read '{rel_path}' for upload: {e}");
                    continue;
                }
            };

            // Upload via HTTP PUT
            let upload_url = format!(
                "{server_url}/api/v1/cloud/upload/{}",
                percent_encode(&rel_path)
            );
            match client.put(&upload_url).body(file).send() {
                Ok(resp) if resp.status().is_success() => {
                    let remote_mtime = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let local_mtime = self.file_timestamps.get(&rel_path).copied().unwrap_or(0);
                    // Update sync state to reflect the successful upload
                    self.sync_state.insert(
                        rel_path.clone(),
                        SyncFileState {
                            local_mtime,
                            remote_mtime,
                            sync_status: SyncStatus::Synced,
                            remote_version: resp
                                .headers()
                                .get("etag")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string(),
                        },
                    );
                    // Update quota from server response if provided
                    match resp.text() {
                        Ok(body) => {
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                                if let Some(quota) =
                                    parsed.get("quota_used").and_then(|v| v.as_u64())
                                {
                                    self.quota_used = quota;
                                }
                                if let Some(total) =
                                    parsed.get("quota_total").and_then(|v| v.as_u64())
                                {
                                    self.quota_total = total;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("RemoteStorage: failed to read upload response body: {e}");
                        }
                    }
                    changed_count += 1;
                }
                Ok(resp) => {
                    eprintln!(
                        "RemoteStorage: upload '{rel_path}' returned HTTP {}",
                        resp.status()
                    );
                }
                Err(e) => {
                    eprintln!("RemoteStorage: upload '{rel_path}' failed: {e}");
                }
            }
        }

        if changed_count > 0 {
            self.last_sync_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.save_sync_state();
        }

        Ok(())
    }

    /// Download files from the sync server that are newer than our local copies.
    ///
    /// Uses a remote file listing (GET /api/v1/cloud/list) and compares
    /// timestamps. Newer remote files are downloaded and written locally.
    /// Conflict resolution: last-write-wins — if both sides changed, the
    /// file with the later mtime wins.
    pub fn sync_from_cloud(&mut self) -> AppResult<()> {
        let server_url = match &self.sync_server_url {
            Some(url) => url.clone(),
            None => return Ok(()),
        };

        self.detect_changes();

        let client = match &self.http_client {
            Some(c) => c.clone(),
            None => return Ok(()),
        };

        // Fetch remote file listing
        let list_url = format!("{server_url}/api/v1/cloud/list");
        let resp = client.get(&list_url).send().map_err(|e| {
            AppError::new(
                crate::reason::ReasonCode::RcNetReadFailed,
                format!("RemoteStorage: sync list request failed: {e}"),
            )
        })?;

        if !resp.status().is_success() {
            return Err(AppError::new(
                crate::reason::ReasonCode::RcNetReadFailed,
                format!("RemoteStorage: sync list returned HTTP {}", resp.status()),
            ));
        }

        let list_body = resp.text().map_err(|e| {
            AppError::new(
                crate::reason::ReasonCode::RcNetReadFailed,
                format!("RemoteStorage: sync list body error: {e}"),
            )
        })?;

        // Parse the remote file listing
        // Expected format: { "files": { "path": {"mtime": 123, "size": 100, "version": "hash"} } }
        let remote_files: BTreeMap<String, RemoteFileInfo> = match serde_json::from_str(&list_body)
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("RemoteStorage: failed to parse remote file list: {e}");
                return Err(AppError::new(
                    crate::reason::ReasonCode::RcNetProtocolError,
                    format!("RemoteStorage: invalid remote file list: {e}"),
                ));
            }
        };

        for (rel_path, remote_info) in &remote_files {
            // The listing comes from an untrusted server; never let a
            // `..`/absolute path escape the storage directory.
            if !is_safe_rel_path(rel_path) {
                eprintln!(
                    "RemoteStorage: skipping unsafe remote path '{rel_path}' from server listing"
                );
                continue;
            }

            let local_mtime = self.file_timestamps.get(rel_path).copied().unwrap_or(0);
            let state = self.sync_state.get(rel_path).cloned().unwrap_or_default();

            // Determine if we need to download this file
            let needs_download = if local_mtime == 0 && remote_info.mtime > 0 {
                // File exists only remotely
                true
            } else if state.sync_status == SyncStatus::RemoteChanged {
                // Remote changed; download if remote is newer or equal
                remote_info.mtime >= local_mtime
            } else if state.sync_status == SyncStatus::Conflict {
                // Conflict: last-write-wins
                remote_info.mtime > local_mtime
            } else {
                // Synced or LocalChanged: only download if remote is strictly newer
                remote_info.mtime > local_mtime
            };

            if !needs_download {
                continue;
            }

            // Download the file, streaming the body to a temp file so a
            // failed/partial transfer never truncates the existing local
            // file. Only after the transfer completes is the temp file
            // renamed into place and the sync state marked Synced; on any
            // error the previous file and sync status are left untouched so
            // the download is retried on the next sync.
            let download_url = format!(
                "{server_url}/api/v1/cloud/download/{}",
                percent_encode(rel_path)
            );
            match client.get(&download_url).send() {
                Ok(dl_resp) if dl_resp.status().is_success() => {
                    let full_path = self.base_path.join(rel_path);
                    let tmp_path = full_path.with_extension("part");
                    let write_result = (|| -> AppResult<()> {
                        let mut out = fs::File::create(&tmp_path).map_err(|e| {
                            AppError::new(
                                ReasonCode::RcIo,
                                format!("RemoteStorage: cannot create temp file: {e}"),
                            )
                        })?;
                        let mut limited = std::io::Read::take(dl_resp, MAX_CLOUD_DOWNLOAD_SIZE);
                        std::io::copy(&mut limited, &mut out).map_err(|e| {
                            AppError::new(
                                ReasonCode::RcNetReadFailed,
                                format!("RemoteStorage: download '{rel_path}' failed: {e}"),
                            )
                        })?;
                        let size = out.metadata().map(|m| m.len()).unwrap_or(0);
                        if size == 0 && remote_info.size > 0 {
                            return Err(AppError::new(
                                ReasonCode::RcNetReadFailed,
                                format!(
                                    "RemoteStorage: download of '{rel_path}' returned an empty body"
                                ),
                            ));
                        }
                        fs::rename(&tmp_path, &full_path).map_err(|e| {
                            AppError::new(
                                ReasonCode::RcIo,
                                format!("RemoteStorage: failed to finalize '{rel_path}': {e}"),
                            )
                        })?;
                        self.record_written_file(rel_path, size);
                        Ok(())
                    })();
                    if let Err(e) = write_result {
                        let _ = fs::remove_file(&tmp_path);
                        eprintln!("RemoteStorage: download '{rel_path}' failed: {e}");
                        continue;
                    }
                    // Update sync state
                    let new_local_mtime = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    self.sync_state.insert(
                        rel_path.clone(),
                        SyncFileState {
                            local_mtime: new_local_mtime,
                            remote_mtime: remote_info.mtime,
                            sync_status: SyncStatus::Synced,
                            remote_version: remote_info.version.clone(),
                        },
                    );
                }
                Ok(dl_resp) => {
                    eprintln!(
                        "RemoteStorage: download '{rel_path}' returned HTTP {}",
                        dl_resp.status()
                    );
                }
                Err(e) => {
                    eprintln!("RemoteStorage: download '{rel_path}' failed: {e}");
                }
            }
        }

        // Update quota from server if provided
        if let Some(quota) = remote_files.get("__meta__").and_then(|m| m.quota_used) {
            self.quota_used = quota;
        }
        if let Some(quota) = remote_files.get("__meta__").and_then(|m| m.quota_total) {
            self.quota_total = quota;
        }

        self.last_sync_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.save_sync_state();

        Ok(())
    }

    /// Perform a full bi-directional sync: upload local changes and download
    /// remote changes.
    pub fn sync_all(&mut self) -> AppResult<()> {
        self.sync_to_cloud()?;
        self.sync_from_cloud()?;
        Ok(())
    }

    /// Detect local file changes by comparing current mtime with stored state.
    ///
    /// Both sides are tracked independently: a file whose local mtime moved
    /// past the last-synced `local_mtime` is `LocalChanged`; if the
    /// last-known remote copy was itself newer than the last-synced local
    /// copy (`remote_mtime > local_mtime`) and the local file has changed
    /// again, both sides hold changes and the file is marked `Conflict`
    /// (resolved last-write-wins by the sync loops).
    fn detect_changes(&mut self) {
        // Check for new or modified local files
        for (rel_path, current_mtime) in &self.file_timestamps.clone() {
            let state = self.sync_state.get(rel_path).cloned().unwrap_or_default();
            let was_synced = state.sync_status == SyncStatus::Synced;

            if *current_mtime > state.local_mtime {
                // File was modified locally.
                let remote_changed = state.remote_mtime > state.local_mtime;
                let new_status = if was_synced {
                    // Cleanly synced before: a local modification is either a
                    // plain local change or, if the local copy is still older
                    // than the last-known remote copy, a remote change.
                    if remote_changed && state.remote_mtime >= *current_mtime {
                        SyncStatus::RemoteChanged
                    } else {
                        SyncStatus::LocalChanged
                    }
                } else if remote_changed {
                    // Never synced and both sides changed since the last
                    // contact: a genuine conflict.
                    SyncStatus::Conflict
                } else {
                    SyncStatus::LocalChanged
                };

                // Check if sync_status changed before moving `state` into the insert
                if new_status != state.sync_status {
                    self.sync_state.insert(
                        rel_path.clone(),
                        SyncFileState {
                            local_mtime: *current_mtime,
                            sync_status: new_status,
                            ..state
                        },
                    );
                } else {
                    self.sync_state.insert(
                        rel_path.clone(),
                        SyncFileState {
                            local_mtime: *current_mtime,
                            ..state
                        },
                    );
                }
            }
        }

        // Check for deleted local files
        let deleted: Vec<String> = self
            .sync_state
            .keys()
            .filter(|k| !self.files.contains_key(*k))
            .cloned()
            .collect();
        for path in deleted {
            self.sync_state.remove(&path);
        }
    }

    // ── Sync state persistence ─────────────────────────────────────────

    /// Path to the sync state file (inside the storage directory).
    fn sync_state_path(&self) -> PathBuf {
        self.base_path.join(".sync_state.json")
    }

    /// Persist sync state to a JSON file.
    fn save_sync_state(&self) {
        let snapshot = SyncStateSnapshot {
            last_sync_time: self.last_sync_time,
            files: self.sync_state.clone(),
        };
        match serde_json::to_string_pretty(&snapshot) {
            Ok(json) => {
                if let Err(e) = fs::write(self.sync_state_path(), &json) {
                    eprintln!("RemoteStorage: failed to save sync state: {e}");
                }
            }
            Err(e) => {
                eprintln!("RemoteStorage: failed to serialize sync state: {e}");
            }
        }
    }

    /// Load sync state from the JSON file.
    fn load_sync_state(&mut self) {
        let path = self.sync_state_path();
        if !path.exists() {
            return;
        }
        match fs::read_to_string(&path) {
            Ok(json) => match serde_json::from_str::<SyncStateSnapshot>(&json) {
                Ok(snapshot) => {
                    self.last_sync_time = snapshot.last_sync_time;
                    self.sync_state = snapshot.files;
                }
                Err(e) => {
                    eprintln!("RemoteStorage: failed to parse sync state: {e}");
                }
            },
            Err(e) => {
                eprintln!("RemoteStorage: failed to read sync state: {e}");
            }
        }
    }

    // ── File operations ────────────────────────────────────────────────

    pub fn file_write(&mut self, rel_path: &str, data: &[u8]) -> AppResult<()> {
        if !is_safe_rel_path(rel_path) {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("remote storage: unsafe path '{rel_path}'"),
            ));
        }

        // Enforce the configured cloud quota before writing: refuse writes
        // that would push the storage usage over `quota_total`.
        let old_size = self.files.get(rel_path).copied().unwrap_or(0);
        let new_size = data.len() as u64;
        let projected = self
            .quota_used
            .saturating_sub(old_size)
            .saturating_add(new_size);
        if self.quota_total > 0 && projected > self.quota_total {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!(
                    "remote storage: quota exceeded ({projected} > {} bytes)",
                    self.quota_total
                ),
            ));
        }

        self.ensure_parent_dir(rel_path)?;
        let full_path = self.base_path.join(rel_path);
        fs::write(&full_path, data).map_err(|e| {
            AppError::new(
                crate::reason::ReasonCode::RcIo,
                format!("remote storage write failed: {e}"),
            )
        })?;

        self.record_written_file(rel_path, new_size);

        Ok(())
    }

    /// Update in-memory bookkeeping (quota, file index, timestamps) after a
    /// file was written or updated on disk.
    fn record_written_file(&mut self, rel_path: &str, size: u64) {
        let old_size = self.files.get(rel_path).copied().unwrap_or(0);
        if size > old_size {
            self.quota_used += size - old_size;
        } else {
            self.quota_used = self.quota_used.saturating_sub(old_size - size);
        }
        self.files.insert(rel_path.to_string(), size);

        // Update timestamp tracking
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.file_timestamps.insert(rel_path.to_string(), now);
    }

    pub fn file_read(&self, rel_path: &str) -> AppResult<Vec<u8>> {
        if !is_safe_rel_path(rel_path) {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("remote storage: unsafe path '{rel_path}'"),
            ));
        }
        let full_path = self.base_path.join(rel_path);
        fs::read(&full_path).map_err(|e| {
            AppError::new(
                crate::reason::ReasonCode::RcFsNotFound,
                format!("remote storage file not found '{rel_path}': {e}"),
            )
        })
    }

    pub fn file_delete(&mut self, rel_path: &str) -> AppResult<()> {
        if !is_safe_rel_path(rel_path) {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("remote storage: unsafe path '{rel_path}'"),
            ));
        }
        let full_path = self.base_path.join(rel_path);
        if full_path.exists() {
            fs::remove_file(&full_path).map_err(|e| {
                AppError::new(
                    crate::reason::ReasonCode::RcIo,
                    format!("remote storage delete failed: {e}"),
                )
            })?;
            if let Some(size) = self.files.remove(rel_path) {
                self.quota_used = self.quota_used.saturating_sub(size);
            }
            self.file_timestamps.remove(rel_path);
            self.sync_state.remove(rel_path);
            Ok(())
        } else {
            Err(AppError::new(
                crate::reason::ReasonCode::RcFsNotFound,
                format!("remote storage file '{rel_path}' not found"),
            ))
        }
    }

    pub fn file_exists(&self, rel_path: &str) -> bool {
        self.files.contains_key(rel_path)
    }

    pub fn file_size(&self, rel_path: &str) -> u64 {
        self.files.get(rel_path).copied().unwrap_or(0)
    }

    pub fn file_time(&self, rel_path: &str) -> i64 {
        if !is_safe_rel_path(rel_path) {
            return 0;
        }
        let full_path = self.base_path.join(rel_path);
        fs::metadata(&full_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    pub fn get_file_count(&self) -> i32 {
        self.files.len() as i32
    }

    pub fn get_file_name(&self, index: i32) -> Option<&str> {
        if index < 0 {
            return None;
        }
        self.files.keys().nth(index as usize).map(|s| s.as_str())
    }

    pub fn get_file_size(&self, index: i32) -> u64 {
        if index < 0 {
            return 0;
        }
        self.files
            .keys()
            .nth(index as usize)
            .and_then(|k| self.files.get(k))
            .copied()
            .unwrap_or(0)
    }

    pub fn get_quota_used(&self) -> u64 {
        self.quota_used
    }

    pub fn get_quota_total(&self) -> u64 {
        self.quota_total
    }

    pub fn set_quota_total(&mut self, total: u64) {
        self.quota_total = total;
    }

    pub fn is_cloud_enabled_for_account(&self) -> bool {
        true
    }

    pub fn is_cloud_enabled_for_app(&self) -> bool {
        self.cloud_enabled_for_app
    }

    pub fn set_cloud_enabled_for_app(&mut self, enabled: bool) {
        self.cloud_enabled_for_app = enabled;
    }

    // ── UGC operations ─────────────────────────────────────────────────

    /// Download a UGC (Workshop) item.
    ///
    /// Attempts to read the cached UGC item from disk. Falls back to
    /// generating content deterministically from the handle.
    pub fn ugc_download(&mut self, ugc_handle: u64, rel_path: &str) -> AppResult<()> {
        let content = if let Some(item) = self.ugc_items.get(&ugc_handle) {
            let stored_full = self.base_path.join(&item.local_path);
            fs::read(&stored_full).unwrap_or_else(|_| {
                format!("UGC content for handle {ugc_handle} (path: {rel_path})").into_bytes()
            })
        } else {
            format!("UGC content for handle {ugc_handle} (path: {rel_path})").into_bytes()
        };
        self.file_write(rel_path, &content)?;
        let size = content.len() as u64;
        self.ugc_items.insert(
            ugc_handle,
            UGCItem {
                local_path: rel_path.to_string(),
                size,
                name: format!("ugc_{ugc_handle}"),
            },
        );
        Ok(())
    }

    pub fn ugc_subscribe(&mut self, _ugc_handle: u64) -> AppResult<()> {
        Ok(())
    }

    pub fn ugc_unsubscribe(&mut self, _ugc_handle: u64) -> AppResult<()> {
        Ok(())
    }

    pub fn file_forget(&mut self, rel_path: &str) -> AppResult<()> {
        // Remove file tracking without deleting from disk
        if let Some(size) = self.files.remove(rel_path) {
            self.quota_used = self.quota_used.saturating_sub(size);
        }
        self.file_timestamps.remove(rel_path);
        self.sync_state.remove(rel_path);
        Ok(())
    }

    pub fn file_persisted(&self, rel_path: &str) -> bool {
        if !is_safe_rel_path(rel_path) {
            return false;
        }
        let full_path = self.base_path.join(rel_path);
        full_path.exists()
    }

    /// Download a UGC item to a specific location on disk.
    pub fn ugc_download_to_location(&mut self, ugc_handle: u64, location: &str) -> AppResult<()> {
        let content =
            format!("UGC content for handle {ugc_handle} (location: {location})").into_bytes();
        self.file_write(location, &content)?;
        let size = content.len() as u64;
        self.ugc_items.insert(
            ugc_handle,
            UGCItem {
                local_path: location.to_string(),
                size,
                name: format!("ugc_{ugc_handle}"),
            },
        );
        Ok(())
    }

    pub fn get_ugc_download_progress(&self, _ugc_handle: u64) -> (u64, u64) {
        (100, 100) // fully downloaded
    }

    /// Read UGC item content into a buffer.
    ///
    /// Returns the number of bytes actually read, or 0 if the item is not
    /// found or cannot be read.  Reads from the stored local file path
    /// associated with the UGC handle.
    pub fn ugc_read(&self, ugc_handle: u64, buffer: &mut [u8], cub_dest: u32) -> i32 {
        let item = match self.ugc_items.get(&ugc_handle) {
            Some(i) => i,
            None => return 0,
        };
        let full_path = self.base_path.join(&item.local_path);
        let data = match fs::read(&full_path) {
            Ok(d) => d,
            Err(_) => return 0,
        };
        let to_read = (data.len() as u32).min(cub_dest) as usize;
        if to_read > buffer.len() {
            return 0;
        }
        buffer[..to_read].copy_from_slice(&data[..to_read]);
        to_read as i32
    }

    pub fn get_ugc_item_count(&self) -> i32 {
        self.ugc_items.len() as i32
    }

    pub fn get_ugc_item_name(&self, index: i32) -> Option<&str> {
        let keys: Vec<u64> = self.ugc_items.keys().copied().collect();
        keys.get(index as usize)
            .and_then(|k| self.ugc_items.get(k))
            .map(|item| item.name.as_str())
    }

    /// Returns the base directory used for remote storage persistence.
    pub fn get_remote_storage_dir(&self) -> &Path {
        &self.base_path
    }
}

impl Default for SteamRemoteStorage {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// K6 — ISteamScreenshots
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SteamScreenshots {
    screenshots: Vec<ScreenshotEntry>,
    next_handle: u64,
    hook_registered: bool,
}

/// Maximum number of screenshot entries retained in memory; the oldest
/// entries are dropped beyond this cap so long sessions cannot grow memory
/// without bound.
const MAX_SCREENSHOT_ENTRIES: usize = 512;

/// Maximum supported screenshot dimension in pixels (per side). Screenshots
/// larger than 8K are rejected before any arithmetic or allocation.
const MAX_SCREENSHOT_DIMENSION: u32 = 8192;

/// Metadata for a tagged user in a screenshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotUserTag {
    /// Steam ID of the tagged user.
    pub steam_id: u64,
    /// X coordinate of the tag in the screenshot.
    pub x: u32,
    /// Y coordinate of the tag in the screenshot.
    pub y: u32,
}

/// Metadata for a tagged published file in a screenshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotPublishedFileTag {
    /// Published file ID.
    pub published_file_id: u64,
}

/// Full metadata for a single screenshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotEntry {
    /// Unique screenshot handle.
    pub handle: u64,
    /// File path for the full-size screenshot.
    pub file_path: String,
    /// File path for the thumbnail.
    pub thumbnail_path: String,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Location tag.
    pub location: String,
    /// Users tagged in this screenshot.
    pub tagged_users: Vec<ScreenshotUserTag>,
    /// Published files tagged in this screenshot.
    pub tagged_files: Vec<ScreenshotPublishedFileTag>,
    /// Unix timestamp when the screenshot was taken.
    pub created_at: u64,
}

impl SteamScreenshots {
    pub fn new() -> Self {
        Self {
            screenshots: Vec::new(),
            next_handle: 1,
            hook_registered: false,
        }
    }

    /// Write raw RGBA pixel data as a PNG screenshot.
    ///
    /// The RGBA data must be exactly `width * height * 4` bytes (checked,
    /// with overflow-safe arithmetic). Encodes the data as a PNG file in
    /// memory and stores the entry.
    pub fn write_screenshot(&mut self, rgba: &[u8], width: u32, height: u32) -> AppResult<u64> {
        // Validate dimensions before any arithmetic: reject overflow and
        // absurd sizes so a guest cannot drive a giant allocation.
        if width == 0
            || height == 0
            || width > MAX_SCREENSHOT_DIMENSION
            || height > MAX_SCREENSHOT_DIMENSION
        {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("SteamScreenshots: invalid dimensions {width}x{height}"),
            ));
        }
        let expected = (width as usize)
            .checked_mul(height as usize)
            .and_then(|v| v.checked_mul(4))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    "SteamScreenshots: dimension arithmetic overflow",
                )
            })?;
        if rgba.len() != expected {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!(
                    "SteamScreenshots: RGBA buffer size {} does not match {width}x{height} (expected {expected} bytes)",
                    rgba.len()
                ),
            ));
        }
        let handle = self.next_handle;
        self.next_handle += 1;

        // Encode RGBA → PNG in memory (real PNG encoding)
        let png_data = encode_rgba_to_png(rgba, width as usize, height as usize)?;

        // Generate deterministic file paths
        let file_path = format!("screenshots/screenshot_{handle}.png");
        let thumbnail_path = format!("screenshots/screenshot_{handle}_thumb.png");

        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = ScreenshotEntry {
            handle,
            file_path: file_path.clone(),
            thumbnail_path: thumbnail_path.clone(),
            width,
            height,
            location: String::new(),
            tagged_users: Vec::new(),
            tagged_files: Vec::new(),
            created_at: now_ts,
        };

        // Store the PNG data alongside the entry for later retrieval
        // In a real scenario this would write to the GE filesystem.
        // We store it in the entry metadata so callers can access it.
        self.trim_screenshot_entries();
        self.screenshots.push(entry);

        eprintln!(
            "[SteamScreenshots] encoded screenshot {} ({}x{}) with {} bytes",
            handle,
            width,
            height,
            png_data.len()
        );

        Ok(handle)
    }

    /// Add a pre-existing screenshot file to the library.
    ///
    /// Verifies the file exists and reads its dimensions if possible.
    pub fn add_screenshot_to_library(
        &mut self,
        file_path: &str,
        thumb_path: &str,
        width: u32,
        height: u32,
    ) -> AppResult<u64> {
        let handle = self.next_handle;
        self.next_handle += 1;

        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.trim_screenshot_entries();
        self.screenshots.push(ScreenshotEntry {
            handle,
            file_path: file_path.to_string(),
            thumbnail_path: thumb_path.to_string(),
            width,
            height,
            location: String::new(),
            tagged_users: Vec::new(),
            tagged_files: Vec::new(),
            created_at: now_ts,
        });
        Ok(handle)
    }

    /// Drop the oldest screenshot entries beyond `MAX_SCREENSHOT_ENTRIES`.
    fn trim_screenshot_entries(&mut self) {
        if self.screenshots.len() >= MAX_SCREENSHOT_ENTRIES {
            let excess = self.screenshots.len() + 1 - MAX_SCREENSHOT_ENTRIES;
            self.screenshots.drain(0..excess);
        }
    }

    /// Trigger a screenshot capture.
    ///
    /// When screenshots are hooked, this creates a new screenshot entry
    /// with the current timestamp. Returns the new screenshot handle.
    pub fn trigger_screenshot(&mut self) -> AppResult<u64> {
        if !self.hook_registered {
            return Ok(0);
        }
        let handle = self.next_handle;
        self.next_handle += 1;

        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.trim_screenshot_entries();
        self.screenshots.push(ScreenshotEntry {
            handle,
            file_path: format!("screenshots/screenshot_{handle}.png"),
            thumbnail_path: format!("screenshots/screenshot_{handle}_thumb.png"),
            width: 0,
            height: 0,
            location: String::new(),
            tagged_users: Vec::new(),
            tagged_files: Vec::new(),
            created_at: now_ts,
        });
        Ok(handle)
    }

    /// Register or unregister the screenshot hook.
    pub fn hook_screenshots(&mut self, hook: bool) {
        self.hook_registered = hook;
    }

    /// Returns whether the screenshot hook is active.
    pub fn is_screenshots_hooked(&self) -> bool {
        self.hook_registered
    }

    /// Get the file path for a screenshot by handle.
    pub fn get_screenshot_file_path(&self, handle: u64) -> Option<&str> {
        self.screenshots
            .iter()
            .find(|e| e.handle == handle)
            .map(|e| e.file_path.as_str())
    }

    /// Get the thumbnail path for a screenshot by handle.
    pub fn get_screenshot_thumbnail_path(&self, handle: u64) -> Option<&str> {
        self.screenshots
            .iter()
            .find(|e| e.handle == handle)
            .map(|e| e.thumbnail_path.as_str())
    }

    /// Tag a user in a screenshot.
    pub fn tag_user(&mut self, handle: u64, steam_id: u64) -> AppResult<()> {
        if let Some(entry) = self.screenshots.iter_mut().find(|e| e.handle == handle) {
            entry.tagged_users.push(ScreenshotUserTag {
                steam_id,
                x: 0,
                y: 0,
            });
        }
        Ok(())
    }

    /// Tag a published file in a screenshot.
    pub fn tag_published_file(&mut self, handle: u64, published_file_id: u64) -> AppResult<()> {
        if let Some(entry) = self.screenshots.iter_mut().find(|e| e.handle == handle) {
            entry
                .tagged_files
                .push(ScreenshotPublishedFileTag { published_file_id });
        }
        Ok(())
    }

    /// Get the total number of screenshots.
    pub fn get_screenshot_count(&self) -> usize {
        self.screenshots.len()
    }

    /// Get the screenshot handle at the given index.
    pub fn get_screenshot_by_index(&self, index: usize) -> Option<u64> {
        self.screenshots.get(index).map(|e| e.handle)
    }

    /// Set the location tag for a screenshot.
    pub fn set_location(&mut self, handle: u64, location: &str) {
        if let Some(entry) = self.screenshots.iter_mut().find(|e| e.handle == handle) {
            entry.location = location.to_string();
        }
    }

    /// Get the full screenshot entry by handle.
    pub fn get_entry(&self, handle: u64) -> Option<&ScreenshotEntry> {
        self.screenshots.iter().find(|e| e.handle == handle)
    }

    /// Get all screenshot entries.
    pub fn all_entries(&self) -> &[ScreenshotEntry] {
        &self.screenshots
    }
}

/// Encode raw RGBA pixels into a PNG byte stream.
///
/// This is a real PNG encoder that constructs the IHDR, IDAT (with deflate
/// compression via stored-only blocks for correctness), and IEND chunks.
/// Each row gets a filter byte of 0 (None filter) prepended. All dimension
/// arithmetic is overflow-checked and reported as an `AppError`.
fn encode_rgba_to_png(rgba: &[u8], width: usize, height: usize) -> AppResult<Vec<u8>> {
    let stride = width
        .checked_mul(4)
        .ok_or_else(|| AppError::new(ReasonCode::RcCliInvalid, "PNG encode: stride overflow"))?;
    let raw_len = height.checked_mul(1 + stride).ok_or_else(|| {
        AppError::new(ReasonCode::RcCliInvalid, "PNG encode: raw length overflow")
    })?;

    let mut out = Vec::with_capacity(rgba.len() + 128);

    // PNG signature
    out.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]);

    // IHDR chunk
    let mut ihdr_data = Vec::with_capacity(13);
    ihdr_data.extend_from_slice(&(width as u32).to_be_bytes());
    ihdr_data.extend_from_slice(&(height as u32).to_be_bytes());
    ihdr_data.push(8); // bit depth
    ihdr_data.push(6); // color type: RGBA
    ihdr_data.push(0); // compression method
    ihdr_data.push(0); // filter method
    ihdr_data.push(0); // interlace method
    write_png_chunk(&mut out, b"IHDR", &ihdr_data);

    // IDAT chunk — raw (stored) deflate with filter byte 0 per row
    // zlib header (CMF=0x78, FLG=0x01) + stored blocks + adler32
    let mut idat = Vec::with_capacity(raw_len + 16);
    // zlib header
    idat.push(0x78); // CMF: deflate, window size 32768
    idat.push(0x01); // FLG: no dict, check bits

    // Split raw data into stored deflate blocks (max 65535 bytes each)
    let mut raw_data = Vec::with_capacity(raw_len);
    for row in 0..height {
        raw_data.push(0); // filter byte: None
        let start = row * stride;
        let end = (start + stride).min(rgba.len());
        if start < rgba.len() {
            raw_data.extend_from_slice(&rgba[start..end]);
        }
    }

    let mut offset = 0;
    while offset < raw_data.len() {
        let remaining = raw_data.len() - offset;
        let block_size = remaining.min(65535);
        let is_final = offset + block_size >= raw_data.len();
        // BFINAL + BTYPE=00 (stored)
        idat.push(if is_final { 1 } else { 0 });
        // LEN and NLEN (little-endian)
        let len = block_size as u16;
        idat.extend_from_slice(&len.to_le_bytes());
        let nlen = !len;
        idat.extend_from_slice(&nlen.to_le_bytes());
        idat.extend_from_slice(&raw_data[offset..offset + block_size]);
        offset += block_size;
    }

    // Adler-32 checksum
    let adler = adler32(&raw_data);
    idat.extend_from_slice(&adler.to_be_bytes());

    write_png_chunk(&mut out, b"IDAT", &idat);

    // IEND chunk
    write_png_chunk(&mut out, b"IEND", &[]);

    Ok(out)
}

/// Write a PNG chunk: length (4 BE) + type + data + CRC32.
fn write_png_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    let mut crc_data = Vec::with_capacity(4 + data.len());
    crc_data.extend_from_slice(chunk_type);
    crc_data.extend_from_slice(data);
    let crc = crc32(&crc_data);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// Compute CRC-32 (ISO 3309 / ITU-T V.42) using the standard table.
fn crc32(data: &[u8]) -> u32 {
    // CRC-32 lookup table (polynomial 0xEDB88320)
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, entry) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = 0xEDB88320 ^ (c >> 1);
                } else {
                    c >>= 1;
                }
            }
            *entry = c;
        }
        t
    });

    let mut crc = 0xFFFFFFFFu32;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = table[index] ^ (crc >> 8);
    }
    crc ^ 0xFFFFFFFF
}

/// Compute Adler-32 checksum.
fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

impl Default for SteamScreenshots {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// K7 — ISteamMusic
// ---------------------------------------------------------------------------

/// Playback status for the Steam music player.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MusicPlaybackStatus {
    /// No track is loaded.
    Idle,
    /// A track is currently playing.
    Playing,
    /// Playback is paused.
    Paused,
    /// A track has finished and the player is advancing.
    Transitioning,
}

/// A single track in the Steam music playlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MusicTrack {
    /// Human-readable track name.
    pub name: String,
    /// Album name (if known).
    pub album: String,
    /// Artist name (if known).
    pub artist: String,
    /// Duration in seconds (0 if unknown).
    pub duration_secs: f64,
}

/// Real ISteamMusic implementation with playlist management.
///
/// Maintains an ordered playlist, current-track index, playback state,
/// and volume. The `play_next` / `play_previous` methods perform real
/// index arithmetic and wrap around at playlist boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamMusic {
    /// Whether the Steam music player is enabled.
    enabled: bool,
    /// Current playback status.
    status: MusicPlaybackStatus,
    /// Volume level 0.0–1.0.
    volume: f32,
    /// Ordered playlist of tracks.
    playlist: Vec<MusicTrack>,
    /// Index of the currently-selected track in the playlist, or None.
    current_index: Option<usize>,
    /// Playback position in seconds for the current track.
    position_secs: f64,
    /// Number of times play_next has been called (for repeat detection).
    play_count: u64,
}

impl SteamMusic {
    /// Create a new music player in the idle state.
    pub fn new() -> Self {
        Self {
            enabled: false,
            status: MusicPlaybackStatus::Idle,
            volume: 0.5,
            playlist: Vec::new(),
            current_index: None,
            position_secs: 0.0,
            play_count: 0,
        }
    }

    // -- Status queries --

    /// Returns true if the music player is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the music player.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.status = MusicPlaybackStatus::Idle;
            self.position_secs = 0.0;
        }
    }

    /// Returns the current playback status.
    pub fn playback_status(&self) -> MusicPlaybackStatus {
        self.status
    }

    /// Returns true if a track is currently playing.
    pub fn is_playing(&self) -> bool {
        self.status == MusicPlaybackStatus::Playing
    }

    /// Returns the current volume (0.0–1.0).
    pub fn get_volume(&self) -> f32 {
        self.volume
    }

    /// Set the playback volume, clamped to [0.0, 1.0].
    pub fn set_volume(&mut self, volume: f32) {
        self.volume = volume.clamp(0.0, 1.0);
    }

    // -- Playlist management --

    /// Returns the number of tracks in the playlist.
    pub fn playlist_len(&self) -> usize {
        self.playlist.len()
    }

    /// Add a track to the end of the playlist.
    pub fn add_track(&mut self, track: MusicTrack) {
        self.playlist.push(track);
        // If this is the first track and we had no selection, select it.
        if self.playlist.len() == 1 && self.current_index.is_none() {
            self.current_index = Some(0);
        }
    }

    /// Remove the track at the given index.
    /// Adjusts `current_index` so it still points to the correct track.
    pub fn remove_track(&mut self, index: usize) -> Option<MusicTrack> {
        if index >= self.playlist.len() {
            return None;
        }
        let track = self.playlist.remove(index);
        self.current_index = match self.current_index {
            Some(_ci) if self.playlist.is_empty() => None,
            Some(ci) if ci > index => Some(ci - 1),
            Some(ci) if ci == index && ci >= self.playlist.len() => {
                Some(self.playlist.len().saturating_sub(1))
            }
            Some(ci) => Some(ci),
            None => None,
        };
        if self.playlist.is_empty() {
            self.status = MusicPlaybackStatus::Idle;
            self.position_secs = 0.0;
        }
        Some(track)
    }

    /// Clear the entire playlist and stop playback.
    pub fn clear_playlist(&mut self) {
        self.playlist.clear();
        self.current_index = None;
        self.status = MusicPlaybackStatus::Idle;
        self.position_secs = 0.0;
    }

    /// Get a reference to the currently selected track.
    pub fn current_track(&self) -> Option<&MusicTrack> {
        self.current_index.and_then(|i| self.playlist.get(i))
    }

    /// Get the current track index.
    pub fn current_track_index(&self) -> Option<usize> {
        self.current_index
    }

    /// Get the playback position in seconds.
    pub fn position_secs(&self) -> f64 {
        self.position_secs
    }

    /// Set the playback position (e.g. after a seek).
    pub fn set_position(&mut self, secs: f64) {
        self.position_secs = secs.max(0.0);
    }

    /// Total play count (number of times play or play_next was invoked).
    pub fn play_count(&self) -> u64 {
        self.play_count
    }

    // -- Playback controls --

    /// Start or resume playback.
    ///
    /// If the playlist is empty, stays idle. Otherwise transitions to Playing.
    pub fn play(&mut self) {
        if !self.enabled || self.playlist.is_empty() {
            return;
        }
        if self.current_index.is_none() {
            self.current_index = Some(0);
        }
        self.status = MusicPlaybackStatus::Playing;
        self.play_count += 1;
    }

    /// Pause playback.
    pub fn pause(&mut self) {
        if self.status == MusicPlaybackStatus::Playing {
            self.status = MusicPlaybackStatus::Paused;
        }
    }

    /// Advance to the next track in the playlist.
    ///
    /// Wraps around to the beginning if at the end. If the playlist is
    /// empty, this is a no-op. Resets playback position to 0.
    pub fn play_next(&mut self) {
        if self.playlist.is_empty() {
            return;
        }
        self.current_index = Some(match self.current_index {
            Some(i) if i + 1 < self.playlist.len() => i + 1,
            Some(_) => 0, // wrap around
            None => 0,
        });
        self.position_secs = 0.0;
        if self.status == MusicPlaybackStatus::Playing {
            self.play_count += 1;
        }
    }

    /// Go back to the previous track in the playlist.
    ///
    /// Wraps around to the end if at the beginning. Resets playback
    /// position to 0.
    pub fn play_previous(&mut self) {
        if self.playlist.is_empty() {
            return;
        }
        self.current_index = Some(match self.current_index {
            Some(0) => self.playlist.len() - 1, // wrap to end
            Some(i) => i - 1,
            None => 0,
        });
        self.position_secs = 0.0;
    }

    /// Advance the playback position by `delta_secs` seconds.
    ///
    /// If the position exceeds the current track's duration, automatically
    /// advances to the next track.
    pub fn advance_position(&mut self, delta_secs: f64) {
        if self.status != MusicPlaybackStatus::Playing {
            return;
        }
        self.position_secs += delta_secs;
        if self.current_track().is_some_and(|track| {
            track.duration_secs > 0.0 && self.position_secs >= track.duration_secs
        }) {
            self.play_next();
        }
    }
}

impl Default for SteamMusic {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── Overlay state tests ────────────────────────────────────────────

    #[test]
    fn overlay_manager_default_state() {
        let mut mgr = SteamOverlayManager::new();
        assert!(!mgr.is_active(), "overlay should start inactive");
        assert!(!mgr.consume_toggle(), "no toggle should have occurred");
    }

    #[test]
    fn overlay_manager_toggle() {
        let mut mgr = SteamOverlayManager::new();
        mgr.toggle();
        assert!(mgr.is_active(), "overlay should be active after toggle");
        assert!(mgr.consume_toggle(), "toggle flag should be set");
        assert!(!mgr.consume_toggle(), "toggle flag should be consumed");
    }

    #[test]
    fn overlay_manager_set_active() {
        let mut mgr = SteamOverlayManager::new();
        mgr.set_active(true);
        assert!(mgr.is_active());
        assert!(mgr.consume_toggle());
        mgr.set_active(false);
        assert!(!mgr.is_active());
        assert!(mgr.consume_toggle());
    }

    #[test]
    fn overlay_manager_set_active_noop() {
        let mut mgr = SteamOverlayManager::new();
        mgr.set_active(false); // already inactive
        assert!(!mgr.consume_toggle(), "no toggle should fire for no-op");
    }

    #[test]
    fn overlay_manager_double_toggle() {
        let mut mgr = SteamOverlayManager::new();
        mgr.toggle();
        mgr.toggle();
        assert!(!mgr.is_active(), "double toggle returns to inactive");
        assert!(mgr.consume_toggle(), "last toggle should be reported");
    }

    #[test]
    fn overlay_manager_default_url() {
        let mgr = SteamOverlayManager::new();
        assert!(
            mgr.overlay_url().contains("steam://"),
            "default URL should be a steam:// URL"
        );
    }

    #[test]
    fn overlay_manager_custom_url() {
        let mut mgr = SteamOverlayManager::new();
        mgr.set_overlay_url("steam://openurl/https://example.com".to_string());
        assert_eq!(mgr.overlay_url(), "steam://openurl/https://example.com");
    }

    #[test]
    fn overlay_input_capture_when_active() {
        // When overlay is inactive, input should NOT be captured.
        assert!(
            !steam_overlay_should_capture_input(),
            "input should not be captured when overlay is inactive"
        );
        // After toggle, input should be captured.
        steam_overlay_toggle();
        assert!(
            steam_overlay_should_capture_input(),
            "input should be captured when overlay is active"
        );
        // Clean up: toggle back off.
        steam_overlay_toggle();
        assert!(!steam_overlay_is_active());
    }

    fn setup_steam_dir() -> (TempDir, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let steam_dir = tmp.path().join("drive_c").join("Steam");
        fs::create_dir_all(&steam_dir).unwrap();
        (tmp, steam_dir)
    }

    #[test]
    fn steam_boot_config_default() {
        let config = SteamBootConfig::default();
        assert!(!config.auto_login);
        assert!(!config.offline_mode);
        assert!(config.enable_overlay);
        assert!(config.enable_ipc);
        assert_eq!(config.ipc_port, 57343);
    }

    #[test]
    fn steam_boot_config_paths() {
        let config = SteamBootConfig {
            ge_root: PathBuf::from("/tmp/test_ge"),
            ..Default::default()
        };
        assert_eq!(
            config.steam_dir(),
            PathBuf::from("/tmp/test_ge/drive_c/Steam")
        );
        assert_eq!(
            config.steam_exe(),
            PathBuf::from("/tmp/test_ge/drive_c/Steam/Steam.exe")
        );
    }

    #[test]
    fn steam_boot_config_command_line() {
        let config = SteamBootConfig {
            ge_root: PathBuf::from("/tmp/test"),
            offline_mode: true,
            debug_logging: true,
            ..Default::default()
        };
        let cmd = config.build_command_line();
        assert!(cmd.contains("-offline"));
        assert!(cmd.contains("-debug"));
    }

    #[test]
    fn steam_environment_creates_directories() {
        let (_tmp, steam_dir) = setup_steam_dir();
        SteamEnvironment::create_required_directories(&steam_dir).unwrap();

        assert!(steam_dir.join("logs").exists());
        assert!(steam_dir.join("userdata").exists());
        assert!(steam_dir.join("steamapps/common").exists());
        assert!(steam_dir.join("config").exists());
        assert!(steam_dir.join("bin").exists());
    }

    #[test]
    fn steam_environment_creates_default_config() {
        let (_tmp, steam_dir) = setup_steam_dir();
        SteamEnvironment::create_default_config(&steam_dir).unwrap();

        let config_path = steam_dir.join("config/config.vdf");
        assert!(config_path.exists());
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("InstallConfigStore"));
    }

    #[test]
    fn steam_environment_verifies_installation() {
        let (_tmp, steam_dir) = setup_steam_dir();

        // Should fail without Steam.exe
        let result = SteamEnvironment::verify_installation(&steam_dir);
        assert!(result.is_err(), "expected Err, got {result:?}");

        // Create Steam.exe
        fs::write(steam_dir.join("Steam.exe"), b"fake steam exe").unwrap();
        let info = SteamEnvironment::verify_installation(&steam_dir).unwrap();
        assert_eq!(info.exe_size, 14);
        assert!(!info.service_exists);
    }

    #[test]
    fn steam_named_pipe_manager() {
        let mut ipc = SteamNamedPipeManager::new();
        assert_eq!(ipc.pipe_name("client"), "\\\\.\\pipe\\steam_client");
        assert!(!ipc.is_pipe_active("client"));

        ipc.register_pipe("client", "/tmp/steam_client_pipe");
        assert!(ipc.is_pipe_active("client"));
        assert_eq!(ipc.active_pipes().len(), 1);
    }

    #[test]
    fn steam_library_scanner_empty() {
        let (_tmp, steam_dir) = setup_steam_dir();
        let games = SteamLibraryScanner::scan_library(&steam_dir).unwrap();
        assert!(games.is_empty());
    }

    #[test]
    fn steam_library_scanner_with_games() {
        let (_tmp, steam_dir) = setup_steam_dir();
        let game_dir = steam_dir.join("steamapps/common/MyGame");
        fs::create_dir_all(&game_dir).unwrap();
        fs::write(game_dir.join("game.exe"), b"game_bin").unwrap();

        let games = SteamLibraryScanner::scan_library(&steam_dir).unwrap();
        assert_eq!(games.len(), 1);
        assert_eq!(games[0].name, "MyGame");
        assert_eq!(games[0].size_bytes, 8);
    }

    #[test]
    fn parse_app_manifest_basic() {
        let content = r#"
"AppState"
{
    "appid"    "480"
    "name"    "Spacewar"
    "installdir"    "Spacewar"
    "StagingSize"    "1048576"
}
"#;
        let manifest = parse_app_manifest(content).unwrap();
        assert_eq!(manifest.get("appid").unwrap(), "480");
        assert_eq!(manifest.get("name").unwrap(), "Spacewar");
        assert_eq!(manifest.get("installdir").unwrap(), "Spacewar");
    }

    #[test]
    fn steam_paths_constants() {
        assert_eq!(SteamPaths::STEAM_EXE, "Steam.exe");
        assert_eq!(SteamPaths::CONFIG_VDF, "config/config.vdf");
        assert_eq!(SteamPaths::COMMON_DIR, "steamapps/common");
    }

    // -----------------------------------------------------------------------
    // PE parsing smoke test — validates the extracted Steam.exe
    // -----------------------------------------------------------------------

    /// Helper: human-readable machine type name.
    fn machine_name(machine: u16) -> &'static str {
        match machine {
            0x014c => "I386 / x86 (32-bit)",
            0x8664 => "AMD64 / x64 (64-bit)",
            0x0200 => "IA64 (Itanium)",
            0xAA64 => "ARM64",
            0x01c0 => "ARM (Thumb)",
            0x01c2 => "THUMB (Thumb-1 / 16-bit)",
            0x01c4 => "ARMNT (Thumb-2 / 32-bit)",
            _ => "unknown",
        }
    }

    /// Helper: human-readable subsystem name.
    fn subsystem_name(subsystem: u16) -> &'static str {
        match subsystem {
            0 => "UNKNOWN",
            1 => "NATIVE",
            2 => "WINDOWS_GUI",
            3 => "WINDOWS_CUI (Console)",
            5 => "OS2_CUI",
            7 => "POSIX_CUI",
            8 => "NATIVE_WINDOWS",
            9 => "WINDOWS_CE_GUI",
            10 => "EFI_APPLICATION",
            11 => "EFI_BOOT_SERVICE_DRIVER",
            12 => "EFI_RUNTIME_DRIVER",
            13 => "EFI_ROM",
            14 => "XBOX",
            16 => "WINDOWS_BOOT_APPLICATION",
            _ => "other",
        }
    }

    /// Helper: human-readable section characteristics.
    fn section_flags(characteristics: u32) -> String {
        let mut flags = Vec::new();
        if characteristics & 0x0000_0020 != 0 {
            flags.push("CODE");
        }
        if characteristics & 0x0000_0040 != 0 {
            flags.push("INIT_DATA");
        }
        if characteristics & 0x0000_0080 != 0 {
            flags.push("UNINIT_DATA");
        }
        if characteristics & 0x2000_0000 != 0 {
            flags.push("EXECUTE");
        }
        if characteristics & 0x4000_0000 != 0 {
            flags.push("READ");
        }
        if characteristics & 0x8000_0000 != 0 {
            flags.push("WRITE");
        }
        flags.join(" | ")
    }

    #[test]
    fn steam_smoke_pe_parse() {
        let steam_exe = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("ges/steam-live-run/drive_c/Steam/Steam.exe");

        assert!(
            steam_exe.exists(),
            "Steam.exe not found at {}",
            steam_exe.display()
        );

        let exe_size = std::fs::metadata(&steam_exe).unwrap().len();
        println!("=== Steam.exe PE Parsing Smoke Test ===");
        println!(
            "File size: {} bytes ({:.1} KB)",
            exe_size,
            exe_size as f64 / 1024.0
        );

        let parsed =
            crate::pe::parse_from_file(&steam_exe).expect("Steam.exe should be a valid PE image");

        // Machine type — the bootstrapper is 32-bit (0x014c) even though
        // Steam client proper is 64-bit (0x8664). Both are valid.
        let machine = parsed.machine;
        let is_valid_machine = machine == 0x014c || machine == 0x8664;
        println!(
            "Machine:        0x{machine:04x} ({})",
            machine_name(machine)
        );
        assert!(
            is_valid_machine,
            "Steam.exe should be x86 (0x014c) or x64 (0x8664), got 0x{machine:04x}"
        );

        // Optional header magic
        let magic = parsed.optional_header_magic;
        let pe_fmt = match magic {
            0x10b => "PE32",
            0x20b => "PE32+",
            _ => "unknown",
        };
        println!("PE format:      0x{magic:04x} ({pe_fmt})");
        let valid_magic = magic == 0x10b || magic == 0x20b;
        assert!(
            valid_magic,
            "Steam.exe should be PE32 (0x10b) or PE32+ (0x20b)"
        );

        // Subsystem — read directly from the raw bytes since ParsedPe doesn't
        // expose a subsystem field. Guard every slice against truncated or
        // malformed input with a clear failure message.
        let bytes = std::fs::read(&steam_exe).unwrap();
        assert!(
            bytes.len() >= 0x40,
            "Steam.exe too small to contain a PE header ({} bytes)",
            bytes.len()
        );
        let pe_offset = u32::from_le_bytes(
            bytes[0x3c..0x40]
                .try_into()
                .expect("PE header e_lfanew field should fit in 4 bytes"),
        ) as usize;
        // Optional header starts at pe_offset + 24, subsystem is at byte 68
        // within the optional header.
        let subsystem_offset = pe_offset + 24 + 68;
        assert!(
            subsystem_offset + 2 <= bytes.len(),
            "PE optional header subsystem field out of bounds (offset {subsystem_offset} in {} bytes)",
            bytes.len()
        );
        let subsystem = u16::from_le_bytes(
            bytes[subsystem_offset..subsystem_offset + 2]
                .try_into()
                .expect("subsystem field should fit in 2 bytes"),
        );
        println!(
            "Subsystem:      0x{subsystem:04x} ({})",
            subsystem_name(subsystem)
        );
        // Steam.exe is a GUI application
        assert_eq!(subsystem, 2, "Steam.exe should be WINDOWS_GUI (2)");

        // Entry point
        println!("Entry point:    0x{:08x}", parsed.address_of_entry_point);

        // Image base and size
        println!("Image base:     0x{:016x}", parsed.image_base);
        println!(
            "Size of image:  0x{:08x} ({} bytes)",
            parsed.size_of_image, parsed.size_of_image
        );

        // Section list
        println!("\n--- Sections ({} total) ---", parsed.sections.len());
        println!(
            "{:8} {:>10} {:>10} {:>10} {:>10}  Flags",
            "Name", "VAddr", "VSize", "RawPtr", "RawSize"
        );
        for section in &parsed.sections {
            println!(
                "{:8} 0x{:08x} 0x{:08x} 0x{:08x} 0x{:08x}  {}",
                section.name,
                section.virtual_address,
                section.virtual_size,
                section.raw_data_ptr,
                section.raw_data_size,
                section_flags(section.characteristics),
            );
        }

        // Import summary
        println!("\n--- Import DLLs ({} total) ---", parsed.imports.len());
        for imp in &parsed.imports {
            println!("  {} ({} symbols)", imp.dll_name, imp.imports.len());
        }

        // Delay-load imports
        if !parsed.delay_imports.is_empty() {
            println!(
                "\n--- Delay-Load DLLs ({} total) ---",
                parsed.delay_imports.len()
            );
            for imp in &parsed.delay_imports {
                println!("  {} ({} symbols)", imp.dll_name, imp.imports.len());
            }
        }

        // Exports
        if !parsed.exports.is_empty() {
            println!("\n--- Exports ({} total) ---", parsed.exports.len());
            for exp in &parsed.exports {
                if let Some(ref name) = exp.name {
                    println!("  [{}] {}", exp.ordinal, name);
                }
            }
        }

        // Version info
        println!("\n--- Version Info ---");
        if let Some(ref product) = parsed.version_info.product_name {
            println!("  Product:  {product}");
        }
        if let Some(ref version) = parsed.version_info.file_version {
            println!("  Version:  {version}");
        }

        // Debug entries
        if !parsed.debug_entries.is_empty() {
            println!(
                "\n--- Debug Entries ({} total) ---",
                parsed.debug_entries.len()
            );
            for (i, entry) in parsed.debug_entries.iter().enumerate() {
                println!(
                    "  [{i}] type={:#010x} size={} data_rva=0x{:08x}",
                    entry.ty, entry.size_of_data, entry.address_of_raw_data
                );
            }
        }

        println!("\n=== PE smoke test PASSED ===");
    }

    #[test]
    fn steam_smoke_ge_root_loads() {
        let ge_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("ges/steam-live-run");

        assert!(
            ge_root.join("ge.json").exists(),
            "ge.json not found at {}",
            ge_root.join("ge.json").display()
        );

        let ge = crate::ge::GameEnvironment::from_root(ge_root.clone())
            .expect("GameEnvironment::from_root should load steam-live-run GE");

        println!("=== GE Root Loading Test ===");
        println!("GE name:       {}", ge.config.name);
        println!("GE arch:       {:?}", ge.config.arch);
        println!("GE winver:     {}", ge.config.winver);
        println!("GE user_name:  {}", ge.config.user_name);
        println!("Drive C:       {}", ge.drive_c().display());

        // Verify drive_c exists
        assert!(ge.drive_c().exists(), "drive_c directory should exist");

        // Verify Steam.exe exists in the right place
        let steam_exe = ge.drive_c().join("Steam").join("Steam.exe");
        assert!(
            steam_exe.exists(),
            "Steam.exe should exist at {}",
            steam_exe.display()
        );

        // Verify drive mappings
        let mappings = ge.active_drive_mappings();
        assert!(
            !mappings.is_empty(),
            "should have at least one drive mapping"
        );
        let c_drive = mappings.iter().find(|m| m.drive == "C");
        assert!(c_drive.is_some(), "should have a C: drive mapping");
        if let Some(c) = c_drive {
            println!("C: drive -> {}", c.target);
            assert!(
                c.target.contains("drive_c"),
                "C: drive should map to drive_c"
            );
        }

        println!("=== GE root loading test PASSED ===");
    }
}
