//! Optimal Steam launch configuration for Casa1.
//!
//! This module provides the complete pipeline for launching the native Windows
//! Steam executable (`Steam.exe`) through Casa1's PE runtime with full graphical
//! rendering capabilities, hardware-accelerated Metal rendering, real audio
//! output, CEF/WKWebView-based UI compositing, and complete feature parity.
//!
//! # Architecture
//!
//! The launch pipeline consists of these stages:
//!
//! 1. **GE Preparation**: Creates or opens a Game Environment with the optimal
//!    configuration for Steam (x86 arch, Windows 11, drive mappings, etc.)
//! 2. **Override Profile**: Registers a Steam-specific override profile that
//!    configures D3D/DXGI DLL overrides, registry entries, and environment
//!    variables for Metal rendering and real audio routing.
//! 3. **Environment Setup**: Creates all required Steam directories, default
//!    config files, and registry entries for Steam to function correctly.
//! 4. **Launch**: Dispatches through the runner with `RunIntent::Play` to
//!    create a live PE session with a real macOS window backed by Metal.
//!
//! # Subsystems Configured
//!
//! - **Graphics**: Metal hardware acceleration via `metal_backend` + `metal_renderer`,
//!   D3D11/D3D12 → Metal translation, DXIL → MSL shader compilation,
//!   DXGI swapchain backed by `CAMetalLayer`, Vulkan/OpenGL → Metal via `vkgl`.
//! - **Audio**: Real audio output via `cpal` through `real_audio`, XAudio2
//!   mastering voices, WASAPI audio clients, DirectSound buffers, WinMM
//!   wave output — all routed to the macOS default audio device.
//! - **Display**: Native `NSWindow`/`NSView` via `mac_window`, `CAMetalLayer`
//!   swapchain for vsync'd presentation, HiDPI/Retina support.
//! - **CEF/WebView**: Chromium Embedded Framework bridge via `cef_bridge` +
//!   `webview2` for Steam's web-based UI (store, library, settings, overlay).
//! - **Steam Integration**: SteamService lifecycle management, named-pipe IPC,
//!   `steam://` protocol handler registration, Steam Input device support.
//! - **Networking**: Full network stack with TLS for Steam store, workshop,
//!   multiplayer, and content delivery.

use crate::error::{AppError, AppResult};
use crate::ge::{
    DllOverride, DllOverrideMode, FsProfile, GeArch, GfxProfile, NetworkPolicy, NetworkProfile,
    OverrideMatchRule, OverridePayload, OverrideProfile,
};
use crate::reason::ReasonCode;
use crate::runner::{RunIntent, RunnerJob};
use crate::steam_integration::{SteamEnvironment, SteamPaths};
use crate::trace::TraceCategory;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Steam launch profile
// ---------------------------------------------------------------------------

/// Optimal configuration profile for launching the Windows Steam client.
///
/// This struct captures all tunable parameters for Steam execution. The
/// `Default` implementation provides the recommended configuration for
/// full feature parity with native Windows Steam.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamLaunchProfile {
    /// Name of the Game Environment to create/open for Steam.
    pub ge_name: String,
    /// Whether to create the GE if it does not already exist.
    pub create_ge: bool,
    /// Whether to enable Metal hardware-accelerated rendering.
    pub metal_rendering: bool,
    /// Whether to enable real audio output via cpal.
    pub real_audio: bool,
    /// Whether to enable the CEF/WKWebView bridge for Steam's web UI.
    pub cef_bridge: bool,
    /// Whether to enable Vulkan/OpenGL → Metal translation via MoltenVK.
    pub vulkan_opengl: bool,
    /// Whether to enable the Steam overlay.
    pub steam_overlay: bool,
    /// Whether to enable Steam IPC (named pipes).
    pub steam_ipc: bool,
    /// Whether to auto-login to Steam.  Not supported in this version:
    /// `create_steam_job` rejects profiles that set it with a clear error.
    pub auto_login: bool,
    /// Whether to start Steam in offline mode.
    pub offline_mode: bool,
    /// Whether to enable debug logging for Steam.
    pub debug_logging: bool,
    /// Whether to enable JIT compilation for the PE runtime.
    pub jit_enabled: bool,
    /// Custom PE runtime instruction budget (0 = unlimited).
    pub instruction_budget: u64,
    /// Additional launch arguments for Steam.exe.
    pub extra_args: Vec<String>,
    /// Steam install directory relative to drive_c.
    pub steam_install_dir: String,
    /// Whether to enable HiDPI/Retina rendering.
    pub hidpi: bool,
    /// Target display resolution width (0 = auto-detect).
    pub resolution_width: u32,
    /// Target display resolution height (0 = auto-detect).
    pub resolution_height: u32,
    /// Whether to enable Steam Input device support.
    pub steam_input: bool,
    /// Whether to enable network access for Steam.
    pub network_enabled: bool,
    /// Whether to register the steam:// URL protocol handler.
    pub register_protocol: bool,
}

impl Default for SteamLaunchProfile {
    fn default() -> Self {
        Self {
            ge_name: "steam".to_string(),
            create_ge: true,
            metal_rendering: true,
            real_audio: true,
            cef_bridge: true,
            vulkan_opengl: true,
            steam_overlay: true,
            steam_ipc: true,
            auto_login: false,
            offline_mode: false,
            debug_logging: false,
            jit_enabled: true,
            instruction_budget: 0, // unlimited
            extra_args: Vec::new(),
            steam_install_dir: "Steam".to_string(),
            hidpi: true,
            resolution_width: 0,  // auto
            resolution_height: 0, // auto
            steam_input: true,
            network_enabled: true,
            register_protocol: true,
        }
    }
}

impl SteamLaunchProfile {
    /// Create a profile optimized for maximum performance.
    ///
    /// Disables debug logging and enables JIT with unlimited instruction
    /// budget.
    pub fn performance() -> Self {
        Self {
            debug_logging: false,
            jit_enabled: true,
            instruction_budget: 0,
            ..Self::default()
        }
    }

    /// Create a profile optimized for debugging Steam issues.
    ///
    /// Enables debug logging, Steam tracing, and limits the instruction
    /// budget for reproducible behavior.
    pub fn debug() -> Self {
        Self {
            debug_logging: true,
            jit_enabled: true,
            instruction_budget: 50_000_000,
            extra_args: vec!["-dev".to_string(), "-console".to_string()],
            ..Self::default()
        }
    }

    /// Create a profile for offline mode.
    pub fn offline() -> Self {
        Self {
            offline_mode: true,
            network_enabled: false,
            ..Self::default()
        }
    }

    /// Resolve the Steam install directory within the GE root.
    pub fn steam_dir(&self, ge_root: &Path) -> PathBuf {
        ge_root.join("drive_c").join(&self.steam_install_dir)
    }

    /// Resolve the path to Steam.exe within the GE root.
    pub fn steam_exe_path(&self, ge_root: &Path) -> PathBuf {
        self.steam_dir(ge_root).join(SteamPaths::STEAM_EXE)
    }
}

// ---------------------------------------------------------------------------
// Steam launch result
// ---------------------------------------------------------------------------

/// Result of a Steam launch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamLaunchResult {
    /// The GE name used for the launch.
    pub ge_name: String,
    /// The GE root path.
    pub ge_root: PathBuf,
    /// Path to Steam.exe.
    pub steam_exe: PathBuf,
    /// Whether the GE was newly created.
    pub ge_created: bool,
    /// Whether the Steam environment was set up.
    pub environment_prepared: bool,
    /// Whether the override profile was registered.
    pub override_registered: bool,
    /// The runner job test ID.
    pub test_id: String,
}

// ---------------------------------------------------------------------------
// Steam launch pipeline
// ---------------------------------------------------------------------------

/// Prepares the Game Environment for Steam execution.
///
/// This function either opens an existing GE named `profile.ge_name` or creates
/// a new one with the optimal configuration for Steam (x86 architecture,
/// Windows 11 23H2, standard drive mappings).
///
/// Returns the `GameEnvironment` and a boolean indicating whether it was newly
/// created.
pub fn prepare_steam_ge(
    profile: &SteamLaunchProfile,
) -> AppResult<(crate::ge::GameEnvironment, bool)> {
    use crate::ge::GameEnvironment;

    // Try to open an existing GE first.
    match GameEnvironment::open(&profile.ge_name) {
        Ok(ge) => {
            eprintln!(
                "[steam_launch] opened existing GE '{}' at {}",
                profile.ge_name,
                ge.root.display()
            );
            Ok((ge, false))
        }
        Err(_) if profile.create_ge => {
            // Steam is a 32-bit application, so we use x86 architecture.
            // Windows 11 23H2 provides the most compatible environment.
            let ge = GameEnvironment::create(&profile.ge_name, GeArch::X86, "win11-23h2")?;
            eprintln!(
                "[steam_launch] created new GE '{}' at {}",
                profile.ge_name,
                ge.root.display()
            );
            Ok((ge, true))
        }
        Err(e) => Err(e),
    }
}

/// The `CASA1_*` launch-specific environment variables derived from a launch
/// profile.
///
/// This set contains ONLY launch-specific Casa1 settings (graphics, audio,
/// CEF, Vulkan/OpenGL, Steam Input, budget).  The runner itself supplies the
/// GE root, registry files, trace file, run intent, and test id via
/// `runner::child_environment` — they are never duplicated here.
fn steam_env_vars(profile: &SteamLaunchProfile) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    // ── Graphics configuration ──────────────────────────────────────────────
    if profile.metal_rendering {
        // Enable Metal hardware acceleration.
        env.insert("CASA1_METAL_RENDERING".to_string(), "1".to_string());
        // Report as NVIDIA vendor for maximum D3D feature level compatibility.
        env.insert("CASA1_GPU_COMPAT_VENDOR".to_string(), "10de".to_string());
        // Enable D3D11 feature level 11_0 for Steam's UI rendering.
        env.insert("CASA1_D3D_FEATURE_LEVEL".to_string(), "11_0".to_string());
        // Enable DXGI swapchain backed by CAMetalLayer.
        env.insert("CASA1_DXGI_METAL_SWAPCHAIN".to_string(), "1".to_string());
    }

    if profile.hidpi {
        // Enable HiDPI/Retina mode for sharp text on Retina displays.
        env.insert("CASA1_HIDPI".to_string(), "1".to_string());
    }

    // ── Audio configuration ─────────────────────────────────────────────────
    if profile.real_audio {
        // Route all audio through real cpal output.
        env.insert("CASA1_REAL_AUDIO".to_string(), "1".to_string());
        // Use the default macOS audio device.
        env.insert("CASA1_AUDIO_DEVICE".to_string(), "default".to_string());
        // Enable XAudio2 real output for Steam audio.
        env.insert("CASA1_XAUDIO2_REAL".to_string(), "1".to_string());
        // Enable DirectSound real output.
        env.insert("CASA1_DSOUND_REAL".to_string(), "1".to_string());
    }

    // ── CEF/WebView configuration ───────────────────────────────────────────
    if profile.cef_bridge {
        // Enable the CEF/WKWebView bridge for Steam's web-based UI.
        env.insert("CASA1_CEF_BRIDGE".to_string(), "1".to_string());
        // Enable WebView2 COM interface for Steam's embedded browser.
        env.insert("CASA1_WEBVIEW2".to_string(), "1".to_string());
        // Enable IOSurface-backed zero-copy compositing for CEF frames.
        env.insert("CASA1_CEF_IOSURFACE".to_string(), "1".to_string());
    }

    // ── Vulkan/OpenGL configuration ─────────────────────────────────────────
    if profile.vulkan_opengl {
        // Enable Vulkan → Metal translation via MoltenVK.
        env.insert("CASA1_VULKAN_METAL".to_string(), "1".to_string());
        // Enable OpenGL → Metal translation.
        env.insert("CASA1_OPENGL_METAL".to_string(), "1".to_string());
    }

    // ── Steam-specific configuration ────────────────────────────────────────
    if profile.debug_logging {
        env.insert("CASA1_STEAM_TRACE".to_string(), "1".to_string());
    }
    if profile.instruction_budget > 0 {
        env.insert(
            "CASA1_PE_RUNTIME_BUDGET".to_string(),
            profile.instruction_budget.to_string(),
        );
    }

    // ── Steam Input configuration ───────────────────────────────────────────
    if profile.steam_input {
        env.insert("CASA1_STEAM_INPUT".to_string(), "1".to_string());
    }

    env
}

/// Creates the Steam-specific override profile for the GE.
///
/// This override profile configures:
/// - DLL overrides for D3D/DXGI to use Metal-backed implementations
/// - Environment variables for Metal rendering, real audio, CEF bridge
/// - Registry entries for Steam compatibility
/// - Graphics profile for optimal rendering
/// - Network profile for Steam connectivity
pub fn build_steam_override_profile(profile: &SteamLaunchProfile) -> OverrideProfile {
    let env_add = steam_env_vars(profile);

    // ── DLL overrides ───────────────────────────────────────────────────────
    // Use Casa1's built-in (Metal-backed) implementations for D3D and DXGI.
    let dll_overrides = vec![
        DllOverride {
            name: "d3d11".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "d3d10".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "d3d9".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "dxgi".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "d3d12".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "dcomp".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "d2d1".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "dwrite".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        // Use Casa1's built-in XAudio2/DirectSound/WASAPI for real audio.
        DllOverride {
            name: "xaudio2_7".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "xaudio2_9".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "dsound".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "winmm".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "mfplat".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        // Use Casa1's CEF/WebView2 bridge for Steam's web UI.
        DllOverride {
            name: "libcef".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "webview2".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        // Use Casa1's built-in Vulkan/OpenGL for compatibility.
        DllOverride {
            name: "vulkan-1".to_string(),
            mode: DllOverrideMode::Builtin,
        },
        DllOverride {
            name: "opengl32".to_string(),
            mode: DllOverrideMode::Builtin,
        },
    ];

    // ── Graphics profile ────────────────────────────────────────────────────
    let gfx_profile = if profile.metal_rendering {
        Some(GfxProfile {
            feature_masks: vec![
                "metal".to_string(),
                "d3d11_fl11_0".to_string(),
                "d3d10_fl10_1".to_string(),
                "d3d9_ex".to_string(),
                "dxgi_1_6".to_string(),
                "bc1237_compression".to_string(),
                "msaa_8x".to_string(),
                "hdr10".to_string(),
            ],
            shader_flags: vec![
                "dxil_to_msl".to_string(),
                "async_pipeline_compile".to_string(),
                "shader_cache".to_string(),
            ],
        })
    } else {
        None
    };

    // ── Network profile ─────────────────────────────────────────────────────
    let network_profile = if profile.network_enabled {
        Some(NetworkProfile {
            policy: NetworkPolicy::AllowAll,
            whitelist: Vec::new(),
        })
    } else {
        Some(NetworkProfile {
            policy: NetworkPolicy::DenyAll,
            whitelist: Vec::new(),
        })
    };

    // ── Filesystem profile ──────────────────────────────────────────────────
    let fs_profile = Some(FsProfile {
        case_mode: "insensitive".to_string(),
        long_paths_enabled: true,
    });

    OverrideProfile {
        id: "steam-optimal".to_string(),
        match_rule: OverrideMatchRule::InstallPathWildcard {
            pattern: "**/Steam.exe".to_string(),
        },
        payload: OverridePayload {
            env_add,
            env_remove: Vec::new(),
            reg_set: Vec::new(),
            reg_delete: Vec::new(),
            dll_override: dll_overrides,
            cpu_profile: None,
            gfx_profile,
            input_profile: None,
            network_profile,
            fs_profile,
        },
    }
}

/// Sets up the Steam directory structure and configuration within the GE.
///
/// Creates all required Steam directories, writes the default `config.vdf`,
/// and ensures the Steam environment is ready for first launch.
pub fn prepare_steam_environment(ge_root: &Path, profile: &SteamLaunchProfile) -> AppResult<()> {
    let steam_dir = profile.steam_dir(ge_root);

    eprintln!(
        "[steam_launch] preparing Steam environment at {}",
        steam_dir.display()
    );

    // Create all required Steam directories.
    SteamEnvironment::create_required_directories(&steam_dir)?;

    // Create default config files if they don't exist.
    SteamEnvironment::create_default_config(&steam_dir)?;

    // Verify the Steam executable exists (if it's already installed).
    let steam_exe = steam_dir.join(SteamPaths::STEAM_EXE);
    if steam_exe.exists() {
        eprintln!(
            "[steam_launch] Steam.exe found at {} ({} bytes)",
            steam_exe.display(),
            std::fs::metadata(&steam_exe).map(|m| m.len()).unwrap_or(0)
        );
    } else {
        eprintln!(
            "[steam_launch] Steam.exe not found at {} — Steam must be installed first",
            steam_exe.display()
        );
        eprintln!("[steam_launch] Use 'macwin ge:install' with a Steam installer to install Steam");
    }

    Ok(())
}

/// Builds the launch-specific job environment map for Steam execution.
///
/// Contains ONLY launch-specific Casa1 settings derived from the profile
/// (graphics, audio, CEF, Vulkan/OpenGL, Steam Input, budget).  The runner
/// supplies the GE root, registry files, trace file, run intent and test id
/// via `runner::child_environment` — those are never duplicated here.
pub fn build_steam_job_env(profile: &SteamLaunchProfile) -> BTreeMap<String, String> {
    steam_env_vars(profile)
}

/// Builds the Steam.exe command-line arguments from the launch profile.
pub fn build_steam_args(profile: &SteamLaunchProfile) -> Vec<String> {
    let mut args = Vec::new();

    // NOTE: `steam_overlay` represents *support only* — no forced `-overlay`
    // startup flag is emitted (the overlay must be enabled from within Steam
    // itself, and a forced flag changes Steam's startup behavior).
    // NOTE: `auto_login` is not supported in v1 (see create_steam_job).
    if profile.offline_mode {
        args.push("-offline".to_string());
    }
    if profile.debug_logging {
        args.push("-debug".to_string());
    }

    args.extend(profile.extra_args.iter().cloned());

    args
}

/// Registers the Steam override profile with the GE.
///
/// This persists the override configuration in the GE's `ge.json` so that
/// it is automatically applied whenever Steam.exe is executed within this GE.
///
/// Upsert semantics: a `steam-optimal` override that already exists is
/// REPLACED by the freshly built profile (the new invocation wins — a
/// `steam:launch` followed by `steam:launch --no-metal` applies the second
/// invocation's configuration).  `save_config()` is only invoked when the
/// effective contents actually changed.
pub fn register_steam_override(
    ge: &mut crate::ge::GameEnvironment,
    profile: &SteamLaunchProfile,
) -> AppResult<()> {
    let override_profile = build_steam_override_profile(profile);

    match ge
        .config
        .override_profiles
        .iter()
        .position(|p| p.id == "steam-optimal")
    {
        Some(index) => {
            if ge.config.override_profiles[index] != override_profile {
                ge.config.override_profiles[index] = override_profile;
                ge.save_config()?;
                eprintln!("[steam_launch] updated Steam override profile 'steam-optimal'");
            } else {
                eprintln!("[steam_launch] Steam override profile 'steam-optimal' unchanged");
            }
        }
        None => {
            ge.config.override_profiles.push(override_profile);
            ge.save_config()?;
            eprintln!("[steam_launch] registered Steam override profile 'steam-optimal'");
        }
    }

    Ok(())
}

/// Creates a `RunnerJob` for launching Steam through the Casa1 runner.
///
/// This constructs the complete job specification including the Steam.exe
/// path, command-line arguments, launch-specific environment variables,
/// JIT mode, Steam IPC listener, and requested window size.
pub fn create_steam_job(
    profile: &SteamLaunchProfile,
    ge: &crate::ge::GameEnvironment,
) -> AppResult<RunnerJob> {
    let steam_exe = profile.steam_exe_path(&ge.root);

    // Verify Steam.exe exists.
    if !steam_exe.exists() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!(
                "Steam.exe not found at {} — install Steam first using 'macwin ge:install'",
                steam_exe.display()
            ),
        ));
    }

    // Auto-login is not supported in this version: `-login` requires
    // interactive credentials handling that v1 does not implement.
    if profile.auto_login {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "Steam auto-login is not supported in this version",
        )
        .with_hint("log in interactively from Steam's UI instead"));
    }

    let args = build_steam_args(profile);
    let test_id = format!(
        "play-Steam-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    let jit_mode = if profile.jit_enabled {
        crate::runner::JitMode::Auto
    } else {
        crate::runner::JitMode::Disabled
    };
    let window_width = (profile.resolution_width > 0).then_some(profile.resolution_width);
    let window_height = (profile.resolution_height > 0).then_some(profile.resolution_height);

    let job = RunnerJob {
        ge_name: ge.config.name.clone(),
        ge_root: ge.root.clone(),
        program: steam_exe,
        args,
        cwd: ge.root.clone(),
        env: build_steam_job_env(profile), // launch-specific settings only; the
        // runner supplies GE/registry/trace/test-id
        dtm: false, // Never use DTM for live Steam execution
        intent: RunIntent::Play,
        trace_categories: if profile.debug_logging {
            vec![
                TraceCategory::Process,
                TraceCategory::D3d12,
                TraceCategory::Dxgi,
                TraceCategory::Shader,
                TraceCategory::Audio,
                TraceCategory::Network,
            ]
        } else {
            vec![TraceCategory::Process]
        },
        test_id: test_id.clone(),
        jit_mode,
        steam_ipc: profile.steam_ipc,
        window_width,
        window_height,
    };

    Ok(job)
}

/// Full Steam launch pipeline.
///
/// This is the main entry point for launching Steam with optimal configuration.
/// It performs the following steps:
///
/// 1. Prepares or creates the GE for Steam
/// 2. Registers the Steam override profile
/// 3. Prepares the Steam directory structure
/// 4. Creates the runner job
///
/// Returns a `SteamLaunchResult` with the launch details and the `RunnerJob`
/// ready for dispatch through the runner.
pub fn prepare_steam_launch(
    profile: &SteamLaunchProfile,
) -> AppResult<(SteamLaunchResult, RunnerJob)> {
    eprintln!("[steam_launch] ═════════════════════════════════════════════════════");
    eprintln!("[steam_launch] Casa1 Steam Launch Pipeline");
    eprintln!(
        "[steam_launch] Profile: ge={}, metal={}, audio={}, cef={}",
        profile.ge_name, profile.metal_rendering, profile.real_audio, profile.cef_bridge,
    );
    eprintln!("[steam_launch] ═════════════════════════════════════════════════════");

    // Step 1: Prepare the GE.
    let (mut ge, ge_created) = prepare_steam_ge(profile)?;

    // Step 2: Register the Steam override profile.
    register_steam_override(&mut ge, profile)?;

    // Step 3: Register the steam:// protocol handler when the profile asks
    // for it (LaunchServices, so the app bundle Info.plist / launch-time
    // registration claim the scheme).  When register_protocol is false the
    // scheme is NOT registered.
    if profile.register_protocol {
        crate::steam_integration::SteamProtocolIntegration::new_registered();
        eprintln!("[steam_launch] steam:// protocol handler registered (register_protocol=true)");
    } else {
        eprintln!(
            "[steam_launch] steam:// protocol registration skipped (register_protocol=false)"
        );
    }

    // Step 4: Prepare the Steam directory structure.
    prepare_steam_environment(&ge.root, profile)?;

    // Step 5: Create the runner job.
    let job = create_steam_job(profile, &ge)?;

    let steam_exe = profile.steam_exe_path(&ge.root);

    eprintln!("[steam_launch] ───────────────────────────────────────────────────");
    eprintln!("[steam_launch] Launch configuration:");
    eprintln!(
        "[steam_launch]   GE:        {} ({})",
        ge.config.name,
        ge.root.display()
    );
    eprintln!("[steam_launch]   Steam.exe: {}", steam_exe.display());
    eprintln!("[steam_launch]   Intent:    play");
    eprintln!("[steam_launch]   DTM:       false");
    eprintln!("[steam_launch]   JIT:       {}", profile.jit_enabled);
    eprintln!("[steam_launch]   Metal:     {}", profile.metal_rendering);
    eprintln!("[steam_launch]   Audio:     {}", profile.real_audio);
    eprintln!("[steam_launch]   CEF:       {}", profile.cef_bridge);
    eprintln!("[steam_launch] ───────────────────────────────────────────────────");

    let result = SteamLaunchResult {
        ge_name: ge.config.name.clone(),
        ge_root: ge.root.clone(),
        steam_exe,
        ge_created,
        environment_prepared: true,
        override_registered: true,
        test_id: job.test_id.clone(),
    };

    Ok((result, job))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_has_metal_rendering() {
        let profile = SteamLaunchProfile::default();
        assert!(profile.metal_rendering);
        assert!(profile.real_audio);
        assert!(profile.cef_bridge);
        assert!(profile.vulkan_opengl);
        assert!(profile.jit_enabled);
        assert!(!profile.debug_logging);
        assert!(!profile.auto_login);
        assert!(!profile.offline_mode);
    }

    #[test]
    fn performance_profile_disables_debug() {
        let profile = SteamLaunchProfile::performance();
        assert!(!profile.debug_logging);
        assert!(profile.jit_enabled);
        assert_eq!(profile.instruction_budget, 0);
    }

    #[test]
    fn debug_profile_enables_tracing() {
        let profile = SteamLaunchProfile::debug();
        assert!(profile.debug_logging);
        assert!(profile.extra_args.contains(&"-dev".to_string()));
        assert!(profile.extra_args.contains(&"-console".to_string()));
    }

    #[test]
    fn offline_profile_disables_network() {
        let profile = SteamLaunchProfile::offline();
        assert!(profile.offline_mode);
        assert!(!profile.network_enabled);
    }

    #[test]
    fn override_profile_has_dll_overrides() {
        let profile = SteamLaunchProfile::default();
        let override_profile = build_steam_override_profile(&profile);
        assert_eq!(override_profile.id, "steam-optimal");
        assert!(!override_profile.payload.dll_override.is_empty());
        // Check key DLL overrides.
        let dll_names: Vec<&str> = override_profile
            .payload
            .dll_override
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert!(dll_names.contains(&"d3d11"));
        assert!(dll_names.contains(&"dxgi"));
        assert!(dll_names.contains(&"xaudio2_7"));
        assert!(dll_names.contains(&"libcef"));
        assert!(dll_names.contains(&"vulkan-1"));
    }

    #[test]
    fn override_profile_has_metal_env_vars() {
        let profile = SteamLaunchProfile::default();
        let override_profile = build_steam_override_profile(&profile);
        assert_eq!(
            override_profile
                .payload
                .env_add
                .get("CASA1_METAL_RENDERING"),
            Some(&"1".to_string())
        );
        assert_eq!(
            override_profile
                .payload
                .env_add
                .get("CASA1_GPU_COMPAT_VENDOR"),
            Some(&"10de".to_string())
        );
    }

    #[test]
    fn override_profile_has_audio_env_vars() {
        let profile = SteamLaunchProfile::default();
        let override_profile = build_steam_override_profile(&profile);
        assert_eq!(
            override_profile.payload.env_add.get("CASA1_REAL_AUDIO"),
            Some(&"1".to_string())
        );
        assert_eq!(
            override_profile.payload.env_add.get("CASA1_XAUDIO2_REAL"),
            Some(&"1".to_string())
        );
    }

    #[test]
    fn steam_args_build_correctly() {
        let profile = SteamLaunchProfile::default();
        let args = build_steam_args(&profile);
        assert!(!args.contains(&"-overlay".to_string()));
        assert!(!args.contains(&"-login".to_string()));
        assert!(!args.contains(&"-offline".to_string()));
    }

    #[test]
    fn steam_args_offline_mode() {
        let profile = SteamLaunchProfile::offline();
        let args = build_steam_args(&profile);
        assert!(args.contains(&"-offline".to_string()));
    }

    #[test]
    fn steam_exe_path_resolves() {
        let profile = SteamLaunchProfile::default();
        let ge_root = PathBuf::from("/tmp/test_ge");
        let exe_path = profile.steam_exe_path(&ge_root);
        assert_eq!(
            exe_path,
            PathBuf::from("/tmp/test_ge/drive_c/Steam/Steam.exe")
        );
    }

    #[test]
    fn build_job_env_has_only_launch_specific_vars() {
        let profile = SteamLaunchProfile::default();
        let env = build_steam_job_env(&profile);
        assert!(env.contains_key("CASA1_METAL_RENDERING"));
        assert!(env.contains_key("CASA1_REAL_AUDIO"));
        assert!(env.contains_key("CASA1_CEF_BRIDGE"));
        // Launch-specific env must never duplicate runner-supplied settings.
        assert!(!env.contains_key("CASA1_GE_ROOT"));
        assert!(!env.contains_key("CASA1_REGISTRY_HKCU"));
        assert!(!env.contains_key("CASA1_TEST_ID"));
        assert!(!env.contains_key("CASA1_RUN_INTENT"));
        // Dead knobs: no crash-workaround and no CASA1_JIT emission.
        assert!(!env.contains_key("CASA1_STEAM_CRASH_WORKAROUND"));
        assert!(!env.contains_key("CASA1_JIT"));
    }

    #[test]
    fn override_profile_omits_dead_knob_env() {
        let profile = SteamLaunchProfile::default();
        let override_profile = build_steam_override_profile(&profile);
        assert!(
            !override_profile
                .payload
                .env_add
                .contains_key("CASA1_STEAM_CRASH_WORKAROUND")
        );
        assert!(!override_profile.payload.env_add.contains_key("CASA1_JIT"));
    }

    #[test]
    fn checked_in_ge_fixture_matches_default_override_profile() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixture_path = manifest.join("ges/steam-live-run-x86/ge.json");
        if !fixture_path.is_file() {
            return;
        }
        let contents = std::fs::read_to_string(&fixture_path).expect("read ge.json fixture");
        let config: crate::ge::GeConfig = serde_json::from_str(&contents).expect("parse ge.json");
        let fixture_override = config
            .override_profiles
            .iter()
            .find(|p| p.id == "steam-optimal")
            .expect("fixture must contain the steam-optimal override");
        let current = build_steam_override_profile(&SteamLaunchProfile::default());
        assert_eq!(
            fixture_override, &current,
            "ges/steam-live-run-x86/ge.json steam-optimal payload drifted from \
             build_steam_override_profile(SteamLaunchProfile::default()) — regenerate it"
        );
    }

    #[test]
    fn no_metal_disables_gpu_vars() {
        let profile = SteamLaunchProfile {
            metal_rendering: false,
            ..SteamLaunchProfile::default()
        };
        let override_profile = build_steam_override_profile(&profile);
        assert!(
            !override_profile
                .payload
                .env_add
                .contains_key("CASA1_METAL_RENDERING")
        );
        assert!(override_profile.payload.gfx_profile.is_none());
    }

    #[test]
    fn no_audio_disables_audio_vars() {
        let profile = SteamLaunchProfile {
            real_audio: false,
            ..SteamLaunchProfile::default()
        };
        let override_profile = build_steam_override_profile(&profile);
        assert!(
            !override_profile
                .payload
                .env_add
                .contains_key("CASA1_REAL_AUDIO")
        );
    }
}
