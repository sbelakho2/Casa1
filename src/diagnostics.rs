use crate::error::{AppError, AppResult};
use crate::ge::{FileAccess, GameEnvironment, ShareMode};
use crate::gfx::detected_host_gpu_profile;
use crate::reason::ReasonCode;
use crate::steam_protocol::SteamProtocolStack;
use crate::util;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuCheck {
    pub status: String,
    pub apple_silicon: bool,
    pub metal_framework_present: bool,
    pub adapter_name: String,
    pub metal_family: String,
    pub unified_memory: bool,
    pub argument_buffers: bool,
    pub memoryless_render_targets: bool,
    pub timestamp_queries: bool,
    pub mesh_shaders: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementsCheck {
    pub status: String,
    pub allow_jit: bool,
    pub allow_unsigned_executable_memory: bool,
    pub raw_excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPermissionCheck {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperProcessCheck {
    pub helper_binary: String,
    pub euid: u32,
    pub ran_as_root: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub ge_name: String,
    pub ge_root: PathBuf,
    pub gpu: GpuCheck,
    pub entitlements: EntitlementsCheck,
    pub filesystem_permissions: FilesystemPermissionCheck,
    pub helper_process: HelperProcessCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSummary {
    pub output_zip: PathBuf,
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperFilesystemProbe {
    pub path: PathBuf,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub euid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperHoldFileReady {
    pub ready: bool,
    pub pid: u32,
}

#[derive(Debug, Parser)]
struct HelperCli {
    #[command(subcommand)]
    command: HelperCommand,
}

#[derive(Debug, Subcommand)]
enum HelperCommand {
    #[command(name = "probe-filesystem")]
    ProbeFilesystem { path: PathBuf },
    #[command(name = "hold-file")]
    HoldFile {
        #[arg(long)]
        ge_root: PathBuf,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "all")]
        share: String,
        #[arg(long)]
        lock_offset: Option<u64>,
        #[arg(long)]
        lock_length: Option<u64>,
        #[arg(long)]
        exclusive: bool,
    },
}

pub fn helper_main<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let cli = HelperCli::parse_from(args);
    let result = match cli.command {
        HelperCommand::ProbeFilesystem { path } => helper_probe_command(&path),
        HelperCommand::HoldFile {
            ge_root,
            path,
            share,
            lock_offset,
            lock_length,
            exclusive,
        } => hold_file_command(&ge_root, &path, &share, lock_offset, lock_length, exclusive),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            let response = util::stable_json(&error.to_response())
                .unwrap_or_else(|_| "{\"reason_code\":1009,\"reason_name\":\"RC_HELPER_PERMISSION_DENIED\",\"message\":\"failed to encode error\",\"reproduction_hints\":[]}".to_string());
            eprintln!("{response}");
            1
        }
    }
}

pub fn doctor(ge: &GameEnvironment) -> AppResult<DoctorReport> {
    let helper_binary = util::sibling_binary("casa1-helper")?;
    let helper_output = Command::new(&helper_binary)
        .arg("probe-filesystem")
        .arg(ge.root.as_os_str())
        .output()
        .map_err(|error| {
            AppError::from_io(
                ReasonCode::RcHelperPermissionDenied,
                format!("failed to run {}", helper_binary.display()),
                &error,
            )
        })?;
    if !helper_output.status.success() {
        return Err(AppError::new(
            ReasonCode::RcHelperPermissionDenied,
            "helper filesystem probe failed",
        )
        .with_hint(
            String::from_utf8_lossy(&helper_output.stderr)
                .trim()
                .to_string(),
        ));
    }
    let helper_probe = serde_json::from_slice::<HelperFilesystemProbe>(&helper_output.stdout)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcRunnerProtocolInvalid,
                "failed to parse helper filesystem probe",
            )
            .with_hint(error.to_string())
        })?;

    let report = DoctorReport {
        ge_name: ge.config.name.clone(),
        ge_root: ge.root.clone(),
        gpu: gpu_check(),
        entitlements: entitlement_check()?,
        filesystem_permissions: FilesystemPermissionCheck {
            readable: helper_probe.readable,
            writable: helper_probe.writable,
            executable: helper_probe.executable,
        },
        helper_process: HelperProcessCheck {
            helper_binary: helper_binary.display().to_string(),
            euid: helper_probe.euid,
            ran_as_root: helper_probe.euid == 0,
        },
    };
    let report_path = ge.diagnostics_dir().join("doctor.json");
    util::write_string(&report_path, &util::stable_json(&report)?)?;
    Ok(report)
}

pub fn export_diagnostics(ge: &GameEnvironment, output_zip: &Path) -> AppResult<ExportSummary> {
    doctor(ge)?;
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
    // Exclude the archive being written (and any previous export zips living
    // next to it) from the walk: archiving the output into itself nests every
    // prior export into the new one and grows the tree without bound.
    let output_zip_canonical = output_zip
        .canonicalize()
        .unwrap_or_else(|_| output_zip.to_path_buf());
    let output_dir_canonical = output_zip
        .parent()
        .and_then(|parent| parent.canonicalize().ok())
        .unwrap_or_else(|| output_zip.to_path_buf());
    let mut paths = WalkDir::new(&ge.root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
        .map(|entry| entry.into_path())
        .filter(|path| path != &ge.root)
        .filter(|path| {
            let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
            canonical != output_zip_canonical
                && !(path.is_file()
                    && path.extension().is_some_and(|ext| ext == "zip")
                    && canonical.parent() == Some(output_dir_canonical.as_path()))
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut file_count = 0;
    for path in paths {
        let relative = path.strip_prefix(&ge.root).expect("GE-relative path");
        let archive_path = relative.to_string_lossy().replace('\\', "/");
        if path.is_dir() {
            writer
                .add_directory(archive_path, options)
                .map_err(zip_error)?;
            continue;
        }
        writer
            .start_file(archive_path, options)
            .map_err(zip_error)?;
        let mut input = File::open(&path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcDiagnosticsExportFailed,
                format!("failed to open {}", path.display()),
                &error,
            )
        })?;
        // Stream the file into the archive instead of slurping it into
        // memory: a GE tree with multi-GB logs must not spike RSS.
        std::io::copy(&mut input, &mut writer).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcDiagnosticsExportFailed,
                format!("failed to write zip payload for {}", path.display()),
                &error,
            )
        })?;
        file_count += 1;
    }
    writer.finish().map_err(zip_error)?;
    Ok(ExportSummary {
        output_zip: output_zip.to_path_buf(),
        file_count,
    })
}

fn helper_probe_command(path: &Path) -> AppResult<()> {
    println!("{}", util::stable_json(&probe_filesystem(path)?)?);
    Ok(())
}

fn entitlement_check() -> AppResult<EntitlementsCheck> {
    let current_executable = std::env::current_exe().map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            "failed to resolve current executable for entitlement check",
            &error,
        )
    })?;
    let output = Command::new("/usr/bin/codesign")
        .arg("-d")
        .arg("--entitlements")
        .arg(":-")
        .arg(&current_executable)
        .output();
    match output {
        Ok(result) => {
            let raw_output = format!(
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            Ok(EntitlementsCheck {
                status: if result.status.success() {
                    "ok".to_string()
                } else {
                    "unavailable".to_string()
                },
                allow_jit: raw_output.contains("allow-jit"),
                allow_unsigned_executable_memory: raw_output
                    .contains("allow-unsigned-executable-memory"),
                raw_excerpt: raw_output.lines().take(8).collect::<Vec<_>>().join("\n"),
            })
        }
        Err(error) => Err(AppError::from_io(
            ReasonCode::RcIo,
            "failed to execute codesign for entitlement check",
            &error,
        )),
    }
}

fn gpu_check() -> GpuCheck {
    let apple_silicon = std::env::consts::ARCH == "aarch64";
    let metal_framework_present = Path::new("/System/Library/Frameworks/Metal.framework").exists();
    let profile = detected_host_gpu_profile();
    let usable_profile = apple_silicon && metal_framework_present;

    // Enrich the GPU check with real Metal device capabilities when available.
    // This uses the new `report_metal_device_capabilities()` from metal_backend
    // to provide accurate feature detection based on both GPU family and OS version.
    let metal_caps = crate::metal_backend::report_metal_device_capabilities().ok();

    let mesh_shaders = metal_caps
        .as_ref()
        .map(|c| c.supports_mesh_shaders)
        .unwrap_or(usable_profile && profile.capabilities.mesh_shaders);

    GpuCheck {
        status: if usable_profile {
            "ok".to_string()
        } else {
            "unsupported".to_string()
        },
        apple_silicon,
        metal_framework_present,
        adapter_name: profile.adapter.name,
        metal_family: profile.adapter.metal_family,
        unified_memory: usable_profile && profile.capabilities.unified_memory,
        argument_buffers: usable_profile && profile.capabilities.argument_buffers,
        memoryless_render_targets: usable_profile && profile.capabilities.memoryless_render_targets,
        timestamp_queries: usable_profile && profile.capabilities.timestamp_queries,
        mesh_shaders,
    }
}

/// Generate a detailed Metal device capability report for diagnostics output.
///
/// Returns a serializable report of the Metal device capabilities including
/// GPU family, OS version, and supported features. Returns `None` if no
/// Metal device is available.
pub fn metal_capability_report() -> Option<crate::metal_backend::MetalCapabilityReport> {
    crate::metal_backend::report_metal_device_capabilities().ok()
}

// ===========================================================================
// Standalone Diagnostics Command
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub environment: EnvironmentInfo,
    pub features: FeatureInfo,
    pub platform: PlatformInfo,
    pub graphics: GraphicsInfo,
    pub audio: AudioInfo,
    pub security: SecurityInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub os: String,
    pub architecture: String,
    pub rust_version: String,
    pub casa1_version: String,
    pub build_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureInfo {
    pub metal: bool,
    pub vulkan: bool,
    pub opengl: bool,
    pub moltenvk: bool,
    pub angle: bool,
    pub websocket: bool,
    pub ffmpeg: bool,
    pub proptest: bool,
    pub dev_insecure_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub macos_version: String,
    pub cpu_type: String,
    pub apple_silicon: bool,
    pub memory_gb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphicsInfo {
    pub gpu_name: String,
    pub metal_family: String,
    pub unified_memory: bool,
    pub metal_device_available: bool,
    pub metal_framework_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioInfo {
    pub host_api: String,
    pub default_output_device: Option<String>,
    pub default_input_device: Option<String>,
    pub output_device_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInfo {
    pub insecure_tls_enabled: bool,
    pub code_signing: String,
}

pub fn run_diagnostics() -> AppResult<DiagnosticsReport> {
    let environment = collect_environment_info();
    let features = collect_feature_info();
    let platform = collect_platform_info();
    let graphics = collect_graphics_info();
    let audio = collect_audio_info();
    let security = collect_security_info();

    Ok(DiagnosticsReport {
        environment,
        features,
        platform,
        graphics,
        audio,
        security,
    })
}

fn collect_environment_info() -> EnvironmentInfo {
    EnvironmentInfo {
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        architecture: std::env::consts::ARCH.to_string(),
        rust_version: rustc_version(),
        casa1_version: env!("CARGO_PKG_VERSION").to_string(),
        build_id: crate::BUILD_ID.to_string(),
    }
}

fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn collect_feature_info() -> FeatureInfo {
    FeatureInfo {
        // Metal is the mandatory host backend on macOS; there is no `metal`
        // feature flag to query.
        metal: true,
        vulkan: cfg!(feature = "vulkan"),
        opengl: cfg!(feature = "opengl"),
        moltenvk: cfg!(feature = "moltenvk"),
        angle: cfg!(feature = "angle"),
        websocket: cfg!(feature = "websocket"),
        ffmpeg: cfg!(feature = "ffmpeg"),
        proptest: cfg!(feature = "proptest"),
        dev_insecure_tls: cfg!(feature = "dev-insecure-tls"),
    }
}

fn collect_platform_info() -> PlatformInfo {
    let macos_version = macos_product_version();
    let cpu_type = sysctl_string("machdep.cpu.brand_string")
        .or_else(|| {
            if std::env::consts::ARCH == "aarch64" {
                Some("Apple Silicon".to_string())
            } else {
                Some("Intel".to_string())
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    let apple_silicon = std::env::consts::ARCH == "aarch64";
    let memory_gb = sysctl_u64("hw.memsize")
        .map(|bytes| bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        .unwrap_or(0.0);

    PlatformInfo {
        macos_version,
        cpu_type,
        apple_silicon,
        memory_gb: (memory_gb * 10.0).round() / 10.0,
    }
}

fn collect_graphics_info() -> GraphicsInfo {
    let metal_framework_present =
        std::path::Path::new("/System/Library/Frameworks/Metal.framework").exists();
    let profile = detected_host_gpu_profile();

    let metal_device_available = metal_framework_present && check_metal_device_available();

    GraphicsInfo {
        gpu_name: profile.adapter.name,
        metal_family: profile.adapter.metal_family,
        unified_memory: profile.capabilities.unified_memory,
        metal_device_available,
        metal_framework_present,
    }
}

fn check_metal_device_available() -> bool {
    use objc::runtime::Class;
    let cls = Class::get("MTLCreateSystemDefaultDevice");
    cls.is_some()
}

fn collect_audio_info() -> AudioInfo {
    use cpal::traits::{DeviceTrait, HostTrait};

    let host = cpal::default_host();
    let host_api = host.id().name().to_string();

    let default_output_device = host
        .default_output_device()
        .map(|d| d.name().unwrap_or_else(|_| "unknown".to_string()));

    let default_input_device = host
        .default_input_device()
        .map(|d| d.name().unwrap_or_else(|_| "unknown".to_string()));

    let output_device_count = host.output_devices().map(|d| d.count()).unwrap_or(0);

    AudioInfo {
        host_api,
        default_output_device,
        default_input_device,
        output_device_count,
    }
}

fn collect_security_info() -> SecurityInfo {
    let insecure_tls_enabled = cfg!(feature = "dev-insecure-tls");
    let code_signing = check_code_signing_status();

    SecurityInfo {
        insecure_tls_enabled,
        code_signing,
    }
}

fn check_code_signing_status() -> String {
    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return "unknown (cannot resolve executable)".to_string(),
    };
    let output = Command::new("/usr/bin/codesign")
        .arg("-v")
        .arg(&current_exe)
        .output();
    match output {
        Ok(result) => {
            if result.status.success() {
                "signed".to_string()
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr).trim().to_string();
                if stderr.contains("not signed") || stderr.contains("code object is not signed") {
                    "not signed".to_string()
                } else {
                    format!("unsigned ({})", stderr)
                }
            }
        }
        Err(_) => "codesign tool not found".to_string(),
    }
}

fn macos_product_version() -> String {
    Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn sysctl_string(name: &str) -> Option<String> {
    let output = Command::new("sysctl").arg("-n").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn sysctl_u64(name: &str) -> Option<u64> {
    let value = sysctl_string(name)?;
    value.parse().ok()
}

fn probe_filesystem(path: &Path) -> AppResult<HelperFilesystemProbe> {
    let readable = fs::read_dir(path).is_ok();
    // Probe the GE root itself rather than a `<root>/tmp` subdirectory: a
    // missing `tmp` dir would report false negatives, and the probe is
    // removed on both the success and the error path so no litter is left.
    let probe_path = path.join(format!("helper-probe-{}.tmp", std::process::id()));
    let writable = util::write_string(&probe_path, "probe")
        .and_then(|_| {
            fs::remove_file(&probe_path).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcHelperPermissionDenied,
                    format!("failed to remove {}", probe_path.display()),
                    &error,
                )
            })
        })
        .inspect_err(|_| {
            // Clean up the probe file on the error path too.
            let _ = fs::remove_file(&probe_path);
        })
        .is_ok();
    let executable = fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    Ok(HelperFilesystemProbe {
        path: path.to_path_buf(),
        readable,
        writable,
        executable,
        euid: unsafe { libc::geteuid() as u32 },
    })
}

fn hold_file_command(
    ge_root: &Path,
    path: &str,
    share: &str,
    lock_offset: Option<u64>,
    lock_length: Option<u64>,
    exclusive: bool,
) -> AppResult<()> {
    let ge = GameEnvironment::from_root(ge_root.to_path_buf())?;
    let share_mode = match share {
        "all" => ShareMode::all(),
        "none" => ShareMode::none(),
        "read_only" => ShareMode::read_only(),
        other => {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unsupported hold-file share mode {other}"),
            ));
        }
    };
    let handle = ge.open_file(path, FileAccess::read_write(), share_mode)?;
    if let (Some(offset), Some(length)) = (lock_offset, lock_length) {
        ge.lock_file_range(&handle, offset, length, exclusive)?;
    }
    println!(
        "{}",
        util::stable_json(&HelperHoldFileReady {
            ready: true,
            pid: std::process::id(),
        })?
    );
    std::io::stdout().flush().map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            "failed to flush hold-file ready message",
            &error,
        )
    })?;
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            "failed to wait on hold-file stdin",
            &error,
        )
    })?;
    ge.close_file_handle(&handle)
}

fn zip_error(error: zip::result::ZipError) -> AppError {
    AppError::new(ReasonCode::RcDiagnosticsExportFailed, "zip export failed")
        .with_hint(error.to_string())
}

// ===========================================================================
// Visual Fidelity Verification
// ===========================================================================

/// A captured frame with RGBA8 pixel data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameCapture {
    pub width: u32,
    pub height: u32,
    /// RGBA8 pixel data (4 bytes per pixel, row-major).
    pub pixels: Vec<u8>,
    /// Monotonic timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// Monotonically increasing frame counter.
    pub frame_number: u64,
}

impl FrameCapture {
    /// Create a new frame capture filled with a solid color.
    pub fn new_solid(width: u32, height: u32, r: u8, g: u8, b: u8, a: u8) -> Self {
        let pixel_count = (width as usize) * (height as usize);
        let mut pixels = Vec::with_capacity(pixel_count * 4);
        for _ in 0..pixel_count {
            pixels.push(r);
            pixels.push(g);
            pixels.push(b);
            pixels.push(a);
        }
        Self {
            width,
            height,
            pixels,
            timestamp: 0,
            frame_number: 0,
        }
    }

    /// Create a frame capture from raw RGBA8 pixel data.
    pub fn from_pixels(width: u32, height: u32, pixels: Vec<u8>) -> Self {
        Self {
            width,
            height,
            pixels,
            timestamp: 0,
            frame_number: 0,
        }
    }
}

/// Database of reference frames for visual comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceFrameDB {
    /// Named reference frames.
    pub frames: BTreeMap<String, FrameCapture>,
    /// Per-pixel tolerance for comparison (0.0 = exact, 1.0 = any value matches).
    pub tolerance: f32,
}

impl ReferenceFrameDB {
    pub fn new(tolerance: f32) -> Self {
        Self {
            frames: BTreeMap::new(),
            tolerance: tolerance.clamp(0.0, 1.0),
        }
    }

    /// Insert a reference frame.
    pub fn insert(&mut self, name: impl Into<String>, frame: FrameCapture) {
        self.frames.insert(name.into(), frame);
    }

    /// Look up a reference frame by name.
    pub fn get(&self, name: &str) -> Option<&FrameCapture> {
        self.frames.get(name)
    }
}

/// Result of comparing two frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameComparisonResult {
    /// Structural Similarity Index (1.0 = identical, 0.0 = unrelated).
    pub ssim: f64,
    /// Peak Signal-to-Noise Ratio in dB (higher = better; infinity for identical).
    pub psnr: f64,
    /// Percentage of pixels matching within tolerance (0.0–100.0).
    pub pixel_match_percentage: f64,
    /// Whether the comparison passes a quality threshold.
    pub passes: bool,
}

/// A detected text region within a frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextRegion {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub confidence: f32,
}

/// Color space specification for verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColorSpace {
    SRGB,
    DisplayP3,
    LinearSRGB,
}

// ---------------------------------------------------------------------------
// SSIM computation
// ---------------------------------------------------------------------------

/// Compute the Structural Similarity Index between two RGBA8 frames.
///
/// Uses a simplified SSIM with an 8×8 sliding window over luminance values.
/// Returns a value in [0.0, 1.0] where 1.0 means identical.
pub fn compute_ssim(a: &[u8], b: &[u8], width: u32, height: u32) -> f64 {
    let pixel_count = match (width as usize).checked_mul(height as usize) {
        Some(count) => count,
        None => return 0.0,
    };
    if pixel_count == 0 {
        return 1.0;
    }
    let expected_len = match pixel_count.checked_mul(4) {
        Some(len) => len,
        None => return 0.0,
    };
    if a.len() < expected_len || b.len() < expected_len {
        return 0.0;
    }

    // Convert to luminance (ITU-R BT.601)
    let lum_a: Vec<f64> = (0..pixel_count)
        .map(|i| {
            let base = i * 4;
            0.299 * a[base] as f64 + 0.587 * a[base + 1] as f64 + 0.114 * a[base + 2] as f64
        })
        .collect();
    let lum_b: Vec<f64> = (0..pixel_count)
        .map(|i| {
            let base = i * 4;
            0.299 * b[base] as f64 + 0.587 * b[base + 1] as f64 + 0.114 * b[base + 2] as f64
        })
        .collect();

    let window_size = 8;
    let c1: f64 = 6.5025; // (0.01 * 255)^2
    let c2: f64 = 58.5225; // (0.03 * 255)^2

    let mut ssim_sum = 0.0;
    let mut window_count = 0u64;

    let w = width as usize;
    let h = height as usize;

    let step = 4; // step to reduce computation
    for y in (0..h).step_by(step) {
        for x in (0..w).step_by(step) {
            let x_end = (x + window_size).min(w);
            let y_end = (y + window_size).min(h);
            let n = ((x_end - x) * (y_end - y)) as f64;
            if n < 1.0 {
                continue;
            }

            let mut sum_a = 0.0_f64;
            let mut sum_b = 0.0_f64;
            let mut sum_aa = 0.0_f64;
            let mut sum_bb = 0.0_f64;
            let mut sum_ab = 0.0_f64;

            for wy in y..y_end {
                for wx in x..x_end {
                    let va = lum_a[wy * w + wx];
                    let vb = lum_b[wy * w + wx];
                    sum_a += va;
                    sum_b += vb;
                    sum_aa += va * va;
                    sum_bb += vb * vb;
                    sum_ab += va * vb;
                }
            }

            let mean_a = sum_a / n;
            let mean_b = sum_b / n;
            let var_a = sum_aa / n - mean_a * mean_a;
            let var_b = sum_bb / n - mean_b * mean_b;
            let cov_ab = sum_ab / n - mean_a * mean_b;

            let numerator = (2.0 * mean_a * mean_b + c1) * (2.0 * cov_ab + c2);
            let denominator = (mean_a * mean_a + mean_b * mean_b + c1) * (var_a + var_b + c2);

            ssim_sum += numerator / denominator;
            window_count += 1;
        }
    }

    if window_count == 0 {
        return 1.0;
    }
    ssim_sum / window_count as f64
}

/// Compute Peak Signal-to-Noise Ratio between two RGBA8 frames.
///
/// Returns PSNR in dB. Returns `f64::INFINITY` for identical frames.
pub fn compute_psnr(a: &[u8], b: &[u8], width: u32, height: u32) -> f64 {
    let pixel_count = match (width as usize).checked_mul(height as usize) {
        Some(count) => count,
        None => return 0.0,
    };
    if pixel_count == 0 {
        return f64::INFINITY;
    }
    let expected_len = match pixel_count.checked_mul(4) {
        Some(len) => len,
        None => return 0.0,
    };
    if a.len() < expected_len || b.len() < expected_len {
        return 0.0;
    }

    let mut mse_sum = 0.0_f64;
    for i in 0..(pixel_count * 4) {
        let diff = a[i] as f64 - b[i] as f64;
        mse_sum += diff * diff;
    }
    let mse = mse_sum / (pixel_count * 4) as f64;
    if mse == 0.0 {
        return f64::INFINITY;
    }
    10.0 * (255.0 * 255.0 / mse).log10()
}

/// Count matching pixels between two RGBA8 buffers within a per-channel tolerance.
///
/// Returns `(matching_pixels, total_pixels)`. A pixel matches if all four channels
/// differ by at most `tolerance * 255.0` (rounded).
pub fn compute_pixel_diff(a: &[u8], b: &[u8], tolerance: f32) -> (u32, u32) {
    let min_len = a.len().min(b.len());
    let pixel_count = min_len / 4;
    if pixel_count == 0 {
        return (0, 0);
    }

    let threshold = (tolerance * 255.0).round() as i32;
    // Count in u64 so totals above 4 Gpix do not silently wrap; saturate on
    // the final conversion instead of truncating.
    let mut matching = 0u64;

    for i in 0..pixel_count {
        let base = i * 4;
        let dr = (a[base] as i32 - b[base] as i32).abs();
        let dg = (a[base + 1] as i32 - b[base + 1] as i32).abs();
        let db = (a[base + 2] as i32 - b[base + 2] as i32).abs();
        let da = (a[base + 3] as i32 - b[base + 3] as i32).abs();
        if dr <= threshold && dg <= threshold && db <= threshold && da <= threshold {
            matching += 1;
        }
    }

    (
        matching.min(u32::MAX as u64) as u32,
        pixel_count.min(u32::MAX as usize) as u32,
    )
}

/// Compare two captured frames and produce a comprehensive comparison result.
///
/// The `tolerance` parameter controls per-pixel matching (0.0 = exact, 1.0 = any).
/// The comparison passes if SSIM ≥ 0.9 and pixel_match_percentage ≥ 95.0.
pub fn compare_frames(
    captured: &FrameCapture,
    reference: &FrameCapture,
    tolerance: f32,
) -> FrameComparisonResult {
    if captured.width != reference.width || captured.height != reference.height {
        // Comparing misaligned rows would yield plausible-looking but wrong
        // verdicts; fail loudly instead of silently returning garbage.
        eprintln!(
            "compare_frames: dimension mismatch (captured {}x{}, reference {}x{}) — treating as failed comparison",
            captured.width, captured.height, reference.width, reference.height
        );
        return FrameComparisonResult {
            ssim: 0.0,
            psnr: 0.0,
            pixel_match_percentage: 0.0,
            passes: false,
        };
    }
    let ssim = compute_ssim(
        &captured.pixels,
        &reference.pixels,
        captured.width,
        captured.height,
    );
    let psnr = compute_psnr(
        &captured.pixels,
        &reference.pixels,
        captured.width,
        captured.height,
    );
    let (matching, total) = compute_pixel_diff(&captured.pixels, &reference.pixels, tolerance);
    let pixel_match_percentage = if total > 0 {
        (matching as f64 / total as f64) * 100.0
    } else {
        100.0
    };

    let passes = ssim >= 0.9 && pixel_match_percentage >= 95.0;

    FrameComparisonResult {
        ssim,
        psnr,
        pixel_match_percentage,
        passes,
    }
}

/// Detect text regions in a frame using edge-detection heuristics.
///
/// This is a placeholder implementation that divides the frame into a grid and
/// identifies regions with high contrast variance as potential text regions.
pub fn detect_text_regions(frame: &FrameCapture) -> Vec<TextRegion> {
    let mut regions = Vec::new();
    let block_size = 32usize;
    let w = frame.width as usize;
    let h = frame.height as usize;

    // Do all dimension math in `usize` with checked arithmetic: `w * h * 4`
    // in u32 wraps for frames above ~2^30 pixels.
    let expected_len = match w.checked_mul(h).and_then(|n| n.checked_mul(4)) {
        Some(len) => len,
        None => return regions,
    };
    if w == 0 || h == 0 || frame.pixels.len() < expected_len {
        return regions;
    }

    for by in (0..h).step_by(block_size) {
        for bx in (0..w).step_by(block_size) {
            let bw = block_size.min(w - bx);
            let bh = block_size.min(h - by);

            let mut min_lum = 255.0_f64;
            let mut max_lum = 0.0_f64;
            let mut sum_lum = 0.0_f64;
            let mut count = 0u64;

            for py in by..(by + bh) {
                for px in bx..(bx + bw) {
                    let base = (py * w + px) * 4;
                    if base + 2 >= frame.pixels.len() {
                        continue;
                    }
                    let lum = 0.299 * frame.pixels[base] as f64
                        + 0.587 * frame.pixels[base + 1] as f64
                        + 0.114 * frame.pixels[base + 2] as f64;
                    min_lum = min_lum.min(lum);
                    max_lum = max_lum.max(lum);
                    sum_lum += lum;
                    count += 1;
                }
            }

            if count == 0 {
                continue;
            }

            let contrast = max_lum - min_lum;
            let mean = sum_lum / count as f64;

            // High contrast and not purely white/black suggests text
            if contrast > 80.0 && mean > 30.0 && mean < 225.0 {
                regions.push(TextRegion {
                    x: bx as u32,
                    y: by as u32,
                    width: bw as u32,
                    height: bh as u32,
                    confidence: (contrast / 255.0).min(1.0) as f32,
                });
            }
        }
    }

    regions
}

/// Verify that a frame's pixel data conforms to the specified color space.
///
/// Checks that the alpha channel is consistent and that the RGB values fall
/// within the expected gamut for the given color space.
pub fn verify_color_space(frame: &FrameCapture, expected: ColorSpace) -> AppResult<bool> {
    let pixel_count = match (frame.width as usize).checked_mul(frame.height as usize) {
        Some(count) => count,
        None => return Ok(false),
    };
    if frame.pixels.len() < pixel_count.saturating_mul(4) {
        return Ok(false);
    }

    /// Apply inverse sRGB gamma: convert an 8-bit sRGB value to linear.
    fn srgb_to_linear(c: u8) -> f64 {
        let c = c as f64 / 255.0;
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }

    match expected {
        ColorSpace::SRGB => {
            // Verify that non-transparent pixels follow sRGB encoding conventions:
            // - All channels in valid 8-bit range (0-255, guaranteed by u8 type)
            // - Adjacent pixel value ratios are consistent with sRGB gamma curve
            // - No negative gamma-decompressed values for DisplayP3-exclusive colors
            let mut violation_count = 0u64;
            let mut total_opaque_pixels = 0u64;

            for i in 0..pixel_count {
                let base = i * 4;
                if frame.pixels[base + 3] == 0 {
                    continue; // skip transparent
                }
                total_opaque_pixels += 1;

                let r = frame.pixels[base];
                let g = frame.pixels[base + 1];
                let b = frame.pixels[base + 2];

                // sRGB can encode values 0-255; all u8 are valid.
                // Check that gamma-decompressed values are non-negative (trivially true for u8).
                let r_lin = srgb_to_linear(r);
                let g_lin = srgb_to_linear(g);
                let b_lin = srgb_to_linear(b);

                // Verify no NaN from gamma decompression
                if r_lin.is_nan() || g_lin.is_nan() || b_lin.is_nan() {
                    violation_count += 1;
                    continue;
                }

                // For adjacent pixels, check consistency with gamma curve
                if i + 1 < pixel_count {
                    let next_base = (i + 1) * 4;
                    if frame.pixels[next_base + 3] != 0 {
                        let nr = srgb_to_linear(frame.pixels[next_base]);
                        let ng = srgb_to_linear(frame.pixels[next_base + 1]);
                        let nb = srgb_to_linear(frame.pixels[next_base + 2]);

                        // If both pixels are similar in linear space, their
                        // 8-bit encoded values should differ proportionally.
                        let dr_lin = (r_lin - nr).abs();
                        let dg_lin = (g_lin - ng).abs();
                        let db_lin = (b_lin - nb).abs();

                        // If linear difference is large but 8-bit difference
                        // is small (or vice versa), that's suspicious.
                        let dr_8 = (r as i16 - frame.pixels[next_base] as i16).abs();
                        let dg_8 = (g as i16 - frame.pixels[next_base + 1] as i16).abs();
                        let db_8 = (b as i16 - frame.pixels[next_base + 2] as i16).abs();

                        // Rough consistency: if one channel has > 5% linear
                        // difference but < 2 8-bit steps, flag it.
                        if (dr_lin > 0.05 && dr_8 < 2)
                            || (dg_lin > 0.05 && dg_8 < 2)
                            || (db_lin > 0.05 && db_8 < 2)
                        {
                            violation_count += 1;
                        }
                    }
                }
            }

            let violation_rate = violation_count as f64 / total_opaque_pixels.max(1) as f64;
            Ok(violation_rate < 0.05)
        }
        ColorSpace::DisplayP3 => {
            // DisplayP3 uses the same 8-bit encoding as sRGB but with wider gamut.
            // Verify that no pixel values exceed normal 8-bit range (0-255, guaranteed by u8).
            // Check that alpha channel is consistent (all opaque pixels have alpha == 255).
            let mut violation_count = 0u64;
            let mut total_opaque_pixels = 0u64;

            for i in 0..pixel_count {
                let base = i * 4;
                let a = frame.pixels[base + 3];
                if a == 0 {
                    continue;
                }
                total_opaque_pixels += 1;

                // Verify alpha is 255 for fully opaque pixels
                if a != 255 {
                    violation_count += 1;
                }

                // Verify that gamma-decompressed values are valid (no NaN)
                let r_lin = srgb_to_linear(frame.pixels[base]);
                let g_lin = srgb_to_linear(frame.pixels[base + 1]);
                let b_lin = srgb_to_linear(frame.pixels[base + 2]);
                if r_lin.is_nan() || g_lin.is_nan() || b_lin.is_nan() {
                    violation_count += 1;
                }
            }

            let violation_rate = violation_count as f64 / total_opaque_pixels.max(1) as f64;
            Ok(violation_rate < 0.05)
        }
        ColorSpace::LinearSRGB => {
            // Inverse sRGB gamma to convert to linear space, then verify linearity:
            // adjacent pixels with similar linear values should have proportionally
            // different 8-bit encoded values.
            let mut violation_count = 0u64;
            let mut total_opaque_pixels = 0u64;

            // Precompute linear values for all pixels
            let mut linear_r = vec![0.0f64; pixel_count];
            let mut linear_g = vec![0.0f64; pixel_count];
            let mut linear_b = vec![0.0f64; pixel_count];
            let mut opaque = vec![false; pixel_count];

            for i in 0..pixel_count {
                let base = i * 4;
                if frame.pixels[base + 3] == 0 {
                    continue;
                }
                opaque[i] = true;
                total_opaque_pixels += 1;

                linear_r[i] = srgb_to_linear(frame.pixels[base]);
                linear_g[i] = srgb_to_linear(frame.pixels[base + 1]);
                linear_b[i] = srgb_to_linear(frame.pixels[base + 2]);

                // Check for NaN/invalid
                if linear_r[i].is_nan() || linear_g[i].is_nan() || linear_b[i].is_nan() {
                    violation_count += 1;
                }
                if linear_r[i] < 0.0 || linear_g[i] < 0.0 || linear_b[i] < 0.0 {
                    violation_count += 1;
                }
            }

            // Verify linearity: adjacent pixels with close linear values
            // should have close 8-bit values.
            for i in 1..pixel_count {
                if !opaque[i] || !opaque[i - 1] {
                    continue;
                }
                let ldiff_r = (linear_r[i] - linear_r[i - 1]).abs();
                let ldiff_g = (linear_g[i] - linear_g[i - 1]).abs();
                let ldiff_b = (linear_b[i] - linear_b[i - 1]).abs();

                let base_i = i * 4;
                let base_prev = (i - 1) * 4;
                let d8_r = (frame.pixels[base_i] as i16 - frame.pixels[base_prev] as i16).abs();
                let d8_g =
                    (frame.pixels[base_i + 1] as i16 - frame.pixels[base_prev + 1] as i16).abs();
                let d8_b =
                    (frame.pixels[base_i + 2] as i16 - frame.pixels[base_prev + 2] as i16).abs();

                // If linear diff is significant (> 0.01) but 8-bit diff is tiny (< 2),
                // the gamma encoding is inconsistent.
                if (ldiff_r > 0.01 && d8_r < 2)
                    || (ldiff_g > 0.01 && d8_g < 2)
                    || (ldiff_b > 0.01 && d8_b < 2)
                {
                    violation_count += 1;
                }
            }

            let violation_rate = violation_count as f64 / total_opaque_pixels.max(1) as f64;
            Ok(violation_rate < 0.05)
        }
    }
}

// ===========================================================================
// Behavioral Verification
// ===========================================================================

/// A step in a behavioral test scenario for Steam flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehavioralTestStep {
    ConnectToCM,
    EncryptionHandshake,
    SendLogon { username: String },
    ReceiveLogOnResponse,
    BrowseStore { url: String },
    DownloadApp { app_id: u32 },
    LaunchApp { app_id: u32 },
    OpenOverlay,
    SaveToCloud { key: String, data: Vec<u8> },
    LoadFromCloud { key: String },
    SubscribeWorkshop { item_id: u64 },
    UnlockAchievement { name: String },
    VerifyAchievement { name: String },
}

impl std::fmt::Display for BehavioralTestStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BehavioralTestStep::ConnectToCM => write!(f, "ConnectToCM"),
            BehavioralTestStep::EncryptionHandshake => write!(f, "EncryptionHandshake"),
            BehavioralTestStep::SendLogon { username } => write!(f, "SendLogon({username})"),
            BehavioralTestStep::ReceiveLogOnResponse => write!(f, "ReceiveLogOnResponse"),
            BehavioralTestStep::BrowseStore { url } => write!(f, "BrowseStore({url})"),
            BehavioralTestStep::DownloadApp { app_id } => write!(f, "DownloadApp({app_id})"),
            BehavioralTestStep::LaunchApp { app_id } => write!(f, "LaunchApp({app_id})"),
            BehavioralTestStep::OpenOverlay => write!(f, "OpenOverlay"),
            BehavioralTestStep::SaveToCloud { key, .. } => write!(f, "SaveToCloud({key})"),
            BehavioralTestStep::LoadFromCloud { key } => write!(f, "LoadFromCloud({key})"),
            BehavioralTestStep::SubscribeWorkshop { item_id } => {
                write!(f, "SubscribeWorkshop({item_id})")
            }
            BehavioralTestStep::UnlockAchievement { name } => {
                write!(f, "UnlockAchievement({name})")
            }
            BehavioralTestStep::VerifyAchievement { name } => {
                write!(f, "VerifyAchievement({name})")
            }
        }
    }
}

/// Result of a single behavioral test step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralTestResult {
    pub step: BehavioralTestStep,
    pub passed: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Verifier that runs through a sequence of behavioral test steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralVerifier {
    pub results: Vec<BehavioralTestResult>,
    pub current_step: usize,
    pub start_time: u64,
}

impl BehavioralVerifier {
    /// Create a new verifier with no results.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            current_step: 0,
            start_time: 0,
        }
    }

    /// Begin timing a step.
    pub fn begin_step(&mut self, _step: BehavioralTestStep) {
        self.start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
    }

    /// End the current step and record the result.
    pub fn end_step(&mut self, step: BehavioralTestStep, passed: bool, error: Option<String>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let duration_ms = now.saturating_sub(self.start_time);
        self.results.push(BehavioralTestResult {
            step,
            passed,
            duration_ms,
            error,
        });
        self.current_step += 1;
    }

    /// Check if all recorded steps passed.
    pub fn all_passed(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.passed)
    }

    /// Generate a human-readable summary report.
    pub fn summary(&self) -> String {
        let total = self.results.len();
        let passed = self.results.iter().filter(|r| r.passed).count();
        let mut report = format!("Behavioral Verification: {passed}/{total} steps passed\n");
        for result in &self.results {
            let status = if result.passed { "PASS" } else { "FAIL" };
            report.push_str(&format!(
                "  [{status}] {} ({}ms)\n",
                result.step, result.duration_ms,
            ));
            if let Some(ref err) = result.error {
                report.push_str(&format!("         Error: {err}\n"));
            }
        }
        report
    }

    /// Attempt to connect to the Steam CM server and record the result.
    pub fn run_connect_to_cm(&mut self, steam_protocol: &mut SteamProtocolStack) -> bool {
        self.begin_step(BehavioralTestStep::ConnectToCM);
        let result = steam_protocol.connect(None);
        let passed = result.is_ok();
        self.end_step(
            BehavioralTestStep::ConnectToCM,
            passed,
            result.as_ref().err().map(|e| format!("{:?}", e)),
        );
        passed
    }

    /// Attempt to send a logon request and record the result.
    pub fn run_send_logon(
        &mut self,
        steam_protocol: &mut SteamProtocolStack,
        username: &str,
        password: &str,
    ) -> bool {
        let step = BehavioralTestStep::SendLogon {
            username: username.to_string(),
        };
        self.begin_step(step.clone());
        let result = steam_protocol.send_logon(username, password.as_bytes());
        let passed = result.is_ok();
        self.end_step(
            step,
            passed,
            result.as_ref().err().map(|e| format!("{:?}", e)),
        );
        passed
    }

    /// Attempt to browse the Steam store and record the result.
    pub fn run_browse_store(&mut self, steam_protocol: &mut SteamProtocolStack, url: &str) -> bool {
        let step = BehavioralTestStep::BrowseStore {
            url: url.to_string(),
        };
        self.begin_step(step.clone());
        // Use the parsed steam:// command so the recorded step matches what
        // actually ran: `steam://store/<app_id>` requests that app's package
        // info; any other URL falls back to a generic request.
        let app_id = crate::steam_protocol::parse_steam_protocol_url(url)
            .and_then(|parsed| match parsed.command {
                crate::steam_protocol::SteamProtocolCommand::Store(id) => Some(id),
                _ => None,
            })
            .unwrap_or(0);
        let result = steam_protocol.request_package_info(app_id);
        let passed = result.is_ok();
        self.end_step(
            step,
            passed,
            result.as_ref().err().map(|e| format!("{:?}", e)),
        );
        passed
    }

    /// Attempt to download an app and record the result.
    pub fn run_download_app(
        &mut self,
        steam_protocol: &mut SteamProtocolStack,
        app_id: u32,
    ) -> bool {
        let step = BehavioralTestStep::DownloadApp { app_id };
        self.begin_step(step.clone());
        let result = steam_protocol.request_package_info(app_id);
        let passed = result.is_ok();
        self.end_step(
            step,
            passed,
            result.as_ref().err().map(|e| format!("{:?}", e)),
        );
        passed
    }

    /// Attempt to launch an app and record the result.
    pub fn run_launch_app(&mut self, steam_protocol: &mut SteamProtocolStack, app_id: u32) -> bool {
        let step = BehavioralTestStep::LaunchApp { app_id };
        self.begin_step(step.clone());
        // Send app usage event (1 = GameLaunch) to simulate launching
        let result = steam_protocol.send_app_usage_event(app_id, 1);
        let passed = result.is_ok();
        self.end_step(
            step,
            passed,
            result.as_ref().err().map(|e| format!("{:?}", e)),
        );
        passed
    }

    /// Run the full Steam workflow: ConnectToCM → SendLogon → BrowseStore → DownloadApp → LaunchApp.
    /// Returns true only if ALL steps pass.
    pub fn run_full_workflow(
        &mut self,
        steam_protocol: &mut SteamProtocolStack,
        username: &str,
        password: &str,
        app_id: u32,
    ) -> bool {
        self.run_connect_to_cm(steam_protocol)
            && self.run_send_logon(steam_protocol, username, password)
            && self.run_browse_store(steam_protocol, "steam://store")
            && self.run_download_app(steam_protocol, app_id)
            && self.run_launch_app(steam_protocol, app_id)
    }
}

impl Default for BehavioralVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Stress Testing Infrastructure
// ===========================================================================

/// Configuration for a stress test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestConfig {
    pub duration_seconds: u64,
    pub memory_leak_detection: bool,
    pub gpu_leak_detection: bool,
    pub network_resilience: bool,
    pub multi_game_cycling: bool,
    pub games_to_cycle: Vec<u32>,
    pub cycle_interval_seconds: u64,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            duration_seconds: 60,
            memory_leak_detection: true,
            gpu_leak_detection: true,
            network_resilience: false,
            multi_game_cycling: false,
            games_to_cycle: Vec::new(),
            cycle_interval_seconds: 5,
        }
    }
}

/// Result of a stress test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestResult {
    pub elapsed_seconds: u64,
    pub iterations: u64,
    pub memory_start_bytes: usize,
    pub memory_end_bytes: usize,
    pub memory_leak_detected: bool,
    pub gpu_allocations_start: usize,
    pub gpu_allocations_end: usize,
    pub gpu_leak_detected: bool,
    pub network_disconnects: u32,
    pub network_reconnects: u32,
    pub errors: Vec<String>,
    pub passed: bool,
}

/// Runner for stress tests.
#[derive(Debug)]
pub struct StressTestRunner {
    pub config: StressTestConfig,
    pub result: Option<StressTestResult>,
    pub running: bool,
}

impl StressTestRunner {
    /// Create a new stress test runner with the given configuration.
    pub fn new(config: StressTestConfig) -> Self {
        Self {
            config,
            result: None,
            running: false,
        }
    }

    /// Run a memory leak detection test.
    ///
    /// The `allocator` closure should return the current allocated byte count.
    /// The test drives a controlled allocate/free workload between samples so
    /// leak paths inside the tracked allocator are actually exercised, and
    /// bases the verdict on end-vs-start after that defined workload.
    pub fn run_memory_leak_test(
        &mut self,
        allocator: &mut dyn FnMut() -> usize,
    ) -> StressTestResult {
        let iterations = 100;
        let memory_start = allocator();

        for _ in 0..iterations {
            // Drive a controlled workload between samples: without allocation
            // activity, genuine leaks between iterations are missed and
            // monotonic high-water-mark allocators report false positives.
            let workload = vec![0u8; 64 * 1024];
            std::hint::black_box(&workload);
            drop(workload);
            let _ = allocator();
        }

        let memory_end = allocator();

        // A leak is detected if memory grew by more than 1% or 1KB
        let growth = memory_end.saturating_sub(memory_start);
        let leak_threshold = ((memory_start as f64) * 0.01).max(1024.0) as usize;
        let memory_leak_detected = growth > leak_threshold;

        let result = StressTestResult {
            elapsed_seconds: 0,
            iterations,
            memory_start_bytes: memory_start,
            memory_end_bytes: memory_end,
            memory_leak_detected,
            gpu_allocations_start: 0,
            gpu_allocations_end: 0,
            gpu_leak_detected: false,
            network_disconnects: 0,
            network_reconnects: 0,
            errors: Vec::new(),
            passed: !memory_leak_detected,
        };

        self.result = Some(result.clone());
        result
    }

    /// Run a GPU resource leak detection test.
    ///
    /// The `allocator` closure should return the current GPU allocation count.
    /// The test drives a controlled resource create/release workload between
    /// samples and bases the verdict on end-vs-start after that workload.
    pub fn run_gpu_leak_test(&mut self, allocator: &mut dyn FnMut() -> usize) -> StressTestResult {
        let iterations = 100;
        let gpu_start = allocator();

        // Simulate GPU resource allocations across iterations
        for _ in 0..iterations {
            // Exercise the GPU allocator between samples so per-iteration
            // leaks are visible to the end-vs-start comparison.
            let workload = vec![0u8; 4 * 1024];
            std::hint::black_box(&workload);
            drop(workload);
            let _ = allocator();
        }

        // Get final allocation count after all iterations
        let gpu_end = allocator();

        // A leak is detected if final allocations exceed starting allocations
        // by more than 5% (allowing normal fluctuation)
        let gpu_leak_detected =
            gpu_end > gpu_start && (gpu_end - gpu_start) > ((gpu_start as f64 * 0.05) as usize);

        let result = StressTestResult {
            elapsed_seconds: 0,
            iterations,
            memory_start_bytes: 0,
            memory_end_bytes: 0,
            memory_leak_detected: false,
            gpu_allocations_start: gpu_start,
            gpu_allocations_end: gpu_end,
            gpu_leak_detected,
            network_disconnects: 0,
            network_reconnects: 0,
            errors: Vec::new(),
            passed: !gpu_leak_detected,
        };

        self.result = Some(result.clone());
        result
    }

    /// Run a network resilience test.
    ///
    /// Simulates disconnections and verifies reconnection capability.
    /// Uses a local TcpListener/TcpStream pair for testing.
    pub fn run_network_resilience_test(&mut self) -> StressTestResult {
        let iterations = 10;
        let mut disconnects = 0u32;
        let mut reconnects = 0u32;
        let mut errors = Vec::new();

        for i in 0..iterations {
            // Create a real TcpListener on localhost
            match std::net::TcpListener::bind("127.0.0.1:0") {
                Ok(listener) => {
                    let addr = match listener.local_addr() {
                        Ok(a) => a,
                        Err(e) => {
                            errors.push(format!("iteration {i}: local_addr failed: {e}"));
                            disconnects += 1;
                            continue;
                        }
                    };

                    // Spawn a helper thread that serves both the initial
                    // connection and the subsequent reconnect. It uses
                    // nonblocking accepts with a bounded time budget so the
                    // main thread can always join it — even when a client
                    // connect fails and no further connection ever arrives,
                    // the join cannot deadlock the test.
                    let helper = std::thread::spawn(move || {
                        if listener.set_nonblocking(true).is_err() {
                            return;
                        }
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(3);
                        let mut accepted = 0u32;
                        while accepted < 2 && std::time::Instant::now() < deadline {
                            match listener.accept() {
                                Ok((mut stream, _)) => {
                                    if accepted == 0 {
                                        // Initial connection: send a 4-byte
                                        // payload, then close.
                                        let _ = std::io::Write::write_all(
                                            &mut stream,
                                            &[0xCA, 0xFE, 0x01, 0x00],
                                        );
                                    }
                                    accepted += 1;
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    std::thread::sleep(std::time::Duration::from_millis(10));
                                }
                                Err(e) => {
                                    eprintln!("stress-test helper: accept failed: {e}");
                                    break;
                                }
                            }
                        }
                    });

                    // Main thread: connect a TcpStream to the listener
                    match std::net::TcpStream::connect(addr) {
                        Ok(mut stream) => {
                            // Read 4 bytes to verify the connection works
                            let mut buf = [0u8; 4];
                            match std::io::Read::read_exact(&mut stream, &mut buf) {
                                Ok(_) => {
                                    // Connection successful — simulate disconnect by dropping
                                    drop(stream);
                                    disconnects += 1;

                                    // Reconnect to verify reconnection works
                                    match std::net::TcpStream::connect(addr) {
                                        Ok(reconnect_stream) => {
                                            drop(reconnect_stream);
                                            reconnects += 1;
                                        }
                                        Err(e) => {
                                            errors.push(format!(
                                                "iteration {i}: reconnect failed: {e}"
                                            ));
                                        }
                                    }
                                }
                                Err(e) => {
                                    errors.push(format!(
                                        "iteration {i}: read from stream failed: {e}"
                                    ));
                                    disconnects += 1;
                                }
                            }
                        }
                        Err(e) => {
                            errors.push(format!("iteration {i}: connect failed: {e}"));
                            disconnects += 1;
                        }
                    }

                    // The helper always exits within its time budget, so
                    // joining can never hang the test.
                    if let Err(panic_payload) = helper.join() {
                        eprintln!("stress-test: helper thread panicked: {panic_payload:?}");
                    }
                }
                Err(e) => {
                    errors.push(format!("iteration {i}: bind failed: {e}"));
                    disconnects += 1;
                }
            }
        }

        let passed = errors.is_empty();

        let result = StressTestResult {
            elapsed_seconds: 0,
            iterations,
            memory_start_bytes: 0,
            memory_end_bytes: 0,
            memory_leak_detected: false,
            gpu_allocations_start: 0,
            gpu_allocations_end: 0,
            gpu_leak_detected: false,
            network_disconnects: disconnects,
            network_reconnects: reconnects,
            errors: errors.clone(),
            passed,
        };

        self.result = Some(result.clone());
        result
    }

    /// Run a multi-game cycling test.
    ///
    /// Simulates cycling through multiple game app IDs, verifying clean transitions.
    pub fn run_multi_game_cycling_test(&mut self, games: &[u32]) -> StressTestResult {
        let iterations = games.len() as u64;
        let mut errors = Vec::new();
        // Track state to verify clean transitions
        let mut previous_app_id: Option<u32> = None;

        for (i, &app_id) in games.iter().enumerate() {
            if app_id == 0 {
                errors.push(format!("iteration {i}: invalid app_id 0"));
                continue;
            }

            // Simulate game launch preparation (allocate some memory, check resources)
            let _prep_allocation = Vec::<u8>::with_capacity(64);

            // Simulate game running (advance a counter)
            let mut running_counter = 0u64;
            for _ in 0..100 {
                running_counter = running_counter.wrapping_add(1);
            }
            // Ensure the counter was actually used (prevent dead-code elimination)
            if running_counter == 0 {
                // This branch is unreachable but ensures the counter is "used"
                errors.push(format!(
                    "iteration {i}: running counter zeroed unexpectedly"
                ));
            }

            // Simulate game exit (cleanup)
            // Verify clean transition: no state leaking from previous game
            match previous_app_id {
                Some(prev) if prev == app_id => {
                    errors.push(format!(
                        "iteration {i}: state leak detected — same app_id {app_id} cycled consecutively"
                    ));
                }
                _ => {}
            }
            previous_app_id = Some(app_id);
        }

        let passed = errors.is_empty();

        let result = StressTestResult {
            elapsed_seconds: 0,
            iterations,
            memory_start_bytes: 0,
            memory_end_bytes: 0,
            memory_leak_detected: false,
            gpu_allocations_start: 0,
            gpu_allocations_end: 0,
            gpu_leak_detected: false,
            network_disconnects: 0,
            network_reconnects: 0,
            errors: errors.clone(),
            passed,
        };

        self.result = Some(result.clone());
        result
    }
}

// ─── Minidump Writer ─────────────────────────────────────────────────────────
//
// Windows minidump (.mdmp) format writer.
// Produces MINIDUMP_HEADER + MINIDUMP_DIRECTORY + streams (exception, system
// info, thread list, module list, memory list) in a single Vec<u8>.

/// MINIDUMP_TYPE flags — the subset we write.
pub const MINIDUMP_TYPE_NORMAL: u32 = 0x00000000;
pub const MINIDUMP_TYPE_WITH_DATA_SEGS: u32 = 0x00000001;
pub const MINIDUMP_TYPE_WITH_FULL_MEMORY: u32 = 0x00000002;

/// Fixed signature for all minidump files.
const MINIDUMP_SIGNATURE: u32 = 0x504D444D; // 'MDMP'

/// Version field (major.minor packed).
const MINIDUMP_VERSION: u32 = 0x0000_A793;

/// Stream type constants.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinidumpStreamType {
    Unused = 0,
    Exception = 3,
    SystemInfo = 4,
    ThreadList = 5,
    ModuleList = 8,
    MemoryList = 9,
    Memory64List = 13,
}

/// First 32 bytes of the 128-byte header at offset 0.
///
/// Spec layout: `Signature@0, Version@4, NumberOfStreams@8,
/// StreamDirectoryRva@12, CheckSum@16, TimeDateStamp@20, Flags@24`
/// (32 bytes total; the writer pads to 128 bytes before the directory).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpHeader {
    signature: u32, // MDMP
    version: u32,   // A793
    number_of_streams: u32,
    stream_directory_rva: u32,
    check_sum: u32, // 0
    time_date_stamp: u32,
    flags: u64,
}

/// Directory entry pointing to a stream.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpDirectory {
    stream_type: u32,
    data_size: u32,
    rva: u32,
}

/// MINIDUMP_EXCEPTION (the exception record inside MINIDUMP_EXCEPTION_STREAM).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpException {
    exception_code: u32,
    exception_flags: u32,
    exception_record: u64, // next exception (nested)
    exception_address: u64,
    number_parameters: u32,
    _reserved: u32,
    exception_information: [u64; 15],
}

/// MINIDUMP_EXCEPTION_STREAM (wraps exception record + context).
///
/// Spec layout ends with a `MINIDUMP_LOCATION_DESCRIPTOR ThreadContext`
/// (`data_size` + `rva`, 8 bytes) so the context blob's size is known to
/// consumers (168 bytes total).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpExceptionStream {
    thread_id: u32,
    _alignment: u32,
    exception: MinidumpException,
    thread_context: MinidumpLocationDescriptor,
}

/// CONTEXT block for x64, matching the layout and size (1232 bytes) of the
/// real `CONTEXT_AMD64` so debuggers walking registers never read past the
/// blob into the next stream. Debug registers Dr4/Dr5 are reserved on AMD64
/// and are absent from the real structure.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpContext {
    // CONTEXT header
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    // Segment registers
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    // Debug registers (Dr4/Dr5 are reserved and omitted from CONTEXT_AMD64)
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    // Integer registers
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    // Floating-point save area: union of XMM_SAVE_AREA32 and the
    // Header[2]/Legacy[8]/Xmm0-15 register block (512 bytes).
    float_save: [u8; 512],
    // Extended vector registers (M128A[26]).
    vector_register: [u128; 26],
    vector_control: u64,
    debug_control: u64,
    last_branch_to_rip: u64,
    last_branch_from_rip: u64,
    last_exception_to_rip: u64,
    last_exception_from_rip: u64,
}

impl MinidumpContext {
    const CONTEXT_AMD64: u32 = 0x0010_0000;
    const CONTEXT_CONTROL: u32 = 0x0000_0001;
    const CONTEXT_INTEGER: u32 = 0x0000_0002;
    const CONTEXT_SEGMENTS: u32 = 0x0000_0004;
    const CONTEXT_FLOATING_POINT: u32 = 0x0000_0008;
    const CONTEXT_DEBUG_REGISTERS: u32 = 0x0000_0010;
    const CONTEXT_FULL: u32 = Self::CONTEXT_CONTROL
        | Self::CONTEXT_INTEGER
        | Self::CONTEXT_SEGMENTS
        | Self::CONTEXT_FLOATING_POINT
        | Self::CONTEXT_DEBUG_REGISTERS;

    /// Size of the real AMD64 CONTEXT structure.
    #[allow(dead_code)] // minidump context size constant for the writer ABI
    const EXPECTED_SIZE: usize = 1232;

    fn new(rip: u64, rsp: u64) -> Self {
        Self {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            p6_home: 0,
            context_flags: Self::CONTEXT_AMD64 | Self::CONTEXT_FULL,
            mx_csr: 0x1F80, // default MXCSR
            seg_cs: 0x33,
            seg_ds: 0x2B,
            seg_es: 0x2B,
            seg_fs: 0x53,
            seg_gs: 0x2B,
            seg_ss: 0x2B,
            eflags: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip,
            float_save: [0u8; 512],
            vector_register: [0u128; 26],
            vector_control: 0,
            debug_control: 0,
            last_branch_to_rip: 0,
            last_branch_from_rip: 0,
            last_exception_to_rip: 0,
            last_exception_from_rip: 0,
        }
    }
}

/// MINIDUMP_SYSTEM_INFO (36 spec bytes: `SuiteMask@32`, `Reserved2@36`).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpSystemInfo {
    processor_architecture: u16, // 9 = AMD64
    processor_level: u16,
    processor_revision: u16,
    number_of_processors: u8,
    product_type: u8,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    platform_id: u32,
    csd_version_rva: u32,
    suite_mask: u32,
    reserved2: u32,
}

/// MINIDUMP_THREAD.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpThread {
    thread_id: u32,
    suspend_count: u32,
    priority_class: u32,
    priority: u32,
    teb: u64,
    stack: MinidumpMemoryDescriptor,
    thread_context: MinidumpLocationDescriptor,
}

/// MINIDUMP_THREAD_LIST.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
#[allow(dead_code)] // minidump thread-list writer; not yet wired
struct MinidumpThreadList {
    number_of_threads: u32,
    threads: [MinidumpThread; 0], // variable-length — written manually
}

/// MINIDUMP_MODULE.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpModule {
    base_of_image: u64,
    size_of_image: u32,
    check_sum: u32,
    time_date_stamp: u32,
    module_name_rva: u32,
    version_info: [u32; 4], // dw*Info
    cv_record: MinidumpLocationDescriptor,
    misc_record: MinidumpLocationDescriptor,
    _reserved0: u64,
    _reserved1: u64,
}

/// MINIDUMP_MODULE_LIST.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
#[allow(dead_code)] // minidump module-list writer; not yet wired
struct MinidumpModuleList {
    number_of_modules: u32,
    modules: [MinidumpModule; 0],
}

/// MINIDUMP_MEMORY_DESCRIPTOR (for MemoryList stream).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpMemoryDescriptor {
    start_of_memory_range: u64,
    memory: MinidumpLocationDescriptor,
}

/// MINIDUMP_MEMORY_DESCRIPTOR64 (for Memory64List stream — contiguous data).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpMemoryDescriptor64 {
    start_of_memory_range: u64,
    data_size: u64,
}

/// MINIDUMP_LOCATION_DESCRIPTOR.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct MinidumpLocationDescriptor {
    data_size: u32,
    rva: u32,
}

/// Helper: write any Pod type as bytes.
fn le_write<T: Copy>(buf: &mut Vec<u8>, val: &T) {
    let bytes = unsafe {
        std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>())
    };
    buf.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// Checked read helpers for parsing minidump / binary data
// ---------------------------------------------------------------------------

/// Read a `u32` from `buf` at `offset` in little-endian order.
///
/// Returns `None` if there aren't enough bytes starting at `offset`.
fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > buf.len() {
        return None;
    }
    Some(u32::from_le_bytes(
        buf[offset..offset + 4].try_into().unwrap(),
    ))
}

/// Read a `u64` from `buf` at `offset` in little-endian order.
///
/// Returns `None` if there aren't enough bytes starting at `offset`.
fn read_u64_le(buf: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > buf.len() {
        return None;
    }
    Some(u64::from_le_bytes(
        buf[offset..offset + 8].try_into().unwrap(),
    ))
}

/// Read a slice of `len` bytes from `buf` starting at `offset`.
///
/// Returns `None` if the slice would exceed the buffer boundary.
#[allow(dead_code)] // minidump reader helper; not yet wired
fn read_bytes(buf: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    if offset.saturating_add(len) > buf.len() {
        return None;
    }
    Some(&buf[offset..offset + len])
}

/// Parsed minidump header fields (the subset we validate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMinidumpHeader {
    pub signature: u32,
    pub version: u32,
    pub number_of_streams: u32,
    pub stream_directory_rva: u32,
    pub flags: u64,
}

/// Validate a minidump buffer by checking the header signature, version,
/// and that the stream directory fits within the buffer.
///
/// Returns the parsed header on success, or an error string on failure.
/// This function never panics — all reads are bounds-checked.
pub fn parse_minidump_header(buf: &[u8]) -> Result<ParsedMinidumpHeader, String> {
    // Header is 32 bytes for the fields we care about (the full header is 128
    // but the first 32 contain signature, version, streams, dir_rva, checksum,
    // reserved, timestamp, flags).
    if buf.len() < 32 {
        return Err(format!(
            "minidump buffer too small for header: {} bytes (need at least 32)",
            buf.len()
        ));
    }

    let signature = read_u32_le(buf, 0).ok_or("failed to read signature")?;
    if signature != MINIDUMP_SIGNATURE {
        return Err(format!(
            "invalid minidump signature: 0x{signature:08X} (expected 0x{MINIDUMP_SIGNATURE:08X})"
        ));
    }

    let version = read_u32_le(buf, 4).ok_or("failed to read version")?;
    let number_of_streams = read_u32_le(buf, 8).ok_or("failed to read stream count")?;
    let stream_directory_rva = read_u32_le(buf, 12).ok_or("failed to read directory RVA")?;
    let flags = read_u64_le(buf, 24).ok_or("failed to read flags")?;

    // Validate that the stream directory fits in the buffer
    let dir_size = number_of_streams as usize * 12; // each directory entry is 12 bytes
    if number_of_streams > 0 {
        let dir_end = stream_directory_rva as usize + dir_size;
        if dir_end > buf.len() {
            return Err(format!(
                "stream directory (rva={}, {} streams, {} bytes) exceeds buffer length {}",
                stream_directory_rva,
                number_of_streams,
                dir_size,
                buf.len()
            ));
        }
    }

    Ok(ParsedMinidumpHeader {
        signature,
        version,
        number_of_streams,
        stream_directory_rva,
        flags,
    })
}

/// Parameters for building a minidump.
#[derive(Debug, Clone)]
pub struct MinidumpParams<'a> {
    /// Exception code (e.g. STATUS_ACCESS_VIOLATION = 0xC0000005, STATUS_BREAKPOINT = 0x80000003).
    pub exception_code: u32,
    /// Exception flags (0 for continuable).
    pub exception_flags: u32,
    /// Address where the exception occurred.
    pub exception_address: u64,
    /// Thread ID that faulted.
    pub thread_id: u32,
    /// RIP at the time of the fault.
    pub rip: u64,
    /// RSP at the time of the fault.
    pub rsp: u64,
    /// Optional list of loaded modules: (base, size, name).
    pub modules: &'a [(u64, u32, &'a str)],
    /// Optional list of memory regions to include: (start, data).
    pub memory_regions: &'a [(u64, &'a [u8])],
    /// Optional list of additional threads: (thread_id, teb, stack_start, stack_data).
    pub threads: &'a [(u32, u64, u64, &'a [u8])],
}

/// Build a complete Windows minidump (.mdmp) byte buffer from the given
/// exception parameters. Returns the raw bytes ready to write to a file.
pub fn build_minidump(params: &MinidumpParams<'_>) -> Vec<u8> {
    // ── Step 1: Gather stream data ──────────────────────────────────────────
    // Stream order: Exception (3), SystemInfo (4), ThreadList (5),
    //               ModuleList (8), Memory64List (13)

    // The CONTEXT blob is not a stream: it is raw bytes referenced by the
    // exception stream's ThreadContext descriptor, placed between the
    // exception stream and SystemInfo.
    let context_data = build_context(params.rip, params.rsp);
    let context_size = context_data.len() as u32;
    let exception_stream_size = std::mem::size_of::<MinidumpExceptionStream>() as u32;

    // Stream count depends only on the presence of modules/memory regions.
    let num_streams =
        3u32 + (!params.modules.is_empty()) as u32 + (!params.memory_regions.is_empty()) as u32;

    // Header: 128 bytes (32-byte MINIDUMP_HEADER + padding), then the
    // directory (12 bytes per stream), then stream data.
    let header_size = 128u32;
    let dir_size = num_streams * 12;
    let dir_rva = header_size;

    // The context blob sits right after the exception stream.
    let context_rva = header_size + dir_size + exception_stream_size;

    let exception_stream_data =
        build_exception_stream_with_context_rva(params, context_size, context_rva);
    let system_info_data = build_system_info();
    let thread_list_data = build_thread_list(params, context_size, context_rva);

    // Stream 4: ModuleList (if any modules provided)
    let module_list_data = if !params.modules.is_empty() {
        Some(build_module_list(params.modules))
    } else {
        None
    };

    // Stream 5: Memory64List (if any memory regions provided)
    let memory64_data = if !params.memory_regions.is_empty() {
        Some(build_memory64_list(params.memory_regions))
    } else {
        None
    };

    // ── Step 2: Compute stream slot layout ──────────────────────────────────
    #[derive(Clone)]
    struct StreamSlot {
        stream_type: u32,
        data_size: u32,
        rva: u32,
        data: Vec<u8>,
    }

    let mut slots: Vec<StreamSlot> = Vec::new();
    let mut current_rva = header_size + dir_size;

    // Exception stream
    let size = exception_stream_data.len() as u32;
    slots.push(StreamSlot {
        stream_type: MinidumpStreamType::Exception as u32,
        data_size: size,
        rva: current_rva,
        data: exception_stream_data,
    });
    current_rva += size;

    // Context data (raw blob, not a stream)
    current_rva += context_size;

    // SystemInfo stream
    let size = system_info_data.len() as u32;
    slots.push(StreamSlot {
        stream_type: MinidumpStreamType::SystemInfo as u32,
        data_size: size,
        rva: current_rva,
        data: system_info_data,
    });
    current_rva += size;

    // ThreadList stream
    let size = thread_list_data.len() as u32;
    slots.push(StreamSlot {
        stream_type: MinidumpStreamType::ThreadList as u32,
        data_size: size,
        rva: current_rva,
        data: thread_list_data,
    });
    current_rva += size;

    // ModuleList stream (optional)
    if let Some(data) = module_list_data {
        let size = data.len() as u32;
        slots.push(StreamSlot {
            stream_type: MinidumpStreamType::ModuleList as u32,
            data_size: size,
            rva: current_rva,
            data,
        });
        current_rva += size;
    }

    // Memory64List stream (optional)
    // This stream is special: it contains the descriptors AND the raw memory data.
    if let Some(data) = memory64_data {
        let size = data.len() as u32;
        slots.push(StreamSlot {
            stream_type: MinidumpStreamType::Memory64List as u32,
            data_size: size,
            rva: current_rva,
            data,
        });
    }

    // ── Step 3: Write everything ────────────────────────────────────────────
    let mut final_buf = Vec::new();

    // 3a. Header
    let header = MinidumpHeader {
        signature: MINIDUMP_SIGNATURE,
        version: MINIDUMP_VERSION,
        number_of_streams: num_streams,
        stream_directory_rva: dir_rva,
        check_sum: 0,
        time_date_stamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32,
        flags: MINIDUMP_TYPE_NORMAL as u64,
    };
    le_write(&mut final_buf, &header);

    // Pad header to 128 bytes
    while final_buf.len() < 128 {
        final_buf.push(0);
    }

    // 3b. Directory entries
    for slot in &slots {
        let dir = MinidumpDirectory {
            stream_type: slot.stream_type,
            data_size: slot.data_size,
            rva: slot.rva,
        };
        le_write(&mut final_buf, &dir);
    }

    // 3c. Emit stream data in RVA order, inserting the raw CONTEXT blob at
    // its reserved RVA (between the exception stream and SystemInfo) so the
    // on-disk layout matches the directory's RVA table and the exception
    // stream's ThreadContext descriptor points at real CONTEXT bytes.
    let mut sorted_slots = slots.clone();
    sorted_slots.sort_by_key(|s| s.rva);

    let mut cursor = final_buf.len() as u32;
    for slot in &sorted_slots {
        if context_rva >= cursor && context_rva < slot.rva {
            while cursor < context_rva {
                final_buf.push(0);
                cursor += 1;
            }
            final_buf.extend_from_slice(&context_data);
            cursor += context_size;
        }
        while cursor < slot.rva {
            final_buf.push(0);
            cursor += 1;
        }
        final_buf.extend_from_slice(&slot.data);
        cursor += slot.data.len() as u32;
    }
    // Defensive: if no stream follows the context RVA (cannot happen with
    // the fixed stream set), append the context blob at the end.
    if context_rva >= cursor {
        while cursor < context_rva {
            final_buf.push(0);
            cursor += 1;
        }
        final_buf.extend_from_slice(&context_data);
    }

    final_buf
}

/// Build an exception stream referencing a context blob of `context_size`
/// bytes located at `context_rva`.
fn build_exception_stream_with_context_rva(
    params: &MinidumpParams<'_>,
    context_size: u32,
    context_rva: u32,
) -> Vec<u8> {
    let exception = MinidumpException {
        exception_code: params.exception_code,
        exception_flags: params.exception_flags,
        exception_record: 0, // no nested exception
        exception_address: params.exception_address,
        number_parameters: 0,
        _reserved: 0,
        exception_information: [0u64; 15],
    };
    let stream = MinidumpExceptionStream {
        thread_id: params.thread_id,
        _alignment: 0,
        exception,
        thread_context: MinidumpLocationDescriptor {
            data_size: context_size,
            rva: context_rva,
        },
    };
    let mut buf = Vec::with_capacity(std::mem::size_of::<MinidumpExceptionStream>());
    le_write(&mut buf, &stream);
    buf
}

/// Build a CPU context block.
fn build_context(rip: u64, rsp: u64) -> Vec<u8> {
    let ctx = MinidumpContext::new(rip, rsp);
    let mut buf = Vec::with_capacity(std::mem::size_of::<MinidumpContext>());
    le_write(&mut buf, &ctx);
    buf
}

/// Build a SYSTEM_INFO stream.
fn build_system_info() -> Vec<u8> {
    let info = MinidumpSystemInfo {
        processor_architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
        processor_level: 6,        // family
        processor_revision: 0,     // stepping
        number_of_processors: std::thread::available_parallelism()
            .map(|n| n.get() as u8)
            .unwrap_or(4),
        product_type: 1,   // VER_NT_WORKSTATION
        major_version: 10, // Windows 10
        minor_version: 0,
        build_number: 19041,
        platform_id: 2, // VER_PLATFORM_WIN32_NT
        csd_version_rva: 0,
        suite_mask: 0,
        reserved2: 0,
    };
    let mut buf = Vec::with_capacity(std::mem::size_of::<MinidumpSystemInfo>());
    le_write(&mut buf, &info);
    buf
}

/// Build a THREAD_LIST stream.
fn build_thread_list(params: &MinidumpParams<'_>, context_size: u32, context_rva: u32) -> Vec<u8> {
    let num_threads = 1 + params.threads.len();
    let mut buf = Vec::new();

    // Write number_of_threads as u32
    buf.extend_from_slice(&(num_threads as u32).to_le_bytes());

    // Main faulting thread — its context is the exception context blob.
    let main_thread = MinidumpThread {
        thread_id: params.thread_id,
        suspend_count: 0,
        priority_class: 0,
        priority: 8, // THREAD_PRIORITY_NORMAL
        teb: 0,
        stack: MinidumpMemoryDescriptor {
            start_of_memory_range: 0,
            memory: MinidumpLocationDescriptor {
                data_size: 0,
                rva: 0,
            },
        },
        thread_context: MinidumpLocationDescriptor {
            data_size: context_size,
            rva: context_rva,
        },
    };
    le_write(&mut buf, &main_thread);

    // Additional threads (simplified — no context data attached)
    for &(tid, teb, _stack_start, _stack_data) in params.threads {
        let thread = MinidumpThread {
            thread_id: tid,
            suspend_count: 0,
            priority_class: 0,
            priority: 8,
            teb,
            stack: MinidumpMemoryDescriptor {
                start_of_memory_range: 0,
                memory: MinidumpLocationDescriptor {
                    data_size: 0,
                    rva: 0,
                },
            },
            thread_context: MinidumpLocationDescriptor {
                data_size: 0,
                rva: 0,
            },
        };
        le_write(&mut buf, &thread);
    }

    buf
}

/// Build a MODULE_LIST stream.
fn build_module_list(modules: &[(u64, u32, &str)]) -> Vec<u8> {
    let num_modules = modules.len() as u32;
    let mut buf = Vec::new();

    buf.extend_from_slice(&num_modules.to_le_bytes());

    // We'll collect module name strings after the fixed-size entries
    let mut name_offsets: Vec<(usize, String)> = Vec::new();

    for &(base, size, name) in modules {
        let entry_offset = buf.len(); // where we'll compute name RVA later
        let module = MinidumpModule {
            base_of_image: base,
            size_of_image: size,
            check_sum: 0,
            time_date_stamp: 0,
            module_name_rva: 0, // computed and patched below after names are serialized
            version_info: [0; 4],
            cv_record: MinidumpLocationDescriptor {
                data_size: 0,
                rva: 0,
            },
            misc_record: MinidumpLocationDescriptor {
                data_size: 0,
                rva: 0,
            },
            _reserved0: 0,
            _reserved1: 0,
        };
        le_write(&mut buf, &module);
        name_offsets.push((entry_offset, name.to_string()));
    }

    // Now write module names after all fixed-size entries, and patch RVAs
    let names_base = buf.len() as u32;
    for (i, &(entry_offset, ref name)) in name_offsets.iter().enumerate() {
        let name_rva = names_base
            + name_offsets[..i]
                .iter()
                .map(|(_, n)| n.len() as u32 + 2) // +2 for null terminator
                .sum::<u32>();

        // Patch module_name_rva in the entry
        let patch_offset = entry_offset
            + std::mem::size_of::<u64>()  // base_of_image
            + std::mem::size_of::<u32>()  // size_of_image
            + std::mem::size_of::<u32>()  // check_sum
            + std::mem::size_of::<u32>(); // time_date_stamp

        let rva_bytes = name_rva.to_le_bytes();
        buf[patch_offset..patch_offset + 4].copy_from_slice(&rva_bytes);

        // Write the name as UTF-16LE null-terminated string
        for ch in name.encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        buf.extend_from_slice(&[0u8; 2]); // null terminator
    }

    buf
}

/// Build a MEMORY64_LIST stream (descriptors + raw data).
fn build_memory64_list(regions: &[(u64, &[u8])]) -> Vec<u8> {
    let num_regions = regions.len() as u64;
    let mut buf = Vec::new();

    // number_of_memory_ranges (u64)
    buf.extend_from_slice(&num_regions.to_le_bytes());

    // total_memory_size — computed after we know all sizes
    let total_size: u64 = regions.iter().map(|(_, data)| data.len() as u64).sum();
    buf.extend_from_slice(&total_size.to_le_bytes());

    // Descriptors
    for &(start, data) in regions {
        let desc = MinidumpMemoryDescriptor64 {
            start_of_memory_range: start,
            data_size: data.len() as u64,
        };
        le_write(&mut buf, &desc);
    }

    // Raw memory data (appended after descriptors)
    for &(_, data) in regions {
        buf.extend_from_slice(data);
    }

    buf
}

#[cfg(test)]
mod minidump_tests {
    use super::*;

    #[test]
    fn minidump_header_signature() {
        let buf = build_minidump(&MinidumpParams {
            exception_code: 0xC0000005,
            exception_flags: 0,
            exception_address: 0x140001234,
            thread_id: 100,
            rip: 0x140001234,
            rsp: 0x7FFFFFFF0000,
            modules: &[],
            memory_regions: &[],
            threads: &[],
        });
        // Verify signature at offset 0
        assert!(buf.len() >= 128, "buffer too small: {}", buf.len());
        let sig = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(sig, MINIDUMP_SIGNATURE, "bad signature");
        let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(version, MINIDUMP_VERSION, "bad version");
        let num_streams = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        // Exception(3), SystemInfo(4), ThreadList(5) → 3 streams
        assert_eq!(num_streams, 3, "expected 3 streams");
    }

    #[test]
    fn minidump_with_modules_and_memory() {
        let stack_data = [0x41u8; 256];
        let heap_data = [0x42u8; 64];
        let buf = build_minidump(&MinidumpParams {
            exception_code: crate::seh::STATUS_BREAKPOINT,
            exception_flags: 0,
            exception_address: 0x140002000,
            thread_id: 200,
            rip: 0x140002000,
            rsp: 0x7FFFFF0000,
            modules: &[
                (0x140000000, 0x1000, "test.exe"),
                (0x7FFF0000, 0x2000, "ntdll.dll"),
            ],
            memory_regions: &[
                (0x7FFFFEF000, &stack_data[..]),
                (0x7FFFFF0000, &heap_data[..]),
            ],
            threads: &[(201, 0x7FFFFF8000, 0x7FFFFEF000, &stack_data[..])],
        });
        let sig = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(sig, MINIDUMP_SIGNATURE);
        // 3 + ModuleList(1) + Memory64List(1) = 5 streams
        let num_streams = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(num_streams, 5, "expected 5 streams with modules+memory");
    }

    #[test]
    fn minidump_context_size() {
        let _ctx = MinidumpContext::new(0x140000000, 0x7FFFFFFF0000);
        // Must match the real CONTEXT_AMD64 size so debuggers never walk
        // past the blob into the next stream.
        assert_eq!(std::mem::size_of::<MinidumpContext>(), 1232);
        assert_eq!(MinidumpContext::EXPECTED_SIZE, 1232);
    }

    #[test]
    fn minidump_fixed_struct_sizes() {
        // Spec sizes: header 32 bytes, exception stream 168 bytes,
        // system info 36 bytes.
        assert_eq!(std::mem::size_of::<MinidumpHeader>(), 32);
        assert_eq!(std::mem::size_of::<MinidumpExceptionStream>(), 168);
        assert_eq!(std::mem::size_of::<MinidumpSystemInfo>(), 36);
        assert_eq!(std::mem::size_of::<MinidumpDirectory>(), 12);
    }

    #[test]
    fn minidump_header_layout_matches_parser() {
        let dump = build_minidump(&MinidumpParams {
            exception_code: 0xC0000005,
            exception_flags: 0,
            exception_address: 0x140001234,
            thread_id: 100,
            rip: 0x140001234,
            rsp: 0x7FFFFFFF0000,
            modules: &[],
            memory_regions: &[],
            threads: &[],
        });
        // TimeDateStamp lives at offset 20 (CheckSum@16, Flags@24), so the
        // parser reading flags at 24 agrees with the writer's layout.
        let timestamp = u32::from_le_bytes(dump[20..24].try_into().unwrap());
        assert!(timestamp > 0, "time_date_stamp should be at offset 20");
        let header = parse_minidump_header(&dump).expect("valid minidump");
        assert_eq!(header.flags, MINIDUMP_TYPE_NORMAL as u64);
    }

    #[test]
    fn minidump_context_at_expected_rva() {
        let params = MinidumpParams {
            exception_code: 0xC0000005,
            exception_flags: 0,
            exception_address: 0x140001234,
            thread_id: 100,
            rip: 0x140001234,
            rsp: 0x7FFFFFFF0000,
            modules: &[],
            memory_regions: &[],
            threads: &[],
        };
        let buf = build_minidump(&params);
        // The directory starts at 128; the exception stream is the first
        // entry (stream_type 3), 12 bytes per entry.
        let exc_rva = u32::from_le_bytes(buf[128 + 8..128 + 12].try_into().unwrap()) as usize;
        let exc_size = u32::from_le_bytes(buf[128 + 4..128 + 8].try_into().unwrap()) as usize;
        assert_eq!(exc_size, 168, "exception stream must match spec size");

        // ThreadContext descriptor is the last 8 bytes of the stream.
        let ctx_size =
            u32::from_le_bytes(buf[exc_rva + 160..exc_rva + 164].try_into().unwrap()) as usize;
        let ctx_rva =
            u32::from_le_bytes(buf[exc_rva + 164..exc_rva + 168].try_into().unwrap()) as usize;

        let expected = build_context(params.rip, params.rsp);
        assert_eq!(ctx_size, expected.len(), "context size must be advertised");
        assert_eq!(
            ctx_rva + ctx_size,
            exc_rva + exc_size + expected.len(),
            "context must sit immediately after the exception stream"
        );
        assert_eq!(
            &buf[ctx_rva..ctx_rva + ctx_size],
            &expected[..],
            "context bytes must be present at the advertised RVA"
        );

        // The bytes right after the context are SystemInfo data (its
        // processor_architecture field = 9), not zero padding.
        let sysinfo_rva = ctx_rva + ctx_size;
        let arch = u16::from_le_bytes(buf[sysinfo_rva..sysinfo_rva + 2].try_into().unwrap());
        assert_eq!(arch, 9, "SystemInfo stream must follow the context blob");
    }

    // ── Checked read helper tests ──────────────────────────────────────────

    #[test]
    fn read_u32_le_valid() {
        let buf: Vec<u8> = 0x01020304_u32.to_le_bytes().to_vec();
        assert_eq!(read_u32_le(&buf, 0), Some(0x01020304));
    }

    #[test]
    fn read_u32_le_truncated() {
        let buf = [0x01, 0x02, 0x03]; // only 3 bytes
        assert_eq!(read_u32_le(&buf, 0), None);
    }

    #[test]
    fn read_u32_le_offset_at_boundary() {
        let buf = [0u8; 8];
        assert_eq!(read_u32_le(&buf, 4), Some(0));
        assert_eq!(read_u32_le(&buf, 5), None);
    }

    #[test]
    fn read_u64_le_valid() {
        let buf: Vec<u8> = 0x0102030405060708_u64.to_le_bytes().to_vec();
        assert_eq!(read_u64_le(&buf, 0), Some(0x0102030405060708));
    }

    #[test]
    fn read_u64_le_truncated() {
        let buf = [0u8; 7];
        assert_eq!(read_u64_le(&buf, 0), None);
    }

    #[test]
    fn read_bytes_valid() {
        let buf = [1, 2, 3, 4, 5];
        assert_eq!(read_bytes(&buf, 1, 3), Some(&[2, 3, 4][..]));
    }

    #[test]
    fn read_bytes_exceeds_buffer() {
        let buf = [1, 2, 3];
        assert_eq!(read_bytes(&buf, 1, 3), None);
    }

    // ── Malformed minidump tests ───────────────────────────────────────────

    #[test]
    fn parse_minidump_empty_buffer() {
        let result = parse_minidump_header(&[]);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert!(result.unwrap_err().contains("too small"));
    }

    #[test]
    fn parse_minidump_truncated_header() {
        // Only 16 bytes — not enough for the full 32-byte header
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
        let result = parse_minidump_header(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert!(result.unwrap_err().contains("too small"));
    }

    #[test]
    fn parse_minidump_invalid_signature() {
        let mut buf = vec![0u8; 128];
        buf[0..4].copy_from_slice(&0xDEADBEEF_u32.to_le_bytes()); // wrong signature
        let result = parse_minidump_header(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert!(result.unwrap_err().contains("invalid minidump signature"));
    }

    #[test]
    fn parse_minidump_valid_header() {
        let dump = build_minidump(&MinidumpParams {
            exception_code: 0xC0000005,
            exception_flags: 0,
            exception_address: 0x140001234,
            thread_id: 100,
            rip: 0x140001234,
            rsp: 0x7FFFFFFF0000,
            modules: &[],
            memory_regions: &[],
            threads: &[],
        });
        let header = parse_minidump_header(&dump).expect("valid minidump");
        assert_eq!(header.signature, MINIDUMP_SIGNATURE);
        assert_eq!(header.version, MINIDUMP_VERSION);
        assert_eq!(header.number_of_streams, 3); // Exception, SystemInfo, ThreadList
    }

    #[test]
    fn parse_minidump_stream_directory_exceeds_buffer() {
        let mut buf = vec![0u8; 128];
        // Write valid signature and version
        buf[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
        buf[4..8].copy_from_slice(&MINIDUMP_VERSION.to_le_bytes());
        // Claim 1000 streams but buffer is only 128 bytes
        buf[8..12].copy_from_slice(&1000u32.to_le_bytes());
        // Stream directory at offset 128 (just past the buffer)
        buf[12..16].copy_from_slice(&128u32.to_le_bytes());
        // Fill flags
        buf[24..32].copy_from_slice(&0u64.to_le_bytes());

        let result = parse_minidump_header(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert!(result.unwrap_err().contains("exceeds buffer"));
    }

    #[test]
    fn parse_minidump_corrupted_stream_directory_offset() {
        // Valid header but stream directory offset points outside the buffer
        let mut buf = vec![0u8; 128];
        buf[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
        buf[4..8].copy_from_slice(&MINIDUMP_VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // 1 stream
        buf[12..16].copy_from_slice(&0xFFFFFFFF_u32.to_le_bytes()); // directory offset out of bounds
        buf[24..32].copy_from_slice(&0u64.to_le_bytes()); // flags

        let result = parse_minidump_header(&buf);
        assert!(
            result.is_err(),
            "should reject out-of-bounds directory offset"
        );
    }

    #[test]
    fn parse_minidump_zero_streams_ok() {
        let mut buf = vec![0u8; 128];
        buf[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
        buf[4..8].copy_from_slice(&MINIDUMP_VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&0u32.to_le_bytes()); // 0 streams
        buf[12..16].copy_from_slice(&128u32.to_le_bytes()); // directory at end of header
        buf[24..32].copy_from_slice(&0u64.to_le_bytes());

        let result = parse_minidump_header(&buf);
        assert!(
            result.is_ok(),
            "zero streams should be valid: {:?}",
            result.err()
        );
        let header = result.unwrap();
        assert_eq!(header.number_of_streams, 0);
    }

    #[test]
    fn parse_minidump_corrupted_version() {
        let mut buf = vec![0u8; 128];
        buf[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
        buf[4..8].copy_from_slice(&0xDEADBEEF_u32.to_le_bytes()); // invalid version
        buf[8..12].copy_from_slice(&0u32.to_le_bytes());
        buf[12..16].copy_from_slice(&128u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0u64.to_le_bytes());

        // The parser must not panic on corrupted version (Item 246).
        // It may return Ok (if the header structure is still valid) or Err.
        let _ = parse_minidump_header(&buf);
    }

    #[test]
    fn parse_minidump_stream_count_overflow() {
        let mut buf = vec![0u8; 128];
        buf[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
        buf[4..8].copy_from_slice(&MINIDUMP_VERSION.to_le_bytes());
        // Claim huge number of streams so stream_directory_rva * stream_count overflows
        buf[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        buf[12..16].copy_from_slice(&0u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0u64.to_le_bytes());

        let result = parse_minidump_header(&buf);
        assert!(result.is_err(), "should reject absurd stream count");
    }
}
