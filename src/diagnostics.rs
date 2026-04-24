use crate::error::{AppError, AppResult};
use crate::ge::{FileAccess, GameEnvironment, ShareMode};
use crate::gfx::detected_host_gpu_profile;
use crate::reason::ReasonCode;
use crate::util;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
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
        .with_hint(String::from_utf8_lossy(&helper_output.stderr).trim().to_string()));
    }
    let helper_probe = serde_json::from_slice::<HelperFilesystemProbe>(&helper_output.stdout).map_err(|error| {
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
    let _ = doctor(ge)?;
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
    let mut paths = WalkDir::new(&ge.root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
        .map(|entry| entry.into_path())
        .filter(|path| path != &ge.root)
        .collect::<Vec<_>>();
    paths.sort();
    let mut file_count = 0;
    for path in paths {
        let relative = path.strip_prefix(&ge.root).expect("GE-relative path");
        let archive_path = relative.to_string_lossy().replace('\\', "/");
        if path.is_dir() {
            writer.add_directory(archive_path, options).map_err(zip_error)?;
            continue;
        }
        writer.start_file(archive_path, options).map_err(zip_error)?;
        let mut input = File::open(&path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcDiagnosticsExportFailed,
                format!("failed to open {}", path.display()),
                &error,
            )
        })?;
        let mut buffer = Vec::new();
        input.read_to_end(&mut buffer).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcDiagnosticsExportFailed,
                format!("failed to read {}", path.display()),
                &error,
            )
        })?;
        writer.write_all(&buffer).map_err(|error| {
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
        mesh_shaders: usable_profile && profile.capabilities.mesh_shaders,
    }
}

fn probe_filesystem(path: &Path) -> AppResult<HelperFilesystemProbe> {
    let readable = fs::read_dir(path).is_ok();
    let probe_path = path.join("tmp").join(format!("helper-probe-{}.tmp", std::process::id()));
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
            ))
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
        AppError::from_io(ReasonCode::RcIo, "failed to wait on hold-file stdin", &error)
    })?;
    ge.close_file_handle(&handle)
}

fn zip_error(error: zip::result::ZipError) -> AppError {
    AppError::new(ReasonCode::RcDiagnosticsExportFailed, "zip export failed")
        .with_hint(error.to_string())
}