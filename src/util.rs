use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const DTM_NAMESPACE: Uuid = Uuid::from_bytes([
    0x43, 0x61, 0x73, 0x61, 0x31, 0x44, 0x54, 0x4d, 0x43, 0x61, 0x73, 0x61, 0x31, 0x30, 0x30, 0x31,
]);

pub fn stable_json<T: Serialize>(value: &T) -> AppResult<String> {
    serde_json::to_string_pretty(value).map_err(|error| {
        AppError::new(ReasonCode::RcIo, "failed to encode stable JSON").with_hint(error.to_string())
    })
}

pub fn current_platform_build() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

pub fn current_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

pub fn sha256_file(path: &Path) -> AppResult<String> {
    let mut file = fs::File::open(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to open {}", path.display()),
            &error,
        )
    })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    Ok(sha256_bytes(&buffer))
}

pub fn parse_env_pair(input: &str) -> AppResult<(String, String)> {
    match input.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_string(), value.to_string())),
        _ => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("invalid environment pair: {input}"),
        )
        .with_hint("expected KEY=VALUE")),
    }
}

pub fn split_command_line(input: &str) -> AppResult<Vec<String>> {
    shlex::split(input).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcCliInvalid,
            "failed to parse command line string",
        )
        .with_hint("check shell quoting in --args")
    })
}

pub fn ensure_parent(path: &Path) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", parent.display()),
                &error,
            )
        })?;
    }
    Ok(())
}

pub fn write_string(path: &Path, contents: &str) -> AppResult<()> {
    ensure_parent(path)?;
    fs::write(path, contents).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write {}", path.display()),
            &error,
        )
    })
}

pub fn deterministic_guid(label: &str, dtm: bool) -> String {
    let seed = if dtm {
        format!("dtm:{label}")
    } else {
        format!("live:{label}:{}:{}", std::process::id(), current_unix_ms())
    };
    Uuid::new_v5(&DTM_NAMESPACE, seed.as_bytes())
        .hyphenated()
        .to_string()
        .to_uppercase()
}

pub fn noncrypto_random_bytes(label: &str, dtm: bool, length: usize) -> Vec<u8> {
    if dtm {
        let mut bytes = Vec::with_capacity(length);
        let mut block = 0_u64;
        while bytes.len() < length {
            let digest = Sha256::digest(format!("dtm-rng:{label}:{block}").as_bytes());
            bytes.extend_from_slice(&digest);
            block += 1;
        }
        bytes.truncate(length);
        return bytes;
    }

    let mut bytes = vec![0; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

pub fn elapsed_offset_ms(start: SystemTime, point: Option<SystemTime>, dtm: bool) -> u64 {
    if dtm {
        return 0;
    }

    match point.and_then(|value| value.duration_since(start).ok()) {
        Some(delta) => delta.as_millis() as u64,
        None => 0,
    }
}

pub fn normalize_windows_path(ge_root: &Path, path: &Path) -> String {
    let drive_c = ge_root.join("drive_c");
    if let Ok(relative) = path.strip_prefix(&drive_c) {
        return to_windows_path("C", relative);
    }

    if let Ok(relative) = path.strip_prefix(ge_root) {
        return to_windows_path("GE", relative);
    }

    let mut pieces = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => pieces.push(value.to_string_lossy().to_lowercase()),
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => pieces.push("..".to_string()),
            Component::Prefix(prefix) => {
                pieces.push(prefix.as_os_str().to_string_lossy().to_lowercase())
            }
        }
    }
    if pieces.is_empty() {
        "Z:\\".to_string()
    } else {
        format!("Z:\\{}", pieces.join("\\"))
    }
}

pub fn sibling_binary(name: &str) -> AppResult<PathBuf> {
    let current_exe = std::env::current_exe().map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            "failed to resolve current executable",
            &error,
        )
    })?;
    let extension = executable_extension();
    let filename = format!("{name}{extension}");
    let mut candidates = Vec::new();
    if let Some(parent) = current_exe.parent() {
        candidates.push(parent.join(&filename));
        if parent.file_name() == Some(OsStr::new("deps")) {
            if let Some(grand_parent) = parent.parent() {
                candidates.push(grand_parent.join(&filename));
            }
        }
    }

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(AppError::new(
        ReasonCode::RcRunnerSpawnFailed,
        format!("unable to locate sibling binary {name}"),
    ))
}

fn executable_extension() -> &'static str {
    if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

fn to_windows_path(prefix: &str, relative: &Path) -> String {
    let mut pieces = Vec::new();
    for component in relative.components() {
        if let Component::Normal(value) = component {
            pieces.push(value.to_string_lossy().to_lowercase());
        }
    }

    if pieces.is_empty() {
        format!("{prefix}:\\")
    } else {
        format!("{prefix}:\\{}", pieces.join("\\"))
    }
}
