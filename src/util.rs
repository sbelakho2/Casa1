use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    Ok(hex_lower(&hasher.finalize()))
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

// Nonces for temp-sibling names; lives next to its only consumer so the
// import block above stays free of static initializers.
static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically replace `path` with `contents`.
///
/// The bytes are written to a temporary file in the SAME directory (so the
/// final rename is atomic on the target filesystem), flushed with `sync_all`,
/// and then renamed over the destination. A concurrent reader therefore sees
/// either the complete old contents or the complete new contents — never a
/// partial or truncated file. On any failure the temp file is removed and the
/// destination is left untouched.
pub fn write_string(path: &Path, contents: &str) -> AppResult<()> {
    write_string_atomic(path, |file| file.write_all(contents.as_bytes()))
}

fn write_string_atomic<F>(path: &Path, write: F) -> AppResult<()>
where
    F: FnOnce(&mut fs::File) -> std::io::Result<()>,
{
    ensure_parent(path)?;
    let temp = temp_sibling(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create temp file for {}", path.display()),
                &error,
            )
        })?;

    let write_result = write(&mut file).and_then(|_| file.sync_all());
    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write {}", path.display()),
            &error,
        ));
    }
    drop(file);

    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to replace {}", path.display()),
            &error,
        ));
    }

    // Persist the directory entry as well; best-effort because some
    // filesystems do not support directory fsync.
    #[cfg(unix)]
    if let Some(parent) = path.parent()
        && let Ok(directory) = fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }

    Ok(())
}

fn temp_sibling(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new("file"))
        .to_string_lossy();
    let nonce = ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".{name}.{}.{}.{}.tmp",
        std::process::id(),
        current_unix_ms(),
        nonce
    ))
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
        if parent.file_name() == Some(OsStr::new("deps"))
            && let Some(grand_parent) = parent.parent()
        {
            candidates.push(grand_parent.join(&filename));
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
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        value.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    fn temp_files(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .expect("read temp dir")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().ends_with(".tmp"))
                    .unwrap_or(false)
            })
            .collect()
    }

    #[test]
    fn partial_write_failure_preserves_the_previous_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        write_string(&path, "old").expect("seed");

        let result = write_string_atomic(&path, |file| {
            file.write_all(b"partial")?;
            Err(std::io::Error::other("injected write failure"))
        });
        let error = result.expect_err("partial write must fail");
        assert_eq!(error.code, ReasonCode::RcIo);
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            "old",
            "the destination must be untouched after a failed write"
        );
        assert!(
            temp_files(dir.path()).is_empty(),
            "failed write must clean up its temp file"
        );
    }

    #[test]
    fn rename_failure_cleans_the_temp_file_and_leaves_the_target_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("destination-is-a-directory");
        fs::create_dir(&path).expect("directory target");

        let error = write_string(&path, "cannot replace a directory")
            .expect_err("rename over a directory must fail");
        assert_eq!(error.code, ReasonCode::RcIo);
        assert_eq!(
            path.is_dir(),
            true,
            "the existing target must not be removed"
        );
        assert_eq!(
            temp_files(dir.path()).len(),
            0,
            "rename failure must clean up its temp file"
        );
    }

    /// Temp-file creation failure (read-only parent directory): write_string
    /// must fail closed with RcIo and leave the previous contents untouched.
    #[cfg(unix)]
    #[test]
    fn write_string_temp_creation_failure_preserves_target_contents() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        write_string(&path, "old").expect("seed");

        let readonly = fs::Permissions::from_mode(0o555);
        let writable = fs::Permissions::from_mode(0o755);
        fs::set_permissions(dir.path(), readonly).expect("drop write permission");

        let result = write_string(&path, "new");

        fs::set_permissions(dir.path(), writable).expect("restore write permission");

        match result {
            Err(error) => {
                assert_eq!(
                    error.code,
                    ReasonCode::RcIo,
                    "temp creation failure must map to RcIo"
                );
                assert!(
                    error.message.contains("failed to create temp file"),
                    "error must pin the temp-creation stage: {}",
                    error.message
                );
                assert_eq!(
                    fs::read_to_string(&path).expect("read"),
                    "old",
                    "the destination must be untouched after a failed creation"
                );
                assert!(
                    temp_files(dir.path()).is_empty(),
                    "failed creation must not leave a temp file"
                );
            }
            // Privileged environments bypass permission bits; the write must
            // then still succeed atomically with the new contents.
            Ok(()) => {
                assert_eq!(
                    fs::read_to_string(&path).expect("read"),
                    "new",
                    "privileged write must still land atomically"
                );
            }
        }
    }

    #[test]
    fn noncrypto_random_bytes_edge_boundaries_are_pinned() {
        // dtm mode is deterministic per label and must stay exact when the
        // request crosses the 32-byte SHA-256 block boundary (40 > 32).
        let first = noncrypto_random_bytes("casa1-edge", true, 40);
        let second = noncrypto_random_bytes("casa1-edge", true, 40);
        assert_eq!(first.len(), 40, "dtm request length is exact across blocks");
        assert_eq!(
            first, second,
            "dtm mode must be deterministic for a fixed label"
        );

        // Non-dtm mode seeds the OS RNG through the system entropy source and
        // returns exactly the requested length.
        let os = noncrypto_random_bytes("casa1-edge", false, 40);
        assert_eq!(os.len(), 40, "os path returns exactly the requested length");
    }

    #[test]
    fn concurrent_readers_never_observe_a_partial_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("atomic.txt");
        let first = "A".repeat(128 * 1024);
        let second = "B".repeat(128 * 1024);
        write_string(&path, &first).expect("seed");

        let stop = Arc::new(AtomicBool::new(false));
        let reader_path = path.clone();
        let reader_stop = Arc::clone(&stop);
        let expected_first = first.clone();
        let expected_second = second.clone();
        let reader = thread::spawn(move || {
            while !reader_stop.load(Ordering::Relaxed) {
                let observed = fs::read_to_string(&reader_path).expect("read snapshot");
                assert!(
                    observed == expected_first || observed == expected_second,
                    "reader observed a partial or truncated snapshot ({} bytes)",
                    observed.len()
                );
            }
        });

        for index in 0..200 {
            let contents = if index % 2 == 0 { &second } else { &first };
            write_string(&path, contents).expect("atomic write");
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().expect("reader thread");
        assert_eq!(
            temp_files(dir.path()).len(),
            0,
            "atomic writer must not leave temp files"
        );
    }
}
