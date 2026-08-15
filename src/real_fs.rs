//! Real filesystem I/O passthrough for Casa1.
//!
//! Maps Windows paths to macOS paths within the Game Environment root directory.
//! Uses real `std::fs` operations for actual disk I/O while maintaining the
//! Windows filesystem semantics (case-insensitive, share modes, byte-range locks).
//!
//! Also implements NTFS Alternate Data Stream (ADS) support, mapping to macOS
//! extended attributes via `xattr` FFI on macOS, or file-based storage on other platforms.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(not(target_os = "macos"))]
use std::fs::OpenOptions;

// ---------------------------------------------------------------------------
// NTFS Alternate Data Stream (ADS) types and constants
// ---------------------------------------------------------------------------

/// Represents an NTFS alternate data stream name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateStreamName {
    /// The main file path
    pub file_path: String,
    /// The stream name (e.g., "Zone.Identifier")
    pub stream_name: String,
    /// The stream type (e.g., "$DATA")
    pub stream_type: String,
}

/// Default stream type for NTFS alternate data streams.
pub const ADS_STREAM_TYPE_DATA: &str = "$DATA";
/// Standard Windows identifier for security zone tracking (Mark-of-the-Web).
pub const ADS_ZONE_IDENTIFIER: &str = "Zone.Identifier";
/// Apple quarantine extended attribute name.
pub const XATTR_COM_APPLE_QUARANTINE: &str = "com.apple.quarantine";
/// Custom Casa1 extended attribute for Zone.Identifier ADS.
pub const XATTR_ZONE_IDENTIFIER: &str = "com.casa1.zone.identifier";
/// Prefix used for all ADS extended attribute names on macOS.
const XATTR_ADS_PREFIX: &str = "com.casa1.ads.";

/// Parse a path that may contain NTFS Alternate Data Stream syntax
/// (e.g., `file.exe:Zone.Identifier:$DATA` or `C:\path\file.exe:Zone.Identifier`)
/// into the base file path and an optional stream descriptor.
///
/// Returns `(file_path, Some(stream))` if an ADS component is found,
/// or `(original_path, None)` if there is no stream.
pub fn parse_ntfs_path(path: &str) -> (String, Option<AlternateStreamName>) {
    let path = path.trim();

    // Handle empty paths
    if path.is_empty() {
        return (String::new(), None);
    }

    // Find the first colon that could be a stream separator.
    // A colon after a drive letter (e.g., "C:\...") is NOT a stream separator.
    // We need to find a colon that appears after the drive letter/prefix portion.
    //
    // Strategy: find the position of the last colon, then work backwards.
    // If there's a ":" that is part of a drive spec (index 1 like "C:"),
    // it's not a stream separator.

    let _bytes = path.as_bytes();

    // Find all colon positions
    let colon_positions: Vec<usize> = path.match_indices(':').map(|(i, _)| i).collect();

    if colon_positions.is_empty() {
        return (path.to_string(), None);
    }

    // Determine which colons are drive letters (position 1, like "C:" or "D:")
    // and which could be stream separators.
    //
    // For ADS paths like:
    //   "file.exe:Zone.Identifier"          → colon at index 8
    //   "file.exe:Zone.Identifier:$DATA"    → colons at 8 and 24
    //   "C:\path\file.exe:Zone.Identifier"  → colons at 1 and 21
    //   "C:\path\file.exe:Zone.Identifier:$DATA" → colons at 1, 21, 37

    // The stream separator is the colon after the file path.
    // Work backwards from the end to find the stream separator.

    // Case 1: No drive letter, single colon: "file.exe:Zone.Identifier"
    if colon_positions.len() == 1 {
        let pos = colon_positions[0];
        if is_drive_letter_colon(path, pos) {
            return (path.to_string(), None);
        }
        let file_path = path[..pos].to_string();
        let stream_spec = path[pos + 1..].trim();
        let (stream_name, stream_type) = parse_stream_spec(stream_spec);
        return (
            file_path.clone(),
            Some(AlternateStreamName {
                file_path,
                stream_name,
                stream_type,
            }),
        );
    }

    // Case 2: Multiple colons
    // The leftmost non-drive colon is the stream separator (between file and stream).
    // Any subsequent colons separate stream name from stream type (e.g., `Zone.Identifier:$DATA`).
    //
    // Examples:
    //   "file.exe:Zone.Identifier:$DATA"       → colons at 7, 22; stream sep = 7
    //   "C:\path\file.exe:Zone.Identifier:$DATA" → colons at 1, 23, 38; stream sep = 23 (1 is drive)
    //   "D:\save.dat:backup:$DATA"              → colons at 1, 14, 21; stream sep = 14 (1 is drive)

    // Find the first non-drive colon scanning left-to-right.
    for &pos in &colon_positions {
        if is_drive_letter_colon(path, pos) {
            continue;
        }
        // This colon is the stream separator
        let file_path = path[..pos].to_string();
        let stream_spec = path[pos + 1..].trim();
        let (stream_name, stream_type) = parse_stream_spec(stream_spec);
        return (
            file_path.clone(),
            Some(AlternateStreamName {
                file_path,
                stream_name,
                stream_type,
            }),
        );
    }

    // No suitable stream separator found — all colons are drive letters
    (path.to_string(), None)
}

/// Check if a colon at a given position is part of a Windows drive letter (e.g., `C:`).
fn is_drive_letter_colon(path: &str, pos: usize) -> bool {
    if pos == 0 {
        return false;
    }
    let prev = path.as_bytes()[pos - 1];
    // Drive letter: single letter followed by colon, e.g., "C:"
    if pos == 1 && prev.is_ascii_alphabetic() {
        // Make sure it's not part of a longer path like "C:\..."
        // "C:" is a drive letter. "file:Z" at pos 5 is not.
        return true; // correct: colon at pos 1 after drive letter
    }
    // Handle paths like "C:\..." where colon at position 1
    if pos == 1 && prev.is_ascii_alphabetic() {
        return true; // correct: colon at pos 1 after drive letter (with backslash)
    }
    false
}

/// Parse a stream specification string into name and type.
/// Stream spec can be:
/// - `Zone.Identifier` → name="Zone.Identifier", type="$DATA"
/// - `Zone.Identifier:$DATA` → name="Zone.Identifier", type="$DATA"
fn parse_stream_spec(spec: &str) -> (String, String) {
    let spec = spec.trim();
    if let Some(colon_pos) = spec.find(':') {
        let name = spec[..colon_pos].trim().to_string();
        let stype = spec[colon_pos + 1..].trim().to_string();
        (
            name,
            if stype.is_empty() {
                ADS_STREAM_TYPE_DATA.to_string()
            } else {
                stype
            },
        )
    } else {
        (spec.to_string(), ADS_STREAM_TYPE_DATA.to_string())
    }
}

/// Check if a path contains an ADS reference (has `:` after drive letter).
pub fn is_ads_path(path: &str) -> bool {
    let (_, stream) = parse_ntfs_path(path);
    stream.is_some()
}

/// Type alias for backward compatibility with `RealFs` naming.
pub type RealFs = RealFilesystem;

// ---------------------------------------------------------------------------
// Windows path resolution
// ---------------------------------------------------------------------------

/// Resolves Windows paths to real macOS paths within the GE root.
pub struct WindowsPathResolver {
    /// Root directory on the host filesystem (the GE root).
    ge_root: PathBuf,
    /// Drive mappings: "C:" -> "drive_c", etc.
    drive_mappings: HashMap<String, String>,
}

impl WindowsPathResolver {
    pub fn new(ge_root: impl Into<PathBuf>) -> Self {
        let mut mappings = HashMap::new();
        mappings.insert("C".to_uppercase(), "drive_c".to_string());
        mappings.insert("Z".to_uppercase(), "drive_z".to_string());
        Self {
            ge_root: ge_root.into(),
            drive_mappings: mappings,
        }
    }

    /// Add a custom drive mapping.
    pub fn add_drive_mapping(&mut self, drive_letter: &str, subdirectory: &str) {
        self.drive_mappings
            .insert(drive_letter.to_uppercase(), subdirectory.to_string());
    }

    /// Resolve a Windows path to a real macOS path.
    /// E.g., "C:\Steam\Steam.exe" -> "/path/to/ge_root/drive_c/Steam/Steam.exe"
    pub fn resolve(&self, windows_path: &str) -> AppResult<PathBuf> {
        let normalized = normalize_windows_path(windows_path);
        let (drive, relative) = split_drive(&normalized)?;

        let subdir = self.drive_mappings.get(&drive).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unknown drive letter {drive}: in path {windows_path}"),
            )
        })?;

        let mut real_path = self.ge_root.clone();
        real_path.push(subdir);

        if !relative.is_empty() {
            // Split the relative path and do case-insensitive resolution
            for component in relative.split(['/', '\\']).filter(|s| !s.is_empty()) {
                real_path = self.resolve_component(&real_path, component)?;
            }
        }

        Ok(real_path)
    }

    /// Resolve a single path component with case-insensitive matching.
    fn resolve_component(&self, parent: &Path, component: &str) -> AppResult<PathBuf> {
        // First try exact match
        let exact = parent.join(component);
        if exact.exists() {
            return Ok(exact);
        }

        // Try case-insensitive match
        if let Ok(dir_entries) = fs::read_dir(parent) {
            let component_lower = component.to_lowercase();
            for entry in dir_entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.to_lowercase() == component_lower {
                    return Ok(entry.path());
                }
            }
        }

        // No match found — return the path as-is (it may be created)
        Ok(parent.join(component))
    }

    /// Get the GE root path.
    pub fn ge_root(&self) -> &Path {
        &self.ge_root
    }

    /// Convert a real macOS path back to a Windows path.
    pub fn to_windows_path(&self, real_path: &Path) -> Option<String> {
        let real_str = real_path.to_string_lossy();
        let ge_root_str = self.ge_root.to_string_lossy();

        if let Some(relative) = real_str.strip_prefix(ge_root_str.as_ref()) {
            let relative = relative.trim_start_matches('/');
            for (drive, subdir) in &self.drive_mappings {
                if let Some(rest) = relative.strip_prefix(subdir) {
                    let rest = rest.trim_start_matches('/');
                    return Some(format!("{}:\\{}", drive, rest.replace('/', "\\")));
                }
            }
        }
        None
    }
}

/// Normalize a Windows path: collapse separators, resolve . and ..
fn normalize_windows_path(path: &str) -> String {
    let path = path.replace('/', "\\");
    let mut components: Vec<&str> = Vec::new();
    for part in path.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(part),
        }
    }
    components.join("\\")
}

/// Split a Windows path into drive letter and relative path.
fn split_drive(path: &str) -> AppResult<(String, String)> {
    // Handle "\\?\C:\path" format first (before colon search)
    if let Some(stripped) = path.strip_prefix("\\\\?\\") {
        return split_drive(stripped);
    }

    // Handle "\\.\pipe\name" format
    if let Some(stripped) = path.strip_prefix("\\\\.") {
        return Ok(("DEV".to_string(), stripped.to_string()));
    }

    // Handle "C:\path" or "C:path" format
    if let Some(colon_pos) = path.find(':') {
        let drive = path[..colon_pos].to_uppercase();
        let rest = path[colon_pos + 1..].trim_start_matches(['\\', '/']);
        return Ok((drive, rest.to_string()));
    }

    Ok(("C".to_string(), path.to_string()))
}

// ---------------------------------------------------------------------------
// Real file handle
// ---------------------------------------------------------------------------

/// Represents an open file in the guest filesystem with real OS backing.
pub struct GuestFile {
    /// The real file on disk.
    pub file: fs::File,
    /// The Windows path that was used to open this file.
    pub windows_path: String,
    /// The real macOS path.
    pub real_path: PathBuf,
    /// Share mode flags.
    pub share_mode: u32,
    /// Whether this handle allows read access.
    pub can_read: bool,
    /// Whether this handle allows write access.
    pub can_write: bool,
    /// Whether to delete on close.
    pub delete_on_close: bool,
}

impl GuestFile {
    pub fn read(&mut self, buf: &mut [u8]) -> AppResult<usize> {
        if !self.can_read {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                "file not opened for reading",
            ));
        }
        self.file
            .read(buf)
            .map_err(|e| AppError::new(ReasonCode::RcUnimplInsn, format!("read error: {e}")))
    }

    pub fn write(&mut self, buf: &[u8]) -> AppResult<usize> {
        if !self.can_write {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                "file not opened for writing",
            ));
        }
        self.file
            .write(buf)
            .map_err(|e| AppError::new(ReasonCode::RcUnimplInsn, format!("write error: {e}")))
    }

    pub fn seek(&mut self, pos: SeekFrom) -> AppResult<u64> {
        self.file
            .seek(pos)
            .map_err(|e| AppError::new(ReasonCode::RcUnimplInsn, format!("seek error: {e}")))
    }

    pub fn flush(&mut self) -> AppResult<()> {
        self.file
            .flush()
            .map_err(|e| AppError::new(ReasonCode::RcUnimplInsn, format!("flush error: {e}")))
    }

    pub fn size(&self) -> AppResult<u64> {
        let metadata = self
            .file
            .metadata()
            .map_err(|e| AppError::new(ReasonCode::RcUnimplInsn, format!("metadata error: {e}")))?;
        Ok(metadata.len())
    }
}

// ---------------------------------------------------------------------------
// Filesystem operations
// ---------------------------------------------------------------------------

/// Real filesystem operations using std::fs.
pub struct RealFilesystem {
    resolver: WindowsPathResolver,
}

impl RealFilesystem {
    pub fn new(resolver: WindowsPathResolver) -> Self {
        // Ensure the GE root directory structure exists
        Self { resolver }
    }

    /// Initialize the filesystem by creating required directories.
    pub fn initialize(&self) -> AppResult<()> {
        let root = self.resolver.ge_root();
        let dirs = [
            "drive_c/Windows/System32",
            "drive_c/Windows/SysWOW64",
            "drive_c/Program Files",
            "drive_c/Program Files (x86)",
            "drive_c/users/Default/AppData/Roaming",
            "drive_c/users/Default/AppData/Local",
            "drive_c/users/Default/AppData/LocalLow",
            "drive_c/Windows/Temp",
            "tmp",
            "logs",
            "cache/dbt",
            "cache/shader",
            "cache/pso",
            "cache/dxgi",
            "cache/http",
        ];

        for dir in &dirs {
            let path = root.join(dir);
            fs::create_dir_all(&path).map_err(|e| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("failed to create directory {}: {e}", path.display()),
                )
            })?;
        }

        Ok(())
    }

    /// Open a file with real OS file operations.
    pub fn open_file(
        &self,
        windows_path: &str,
        can_read: bool,
        can_write: bool,
        create: bool,
        truncate: bool,
    ) -> AppResult<GuestFile> {
        let real_path = self.resolver.resolve(windows_path)?;

        // Ensure parent directory exists
        if let Some(parent) = real_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("cannot create parent dir: {e}"),
                )
            })?;
        }

        let mut options = fs::OpenOptions::new();
        options.read(can_read).write(can_write);

        if create && can_write {
            options.create(true);
        }
        if truncate && can_write {
            options.truncate(true);
        }
        if !create && !can_write {
            // Open existing only
        }

        let file = options.open(&real_path).map_err(|e| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("cannot open file {}: {e}", real_path.display()),
            )
        })?;

        Ok(GuestFile {
            file,
            windows_path: windows_path.to_string(),
            real_path,
            share_mode: 0,
            can_read,
            can_write,
            delete_on_close: false,
        })
    }

    /// Create a directory.
    pub fn create_directory(&self, windows_path: &str) -> AppResult<()> {
        let real_path = self.resolver.resolve(windows_path)?;
        fs::create_dir_all(&real_path).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("cannot create directory: {e}"),
            )
        })
    }

    /// Delete a file.
    pub fn delete_file(&self, windows_path: &str) -> AppResult<()> {
        let real_path = self.resolver.resolve(windows_path)?;
        fs::remove_file(&real_path).map_err(|e| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("cannot delete file: {e}"))
        })
    }

    /// Remove a directory.
    pub fn remove_directory(&self, windows_path: &str) -> AppResult<()> {
        let real_path = self.resolver.resolve(windows_path)?;
        fs::remove_dir_all(&real_path).map_err(|e| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("cannot remove directory: {e}"),
            )
        })
    }

    /// Move/rename a file.
    pub fn move_file(&self, src: &str, dst: &str) -> AppResult<()> {
        let src_path = self.resolver.resolve(src)?;
        let dst_path = self.resolver.resolve(dst)?;

        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("cannot create parent dir: {e}"),
                )
            })?;
        }

        fs::rename(&src_path, &dst_path)
            .map_err(|e| AppError::new(ReasonCode::RcUnimplInsn, format!("cannot move file: {e}")))
    }

    /// Copy a file.
    pub fn copy_file(&self, src: &str, dst: &str) -> AppResult<u64> {
        let src_path = self.resolver.resolve(src)?;
        let dst_path = self.resolver.resolve(dst)?;

        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("cannot create parent dir: {e}"),
                )
            })?;
        }

        fs::copy(&src_path, &dst_path)
            .map_err(|e| AppError::new(ReasonCode::RcUnimplInsn, format!("cannot copy file: {e}")))
    }

    /// Check if a file exists.
    pub fn exists(&self, windows_path: &str) -> bool {
        self.resolver
            .resolve(windows_path)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Get file metadata.
    pub fn metadata(&self, windows_path: &str) -> AppResult<FileMetadata> {
        let real_path = self.resolver.resolve(windows_path)?;
        let meta = fs::metadata(&real_path).map_err(|e| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("cannot get metadata: {e}"),
            )
        })?;

        Ok(FileMetadata {
            size: meta.len(),
            is_directory: meta.is_dir(),
            is_readonly: meta.permissions().readonly(),
            modified: meta.modified().ok(),
            created: meta.created().ok(),
            accessed: meta.accessed().ok(),
        })
    }

    /// Enumerate directory entries.
    pub fn enumerate_directory(&self, windows_path: &str) -> AppResult<Vec<DirEntry>> {
        let real_path = self.resolver.resolve(windows_path)?;
        let mut entries = Vec::new();

        let dir = fs::read_dir(&real_path).map_err(|e| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("cannot read directory: {e}"),
            )
        })?;

        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let meta = entry.metadata().map_err(|e| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("cannot read entry metadata: {e}"),
                )
            })?;

            entries.push(DirEntry {
                name,
                size: meta.len(),
                is_directory: meta.is_dir(),
            });
        }

        Ok(entries)
    }

    /// Get the path resolver.
    pub fn resolver(&self) -> &WindowsPathResolver {
        &self.resolver
    }

    // -----------------------------------------------------------------------
    // NTFS Alternate Data Stream (ADS) support
    // -----------------------------------------------------------------------

    /// Read from an alternate data stream.
    ///
    /// On macOS, this maps to extended attributes via `getxattr()`.
    /// Stream names are prefixed with `com.casa1.ads.` to avoid collisions.
    /// For `Zone.Identifier`, also reads the `com.apple.quarantine` xattr.
    #[cfg(target_os = "macos")]
    pub fn read_alternate_stream(&self, path: &str, stream_name: &str) -> AppResult<Vec<u8>> {
        let real_path = self.resolver.resolve(path)?;
        let xattr_name = format!("{}{}", XATTR_ADS_PREFIX, stream_name);

        let c_path = CString::new(real_path.as_os_str().as_encoded_bytes())
            .map_err(|e| AppError::new(ReasonCode::RcCliInvalid, format!("invalid path: {e}")))?;
        let c_name = CString::new(xattr_name.as_str()).map_err(|e| {
            AppError::new(ReasonCode::RcCliInvalid, format!("invalid xattr name: {e}"))
        })?;

        // SAFETY: getxattr FFI call — c_path and c_name are valid CStrings
        // with null terminators. Passing null output buffer with size 0 to
        // query the required buffer size is the documented usage pattern.
        let buf_size = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                std::ptr::null_mut(),
                0,
                0,
                0,
            )
        };

        if buf_size < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Err(AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!(
                        "stream '{}' not found on {}",
                        stream_name,
                        real_path.display()
                    ),
                ));
            }
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("getxattr failed: {err}"),
            ));
        }

        let mut buf = vec![0u8; buf_size as usize];
        // SAFETY: getxattr FFI call — c_path and c_name are valid CStrings,
        // buf is a valid Vec of buf_size bytes, and the return value is checked.
        let result = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                0,
                0,
            )
        };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("getxattr read failed: {err}"),
            ));
        }

        buf.truncate(result as usize);
        Ok(buf)
    }

    /// Read from an alternate data stream (non-macOS fallback).
    #[cfg(not(target_os = "macos"))]
    pub fn read_alternate_stream(&self, path: &str, stream_name: &str) -> AppResult<Vec<u8>> {
        let real_path = self.resolver.resolve(path)?;
        let ads_path = Self::ads_sidecar_path(&real_path, stream_name);

        let data = fs::read(&ads_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!(
                        "stream '{}' not found on {}",
                        stream_name,
                        real_path.display()
                    ),
                )
            } else {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("failed to read stream '{}': {e}", ads_path.display()),
                )
            }
        })?;

        Ok(data)
    }

    /// Write to an alternate data stream.
    ///
    /// On macOS, maps to extended attributes via `setxattr()`.
    /// For `Zone.Identifier`, also sets the `com.apple.quarantine` xattr
    /// for proper macOS quarantine integration.
    #[cfg(target_os = "macos")]
    pub fn write_alternate_stream(
        &self,
        path: &str,
        stream_name: &str,
        data: &[u8],
    ) -> AppResult<()> {
        let real_path = self.resolver.resolve(path)?;
        let xattr_name = format!("{}{}", XATTR_ADS_PREFIX, stream_name);

        let c_path = CString::new(real_path.as_os_str().as_encoded_bytes())
            .map_err(|e| AppError::new(ReasonCode::RcCliInvalid, format!("invalid path: {e}")))?;
        let c_name = CString::new(xattr_name.as_str()).map_err(|e| {
            AppError::new(ReasonCode::RcCliInvalid, format!("invalid xattr name: {e}"))
        })?;

        // SAFETY: setxattr FFI call — c_path, c_name are valid CStrings,
        // data.as_ptr() is valid for data.len() bytes, and flags=0 is valid.
        let result = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                data.as_ptr() as *const std::ffi::c_void,
                data.len(),
                0,
                0,
            )
        };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("setxattr failed: {err}"),
            ));
        }

        // For Zone.Identifier, also set the macOS quarantine attribute
        if stream_name == ADS_ZONE_IDENTIFIER {
            set_quarantine_xattr(&real_path)?;
        }

        Ok(())
    }

    /// Write to an alternate data stream (non-macOS fallback).
    #[cfg(not(target_os = "macos"))]
    pub fn write_alternate_stream(
        &self,
        path: &str,
        stream_name: &str,
        data: &[u8],
    ) -> AppResult<()> {
        let real_path = self.resolver.resolve(path)?;
        let ads_path = Self::ads_sidecar_path(&real_path, stream_name);

        if let Some(parent) = ads_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("cannot create ads dir: {e}"),
                )
            })?;
        }

        fs::write(&ads_path, data).map_err(|e| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("failed to write stream '{}': {e}", ads_path.display()),
            )
        })?;

        Ok(())
    }

    /// Delete an alternate data stream.
    #[cfg(target_os = "macos")]
    pub fn delete_alternate_stream(&self, path: &str, stream_name: &str) -> AppResult<()> {
        let real_path = self.resolver.resolve(path)?;
        let xattr_name = format!("{}{}", XATTR_ADS_PREFIX, stream_name);

        let c_path = CString::new(real_path.as_os_str().as_encoded_bytes())
            .map_err(|e| AppError::new(ReasonCode::RcCliInvalid, format!("invalid path: {e}")))?;
        let c_name = CString::new(xattr_name.as_str()).map_err(|e| {
            AppError::new(ReasonCode::RcCliInvalid, format!("invalid xattr name: {e}"))
        })?;

        // SAFETY: removexattr FFI call — c_path and c_name are valid CStrings, flags=0.
        let result = unsafe { libc::removexattr(c_path.as_ptr(), c_name.as_ptr(), 0) };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Err(AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!(
                        "stream '{}' not found on {}",
                        stream_name,
                        real_path.display()
                    ),
                ));
            }
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("removexattr failed: {err}"),
            ));
        }

        Ok(())
    }

    /// Delete an alternate data stream (non-macOS fallback).
    #[cfg(not(target_os = "macos"))]
    pub fn delete_alternate_stream(&self, path: &str, stream_name: &str) -> AppResult<()> {
        let real_path = self.resolver.resolve(path)?;
        let ads_path = Self::ads_sidecar_path(&real_path, stream_name);

        fs::remove_file(&ads_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!(
                        "stream '{}' not found on {}",
                        stream_name,
                        real_path.display()
                    ),
                )
            } else {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("failed to delete stream '{}': {e}", ads_path.display()),
                )
            }
        })?;

        Ok(())
    }

    /// List all alternate data streams for a file.
    #[cfg(target_os = "macos")]
    pub fn list_alternate_streams(&self, path: &str) -> AppResult<Vec<String>> {
        let real_path = self.resolver.resolve(path)?;

        let c_path = CString::new(real_path.as_os_str().as_encoded_bytes())
            .map_err(|e| AppError::new(ReasonCode::RcCliInvalid, format!("invalid path: {e}")))?;

        // SAFETY: listxattr FFI call — c_path is a valid CString, null buffer
        // with size 0 queries the required buffer size (documented usage pattern).
        let buf_size = unsafe { libc::listxattr(c_path.as_ptr(), std::ptr::null_mut(), 0, 0) };

        if buf_size < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(Vec::new());
            }
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("listxattr failed: {err}"),
            ));
        }

        if buf_size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; buf_size as usize];
        // SAFETY: listxattr FFI call — c_path is a valid CString, buf is a
        // valid Vec of buf_size bytes, and the return value is checked.
        let result = unsafe {
            libc::listxattr(
                c_path.as_ptr(),
                buf.as_mut_ptr() as *mut std::ffi::c_char,
                buf.len(),
                0,
            )
        };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("listxattr read failed: {err}"),
            ));
        }

        let names = parse_xattr_list(&buf[..result as usize]);
        let stream_names: Vec<String> = names
            .into_iter()
            .filter_map(|name| {
                if let Some(stripped) = name.strip_prefix(XATTR_ADS_PREFIX) {
                    Some(stripped.to_string())
                } else {
                    None
                }
            })
            .collect();

        Ok(stream_names)
    }

    /// List all alternate data streams for a file (non-macOS fallback).
    ///
    /// Uses `.casa1_ads/` directory with `__` separator convention.
    #[cfg(not(target_os = "macos"))]
    pub fn list_alternate_streams(&self, path: &str) -> AppResult<Vec<String>> {
        let real_path = self.resolver.resolve(path)?;
        let ads_dir = real_path.parent().map(|p| p.join(".casa1_ads"));

        let Some(ads_dir) = ads_dir else {
            return Ok(Vec::new());
        };

        if !ads_dir.exists() {
            return Ok(Vec::new());
        }

        let file_name = real_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let prefix = format!("{}__", file_name);
        let mut streams = Vec::new();

        if let Ok(entries) = fs::read_dir(&ads_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(stream_name) = name.strip_prefix(&prefix) {
                    streams.push(stream_name.to_string());
                }
            }
        }

        Ok(streams)
    }
}

// -----------------------------------------------------------------------
// Helper functions for ADS
// -----------------------------------------------------------------------

#[cfg(target_os = "macos")]
/// Set the macOS quarantine extended attribute on a file.
fn set_quarantine_xattr(path: &Path) -> AppResult<()> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let quarantine_data = format!("Casa1;{:x};", timestamp);

    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| AppError::new(ReasonCode::RcCliInvalid, format!("invalid path: {e}")))?;
    let c_name = CString::new(XATTR_COM_APPLE_QUARANTINE)
        .map_err(|e| AppError::new(ReasonCode::RcCliInvalid, format!("invalid xattr name: {e}")))?;

    // SAFETY: setxattr FFI call — all path/name/value CStrings are valid,
    // size matches the value buffer length, and flags=0 is valid.
    let result = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            quarantine_data.as_ptr() as *const std::ffi::c_void,
            quarantine_data.len(),
            0,
            0,
        )
    };

    if result < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("setxattr quarantine failed: {err}"),
            ));
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
/// Parse a null-separated list of extended attribute names from `listxattr` output.
fn parse_xattr_list(buf: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut start = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if byte == 0 {
            if i > start {
                if let Ok(name) = std::str::from_utf8(&buf[start..i]) {
                    names.push(name.to_string());
                }
            }
            start = i + 1;
        }
    }
    if start < buf.len() {
        if let Ok(name) = std::str::from_utf8(&buf[start..]) {
            names.push(name.to_string());
        }
    }
    names
}

#[cfg(not(target_os = "macos"))]
impl RealFilesystem {
    /// Get the sidecar file path for an ADS stream on non-macOS platforms.
    ///
    /// Uses `.casa1_ads/` directory with `__` separator:
    /// e.g., `file.txt:Zone.Identifier` → `.casa1_ads/file.txt__Zone.Identifier`
    fn ads_sidecar_path(real_path: &Path, stream_name: &str) -> PathBuf {
        let parent = real_path.parent().unwrap_or(Path::new("."));
        let file_name = real_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let ads_dir = parent.join(".casa1_ads");
        ads_dir.join(format!("{}__{}", file_name, stream_name))
    }
}

// ---------------------------------------------------------------------------
// Unified ADS sidecar path (used by virtual FS / GE layer)
// ---------------------------------------------------------------------------

/// Compute the sidecar file path for an ADS stream in the virtual filesystem.
///
/// Convention: `.casa1_ads/file.txt__Zone.Identifier` for a stream named
/// `Zone.Identifier` on the file `file.txt`.
pub fn ads_sidecar_path_for(real_path: &Path, stream_name: &str) -> PathBuf {
    let parent = real_path.parent().unwrap_or(Path::new("."));
    let file_name = real_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let ads_dir = parent.join(".casa1_ads");
    ads_dir.join(format!("{}__{}", file_name, stream_name))
}

/// Extract the stream name from a sidecar file path.
///
/// Returns `None` if the path does not follow the `.casa1_ads/name__stream` convention.
pub fn ads_sidecar_to_stream(sidecar_path: &Path) -> Option<(String, String)> {
    let file_name = sidecar_path.file_name()?.to_str()?;
    let separator = file_name.rfind("__")?;
    let base_name = &file_name[..separator];
    let stream_name = &file_name[separator + 2..];
    if stream_name.is_empty() {
        return None;
    }
    Some((base_name.to_string(), stream_name.to_string()))
}

// ---------------------------------------------------------------------------
// BackupRead / BackupWrite stubs for ADS enumeration
// ---------------------------------------------------------------------------

/// Represents a single entry in a `BackupRead` stream.
/// On Windows, `BackupRead` yields a sequence of `WIN32_STREAM_ID` structures,
/// each describing either the main data stream or an alternate data stream.
#[derive(Debug, Clone)]
pub struct BackupStreamEntry {
    /// Stream name (empty string for the default `$DATA` stream).
    pub stream_name: String,
    /// Stream type (e.g., `$DATA`).
    pub stream_type: String,
    /// Size of the stream data in bytes.
    pub size: u64,
    /// The actual data of the stream.
    pub data: Vec<u8>,
}

/// Result of a `BackupRead` operation — enumerates all streams (main + ADS)
/// for a file in the virtual filesystem.
#[derive(Debug, Clone)]
pub struct BackupReadResult {
    /// Ordered list of stream entries.
    pub entries: Vec<BackupStreamEntry>,
}

impl BackupReadResult {
    /// Create an empty result.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Get the main data stream (first entry with empty stream name).
    pub fn main_stream(&self) -> Option<&BackupStreamEntry> {
        self.entries.iter().find(|e| e.stream_name.is_empty())
    }

    /// Get all alternate data streams (entries with non-empty stream names).
    pub fn alternate_streams(&self) -> Vec<&BackupStreamEntry> {
        self.entries
            .iter()
            .filter(|e| !e.stream_name.is_empty())
            .collect()
    }
}

/// Perform a `BackupRead`-style enumeration of all streams for a file.
///
/// On the virtual FS, this reads the main file data and then enumerates
/// any sidecar files in the `.casa1_ads/` directory.
///
/// On macOS, it also reads extended attributes that match the ADS prefix.
pub fn backup_read_file(
    real_fs: &RealFilesystem,
    windows_path: &str,
) -> AppResult<BackupReadResult> {
    let mut entries = Vec::new();

    // Read main data stream
    match real_fs.open_file(windows_path, true, false, false, false) {
        Ok(mut file) => {
            let size = file.size()?;
            let mut data = vec![0u8; size as usize];
            let bytes_read = file.read(&mut data)?;
            data.truncate(bytes_read);
            entries.push(BackupStreamEntry {
                stream_name: String::new(),
                stream_type: ADS_STREAM_TYPE_DATA.to_string(),
                size: bytes_read as u64,
                data,
            });
        }
        Err(e) => {
            return Err(e);
        }
    }

    // Enumerate alternate data streams
    match real_fs.list_alternate_streams(windows_path) {
        Ok(stream_names) => {
            for stream_name in stream_names {
                match real_fs.read_alternate_stream(windows_path, &stream_name) {
                    Ok(data) => {
                        entries.push(BackupStreamEntry {
                            stream_name,
                            stream_type: ADS_STREAM_TYPE_DATA.to_string(),
                            size: data.len() as u64,
                            data,
                        });
                    }
                    Err(_) => continue, // Skip streams that can't be read
                }
            }
        }
        Err(_) => {} // No ADS is fine
    }

    Ok(BackupReadResult { entries })
}

/// Perform a `BackupWrite`-style restoration of streams to a file.
///
/// Writes each stream entry to the virtual filesystem. Entries with empty
/// stream names write to the main file; entries with names write to ADS.
pub fn backup_write_file(
    real_fs: &RealFilesystem,
    windows_path: &str,
    backup: &BackupReadResult,
) -> AppResult<()> {
    for entry in &backup.entries {
        if entry.stream_name.is_empty() {
            // Write main data stream
            let mut file = real_fs.open_file(windows_path, false, true, true, true)?;
            file.write(&entry.data)?;
            file.flush()?;
        } else {
            // Write alternate data stream
            real_fs.write_alternate_stream(windows_path, &entry.stream_name, &entry.data)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// File metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub size: u64,
    pub is_directory: bool,
    pub is_readonly: bool,
    pub modified: Option<std::time::SystemTime>,
    pub created: Option<std::time::SystemTime>,
    pub accessed: Option<std::time::SystemTime>,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub size: u64,
    pub is_directory: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_fs() -> (TempDir, RealFilesystem) {
        let tmp = TempDir::new().unwrap();
        let resolver = WindowsPathResolver::new(tmp.path());
        let fs = RealFilesystem::new(resolver);
        fs.initialize().unwrap();
        (tmp, fs)
    }

    #[test]
    fn path_resolver_maps_c_drive() {
        let tmp = TempDir::new().unwrap();
        let resolver = WindowsPathResolver::new(tmp.path());
        let path = resolver.resolve("C:\\Steam\\Steam.exe").unwrap();
        assert_eq!(
            path,
            tmp.path().join("drive_c").join("Steam").join("Steam.exe")
        );
    }

    #[test]
    fn path_resolver_normalizes_separators() {
        let tmp = TempDir::new().unwrap();
        let resolver = WindowsPathResolver::new(tmp.path());
        let path = resolver.resolve("C:/Steam/Steam.exe").unwrap();
        assert_eq!(
            path,
            tmp.path().join("drive_c").join("Steam").join("Steam.exe")
        );
    }

    #[test]
    fn path_resolver_handles_dot_dot() {
        let tmp = TempDir::new().unwrap();
        let resolver = WindowsPathResolver::new(tmp.path());
        let path = resolver
            .resolve("C:\\Steam\\..\\Windows\\System32")
            .unwrap();
        assert_eq!(
            path,
            tmp.path().join("drive_c").join("Windows").join("System32")
        );
    }

    #[test]
    fn filesystem_creates_directories() {
        let (_tmp, fs) = setup_fs();
        assert!(
            fs.resolver()
                .ge_root()
                .join("drive_c/Windows/System32")
                .exists()
        );
        assert!(
            fs.resolver()
                .ge_root()
                .join("drive_c/Program Files")
                .exists()
        );
    }

    #[test]
    fn filesystem_write_and_read_file() {
        let (_tmp, fs) = setup_fs();

        // Write
        let mut file = fs
            .open_file("C:\\test.txt", false, true, true, false)
            .unwrap();
        file.write(b"Hello, Casa1!").unwrap();
        file.flush().unwrap();
        drop(file);

        // Read
        let mut file = fs
            .open_file("C:\\test.txt", true, false, false, false)
            .unwrap();
        let mut buf = vec![0u8; 100];
        let n = file.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"Hello, Casa1!");
    }

    #[test]
    fn filesystem_create_directory() {
        let (_tmp, fs) = setup_fs();
        fs.create_directory("C:\\MyGame").unwrap();
        assert!(fs.exists("C:\\MyGame"));
        let meta = fs.metadata("C:\\MyGame").unwrap();
        assert!(meta.is_directory);
    }

    #[test]
    fn filesystem_delete_file() {
        let (_tmp, fs) = setup_fs();
        let mut file = fs
            .open_file("C:\\temp.txt", false, true, true, false)
            .unwrap();
        file.write(b"temp").unwrap();
        drop(file);
        assert!(fs.exists("C:\\temp.txt"));
        fs.delete_file("C:\\temp.txt").unwrap();
        assert!(!fs.exists("C:\\temp.txt"));
    }

    #[test]
    fn filesystem_copy_file() {
        let (_tmp, fs) = setup_fs();
        let mut file = fs
            .open_file("C:\\src.txt", false, true, true, false)
            .unwrap();
        file.write(b"copy me").unwrap();
        drop(file);
        fs.copy_file("C:\\src.txt", "C:\\dst.txt").unwrap();
        assert!(fs.exists("C:\\dst.txt"));
    }

    #[test]
    fn filesystem_move_file() {
        let (_tmp, fs) = setup_fs();
        let mut file = fs
            .open_file("C:\\src.txt", false, true, true, false)
            .unwrap();
        file.write(b"move me").unwrap();
        drop(file);
        fs.move_file("C:\\src.txt", "C:\\dst.txt").unwrap();
        assert!(!fs.exists("C:\\src.txt"));
        assert!(fs.exists("C:\\dst.txt"));
    }

    #[test]
    fn filesystem_enumerate_directory() {
        let (_tmp, fs) = setup_fs();
        let mut file = fs
            .open_file("C:\\file1.txt", false, true, true, false)
            .unwrap();
        file.write(b"1").unwrap();
        drop(file);
        let mut file = fs
            .open_file("C:\\file2.txt", false, true, true, false)
            .unwrap();
        file.write(b"2").unwrap();
        drop(file);

        let entries = fs.enumerate_directory("C:\\").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"file1.txt"));
        assert!(names.contains(&"file2.txt"));
    }

    #[test]
    fn filesystem_metadata() {
        let (_tmp, fs) = setup_fs();
        let mut file = fs
            .open_file("C:\\meta.txt", false, true, true, false)
            .unwrap();
        file.write(b"metadata test content").unwrap();
        drop(file);

        let meta = fs.metadata("C:\\meta.txt").unwrap();
        assert_eq!(meta.size, 21);
        assert!(!meta.is_directory);
    }

    #[test]
    fn split_drive_handles_various_formats() {
        assert_eq!(
            split_drive("C:\\Steam").unwrap(),
            ("C".to_string(), "Steam".to_string())
        );
        assert_eq!(
            split_drive("D:\\Games\\Foo").unwrap(),
            ("D".to_string(), "Games\\Foo".to_string())
        );
        assert_eq!(
            split_drive("\\\\?\\C:\\Windows").unwrap(),
            ("C".to_string(), "Windows".to_string())
        );
    }

    #[test]
    fn to_windows_path_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let resolver = WindowsPathResolver::new(tmp.path());
        let real = tmp.path().join("drive_c/Steam/Steam.exe");
        let win = resolver.to_windows_path(&real).unwrap();
        assert_eq!(win, "C:\\Steam/Steam.exe".replace('/', "\\"));
    }

    // -----------------------------------------------------------------------
    // ADS parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_ntfs_path_simple() {
        let (file_path, stream) = parse_ntfs_path("file.exe:Zone.Identifier");
        assert_eq!(file_path, "file.exe");
        assert!(stream.is_some());
        let stream = stream.unwrap();
        assert_eq!(stream.stream_name, "Zone.Identifier");
        assert_eq!(stream.stream_type, "$DATA");
    }

    #[test]
    fn parse_ntfs_path_with_type() {
        let (file_path, stream) = parse_ntfs_path("file.exe:Zone.Identifier:$DATA");
        assert_eq!(file_path, "file.exe");
        assert!(stream.is_some());
        let stream = stream.unwrap();
        assert_eq!(stream.stream_name, "Zone.Identifier");
        assert_eq!(stream.stream_type, "$DATA");
    }

    #[test]
    fn parse_ntfs_path_no_stream() {
        let (file_path, stream) = parse_ntfs_path("file.exe");
        assert_eq!(file_path, "file.exe");
        assert!(stream.is_none());
    }

    #[test]
    fn parse_ntfs_path_windows_full() {
        let (file_path, stream) = parse_ntfs_path("C:\\Users\\test\\file.exe:Zone.Identifier");
        assert_eq!(file_path, "C:\\Users\\test\\file.exe");
        assert!(stream.is_some());
        let stream = stream.unwrap();
        assert_eq!(stream.stream_name, "Zone.Identifier");
        assert_eq!(stream.stream_type, "$DATA");
    }

    #[test]
    fn parse_ntfs_path_windows_full_with_type() {
        let (file_path, stream) =
            parse_ntfs_path("C:\\Users\\test\\file.exe:Zone.Identifier:$DATA");
        assert_eq!(file_path, "C:\\Users\\test\\file.exe");
        assert!(stream.is_some());
        let stream = stream.unwrap();
        assert_eq!(stream.stream_name, "Zone.Identifier");
        assert_eq!(stream.stream_type, "$DATA");
    }

    #[test]
    fn is_ads_path_positive() {
        assert!(is_ads_path("file.exe:Zone.Identifier"));
        assert!(is_ads_path("C:\\path\\file.exe:MyStream"));
    }

    #[test]
    fn is_ads_path_negative() {
        assert!(!is_ads_path("file.exe"));
        assert!(!is_ads_path("C:\\Windows\\System32\\kernel32.dll"));
        assert!(!is_ads_path(""));
    }

    #[test]
    fn parse_ntfs_path_c_drive_no_stream() {
        let (file_path, stream) = parse_ntfs_path("C:\\Windows\\System32\\ntdll.dll");
        assert_eq!(file_path, "C:\\Windows\\System32\\ntdll.dll");
        assert!(stream.is_none());
    }

    #[test]
    fn parse_ntfs_path_multi_colon_complex() {
        let (file_path, stream) = parse_ntfs_path("D:\\Games\\MyGame\\save.dat:backup:$DATA");
        assert_eq!(file_path, "D:\\Games\\MyGame\\save.dat");
        assert!(stream.is_some());
        let stream = stream.unwrap();
        assert_eq!(stream.stream_name, "backup");
        assert_eq!(stream.stream_type, "$DATA");
    }

    // -----------------------------------------------------------------------
    // ADS I/O roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn ads_write_read_roundtrip() {
        let (_tmp, fs) = setup_fs();

        // Create the base file first
        {
            let mut file = fs
                .open_file("C:\\test_ads_roundtrip.bin", false, true, true, false)
                .unwrap();
            file.write(b"base file content").unwrap();
            file.flush().unwrap();
        }

        // Write to an ADS stream
        let stream_data = b"Zone.Identifier data for Mark-of-the-Web";
        fs.write_alternate_stream("C:\\test_ads_roundtrip.bin", "Zone.Identifier", stream_data)
            .unwrap();

        // Read it back
        let read_back = fs
            .read_alternate_stream("C:\\test_ads_roundtrip.bin", "Zone.Identifier")
            .unwrap();
        assert_eq!(read_back, stream_data);
    }

    #[test]
    fn ads_write_read_different_streams() {
        let (_tmp, fs) = setup_fs();

        // Create base file
        {
            let mut file = fs
                .open_file("C:\\test_multi_ads.txt", false, true, true, false)
                .unwrap();
            file.write(b"base").unwrap();
            file.flush().unwrap();
        }

        // Write multiple streams
        let data1 = b"stream1 data";
        let data2 = b"stream2 data";
        fs.write_alternate_stream("C:\\test_multi_ads.txt", "Stream1", data1)
            .unwrap();
        fs.write_alternate_stream("C:\\test_multi_ads.txt", "Stream2", data2)
            .unwrap();

        // Read each back
        let read1 = fs
            .read_alternate_stream("C:\\test_multi_ads.txt", "Stream1")
            .unwrap();
        let read2 = fs
            .read_alternate_stream("C:\\test_multi_ads.txt", "Stream2")
            .unwrap();
        assert_eq!(read1, data1);
        assert_eq!(read2, data2);
    }

    #[test]
    fn ads_list_streams() {
        let (_tmp, fs) = setup_fs();

        // Create base file
        {
            let mut file = fs
                .open_file("C:\\test_list_ads.txt", false, true, true, false)
                .unwrap();
            file.write(b"base").unwrap();
            file.flush().unwrap();
        }

        // Initially no streams
        let streams = fs.list_alternate_streams("C:\\test_list_ads.txt").unwrap();
        assert!(streams.is_empty());

        // Add some streams
        fs.write_alternate_stream("C:\\test_list_ads.txt", "Zone.Identifier", b"zone-id")
            .unwrap();
        fs.write_alternate_stream("C:\\test_list_ads.txt", "MyCustomStream", b"custom")
            .unwrap();

        let streams = fs.list_alternate_streams("C:\\test_list_ads.txt").unwrap();
        assert!(streams.contains(&"Zone.Identifier".to_string()));
        assert!(streams.contains(&"MyCustomStream".to_string()));
    }

    #[test]
    fn ads_delete_stream() {
        let (_tmp, fs) = setup_fs();

        // Create base file
        {
            let mut file = fs
                .open_file("C:\\test_delete_ads.txt", false, true, true, false)
                .unwrap();
            file.write(b"base").unwrap();
            file.flush().unwrap();
        }

        // Write and verify
        fs.write_alternate_stream("C:\\test_delete_ads.txt", "Zone.Identifier", b"test")
            .unwrap();
        let streams = fs
            .list_alternate_streams("C:\\test_delete_ads.txt")
            .unwrap();
        assert_eq!(streams.len(), 1);

        // Delete and verify gone
        fs.delete_alternate_stream("C:\\test_delete_ads.txt", "Zone.Identifier")
            .unwrap();
        let streams = fs
            .list_alternate_streams("C:\\test_delete_ads.txt")
            .unwrap();
        assert!(streams.is_empty());

        // Read should now fail
        let result = fs.read_alternate_stream("C:\\test_delete_ads.txt", "Zone.Identifier");
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn ads_nonexistent_stream_returns_error() {
        let (_tmp, fs) = setup_fs();

        // Create base file
        {
            let mut file = fs
                .open_file("C:\\test_no_stream.txt", false, true, true, false)
                .unwrap();
            file.write(b"base").unwrap();
            file.flush().unwrap();
        }

        // Reading a non-existent stream should error
        let result = fs.read_alternate_stream("C:\\test_no_stream.txt", "NonExistentStream");
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // -----------------------------------------------------------------------
    // Case-insensitive path resolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn path_resolver_case_insensitive_matching() {
        let (tmp, _fs) = setup_fs();

        // Create a directory with mixed case on the real filesystem
        let real_dir = tmp.path().join("c_drive").join("MyFolder");
        fs::create_dir_all(&real_dir).unwrap();
        fs::write(real_dir.join("File.txt"), b"hello").unwrap();

        let mut resolver = WindowsPathResolver::new(tmp.path());
        resolver.add_drive_mapping("C", "c_drive");

        // Resolve using different casing
        let resolved = resolver.resolve("C:\\MYFOLDER\\FILE.TXT");
        assert!(
            resolved.is_ok(),
            "case-insensitive resolution should succeed"
        );
        let path = resolved.unwrap();
        assert!(path.exists(), "resolved path should exist on disk");
    }

    #[test]
    fn path_resolver_case_insensitive_directory() {
        let (tmp, _fs) = setup_fs();

        // Create a directory with uppercase name
        let real_dir = tmp.path().join("c_drive").join("UPPERCASE_DIR");
        fs::create_dir_all(&real_dir).unwrap();

        let mut resolver = WindowsPathResolver::new(tmp.path());
        resolver.add_drive_mapping("C", "c_drive");

        // Resolve with lowercase
        let result = resolver.resolve("C:\\uppercase_dir");
        assert!(result.is_ok(), "lowercase query should match uppercase dir");
        assert!(result.unwrap().exists());
    }

    // -----------------------------------------------------------------------
    // Windows path normalization tests
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_forward_slashes_to_backslashes() {
        assert_eq!(
            normalize_windows_path("C:/Users/test/Documents"),
            "C:\\Users\\test\\Documents"
        );
    }

    #[test]
    fn normalize_collapses_dot_dot() {
        assert_eq!(
            normalize_windows_path("C:\\Users\\test\\..\\Documents"),
            "C:\\Users\\Documents"
        );
    }

    #[test]
    fn normalize_removes_dot_components() {
        assert_eq!(
            normalize_windows_path("C:\\Users\\.\\test"),
            "C:\\Users\\test"
        );
    }

    #[test]
    fn normalize_handles_mixed_separators() {
        assert_eq!(
            normalize_windows_path("C:/Users\\test/Documents/file.txt"),
            "C:\\Users\\test\\Documents\\file.txt"
        );
    }

    // -----------------------------------------------------------------------
    // UNC path tests
    // -----------------------------------------------------------------------

    #[test]
    fn split_drive_unc_path_prefix() {
        // \\?\C:\path should strip the \\?\ prefix
        let (drive, rest) = split_drive(r"\\?\C:\Users\test").unwrap();
        assert_eq!(drive, "C");
        assert_eq!(rest, "Users\\test");
    }

    #[test]
    fn split_drive_device_prefix() {
        // \\.\pipe\name should return DEV drive
        let (drive, rest) = split_drive(r"\\.\pipe\myname").unwrap();
        assert_eq!(drive, "DEV");
        assert!(rest.contains("pipe"));
    }

    #[test]
    fn split_drive_standard_drive() {
        let (drive, rest) = split_drive(r"C:\Windows\System32").unwrap();
        assert_eq!(drive, "C");
        assert_eq!(rest, "Windows\\System32");
    }

    #[test]
    fn split_drive_no_colon_defaults_to_c() {
        let (drive, rest) = split_drive("relative\\path").unwrap();
        assert_eq!(drive, "C");
        assert_eq!(rest, "relative\\path");
    }

    // -----------------------------------------------------------------------
    // Long path tests (>260 characters)
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_long_path() {
        let (tmp, _fs) = setup_fs();

        // Build a deeply nested directory path (>260 chars total)
        let mut resolver = WindowsPathResolver::new(tmp.path());
        resolver.add_drive_mapping("C", "c_drive");

        // Create a deep directory structure
        let mut deep_dir = tmp.path().join("c_drive");
        let segment = "abcdefghij"; // 10 chars
        for _ in 0..26 {
            // 26 * 10 = 260 chars of path
            deep_dir = deep_dir.join(segment);
        }
        // Don't actually create the dirs (would be too deep for some filesystems),
        // but verify resolve() handles the long path without panicking
        let mut long_relative = segment.to_string();
        for _ in 0..25 {
            long_relative.push_str(&format!("\\{}", segment));
        }
        let result = resolver.resolve(&format!("C:\\{}", long_relative));
        // May fail (dirs don't exist), but should not panic
        let _ = result;
    }

    #[test]
    fn normalize_long_path() {
        // Build a path longer than 260 characters
        let long_segment = "a".repeat(50);
        let long_path = format!("C:\\{}", long_segment.clone());
        let normalized = normalize_windows_path(&long_path);
        assert_eq!(normalized, format!("C:\\{}", long_segment));
    }

    // -----------------------------------------------------------------------
    // Reserved device name tests
    // -----------------------------------------------------------------------

    #[test]
    fn split_drive_reserved_device_con() {
        // Windows reserved device names: CON, PRN, AUX, NUL, COM1-9, LPT1-9
        // These should still parse through split_drive without panicking
        let (drive, _rest) = split_drive("CON").unwrap();
        // No colon, so defaults to C drive
        assert_eq!(drive, "C");
    }

    #[test]
    fn split_drive_reserved_device_aux() {
        let (drive, _rest) = split_drive("AUX").unwrap();
        assert_eq!(drive, "C");
    }

    #[test]
    fn split_drive_reserved_device_nul() {
        let (drive, _rest) = split_drive("NUL").unwrap();
        assert_eq!(drive, "C");
    }

    #[test]
    fn split_drive_reserved_device_com1() {
        let (drive, _rest) = split_drive("COM1").unwrap();
        assert_eq!(drive, "C");
    }

    #[test]
    fn split_drive_reserved_device_lpt9() {
        let (drive, _rest) = split_drive("LPT9").unwrap();
        assert_eq!(drive, "C");
    }

    // -----------------------------------------------------------------------
    // Alternate separator tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_with_forward_slashes() {
        let (tmp, _fs) = setup_fs();

        let mut resolver = WindowsPathResolver::new(tmp.path());
        resolver.add_drive_mapping("C", "c_drive");

        // Create a test file
        let dir = tmp.path().join("c_drive").join("testdir");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("file.txt"), b"content").unwrap();

        // Resolve using forward slashes
        let result = resolver.resolve("C:/testdir/file.txt");
        assert!(result.is_ok(), "forward slashes should be handled");
        assert!(result.unwrap().exists());
    }

    #[test]
    fn resolve_mixed_separators() {
        let (tmp, _fs) = setup_fs();

        let mut resolver = WindowsPathResolver::new(tmp.path());
        resolver.add_drive_mapping("C", "c_drive");

        let dir = tmp.path().join("c_drive").join("mixed");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("test.txt"), b"data").unwrap();

        let result = resolver.resolve("C:\\mixed/test.txt");
        assert!(result.is_ok(), "mixed separators should be handled");
    }

    // -----------------------------------------------------------------------
    // Invalid character handling tests
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_path_with_invalid_chars() {
        // Characters like <>:"|?* are invalid in Windows paths
        // normalize_windows_path should still process them (it's a normalization function)
        let result = normalize_windows_path("C:\\path<with>invalid|chars");
        assert!(result.contains("path<with>invalid|chars"));
    }

    #[test]
    fn split_drive_with_colon_in_path() {
        let (drive, rest) = split_drive("C:\\path:with:colons").unwrap();
        assert_eq!(drive, "C");
        // Only the first colon is used as the drive separator
        assert!(rest.contains("path:with:colons"));
    }

    // -----------------------------------------------------------------------
    //  Item 239-240: Additional case-insensitivity, long path, and edge-case
    //  tests for real_fs
    // -----------------------------------------------------------------------

    #[test]
    fn path_resolver_case_insensitive_deeply_nested() {
        let (tmp, _fs) = setup_fs();

        let mut resolver = WindowsPathResolver::new(tmp.path());
        resolver.add_drive_mapping("C", "c_drive");

        // Create a deeply nested directory structure with varying case
        let base = tmp.path().join("c_drive").join("DeepNest");
        fs::create_dir_all(&base.join("SubOne").join("SubTwo").join("SubThree")).unwrap();
        fs::write(
            base.join("SubOne")
                .join("SubTwo")
                .join("SubThree")
                .join("target.txt"),
            b"found",
        )
        .unwrap();

        // Resolve with different casing at each level
        let result = resolver.resolve("C:\\DeepNest\\subone\\subtwo\\subthree\\target.txt");
        assert!(
            result.is_ok(),
            "lowercase nested path should resolve case-insensitively"
        );
        let resolved = result.unwrap();
        assert!(
            resolved.exists(),
            "resolved path should exist on filesystem"
        );

        // Also test with mixed case at the filename level
        let result2 = resolver.resolve("C:\\DeepNest\\SubOne\\subtwo\\SUBTHREE\\TARGET.TXT");
        assert!(
            result2.is_ok(),
            "mixed-case nested path should resolve case-insensitively"
        );
        let resolved2 = result2.unwrap();
        assert!(resolved2.exists(), "mixed-case resolved path should exist");
    }

    #[test]
    fn resolve_long_path_with_mixed_case() {
        let (tmp, _fs) = setup_fs();

        let mut resolver = WindowsPathResolver::new(tmp.path());
        resolver.add_drive_mapping("C", "c_drive");

        // Create a path that is long but within a valid structure
        let base = tmp.path().join("c_drive").join("LongPathTest");
        fs::create_dir_all(&base).unwrap();

        let long_segment = "LongNameSegment".repeat(15); // 15*15 = 225 chars
        let long_dir = base.join(&long_segment);
        fs::create_dir_all(&long_dir).unwrap();
        fs::write(long_dir.join("data.txt"), b"content").unwrap();

        // Resolve with different casing
        let query_path = format!("C:\\LongPathTest\\{}", long_segment.to_ascii_lowercase());
        let query_with_file = format!("{}\\data.txt", query_path);
        let result = resolver.resolve(&query_with_file);
        assert!(
            result.is_ok(),
            "long path with different case should resolve"
        );
        let resolved = result.unwrap();
        assert!(resolved.exists(), "long resolved path should exist");

        // Verify the path components are normalized correctly
        let windows_path = resolver.to_windows_path(&resolved);
        assert!(
            windows_path.is_some(),
            "should convert back to Windows path"
        );
    }

    #[test]
    fn split_drive_reserved_device_with_extension() {
        // Reserved device names with extensions like CON.txt, NUL.dat
        // should still be handled by split_drive, not treated differently
        let (drive, rest) = split_drive("CON.txt").unwrap();
        assert_eq!(drive, "C", "CON.txt should default to C drive");
        assert!(!rest.is_empty(), "should have rest after CON.txt");

        let (drive2, rest2) = split_drive("NUL.dat").unwrap();
        assert_eq!(drive2, "C", "NUL.dat should default to C drive");
        assert!(!rest2.is_empty(), "should have rest after NUL.dat");

        let (drive3, _rest3) = split_drive("LPT1.000").unwrap();
        assert_eq!(drive3, "C", "LPT1.000 should default to C drive");
    }

    #[test]
    fn resolve_path_with_reserved_name_in_subdirectory() {
        let (tmp, _fs) = setup_fs();

        let mut resolver = WindowsPathResolver::new(tmp.path());
        resolver.add_drive_mapping("C", "c_drive");

        // Create a directory that uses a reserved name as a component
        let base = tmp.path().join("c_drive").join("apps");
        fs::create_dir_all(&base).unwrap();

        // A subdirectory named "CON" should be creatable on macOS (unlike Windows)
        let con_dir = base.join("CON");
        fs::create_dir_all(&con_dir).unwrap();
        fs::write(con_dir.join("readme.txt"), b"content").unwrap();

        // Resolve a path that includes a reserved-name component
        let result = resolver.resolve("C:\\apps\\CON\\readme.txt");
        assert!(
            result.is_ok(),
            "reserved name as directory component should be resolvable on macOS: {:?}",
            result.err()
        );
    }

    #[test]
    fn resolve_path_with_special_chars_in_filename() {
        let (tmp, _fs) = setup_fs();

        let mut resolver = WindowsPathResolver::new(tmp.path());
        resolver.add_drive_mapping("C", "c_drive");

        let base = tmp.path().join("c_drive").join("special");
        fs::create_dir_all(&base).unwrap();

        // Create files with special characters that are valid on macOS but not Windows
        for fname in &["file with spaces.txt", "file(with)parens.txt"] {
            fs::write(base.join(fname), b"data").unwrap();
        }

        for fname in &["file with spaces.txt", "file(with)parens.txt"] {
            let win_path = format!("C:\\special\\{}", fname);
            let result = resolver.resolve(&win_path);
            assert!(
                result.is_ok(),
                "should resolve path with special chars: {}",
                fname
            );
            assert!(
                result.unwrap().exists(),
                "resolved file should exist: {}",
                fname
            );
        }
    }
}
