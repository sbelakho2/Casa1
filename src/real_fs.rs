//! Real filesystem I/O passthrough for Casa1.
//!
//! Maps Windows paths to macOS paths within the Game Environment root directory.
//! Uses real `std::fs` operations for actual disk I/O while maintaining the
//! Windows filesystem semantics (case-insensitive, share modes, byte-range locks).

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

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
        self.drive_mappings.insert(drive_letter.to_uppercase(), subdirectory.to_string());
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
            ".." => { components.pop(); }
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
            return Err(AppError::new(ReasonCode::RcCliInvalid, "file not opened for reading"));
        }
        self.file.read(buf).map_err(|e| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("read error: {e}"))
        })
    }

    pub fn write(&mut self, buf: &[u8]) -> AppResult<usize> {
        if !self.can_write {
            return Err(AppError::new(ReasonCode::RcCliInvalid, "file not opened for writing"));
        }
        self.file.write(buf).map_err(|e| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("write error: {e}"))
        })
    }

    pub fn seek(&mut self, pos: SeekFrom) -> AppResult<u64> {
        self.file.seek(pos).map_err(|e| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("seek error: {e}"))
        })
    }

    pub fn flush(&mut self) -> AppResult<()> {
        self.file.flush().map_err(|e| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("flush error: {e}"))
        })
    }

    pub fn size(&self) -> AppResult<u64> {
        let metadata = self.file.metadata().map_err(|e| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("metadata error: {e}"))
        })?;
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
                AppError::new(ReasonCode::RcCliInvalid, format!("cannot create parent dir: {e}"))
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
            AppError::new(ReasonCode::RcCliInvalid, format!("cannot create directory: {e}"))
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
            AppError::new(ReasonCode::RcUnimplInsn, format!("cannot remove directory: {e}"))
        })
    }

    /// Move/rename a file.
    pub fn move_file(&self, src: &str, dst: &str) -> AppResult<()> {
        let src_path = self.resolver.resolve(src)?;
        let dst_path = self.resolver.resolve(dst)?;

        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::new(ReasonCode::RcCliInvalid, format!("cannot create parent dir: {e}"))
            })?;
        }

        fs::rename(&src_path, &dst_path).map_err(|e| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("cannot move file: {e}"))
        })
    }

    /// Copy a file.
    pub fn copy_file(&self, src: &str, dst: &str) -> AppResult<u64> {
        let src_path = self.resolver.resolve(src)?;
        let dst_path = self.resolver.resolve(dst)?;

        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::new(ReasonCode::RcCliInvalid, format!("cannot create parent dir: {e}"))
            })?;
        }

        fs::copy(&src_path, &dst_path).map_err(|e| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("cannot copy file: {e}"))
        })
    }

    /// Check if a file exists.
    pub fn exists(&self, windows_path: &str) -> bool {
        self.resolver.resolve(windows_path)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Get file metadata.
    pub fn metadata(&self, windows_path: &str) -> AppResult<FileMetadata> {
        let real_path = self.resolver.resolve(windows_path)?;
        let meta = fs::metadata(&real_path).map_err(|e| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("cannot get metadata: {e}"))
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
            AppError::new(ReasonCode::RcUnimplInsn, format!("cannot read directory: {e}"))
        })?;

        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let meta = entry.metadata().map_err(|e| {
                AppError::new(ReasonCode::RcUnimplInsn, format!("cannot read entry metadata: {e}"))
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
        assert_eq!(path, tmp.path().join("drive_c").join("Steam").join("Steam.exe"));
    }

    #[test]
    fn path_resolver_normalizes_separators() {
        let tmp = TempDir::new().unwrap();
        let resolver = WindowsPathResolver::new(tmp.path());
        let path = resolver.resolve("C:/Steam/Steam.exe").unwrap();
        assert_eq!(path, tmp.path().join("drive_c").join("Steam").join("Steam.exe"));
    }

    #[test]
    fn path_resolver_handles_dot_dot() {
        let tmp = TempDir::new().unwrap();
        let resolver = WindowsPathResolver::new(tmp.path());
        let path = resolver.resolve("C:\\Steam\\..\\Windows\\System32").unwrap();
        assert_eq!(path, tmp.path().join("drive_c").join("Windows").join("System32"));
    }

    #[test]
    fn filesystem_creates_directories() {
        let (_tmp, fs) = setup_fs();
        assert!(fs.resolver().ge_root().join("drive_c/Windows/System32").exists());
        assert!(fs.resolver().ge_root().join("drive_c/Program Files").exists());
    }

    #[test]
    fn filesystem_write_and_read_file() {
        let (_tmp, fs) = setup_fs();

        // Write
        let mut file = fs.open_file("C:\\test.txt", false, true, true, false).unwrap();
        file.write(b"Hello, Casa1!").unwrap();
        file.flush().unwrap();
        drop(file);

        // Read
        let mut file = fs.open_file("C:\\test.txt", true, false, false, false).unwrap();
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
        let mut file = fs.open_file("C:\\temp.txt", false, true, true, false).unwrap();
        file.write(b"temp").unwrap();
        drop(file);
        assert!(fs.exists("C:\\temp.txt"));
        fs.delete_file("C:\\temp.txt").unwrap();
        assert!(!fs.exists("C:\\temp.txt"));
    }

    #[test]
    fn filesystem_copy_file() {
        let (_tmp, fs) = setup_fs();
        let mut file = fs.open_file("C:\\src.txt", false, true, true, false).unwrap();
        file.write(b"copy me").unwrap();
        drop(file);
        fs.copy_file("C:\\src.txt", "C:\\dst.txt").unwrap();
        assert!(fs.exists("C:\\dst.txt"));
    }

    #[test]
    fn filesystem_move_file() {
        let (_tmp, fs) = setup_fs();
        let mut file = fs.open_file("C:\\src.txt", false, true, true, false).unwrap();
        file.write(b"move me").unwrap();
        drop(file);
        fs.move_file("C:\\src.txt", "C:\\dst.txt").unwrap();
        assert!(!fs.exists("C:\\src.txt"));
        assert!(fs.exists("C:\\dst.txt"));
    }

    #[test]
    fn filesystem_enumerate_directory() {
        let (_tmp, fs) = setup_fs();
        let mut file = fs.open_file("C:\\file1.txt", false, true, true, false).unwrap();
        file.write(b"1").unwrap();
        drop(file);
        let mut file = fs.open_file("C:\\file2.txt", false, true, true, false).unwrap();
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
        let mut file = fs.open_file("C:\\meta.txt", false, true, true, false).unwrap();
        file.write(b"metadata test content").unwrap();
        drop(file);

        let meta = fs.metadata("C:\\meta.txt").unwrap();
        assert_eq!(meta.size, 21);
        assert!(!meta.is_directory);
    }

    #[test]
    fn split_drive_handles_various_formats() {
        assert_eq!(split_drive("C:\\Steam").unwrap(), ("C".to_string(), "Steam".to_string()));
        assert_eq!(split_drive("D:\\Games\\Foo").unwrap(), ("D".to_string(), "Games\\Foo".to_string()));
        assert_eq!(split_drive("\\\\?\\C:\\Windows").unwrap(), ("C".to_string(), "Windows".to_string()));
    }

    #[test]
    fn to_windows_path_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let resolver = WindowsPathResolver::new(tmp.path());
        let real = tmp.path().join("drive_c/Steam/Steam.exe");
        let win = resolver.to_windows_path(&real).unwrap();
        assert_eq!(win, "C:\\Steam/Steam.exe".replace('/', "\\"));
    }
}
