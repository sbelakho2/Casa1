//! Search-path resolution helpers.

use super::*;

/// Resolve a file name against the Windows search path (SearchPathW).
///
/// With an explicit `search_dirs` list, each `;`-separated entry is tried in
/// order (an empty entry means the current directory).  With `None`, the
/// standard DLL search order applies: the current (application) directory,
/// `C:\Windows\System32`, `C:\Windows`, then the PATH environment entries.
/// `extension` (e.g. `.exe`) is appended when the file name has no
/// extension.  Returns the first existing candidate as a guest path, or
/// `None` when nothing exists.
pub(crate) fn resolve_search_path(
    win32: &crate::win32::Win32Subsystem,
    current_directory: &str,
    environment: &BTreeMap<String, String>,
    search_dirs: Option<&str>,
    file_name: &str,
    extension: Option<&str>,
) -> Option<String> {
    if file_name.is_empty() {
        return None;
    }
    let mut name = file_name.to_string();
    let has_extension = file_name
        .rsplit(['\\', '/'])
        .next()
        .is_some_and(|component| component.contains('.'));
    if !has_extension
        && let Some(extension) = extension
        && !extension.is_empty()
    {
        name.push_str(extension);
    }
    let mut directories = Vec::new();
    match search_dirs {
        Some(list) => {
            for entry in list.split(';') {
                let trimmed = entry.trim_end_matches(['\\', '/']);
                if trimmed.is_empty() {
                    directories.push(current_directory.to_string());
                } else {
                    directories.push(trimmed.to_string());
                }
            }
        }
        None => {
            directories.push(current_directory.to_string());
            directories.push(r"C:\Windows\System32".to_string());
            directories.push(r"C:\Windows".to_string());
            if let Some(path_value) = environment.get("PATH") {
                for entry in path_value.split(';') {
                    let trimmed = entry.trim_end_matches(['\\', '/']);
                    if !trimmed.is_empty() {
                        directories.push(trimmed.to_string());
                    }
                }
            }
        }
    }
    for directory in directories {
        let candidate = if directory.ends_with(['\\', '/']) {
            format!("{directory}{name}")
        } else {
            format!("{directory}\\{name}")
        };
        if win32.get_file_attributes_w(&candidate).is_ok() {
            return Some(candidate);
        }
    }
    None
}
