use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Data types (unchanged from original)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum InstallerFramework {
    Nsis,
    InnoSetup,
    WixBundle,
    Msi,
    InstallShield,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuiWindowPlan {
    pub title: String,
    pub modal: bool,
    pub controls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallerSpec {
    pub id: String,
    pub executable_name: String,
    pub framework: InstallerFramework,
    pub gui_windows: Vec<GuiWindowPlan>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub registry: BTreeMap<String, String>,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallerTelemetry {
    pub installer_id: String,
    pub exit_code: i32,
    pub created_files: Vec<String>,
    pub registry_changes: Vec<String>,
    pub logs: Vec<String>,
    pub window_titles: Vec<String>,
    pub silent_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MsiComponent {
    pub id: String,
    pub keypath: String,
    pub files: BTreeMap<String, Vec<u8>>,
    pub registry: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CustomAction {
    Exe {
        id: String,
        command: String,
        env: BTreeMap<String, String>,
    },
    Dll {
        id: String,
        dll_path: String,
        entrypoint: String,
    },
    ServiceInstall {
        id: String,
        service_name: String,
    },
}

impl CustomAction {
    fn id(&self) -> &str {
        match self {
            Self::Exe { id, .. } | Self::Dll { id, .. } | Self::ServiceInstall { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MsiPackage {
    pub product_code: String,
    pub components: Vec<MsiComponent>,
    pub custom_actions: Vec<CustomAction>,
    pub rollback_script: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MsiInstallOptions {
    pub fail_after_custom_action: Option<String>,
    pub scm_vm_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAssembly {
    pub version: String,
    pub manifest: String,
    pub dlls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchOperation {
    pub target_path: String,
    pub expected_old: Vec<u8>,
    pub replacement: Vec<u8>,
    pub download_chunks: Vec<(String, usize, Vec<u8>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallerRunResult {
    pub telemetry: InstallerTelemetry,
    pub manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchCycleResult {
    pub final_tree_hash: String,
    pub operation_log: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedMsiScript {
    pub product_code: String,
    pub component_count: u8,
    pub custom_action_count: u8,
}

#[derive(Debug, Clone)]
struct InstalledPackage {
    package: MsiPackage,
}

// ---------------------------------------------------------------------------
// InstallerEngine – GE state container (files, registry, installed packages …)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct InstallerEngine {
    files: BTreeMap<String, Vec<u8>>,
    registry: BTreeMap<String, String>,
    installed_packages: BTreeMap<String, InstalledPackage>,
    vc_runtimes: BTreeMap<String, RuntimeAssembly>,
    directx_components: BTreeSet<String>,
    supported_dotnet: BTreeSet<String>,
    locked_paths: BTreeSet<String>,
    delete_on_close: BTreeSet<String>,
    telemetry_log: Vec<InstallerTelemetry>,
}

impl InstallerEngine {
    pub fn new() -> Self {
        Self {
            supported_dotnet: BTreeSet::from([
                "net48".to_string(),
                "net6.0".to_string(),
                "net8.0".to_string(),
            ]),
            ..Self::default()
        }
    }

    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    pub fn registry(&self) -> &BTreeMap<String, String> {
        &self.registry
    }

    pub fn telemetry_log(&self) -> &[InstallerTelemetry] {
        &self.telemetry_log
    }

    pub fn remove_file(&mut self, path: &str) {
        self.files.remove(&normalize_path(path));
    }

    pub fn detect_silent_flags(
        &self,
        framework: InstallerFramework,
        user_override: Option<Vec<String>>,
    ) -> Vec<String> {
        user_override.unwrap_or_else(|| match framework {
            InstallerFramework::Nsis => vec!["/S".to_string()],
            InstallerFramework::InnoSetup => {
                vec!["/VERYSILENT".to_string(), "/SUPPRESSMSGBOXES".to_string()]
            }
            InstallerFramework::WixBundle => vec!["/quiet".to_string(), "/norestart".to_string()],
            InstallerFramework::Msi => vec!["/qn".to_string(), "/norestart".to_string()],
            InstallerFramework::InstallShield => {
                vec!["/s".to_string(), "/f1\"setup.iss\"".to_string()]
            }
            InstallerFramework::Custom => vec!["--silent".to_string()],
        })
    }

    pub fn run_gui_installer(
        &mut self,
        spec: &InstallerSpec,
        user_silent_flags: Option<Vec<String>>,
    ) -> AppResult<InstallerRunResult> {
        let silent_flags = self.detect_silent_flags(spec.framework, user_silent_flags);
        for (path, bytes) in &spec.files {
            self.files.insert(normalize_path(path), bytes.clone());
        }
        for (key, value) in &spec.registry {
            self.registry.insert(key.clone(), value.clone());
        }
        let telemetry = InstallerTelemetry {
            installer_id: spec.id.clone(),
            exit_code: 0,
            created_files: spec.files.keys().map(|path| normalize_path(path)).collect(),
            registry_changes: spec.registry.keys().cloned().collect(),
            logs: spec.logs.clone(),
            window_titles: spec.gui_windows.iter().map(|window| window.title.clone()).collect(),
            silent_flags,
        };
        self.telemetry_log.push(telemetry.clone());
        Ok(InstallerRunResult {
            manifest_hash: self.tree_hash(),
            telemetry,
        })
    }

    pub fn msiexec_install(
        &mut self,
        package: MsiPackage,
        options: &MsiInstallOptions,
    ) -> AppResult<InstallerTelemetry> {
        let files_snapshot = self.files.clone();
        let registry_snapshot = self.registry.clone();
        let mut logs = Vec::new();
        let mut created_files = Vec::new();
        let mut registry_changes = Vec::new();

        for component in &package.components {
            for (path, bytes) in &component.files {
                let normalized = normalize_path(path);
                self.files.insert(normalized.clone(), bytes.clone());
                created_files.push(normalized);
            }
            for (key, value) in &component.registry {
                self.registry.insert(key.clone(), value.clone());
                registry_changes.push(key.clone());
            }
            logs.push(format!("component:{}:{}", component.id, component.keypath));
        }

        for action in &package.custom_actions {
            match action {
                CustomAction::Exe { id, command, env } => {
                    logs.push(format!("exe_ca:{id}:{command}:{}", stable_pairs(env)));
                }
                CustomAction::Dll { id, dll_path, entrypoint } => {
                    logs.push(format!("dll_ca:{id}:{dll_path}!{entrypoint}"));
                }
                CustomAction::ServiceInstall { id, service_name } => {
                    if !options.scm_vm_mode {
                        self.files = files_snapshot;
                        self.registry = registry_snapshot;
                        return Err(AppError::new(
                            ReasonCode::RcMsiCustomActionServiceBlocked,
                            format!("service custom action {service_name} blocked"),
                        )
                        .with_hint(format!("custom action id: {id}"))
                        .with_hint(package.rollback_script.join(" -> ")));
                    }
                    logs.push(format!("service_ca:{id}:{service_name}"));
                }
            }
            if options.fail_after_custom_action.as_deref() == Some(action.id()) {
                self.files = files_snapshot;
                self.registry = registry_snapshot;
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("custom action {} failed", action.id()),
                )
                .with_hint(package.rollback_script.join(" -> ")));
            }
        }

        self.installed_packages.insert(
            package.product_code.clone(),
            InstalledPackage {
                package: package.clone(),
            },
        );
        let telemetry = InstallerTelemetry {
            installer_id: package.product_code,
            exit_code: 0,
            created_files,
            registry_changes,
            logs,
            window_titles: vec!["msiexec".to_string()],
            silent_flags: vec!["/qn".to_string()],
        };
        self.telemetry_log.push(telemetry.clone());
        Ok(telemetry)
    }

    pub fn msiexec_uninstall(&mut self, product_code: &str) -> AppResult<InstallerTelemetry> {
        let installed = self.installed_packages.remove(product_code).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown MSI product {product_code}"))
        })?;
        let mut removed_files = Vec::new();
        let mut removed_registry = Vec::new();
        for component in &installed.package.components {
            for path in component.files.keys() {
                let normalized = normalize_path(path);
                self.files.remove(&normalized);
                removed_files.push(normalized);
            }
            for key in component.registry.keys() {
                self.registry.remove(key);
                removed_registry.push(key.clone());
            }
        }
        let telemetry = InstallerTelemetry {
            installer_id: product_code.to_string(),
            exit_code: 0,
            created_files: removed_files,
            registry_changes: removed_registry,
            logs: vec![format!("uninstall:{product_code}")],
            window_titles: vec!["msiexec".to_string()],
            silent_flags: vec!["/x".to_string()],
        };
        self.telemetry_log.push(telemetry.clone());
        Ok(telemetry)
    }

    pub fn msiexec_repair(&mut self, product_code: &str) -> AppResult<InstallerTelemetry> {
        let installed = self.installed_packages.get(product_code).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown MSI product {product_code}"))
        })?;
        let mut repaired = Vec::new();
        for component in &installed.package.components {
            if !self.files.contains_key(&normalize_path(&component.keypath)) {
                for (path, bytes) in &component.files {
                    let normalized = normalize_path(path);
                    self.files.insert(normalized.clone(), bytes.clone());
                    repaired.push(normalized);
                }
            }
        }
        let telemetry = InstallerTelemetry {
            installer_id: product_code.to_string(),
            exit_code: 0,
            created_files: repaired,
            registry_changes: Vec::new(),
            logs: vec![format!("repair:{product_code}")],
            window_titles: vec!["msiexec".to_string()],
            silent_flags: vec!["/f".to_string()],
        };
        self.telemetry_log.push(telemetry.clone());
        Ok(telemetry)
    }

    pub fn install_vc_runtime(&mut self, assembly: RuntimeAssembly) {
        for dll in &assembly.dlls {
            self.files.insert(
                normalize_path(&format!("C:/Windows/WinSxS/{}/{}", assembly.version, dll)),
                assembly.manifest.as_bytes().to_vec(),
            );
        }
        self.vc_runtimes.insert(assembly.version.clone(), assembly);
    }

    pub fn activate_vc_runtime(&self, version: &str, required_dlls: &[&str]) -> bool {
        self.vc_runtimes
            .get(version)
            .is_some_and(|assembly| required_dlls.iter().all(|dll| assembly.dlls.iter().any(|entry| entry == dll)))
    }

    pub fn provide_directx_component(&mut self, dll_name: &str) {
        self.directx_components.insert(dll_name.to_ascii_lowercase());
        self.files.insert(
            normalize_path(&format!("C:/Windows/System32/{dll_name}")),
            format!("builtin:{dll_name}").into_bytes(),
        );
    }

    pub fn has_directx_component(&self, dll_name: &str) -> bool {
        self.directx_components.contains(&dll_name.to_ascii_lowercase())
    }

    pub fn require_dotnet(&self, version: &str) -> AppResult<()> {
        if self.supported_dotnet.contains(version) {
            Ok(())
        } else {
            Err(AppError::new(
                ReasonCode::RcDotnetUnsupported,
                format!("unsupported .NET runtime {version}"),
            ))
        }
    }

    pub fn lock_file(&mut self, path: &str, delete_on_close: bool) {
        let normalized = normalize_path(path);
        self.locked_paths.insert(normalized.clone());
        if delete_on_close {
            self.delete_on_close.insert(normalized);
        }
    }

    pub fn unlock_file(&mut self, path: &str) {
        let normalized = normalize_path(path);
        self.locked_paths.remove(&normalized);
        self.delete_on_close.remove(&normalized);
    }

    pub fn apply_patch_cycle(&mut self, operations: &[PatchOperation]) -> AppResult<PatchCycleResult> {
        let mut log = Vec::new();
        for operation in operations {
            let normalized = normalize_path(&operation.target_path);
            let existing = self.files.get(&normalized).cloned().unwrap_or_default();
            if existing != operation.expected_old {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("patch mismatch for {normalized}"),
                ));
            }
            let mut assembled = vec![0_u8; operation.replacement.len()];
            for (case_path, offset, bytes) in &operation.download_chunks {
                if normalize_path(case_path) != normalized {
                    return Err(AppError::new(
                        ReasonCode::RcIo,
                        format!("download chunk path mismatch for {case_path}"),
                    ));
                }
                let end = offset + bytes.len();
                assembled[*offset..end].copy_from_slice(bytes);
            }
            if assembled != operation.replacement {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("incomplete patch payload for {normalized}"),
                ));
            }

            let temp_path = format!("{normalized}.tmp");
            log.push(format!("write_temp:{temp_path}"));
            log.push(format!("fsync:{temp_path}"));
            if self.locked_paths.contains(&normalized) && !self.delete_on_close.contains(&normalized) {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("patch target locked: {normalized}"),
                ));
            }
            log.push(format!("rename:{temp_path}->{normalized}"));
            if self.delete_on_close.contains(&normalized) {
                log.push(format!("delete_on_close:{normalized}"));
            } else {
                log.push(format!("delete_old:{normalized}"));
            }
            self.files.insert(normalized, operation.replacement.clone());
        }
        Ok(PatchCycleResult {
            final_tree_hash: self.tree_hash(),
            operation_log: log,
        })
    }

    pub fn tree_hash(&self) -> String {
        let mut entries = Vec::new();
        for (path, bytes) in &self.files {
            entries.push(format!("{path}|{}", util::sha256_bytes(bytes)));
        }
        for (key, value) in &self.registry {
            entries.push(format!("{key}={value}"));
        }
        entries.sort();
        util::sha256_bytes(entries.join("\n").as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Helper functions for installer detection and extraction
// ---------------------------------------------------------------------------

/// Search for `magic` byte sequence in `data`, returning the offset of the
/// first occurrence, or `None` if not found.
pub fn search_magic_bytes(data: &[u8], magic: &[u8]) -> Option<usize> {
    if magic.is_empty() {
        return None;
    }
    data.windows(magic.len()).position(|window| window == magic)
}

/// Extract the overlay data from a PE executable (data beyond the last PE
/// section).  Returns the raw overlay bytes.
pub fn extract_exe_overlay(path: &Path) -> AppResult<Vec<u8>> {
    let data = fs::read(path)
        .map_err(|e| AppError::from_io(ReasonCode::RcIo, format!("failed to read {}", path.display()), &e))?;

    if data.len() < 64 {
        return Err(AppError::new(
            ReasonCode::RcPeParseInvalid,
            format!("file too small to be a PE: {}", path.display()),
        ));
    }

    // DOS header – e_lfanew at offset 0x3C
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 4 > data.len() {
        return Err(AppError::new(
            ReasonCode::RcPeParseInvalid,
            format!("invalid e_lfanew in {}", path.display()),
        ));
    }

    // PE magic "PE\0\0"
    if &data[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return Err(AppError::new(
            ReasonCode::RcPeParseInvalid,
            format!("not a valid PE file: {}", path.display()),
        ));
    }

    // Number of sections is at e_lfanew + 6 (u16)
    let num_sections =
        u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]) as usize;

    // Size of optional header at e_lfanew + 20 (u16)
    let opt_header_size =
        u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;

    // Section headers start after the PE signature (4) + COFF header (20) + optional header
    let sections_offset = e_lfanew + 4 + 20 + opt_header_size;
    if sections_offset + num_sections * 40 > data.len() {
        return Err(AppError::new(
            ReasonCode::RcPeParseInvalid,
            format!("section headers exceed file size in {}", path.display()),
        ));
    }

    // Find the end of the last section (pointer_to_raw_data + size_of_raw_data)
    let mut overlay_start = sections_offset;
    for i in 0..num_sections {
        let section_entry = sections_offset + i * 40;
        if section_entry + 40 > data.len() {
            break;
        }
        // PointerToRawData at offset 20 within the 40-byte section header
        let raw_ptr = u32::from_le_bytes([
            data[section_entry + 20],
            data[section_entry + 21],
            data[section_entry + 22],
            data[section_entry + 23],
        ]) as usize;
        // SizeOfRawData at offset 16
        let raw_size = u32::from_le_bytes([
            data[section_entry + 16],
            data[section_entry + 17],
            data[section_entry + 18],
            data[section_entry + 19],
        ]) as usize;

        let section_end = raw_ptr.saturating_add(raw_size);
        if section_end > overlay_start {
            overlay_start = section_end;
        }
    }

    if overlay_start >= data.len() {
        return Ok(Vec::new());
    }

    Ok(data[overlay_start..].to_vec())
}

/// Read a specific `VS_FIXEDFILEINFO` string from a PE file's version
/// resource.  Common `string_name` values: `"FileDescription"`,
/// `"CompanyName"`, `"ProductName"`, etc.
pub fn read_pe_version_string(path: &Path, string_name: &str) -> AppResult<Option<String>> {
    let data = fs::read(path)
        .map_err(|e| AppError::from_io(ReasonCode::RcIo, format!("failed to read {}", path.display()), &e))?;

    if data.len() < 64 {
        return Ok(None);
    }

    // DOS header
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 4 > data.len() {
        return Ok(None);
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return Ok(None);
    }

    // Number of data directories in optional header – stored at e_lfanew + 24 (COFF) and depends on magic
    let magic = u16::from_le_bytes([data[e_lfanew + 24], data[e_lfanew + 25]]);
    let (data_dir_offset, data_dir_count) = match magic {
        0x10b => {
            // PE32: optional header is 96 bytes; data dir at e_lfanew + 24 + 96
            let opt_header_size =
                u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;
            (e_lfanew + 24 + opt_header_size - (opt_header_size.saturating_sub(96)), 16)
        }
        0x20b => {
            // PE32+: optional header is 112 bytes
            let opt_header_size =
                u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;
            (e_lfanew + 24 + opt_header_size - (opt_header_size.saturating_sub(112)), 16)
        }
        _ => return Ok(None),
    };

    // Resource directory entry is the 3rd entry (index 2)
    let res_rva_offset = data_dir_offset + 2 * 8;
    if res_rva_offset + 8 > data.len() {
        return Ok(None);
    }
    let res_rva = u32::from_le_bytes([
        data[res_rva_offset],
        data[res_rva_offset + 1],
        data[res_rva_offset + 2],
        data[res_rva_offset + 3],
    ]) as usize;

    if res_rva == 0 {
        return Ok(None);
    }

    // Walk the resource directory tree to find the version info
    // We use a simpler approach: scan the file for "VS_VERSION_INFO" or the string name
    // in the resource section area.
    // For simplicity, scan the entire file for the StringFileInfo structure.
    if let Some(value) = scan_version_string(&data, string_name) {
        return Ok(Some(value));
    }

    Ok(None)
}

/// Naive scan for a version-info string inside a resource section.
/// Looks for `"StringName"` followed by the UTF-16LE value in
/// `VS_VERSION_INFO` structures.
fn scan_version_string(data: &[u8], target_name: &str) -> Option<String> {
    // Target name as UTF-16LE bytes for searching
    let target_utf16: Vec<u8> = target_name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Scan for the target name in the file
    search_magic_bytes(data, &target_utf16).and_then(|name_pos| {
        // After the name bytes, there's a null terminator (2 bytes) and padding to align
        // Then comes the value as UTF-16LE string.
        let value_start = name_pos + target_utf16.len();
        // Skip null terminator
        let value_start = value_start + 2;
        // Align to 4-byte boundary
        let value_start = (value_start + 3) & !3;

        // Read until another null terminator
        let mut value_utf16 = Vec::new();
        let mut pos = value_start;
        while pos + 1 < data.len() {
            let byte = u16::from_le_bytes([data[pos], data[pos + 1]]);
            if byte == 0 {
                break;
            }
            value_utf16.push(byte);
            pos += 2;
        }

        if value_utf16.is_empty() {
            return None;
        }
        String::from_utf16(&value_utf16).ok()
    })
}

/// Register an installed application in the GE registry (the in-memory
/// `InstallerEngine` state).  Writes the uninstall key under the simulated
/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{name}` path.
pub fn register_installed_app(
    engine: &mut InstallerEngine,
    name: &str,
    install_path: &str,
    uninstall_cmd: &str,
) -> AppResult<()> {
    let key = normalize_path(&format!(
        "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{}",
        name
    ));
    engine
        .registry
        .insert(format!("{key}/displayname"), name.to_string());
    engine
        .registry
        .insert(format!("{key}/installlocation"), install_path.to_string());
    engine
        .registry
        .insert(format!("{key}/uninstallstring"), uninstall_cmd.to_string());
    engine
        .registry
        .insert(format!("{key}/displayversion"), "1.0.0".to_string());
    Ok(())
}

/// Decompress a zlib-compressed data block using flate2 (RFC 1950).
/// Returns the decompressed bytes, or an error if decompression fails.
pub fn decompress_zlib_block(data: &[u8]) -> AppResult<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| AppError::new(ReasonCode::RcIo, "zlib decompression failed").with_hint(e.to_string()))?;
    Ok(decompressed)
}

// ---------------------------------------------------------------------------
// InstallShield Engine
// ---------------------------------------------------------------------------

/// Windows InstallShield installers are `setup.exe` files that embed a cabinet
/// (`.cab`) containing the actual payload.  They commonly accept `/s` for
/// silent installation, `/f1"setup.iss"` for a response file, and
/// `/f2"setup.log"` for a log file.
pub struct InstallShieldEngine {
    pub installer_path: PathBuf,
    pub cab_data: Vec<u8>,
}

impl InstallShieldEngine {
    /// Detect whether `path` is an InstallShield installer by checking:
    ///
    /// * PE resource version info containing "InstallShield", or
    /// * PE section names containing an "IS" prefix, or
    /// * The presence of `ISc(` magic bytes (0x49 0x53 0x63 0x28) in the
    ///   overlay or throughout the file.
    pub fn detect(path: &Path) -> bool {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return false,
        };

        if data.len() < 64 {
            return false;
        }

        // Check for "InstallShield" in version strings
        if let Ok(Some(desc)) = read_pe_version_string(path, "FileDescription") {
            if desc.contains("InstallShield") {
                return true;
            }
        }

        // Check PE section names for "IS" prefix
        if has_installshield_sections(&data) {
            return true;
        }

        // Check for ISc( magic in the overlay
        if let Ok(overlay) = extract_exe_overlay(path) {
            if search_magic_bytes(&overlay, b"ISc(").is_some() {
                return true;
            }
        }

        // Also check the whole file for the marker
        search_magic_bytes(&data, b"ISc(").is_some()
    }

    /// Extract files from a Microsoft CAB archive embedded in the overlay.
    ///
    /// Parses the CAB header (CFHEADER), walks the folder/file structures
    /// (CFFOLDER / CFFILE), decompresses zlib/deflate data blocks (CFDATA),
    /// and writes each file into the engine's virtual filesystem.
    fn extract_cab_files(
        cab_bytes: &[u8],
        engine: &mut InstallerEngine,
        install_dir: &str,
    ) -> AppResult<Vec<String>> {
        let mut created_files = Vec::new();

        // CAB files start with "MSCF" magic at offset 0 of the CAB data
        // (after the ISc( prefix has been stripped).
        if cab_bytes.len() < 36 || &cab_bytes[..4] != b"MSCF" {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "InstallShield CAB missing MSCF magic",
            ));
        }

        // CFHEADER fields (all little-endian)
        let file_offset = u32::from_le_bytes([
            cab_bytes[16], cab_bytes[17], cab_bytes[18], cab_bytes[19],
        ]) as usize;
        let folder_count =
            u16::from_le_bytes([cab_bytes[26], cab_bytes[27]]) as usize;
        let file_count =
            u16::from_le_bytes([cab_bytes[28], cab_bytes[29]]) as usize;
        let flags = u16::from_le_bytes([cab_bytes[30], cab_bytes[31]]);

        // Flags bit 2 = reserved area present
        let reserved_size: usize = if flags & 4 != 0 {
            u16::from_le_bytes([cab_bytes[32], cab_bytes[33]]) as usize
        } else {
            0
        };
        // Header size: 36 bytes + folder entries + reserved + padding
        let folders_offset = 36;
        let files_offset = file_offset;

        // Parse folder entries (CFFOLDER, each 8 bytes)
        let mut folder_blocks_offset = Vec::new(); // offset of first data block for each folder
        let mut folder_comp_type = Vec::new();     // compression type per folder
        for i in 0..folder_count {
            let fo = folders_offset + i * 8;
            if fo + 8 > cab_bytes.len() {
                break;
            }
            let block_offset = u32::from_le_bytes([
                cab_bytes[fo], cab_bytes[fo + 1], cab_bytes[fo + 2], cab_bytes[fo + 3],
            ]) as usize;
            let comp_type =
                u16::from_le_bytes([cab_bytes[fo + 6], cab_bytes[fo + 7]]);
            folder_blocks_offset.push(block_offset);
            folder_comp_type.push(comp_type);
        }

        // Parse file entries (CFFILE, variable length)
        for i in 0..file_count {
            let mut fe = files_offset;
            // Scan forward to the i-th file entry
            for _ in 0..i {
                if fe + 4 > cab_bytes.len() {
                    break;
                }
                let name_len = {
                    let mut len = 0usize;
                    while fe + 16 + len < cab_bytes.len() && cab_bytes[fe + 16 + len] != 0 {
                        len += 1;
                    }
                    len
                };
                fe += 16 + name_len + 1; // skip past entry + null
            }
            if fe + 16 > cab_bytes.len() {
                break;
            }

            let uncomp_size = u32::from_le_bytes([
                cab_bytes[fe], cab_bytes[fe + 1], cab_bytes[fe + 2], cab_bytes[fe + 3],
            ]) as usize;
            let folder_offset =
                u32::from_le_bytes([cab_bytes[fe + 4], cab_bytes[fe + 5], cab_bytes[fe + 6], cab_bytes[fe + 7]])
                    as usize;
            let folder_idx =
                u16::from_le_bytes([cab_bytes[fe + 8], cab_bytes[fe + 9]]) as usize;

            // Read null-terminated filename
            let name_start = fe + 16;
            let name_end = cab_bytes[name_start..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(cab_bytes.len() - name_start);
            if name_end == 0 {
                continue;
            }
            let filename = match std::str::from_utf8(&cab_bytes[name_start..name_start + name_end]) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Find the corresponding data blocks for this folder
            if folder_idx >= folder_count {
                continue;
            }
            let block_start = folder_blocks_offset[folder_idx];
            let comp_type = folder_comp_type[folder_idx];

            // Collect all data blocks for this folder
            let mut folder_decompressed = Vec::new();
            let mut block_pos = block_start;
            loop {
                if block_pos + 4 > cab_bytes.len() {
                    break;
                }
                // CFDATA header: 2 bytes checksum(optional), 2 bytes compressed size, 2 bytes uncompressed size
                let data_hdr_size = if comp_type == 0 { 6 } else { 8 };
                if block_pos + data_hdr_size > cab_bytes.len() {
                    break;
                }
                let chk_offset = if comp_type == 0 { 0 } else { 2 };
                let comp_size = u16::from_le_bytes([
                    cab_bytes[block_pos + chk_offset],
                    cab_bytes[block_pos + chk_offset + 1],
                ]) as usize;
                let uncomp_size = u16::from_le_bytes([
                    cab_bytes[block_pos + chk_offset + 2],
                    cab_bytes[block_pos + chk_offset + 3],
                ]) as usize;

                let data_start = block_pos + data_hdr_size;
                if data_start + comp_size > cab_bytes.len() {
                    break;
                }
                let block_data = &cab_bytes[data_start..data_start + comp_size];

                if comp_type == 0 {
                    // No compression (stored)
                    folder_decompressed.extend_from_slice(block_data);
                } else {
                    // Compressed (deflate/zlib) – decompress
                    match decompress_zlib_block(block_data) {
                        Ok(d) => folder_decompressed.extend_from_slice(&d),
                        Err(_) => {
                            // Try raw deflate (no zlib wrapper)
                            let mut decoder = flate2::read::DeflateDecoder::new(block_data);
                            let mut buf = Vec::new();
                            if decoder.read_to_end(&mut buf).is_ok() {
                                folder_decompressed.extend_from_slice(&buf);
                            }
                            // If both fail, extend raw data
                            else {
                                folder_decompressed.extend_from_slice(block_data);
                            }
                        }
                    }
                }

                // Check if this data block's uncomp_size is less than 0x8000,
                // which signals the last block in this folder
                if uncomp_size < 0x8000 {
                    break;
                }
                block_pos = data_start + comp_size;
            }

            // Extract this file's portion from the decompressed folder data
            if folder_offset + uncomp_size <= folder_decompressed.len() {
                let file_bytes =
                    &folder_decompressed[folder_offset..folder_offset + uncomp_size];
                let file_path = normalize_path(&format!("{install_dir}/{filename}"));
                engine.files.insert(file_path.clone(), file_bytes.to_vec());
                created_files.push(file_path);
            }
        }

        Ok(created_files)
    }

    /// Run an InstallShield installer.
    ///
    /// 1. Detects the installer EXE in the archive path.
    /// 2. Looks for an embedded CAB file (`ISc(` magic).
    /// 3. Extracts files from the embedded CAB into the virtual filesystem.
    /// 4. Registers installed components in the GE registry.
    pub fn install(&self, engine: &mut InstallerEngine) -> AppResult<String> {
        let install_dir = format!(
            "C:/Program Files/InstallShield/{}",
            self.installer_path
                .file_stem()
                .map(|s| s.to_string_lossy())
                .unwrap_or_else(|| std::borrow::Cow::Borrowed("app"))
        );

        // If cab_data was pre-populated, use it directly.
        // Otherwise, extract from the overlay at install time.
        let cab_bytes: Vec<u8> = if !self.cab_data.is_empty() {
            self.cab_data.clone()
        } else {
            let data = fs::read(&self.installer_path).map_err(|e| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to read InstallShield installer {}", self.installer_path.display()),
                    &e,
                )
            })?;

            // Search for embedded CAB (ISc( magic)
            match search_magic_bytes(&data, b"ISc(") {
                Some(cab_start) => {
                    let cab_content = &data[cab_start..];
                    let end = cab_content
                        .windows(4)
                        .skip(1)
                        .position(|w| w == b"ISc(")
                        .map(|pos| pos + 4)
                        .unwrap_or(cab_content.len());
                    cab_content[..end.min(cab_content.len())].to_vec()
                }
                None => {
                    return Err(AppError::new(
                        ReasonCode::RcPeParseInvalid,
                        format!("no embedded CAB found in InstallShield installer {}", self.installer_path.display()),
                    ));
                }
            }
        };

        // Skip the 4-byte "ISc(" marker to get the raw CAB content
        let cab_payload = if cab_bytes.len() > 4 && &cab_bytes[..4] == b"ISc(" {
            &cab_bytes[4..]
        } else {
            &cab_bytes[..]
        };

        // Extract files from the embedded CAB
        let created_files =
            Self::extract_cab_files(cab_payload, engine, &install_dir)?;

        // Register in the GE registry
        let app_name = self
            .installer_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "InstallShieldApp".to_string());
        let uninstall_cmd = format!("{install_dir}/uninstall.exe");
        register_installed_app(engine, &app_name, &install_dir, &uninstall_cmd)?;

        let telemetry = InstallerTelemetry {
            installer_id: format!("installshield:{}", self.installer_path.display()),
            exit_code: 0,
            created_files: created_files.iter().map(|p| normalize_path(p)).collect(),
            registry_changes: Vec::new(),
            logs: vec![
                format!("installshield:{}", self.installer_path.display()),
                format!("install_dir:{install_dir}"),
                format!("cab_bytes:{}", cab_bytes.len()),
            ],
            window_titles: vec!["InstallShield".to_string()],
            silent_flags: vec!["/s".to_string()],
        };
        engine.telemetry_log.push(telemetry);

        Ok(install_dir)
    }

    /// Uninstall an InstallShield application.
    ///
    /// 1. Looks up the uninstall registry key in
    ///    `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`.
    /// 2. Executes the `UninstallString` if present (simulated).
    /// 3. Cleans up installed files.
    pub fn uninstall(&self, engine: &mut InstallerEngine) -> AppResult<()> {
        let name = self
            .installer_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "InstallShieldApp".to_string());

        let uninstall_key = format!(
            "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{name}"
        );

        // Clean up files that were installed
        let prefix = format!(
            "c:/program files/installshield/{}",
            name.to_ascii_lowercase()
        );
        let to_remove: Vec<String> = engine
            .files
            .keys()
            .filter(|p| p.starts_with(&prefix))
            .cloned()
            .collect();
        for path in &to_remove {
            engine.files.remove(path);
        }

        // Remove registry keys
        engine.registry.retain(|k, _| !k.starts_with(&uninstall_key.to_ascii_lowercase()));

        let telemetry = InstallerTelemetry {
            installer_id: format!("installshield-uninstall:{name}"),
            exit_code: 0,
            created_files: to_remove,
            registry_changes: vec![uninstall_key],
            logs: vec![format!("uninstall:installshield:{name}")],
            window_titles: vec!["InstallShield".to_string()],
            silent_flags: vec!["/s".to_string()],
        };
        engine.telemetry_log.push(telemetry);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InstallShield Script Parsing
// ---------------------------------------------------------------------------

/// A parsed InstallShield script (.iss) command.
///
/// InstallShield response files (.iss) contain simple key=value pairs that
/// automate the installer. This struct represents a single parsed command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IssCommand {
    /// Set a variable: `{section}-{key}={value}`
    SetVariable {
        section: String,
        key: String,
        value: String,
    },
    /// Run an executable after installation.
    RunAfterInstall {
        path: String,
        args: String,
    },
    /// Register a DLL.
    RegisterDll {
        path: String,
        self_register: bool,
    },
    /// Create a shortcut.
    CreateShortcut {
        name: String,
        target: String,
        args: String,
        working_dir: String,
    },
    /// Add a registry key.
    RegistryAdd {
        root: String,
        key: String,
        name: String,
        value: String,
    },
    /// Comment or unrecognized line.
    Comment(String),
}

/// Result of parsing an InstallShield response file (.iss).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssScript {
    /// The parsed commands in order.
    pub commands: Vec<IssCommand>,
    /// The number of sections found.
    pub section_count: usize,
    /// Whether the script is valid (parseable).
    pub is_valid: bool,
}

impl IssScript {
    /// Parse an InstallShield response file (.iss) content.
    ///
    /// The .iss format is INI-like with sections like `[Install]`, `[Registry]`, etc.
    /// Each section contains key=value pairs.
    pub fn parse(content: &str) -> Self {
        let mut commands = Vec::new();
        let mut section_count = 0;
        let mut current_section = String::new();
        let mut is_valid = true;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Section header
            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len() - 1].to_string();
                section_count += 1;
                continue;
            }

            // Comment
            if line.starts_with(';') || line.starts_with('#') || line.starts_with("//") {
                commands.push(IssCommand::Comment(line.to_string()));
                continue;
            }

            // Key=Value pair
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim().to_string();
                let value = line[eq_pos + 1..].trim().to_string();

                // Interpret based on section
                match current_section.to_lowercase().as_str() {
                    "install" | "setup" => {
                        commands.push(IssCommand::SetVariable {
                            section: current_section.clone(),
                            key,
                            value,
                        });
                    }
                    "registry" => {
                        // Format: RootKey\SubKey,ValueName,ValueData
                        let parts: Vec<&str> = value.splitn(3, ',').collect();
                        if parts.len() >= 3 {
                            commands.push(IssCommand::RegistryAdd {
                                root: parts[0].to_string(),
                                key: parts[1].to_string(),
                                name: key,
                                value: parts[2].to_string(),
                            });
                        } else {
                            commands.push(IssCommand::SetVariable {
                                section: current_section.clone(),
                                key,
                                value,
                            });
                        }
                    }
                    "runtimes" | "postinstall" => {
                        if key.to_lowercase().contains("run") || key.to_lowercase().contains("exec") {
                            let parts: Vec<&str> = value.splitn(2, ' ').collect();
                            commands.push(IssCommand::RunAfterInstall {
                                path: parts.first().unwrap_or(&"").to_string(),
                                args: parts.get(1).unwrap_or(&"").to_string(),
                            });
                        } else {
                            commands.push(IssCommand::SetVariable {
                                section: current_section.clone(),
                                key,
                                value,
                            });
                        }
                    }
                    _ => {
                        commands.push(IssCommand::SetVariable {
                            section: current_section.clone(),
                            key,
                            value,
                        });
                    }
                }
            } else {
                // Unrecognized line — treat as comment
                is_valid = false;
                commands.push(IssCommand::Comment(line.to_string()));
            }
        }

        Self {
            commands,
            section_count,
            is_valid: is_valid || section_count > 0,
        }
    }

    /// Get all variables from a specific section.
    pub fn variables_for_section(&self, section: &str) -> Vec<(String, String)> {
        self.commands
            .iter()
            .filter_map(|cmd| {
                if let IssCommand::SetVariable { section: s, key, value } = cmd {
                    if s.eq_ignore_ascii_case(section) {
                        return Some((key.clone(), value.clone()));
                    }
                }
                None
            })
            .collect()
    }

    /// Get all registry operations.
    pub fn registry_operations(&self) -> Vec<&IssCommand> {
        self.commands
            .iter()
            .filter(|cmd| matches!(cmd, IssCommand::RegistryAdd { .. }))
            .collect()
    }

    /// Get all post-install commands.
    pub fn post_install_commands(&self) -> Vec<&IssCommand> {
        self.commands
            .iter()
            .filter(|cmd| matches!(cmd, IssCommand::RunAfterInstall { .. }))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ISSetup.dll Custom Action Stub
// ---------------------------------------------------------------------------

/// Stub for the InstallShield `ISSetup.dll` custom action DLL.
///
/// InstallShield installers often call custom actions from `ISSetup.dll`
/// during installation. This stub intercepts those calls and provides
/// reasonable default behavior.
#[derive(Debug, Clone)]
pub struct ISSetupDllStub {
    /// Log of intercepted custom action calls.
    pub call_log: Vec<ISSetupAction>,
}

/// Represents a single intercepted ISSetup.dll custom action call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ISSetupAction {
    /// The function name that was called (e.g., "OnBegin", "OnMoved").
    pub function_name: String,
    /// The action type.
    pub action_type: ISSetupActionType,
    /// Whether the action was handled successfully.
    pub succeeded: bool,
    /// Any log message from the action.
    pub log_message: String,
}

/// Types of InstallShield custom actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ISSetupActionType {
    /// Called at the beginning of installation.
    OnBegin,
    /// Called before files are moved.
    OnMoving,
    /// Called after files are moved.
    OnMoved,
    /// Called at the end of installation.
    OnEnd,
    /// Called to register components.
    OnRegisterFiles,
    /// Called during UI initialization.
    OnUIInit,
    /// Called during UI maintenance.
    OnMaintUIInit,
    /// Generic custom action.
    Custom(String),
}

impl ISSetupDllStub {
    /// Create a new ISSetup.dll stub.
    pub fn new() -> Self {
        Self { call_log: Vec::new() }
    }

    /// Handle a call to an ISSetup.dll exported function.
    ///
    /// Returns `true` if the call was handled successfully.
    pub fn handle_call(&mut self, function_name: &str) -> bool {
        let action_type = match function_name {
            "OnBegin" => ISSetupActionType::OnBegin,
            "OnMoving" => ISSetupActionType::OnMoving,
            "OnMoved" => ISSetupActionType::OnMoved,
            "OnEnd" => ISSetupActionType::OnEnd,
            "OnRegisterFiles" => ISSetupActionType::OnRegisterFiles,
            "OnUIInit" => ISSetupActionType::OnUIInit,
            "OnMaintUIInit" => ISSetupActionType::OnMaintUIInit,
            other => ISSetupActionType::Custom(other.to_string()),
        };

        let log_message = format!("ISSetup.dll stub: handled {}", function_name);
        let action = ISSetupAction {
            function_name: function_name.to_string(),
            action_type,
            succeeded: true,
            log_message,
        };
        self.call_log.push(action);
        true
    }

    /// Get the number of intercepted calls.
    pub fn call_count(&self) -> usize {
        self.call_log.len()
    }

    /// Check if a specific function was called.
    pub fn was_called(&self, function_name: &str) -> bool {
        self.call_log.iter().any(|a| a.function_name == function_name)
    }

    /// Get all calls of a specific action type.
    pub fn calls_of_type(&self, action_type: &ISSetupActionType) -> Vec<&ISSetupAction> {
        self.call_log.iter().filter(|a| &a.action_type == action_type).collect()
    }
}

impl Default for ISSetupDllStub {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NSIS Engine
// ---------------------------------------------------------------------------

/// Nullsoft Scriptable Install System (NSIS) installers are PE EXEs with a
/// specific NSIS header signature and embedded compressed data (zlib blocks).
/// They commonly accept `/S` for silent installation and `/D=` to set the
/// install directory.
pub struct NsisEngine {
    pub installer_path: PathBuf,
    pub extract_dir: PathBuf,
}

impl NsisEngine {
    /// Detect whether `path` is an NSIS installer by checking:
    ///
    /// * PE resource strings containing "Nullsoft Installer", or
    /// * The presence of NSIS magic bytes `0x6E 0x73 0x69 0x73` (`nsis`) in
    ///   the overlay or throughout the file.
    pub fn detect(path: &Path) -> bool {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return false,
        };

        if data.len() < 64 {
            return false;
        }

        // Check for "Nullsoft Installer" in version strings
        if let Ok(Some(desc)) = read_pe_version_string(path, "FileDescription") {
            if desc.contains("Nullsoft") || desc.contains("NSIS") {
                return true;
            }
        }

        // Check for NSIS magic "nsis" in the overlay
        if let Ok(overlay) = extract_exe_overlay(path) {
            if search_magic_bytes(&overlay, b"nsis").is_some() {
                return true;
            }
        }

        // Check for the NullsoftInstaller signature in the whole file
        if search_magic_bytes(&data, b"NullsoftInstaller").is_some() {
            return true;
        }

        // Check for "nsis" magic in the header area
        search_magic_bytes(&data, b"nsis").is_some()
    }

    /// Walk the NSIS entry chain starting at `header_offset` within `overlay`,
    /// decompress zlib-compressed blocks, and insert files into `engine`.
    fn extract_nsis_entries(
        overlay: &[u8],
        header_offset: usize,
        engine: &mut InstallerEngine,
        install_dir: &str,
    ) -> AppResult<Vec<String>> {
        let mut created_files = Vec::new();
        let mut offset = header_offset;

        loop {
            if offset + 12 > overlay.len() {
                break;
            }
            // NSIS entry header (each entry is a doubly-linked list node):
            //   0-3:   next_header (u32 offset, 0 = end)
            //   4-7:   uncompressed_size (u32)
            //   8-11:  compressed_size (u32, bit 31 set = compressed)
            let next_header = u32::from_le_bytes([
                overlay[offset],
                overlay[offset + 1],
                overlay[offset + 2],
                overlay[offset + 3],
            ]) as usize;
            let uncomp_size = u32::from_le_bytes([
                overlay[offset + 4],
                overlay[offset + 5],
                overlay[offset + 6],
                overlay[offset + 7],
            ]) as usize;
            let compressed_size_raw = u32::from_le_bytes([
                overlay[offset + 8],
                overlay[offset + 9],
                overlay[offset + 10],
                overlay[offset + 11],
            ]) as usize;

            let is_compressed = compressed_size_raw & 0x8000_0000 != 0;
            let compressed_size = compressed_size_raw & 0x7FFF_FFFF;

            // Read null-terminated filename starting after the 12-byte header
            let name_start = offset + 12;
            let name_len = overlay[name_start..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(overlay.len() - name_start);
            if name_len == 0 || name_len > 512 {
                if next_header == 0 {
                    break;
                }
                offset = next_header;
                continue;
            }
            let filename = match std::str::from_utf8(&overlay[name_start..name_start + name_len]) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    if next_header == 0 {
                        break;
                    }
                    offset = next_header;
                    continue;
                }
            };

            // Data starts after the null terminator, aligned to 4-byte boundary
            let data_start = (name_start + name_len + 1 + 3) & !3;

            if is_compressed && compressed_size > 0
                && data_start + compressed_size <= overlay.len()
            {
                let compressed_block = &overlay[data_start..data_start + compressed_size];
                match decompress_zlib_block(compressed_block) {
                    Ok(decompressed) => {
                        let file_bytes = if decompressed.len() >= uncomp_size {
                            decompressed[..uncomp_size].to_vec()
                        } else {
                            decompressed
                        };
                        let file_path =
                            normalize_path(&format!("{install_dir}/{filename}"));
                        engine.files.insert(file_path.clone(), file_bytes);
                        created_files.push(file_path);
                    }
                    Err(_) => {
                        // Fallback: try raw deflate (no zlib wrapper)
                        let mut decoder = flate2::read::DeflateDecoder::new(compressed_block);
                        let mut buf = Vec::new();
                        if decoder.read_to_end(&mut buf).is_ok() {
                            let file_bytes = if buf.len() >= uncomp_size {
                                buf[..uncomp_size].to_vec()
                            } else {
                                buf
                            };
                            let file_path =
                                normalize_path(&format!("{install_dir}/{filename}"));
                            engine.files.insert(file_path.clone(), file_bytes);
                            created_files.push(file_path);
                        }
                    }
                }
            } else if !is_compressed && data_start + uncomp_size <= overlay.len() {
                // Stored (uncompressed) entry
                let file_bytes = &overlay[data_start..data_start + uncomp_size];
                let file_path = normalize_path(&format!("{install_dir}/{filename}"));
                engine.files.insert(file_path.clone(), file_bytes.to_vec());
                created_files.push(file_path);
            }

            if next_header == 0 {
                break;
            }
            offset = next_header;
        }

        Ok(created_files)
    }

    /// Run an NSIS installer.
    ///
    /// 1. Parses the NSIS header from the PE file overlay.
    /// 2. Locates the embedded NSIS data (looks for `nsis` magic).
    /// 3. Walks the entry chain, decompresses zlib blocks, extracts files.
    /// 4. Registers the install location.
    pub fn install(&self, engine: &mut InstallerEngine) -> AppResult<String> {
        let install_dir = format!(
            "C:/Program Files/{}",
            self.installer_path
                .file_stem()
                .map(|s| s.to_string_lossy())
                .unwrap_or_else(|| std::borrow::Cow::Borrowed("NSISApp"))
        );

        // Read overlay from the PE file
        let overlay = extract_exe_overlay(&self.installer_path)?;

        // Look for NSIS magic "nsis" (0x6E 0x73 0x69 0x73)
        let nsis_offset = search_magic_bytes(&overlay, b"nsis").ok_or_else(|| {
            AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!("NSIS magic not found in {}", self.installer_path.display()),
            )
        })?;

        // After the 4-byte magic, the first_header field (u32 LE) gives the
        // offset (relative to the NSIS block start) of the first entry.
        if nsis_offset + 8 > overlay.len() {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "NSIS header truncated after magic",
            ));
        }
        let first_header_rel = u32::from_le_bytes([
            overlay[nsis_offset + 4],
            overlay[nsis_offset + 5],
            overlay[nsis_offset + 6],
            overlay[nsis_offset + 7],
        ]) as usize;

        // first_header is relative to the NSIS block start (= nsis_offset)
        let first_header_abs = nsis_offset + first_header_rel;

        // Walk the entry chain and extract files using zlib decompression
        let created_files = if first_header_abs + 12 <= overlay.len() {
            Self::extract_nsis_entries(&overlay, first_header_abs, engine, &install_dir)?
        } else {
            Vec::new()
        };

        // Register in the GE registry
        let app_name = self
            .installer_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "NSISApp".to_string());
        let uninstall_cmd = format!("{install_dir}/uninstall.exe");
        register_installed_app(engine, &app_name, &install_dir, &uninstall_cmd)?;

        let telemetry = InstallerTelemetry {
            installer_id: format!("nsis:{}", self.installer_path.display()),
            exit_code: 0,
            created_files: created_files.iter().map(|p| normalize_path(p)).collect(),
            registry_changes: Vec::new(),
            logs: vec![
                format!("nsis:{}", self.installer_path.display()),
                format!("install_dir:{install_dir}"),
                format!("nsis_offset:{nsis_offset:#x}"),
                format!("entries:{}", created_files.len()),
            ],
            window_titles: vec!["NSIS Installer".to_string()],
            silent_flags: vec!["/S".to_string()],
        };
        engine.telemetry_log.push(telemetry);

        Ok(install_dir)
    }

    /// Uninstall an NSIS application.
    ///
    /// NSIS typically writes an `uninstall.exe` to the install directory.
    /// Look in the registry for NSIS uninstall entries.
    pub fn uninstall(&self, engine: &mut InstallerEngine) -> AppResult<()> {
        let name = self
            .installer_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "NSISApp".to_string());

        let uninstall_key = format!(
            "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{name}"
        );

        // Clean up installed files
        let prefix = format!(
            "c:/program files/{}",
            name.to_ascii_lowercase()
        );
        let to_remove: Vec<String> = engine
            .files
            .keys()
            .filter(|p| p.starts_with(&prefix))
            .cloned()
            .collect();
        for path in &to_remove {
            engine.files.remove(path);
        }

        // Remove registry keys
        engine.registry.retain(|k, _| !k.starts_with(&uninstall_key.to_ascii_lowercase()));

        let telemetry = InstallerTelemetry {
            installer_id: format!("nsis-uninstall:{name}"),
            exit_code: 0,
            created_files: to_remove,
            registry_changes: vec![uninstall_key],
            logs: vec![format!("uninstall:nsis:{name}")],
            window_titles: vec!["NSIS Installer".to_string()],
            silent_flags: vec!["/S".to_string()],
        };
        engine.telemetry_log.push(telemetry);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InnoSetup Engine
// ---------------------------------------------------------------------------

/// InnoSetup installers are PE EXEs with an embedded "Inno Setup" signature.
/// They use a custom binary format with compressed data (zlib) and accept
/// `/SILENT`, `/VERYSILENT`, `/DIR="x:\path"`, `/NORESTART`.
pub struct InnoSetupEngine {
    pub installer_path: PathBuf,
    pub extract_dir: PathBuf,
}

impl InnoSetupEngine {
    /// Detect whether `path` is an InnoSetup installer by checking:
    ///
    /// * PE resource version info containing "Inno Setup", or
    /// * The presence of "Inno" magic bytes in the PE overlay.
    pub fn detect(path: &Path) -> bool {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return false,
        };

        if data.len() < 64 {
            return false;
        }

        // Check for "Inno Setup" in version strings
        if let Ok(Some(desc)) = read_pe_version_string(path, "FileDescription") {
            if desc.contains("Inno Setup") {
                return true;
            }
        }

        // Check for "Inno" magic in the overlay after sections
        if let Ok(overlay) = extract_exe_overlay(path) {
            if search_magic_bytes(&overlay, b"Inno").is_some() {
                return true;
            }
        }

        // Also search the entire file for "Inno" marker
        if search_magic_bytes(&data, b"Inno").is_some() {
            return true;
        }

        // Check for setup header magic "zbin" (used by some InnoSetup versions)
        search_magic_bytes(&data, b"zbin").is_some()
    }

    /// Parse InnoSetup file entries from the decompressed setup data and
    /// insert them into `engine`.
    fn extract_innosetup_entries(
        decompressed: &[u8],
        engine: &mut InstallerEngine,
        install_dir: &str,
    ) -> AppResult<Vec<String>> {
        let mut created_files = Vec::new();

        // InnoSetup's decompressed "setup.dat" contains:
        //   - 4 bytes: magic "zbin" (or other marker)
        //   - 4 bytes: total entries (or offset to entry list)
        //   - For each entry:
        //      - 4 bytes: offset within the decompressed block
        //      - 4 bytes: size
        //      - variable: null-terminated filename
        //      - ... then the file data at the offset

        if decompressed.len() < 8 {
            return Ok(created_files);
        }

        // Try to extract entries: scan for null-terminated strings and look
        // for file-like patterns in the decompressed data.
        // The first 4 bytes may be a magic or version identifier.
        // We scan for filename patterns in the decompressed blob.

        // Strategy: look for slash/backslash-containing names near data offsets
        let mut pos = 8;
        let mut entry_idx = 0u32;

        while pos + 16 < decompressed.len() && entry_idx < 256 {
            // Try to read a potential entry header:
            //   u32: data_offset
            //   u32: data_size
            let data_offset = u32::from_le_bytes([
                decompressed[pos],
                decompressed[pos + 1],
                decompressed[pos + 2],
                decompressed[pos + 3],
            ]) as usize;
            let data_size = u32::from_le_bytes([
                decompressed[pos + 4],
                decompressed[pos + 5],
                decompressed[pos + 6],
                decompressed[pos + 7],
            ]) as usize;

            // Sanity check the offset/size
            if data_offset == 0 || data_size == 0 || data_offset + data_size > decompressed.len() {
                // Look for a null-terminated filename string instead
                let name_start = pos;
                // Check for common file extensions
                let candidate_region = &decompressed[pos..(pos + 256).min(decompressed.len())];
                if let Some(slash_pos) = candidate_region.iter().position(|&b| b == b'/' || b == b'\\') {
                    let name_end = candidate_region[slash_pos..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(candidate_region.len() - slash_pos);
                    if name_end > 0 && name_end < 256 {
                        let full_name_start = pos + slash_pos;
                        let full_name_end = full_name_start + name_end;
                        if let Ok(name) = std::str::from_utf8(&decompressed[full_name_start..full_name_end]) {
                            let normalized_name = name.replace('\\', "/");
                            // Try to determine the data body: look backwards for a plausible size prefix
                            let file_path = normalize_path(&format!("{install_dir}/{normalized_name}"));
                            let file_bytes = decompressed[pos..(pos + 128).min(decompressed.len())].to_vec();
                            engine.files.insert(file_path.clone(), file_bytes);
                            created_files.push(file_path);
                            entry_idx += 1;
                        }
                    }
                }
                pos += 32;
                continue;
            }

            // Read filename after the header
            let name_start = pos + 8;
            let name_len = decompressed[name_start..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(decompressed.len() - name_start);

            if name_len > 0 && name_len < 512 {
                if let Ok(name) = std::str::from_utf8(&decompressed[name_start..name_start + name_len]) {
                    let normalized_name = name.replace('\\', "/");
                    if !normalized_name.is_empty() {
                        let file_path = normalize_path(&format!("{install_dir}/{normalized_name}"));
                        let file_end = (data_offset + data_size).min(decompressed.len());
                        let file_bytes = decompressed[data_offset..file_end].to_vec();
                        engine.files.insert(file_path.clone(), file_bytes);
                        created_files.push(file_path);
                        entry_idx += 1;
                    }
                }
            }

            // Move to next entry: after the null-terminated name (aligned)
            let name_end_aligned = ((name_start + name_len + 1 + 3) & !3).max(pos + 16);
            pos = name_end_aligned;
        }

        Ok(created_files)
    }

    /// Run an InnoSetup installer.
    ///
    /// 1. Parses the PE to find the InnoSetup header (searches for "Inno"
    ///    magic in the overlay).
    /// 2. Reads compressed data blocks from the header, decompresses them
    ///    using zlib, and extracts file entries.
    /// 3. Registers the install location.
    pub fn install(&self, engine: &mut InstallerEngine) -> AppResult<String> {
        let install_dir = format!(
            "C:/Program Files/{}",
            self.installer_path
                .file_stem()
                .map(|s| s.to_string_lossy())
                .unwrap_or_else(|| std::borrow::Cow::Borrowed("InnoSetupApp"))
        );

        let overlay = extract_exe_overlay(&self.installer_path)?;

        // Locate the InnoSetup header in the overlay
        let inno_offset = search_magic_bytes(&overlay, b"Inno").ok_or_else(|| {
            AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!("InnoSetup magic not found in {}", self.installer_path.display()),
            )
        })?;

        // InnoSetup header after the "Inno" magic (4 bytes):
        //   4 bytes: header_size
        //   4 bytes: compressed_data_offset
        //   4 bytes: compressed_data_size
        //   4 bytes: uncompressed_data_size
        if inno_offset + 20 > overlay.len() {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "InnoSetup header truncated",
            ));
        }

        let _header_size = u32::from_le_bytes([
            overlay[inno_offset + 4],
            overlay[inno_offset + 5],
            overlay[inno_offset + 6],
            overlay[inno_offset + 7],
        ]) as usize;
        let comp_off = u32::from_le_bytes([
            overlay[inno_offset + 8],
            overlay[inno_offset + 9],
            overlay[inno_offset + 10],
            overlay[inno_offset + 11],
        ]) as usize;
        let comp_sz = u32::from_le_bytes([
            overlay[inno_offset + 12],
            overlay[inno_offset + 13],
            overlay[inno_offset + 14],
            overlay[inno_offset + 15],
        ]) as usize;
        let uncomp_sz = u32::from_le_bytes([
            overlay[inno_offset + 16],
            overlay[inno_offset + 17],
            overlay[inno_offset + 18],
            overlay[inno_offset + 19],
        ]) as usize;

        // Decompress the embedded data
        let absolute_comp_offset = inno_offset + comp_off;
        let created_files = if comp_sz > 0
            && absolute_comp_offset + comp_sz <= overlay.len()
        {
            let compressed_block = &overlay[absolute_comp_offset..absolute_comp_offset + comp_sz];

            // Try zlib decompression first
            let decompressed = match decompress_zlib_block(compressed_block) {
                Ok(d) => d,
                Err(_) => {
                    // Fallback: try raw deflate (some InnoSetup versions use this)
                    let mut decoder = flate2::read::DeflateDecoder::new(compressed_block);
                    let mut buf = Vec::new();
                    decoder.read_to_end(&mut buf).map_err(|e| {
                        AppError::new(ReasonCode::RcIo, "InnoSetup zlib/deflate decompression failed")
                            .with_hint(e.to_string())
                    })?;
                    buf
                }
            };

            // If decompressed size matches or we have data, extract entries
            if !decompressed.is_empty() {
                // If the uncompressed data is much larger than what we got,
                // there may be multiple blocks. For now, work with what we have.
                let actual_uncomp = if uncomp_sz > 0 && decompressed.len() >= uncomp_sz {
                    &decompressed[..uncomp_sz]
                } else {
                    &decompressed[..]
                };

                Self::extract_innosetup_entries(actual_uncomp, engine, &install_dir)?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Register in the GE registry
        let app_name = self
            .installer_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "InnoSetupApp".to_string());
        let uninstall_cmd = format!("{install_dir}/unins000.exe");
        register_installed_app(engine, &app_name, &install_dir, &uninstall_cmd)?;

        let telemetry = InstallerTelemetry {
            installer_id: format!("innosetup:{}", self.installer_path.display()),
            exit_code: 0,
            created_files: created_files.iter().map(|p| normalize_path(p)).collect(),
            registry_changes: Vec::new(),
            logs: vec![
                format!("innosetup:{}", self.installer_path.display()),
                format!("install_dir:{install_dir}"),
                format!("inno_offset:{inno_offset:#x}"),
                format!("entries:{}", created_files.len()),
            ],
            window_titles: vec!["Inno Setup".to_string()],
            silent_flags: vec!["/VERYSILENT".to_string()],
        };
        engine.telemetry_log.push(telemetry);

        Ok(install_dir)
    }

    /// Uninstall an InnoSetup application.
    ///
    /// InnoSetup writes `unins???.exe` to the install directory and creates
    /// registry entries under
    /// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`.
    pub fn uninstall(&self, engine: &mut InstallerEngine) -> AppResult<()> {
        let name = self
            .installer_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "InnoSetupApp".to_string());

        let uninstall_key = format!(
            "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{name}"
        );

        // Clean up installed files
        let prefix = format!(
            "c:/program files/{}",
            name.to_ascii_lowercase()
        );
        let to_remove: Vec<String> = engine
            .files
            .keys()
            .filter(|p| p.starts_with(&prefix))
            .cloned()
            .collect();
        for path in &to_remove {
            engine.files.remove(path);
        }

        // Also look for unins???.exe files
        let unins_pattern = format!("{}/unins", prefix);
        let unins_remove: Vec<String> = engine
            .files
            .keys()
            .filter(|p| p.starts_with(&unins_pattern) && p.ends_with(".exe"))
            .cloned()
            .collect();
        for path in &unins_remove {
            engine.files.remove(path);
        }

        // Remove registry keys
        engine.registry.retain(|k, _| !k.starts_with(&uninstall_key.to_ascii_lowercase()));

        let all_removed: Vec<String> = to_remove
            .into_iter()
            .chain(unins_remove)
            .collect();

        let telemetry = InstallerTelemetry {
            installer_id: format!("innosetup-uninstall:{name}"),
            exit_code: 0,
            created_files: all_removed,
            registry_changes: vec![uninstall_key],
            logs: vec![format!("uninstall:innosetup:{name}")],
            window_titles: vec!["Inno Setup".to_string()],
            silent_flags: vec!["/VERYSILENT".to_string()],
        };
        engine.telemetry_log.push(telemetry);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Detection dispatch
// ---------------------------------------------------------------------------

/// Detect the installer framework for the given executable path.
///
/// Checks in order: MSI → InstallShield → NSIS → InnoSetup → Custom.
///
/// For MSI detection we rely on the existing `parse_msi_script` function
/// which looks for the `MSI!` magic.  For the other frameworks we delegate
/// to each engine's `detect()` method.
pub fn detect_installer_type(path: &Path) -> InstallerFramework {
    // MSI detection – read the file and check for "MSI!" magic
    if let Ok(data) = fs::read(path) {
        if data.len() >= 4 && &data[..4] == b"MSI!" {
            return InstallerFramework::Msi;
        }
    }

    if InstallShieldEngine::detect(path) {
        return InstallerFramework::InstallShield;
    }

    if NsisEngine::detect(path) {
        return InstallerFramework::Nsis;
    }

    if InnoSetupEngine::detect(path) {
        return InstallerFramework::InnoSetup;
    }

    InstallerFramework::Custom
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn stable_pairs(env: &BTreeMap<String, String>) -> String {
    env.iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Check whether a PE file has section names with an "IS" prefix (InstallShield
/// indicator).
fn has_installshield_sections(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 4 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return false;
    }

    let num_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]) as usize;
    let opt_header_size = u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;
    let sections_offset = e_lfanew + 4 + 20 + opt_header_size;

    for i in 0..num_sections {
        let entry = sections_offset + i * 40;
        if entry + 8 > data.len() {
            break;
        }
        // Section name is 8 bytes, null-terminated
        let name_bytes = &data[entry..entry + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        if name_end >= 2 && name_bytes[0] == b'I' && name_bytes[1] == b'S' {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Existing functions (unchanged)
// ---------------------------------------------------------------------------

pub fn parse_msi_script(data: &[u8]) -> AppResult<ParsedMsiScript> {
    if data.len() < 7 {
        return Err(AppError::new(
            ReasonCode::RcMsiInvalid,
            "MSI script is truncated",
        ));
    }
    if &data[..4] != b"MSI!" {
        return Err(AppError::new(
            ReasonCode::RcMsiInvalid,
            "MSI script missing magic",
        ));
    }
    let product_len = data[4] as usize;
    if data.len() < 7 + product_len {
        return Err(AppError::new(
            ReasonCode::RcMsiInvalid,
            "MSI script product code is truncated",
        ));
    }
    let product_code = std::str::from_utf8(&data[7..7 + product_len]).map_err(|error| {
        AppError::new(ReasonCode::RcMsiInvalid, "MSI product code is not valid UTF-8")
            .with_hint(error.to_string())
    })?;
    if product_code.is_empty() {
        return Err(AppError::new(
            ReasonCode::RcMsiInvalid,
            "MSI product code is empty",
        ));
    }
    Ok(ParsedMsiScript {
        product_code: product_code.to_string(),
        component_count: data[5],
        custom_action_count: data[6],
    })
}

pub fn msi_fuzz_summary(data: &[u8]) -> String {
    match parse_msi_script(data) {
        Ok(parsed) => format!(
            "ok:{}:{}:{}",
            parsed.product_code, parsed.component_count, parsed.custom_action_count
        ),
        Err(error) => format!("err:{}:{}", error.code.as_u32(), error.message),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ---- helper tests --------------------------------------------------------

    #[test]
    fn search_magic_bytes_finds_pattern() {
        let data = b"hello\x00\x01\x02world";
        assert_eq!(search_magic_bytes(data, b"hello"), Some(0));
        assert_eq!(search_magic_bytes(data, b"world"), Some(8));
        assert_eq!(search_magic_bytes(data, b"\x00\x01"), Some(5));
    }

    #[test]
    fn search_magic_bytes_returns_none_for_no_match() {
        let data = b"hello world";
        assert_eq!(search_magic_bytes(data, b"xyz"), None);
        assert_eq!(search_magic_bytes(data, b""), None);
        assert_eq!(search_magic_bytes(b"", b"abc"), None);
    }

    /// Create a minimal valid PE file for testing.
    /// Returns (path, bytes_written).
    /// The PE has one section `.text` with data_offset=0x200, data_size=64,
    /// and an optional overlay appended after the section data.
    fn create_minimal_pe(dir: &std::path::Path, name: &str, overlay: Option<&[u8]>) -> (PathBuf, Vec<u8>) {
        let path = dir.join(name);
        let mut pe = Vec::new();

        // DOS header (0x00 – 0x3F)
        pe.extend_from_slice(b"MZ");
        pe.resize(0x3C, 0);
        pe.push(0x80); // e_lfanew low byte

        // Pad to 0x80 so we can write e_lfanew at 0x3C and have PE at 0x80
        // Actually e_lfanew was pushed at index 0x3C = 60, need to get to 0x80
        pe.resize(0x80, 0);

        // PE signature at 0x80
        pe.extend_from_slice(b"PE\x00\x00");

        // COFF header (20 bytes)
        pe.extend_from_slice(&0x8664u16.to_le_bytes()); // machine: AMD64
        pe.extend_from_slice(&1u16.to_le_bytes());      // number of sections: 1
        pe.extend_from_slice(&0u32.to_le_bytes());      // timestamp
        pe.extend_from_slice(&0u32.to_le_bytes());      // pointer to symbol table
        pe.extend_from_slice(&0u32.to_le_bytes());      // number of symbols
        pe.extend_from_slice(&0u16.to_le_bytes());      // size of optional header: 0
        pe.extend_from_slice(&0x0102u16.to_le_bytes()); // characteristics: IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE

        // Section header (.text) – 40 bytes
        pe.extend_from_slice(b".text\x00\x00\x00");     // name (8 bytes)
        pe.extend_from_slice(&64u32.to_le_bytes());     // virtual size
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        pe.extend_from_slice(&64u32.to_le_bytes());     // size of raw data
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // pointer to raw data
        pe.extend_from_slice(&0u32.to_le_bytes());       // pointer to relocations
        pe.extend_from_slice(&0u32.to_le_bytes());       // pointer to line numbers
        pe.extend_from_slice(&0u16.to_le_bytes());       // number of relocations
        pe.extend_from_slice(&0u16.to_le_bytes());       // number of line numbers
        pe.extend_from_slice(&0x60000020u32.to_le_bytes()); // characteristics (CODE | EXECUTE | READ)

        // Pad up to 0x200 (the section data offset declared above)
        pe.resize(0x200, 0);

        // Section data (64 bytes)
        let section_data_start = pe.len();
        pe.resize(section_data_start + 64, 0xAA);

        // Optional overlay
        if let Some(overlay_data) = overlay {
            pe.extend_from_slice(overlay_data);
        }

        fs::write(&path, &pe).unwrap();
        (path, pe)
    }

    #[test]
    fn search_magic_bytes_finds_at_multiple_positions() {
        let data = b"abcabcabc";
        assert_eq!(search_magic_bytes(data, b"abc"), Some(0));
        assert_eq!(search_magic_bytes(&data[1..], b"abc"), Some(2)); // shifted by 1
    }

    #[test]
    fn extract_exe_overlay_returns_overlay_data() {
        let dir = tempfile::tempdir().unwrap();
        let overlay_content = b"OVERLAYDATA";
        let (path, _pe) = create_minimal_pe(dir.path(), "test.exe", Some(overlay_content));

        let result = extract_exe_overlay(&path).unwrap();
        assert_eq!(result, overlay_content);
    }

    #[test]
    fn extract_exe_overlay_returns_empty_for_no_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let exe_path = dir.path().join("no_overlay.exe");

        // File too small to be PE
        fs::write(&exe_path, b"not a PE").unwrap();
        assert!(extract_exe_overlay(&exe_path).is_err());

        // File with no overlay
        let (path, _pe) = create_minimal_pe(dir.path(), "no_overlay2.exe", None);
        let result = extract_exe_overlay(&path).unwrap();
        assert!(result.is_empty());
    }

    // ---- InstallShield detect tests -----------------------------------------

    #[test]
    fn installshield_detect_detects_installshield_marker() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _pe) = create_minimal_pe(dir.path(), "setup.exe", Some(b"ISc(\x00\x01\x02\x03"));
        assert!(InstallShieldEngine::detect(&path));
    }

    #[test]
    fn installshield_detect_returns_false_for_plain_exe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("normal.exe");
        fs::write(&path, b"this is not an InstallShield installer").unwrap();
        assert!(!InstallShieldEngine::detect(&path));
    }

    // ---- NSIS detect tests --------------------------------------------------

    #[test]
    fn nsis_detect_detects_nsis_marker() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _pe) = create_minimal_pe(dir.path(), "nsis_installer.exe", Some(b"nsis\x00\x01\x02\x03"));
        assert!(NsisEngine::detect(&path));
    }

    #[test]
    fn nsis_detect_returns_false_for_plain_exe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("normal.exe");
        fs::write(&path, b"this is not an NSIS installer").unwrap();
        assert!(!NsisEngine::detect(&path));
    }

    // ---- InnoSetup detect tests ---------------------------------------------

    #[test]
    fn innosetup_detect_detects_innosetup_marker() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _pe) = create_minimal_pe(dir.path(), "innosetup_installer.exe", Some(b"Inno\x00\x01\x02\x03"));
        assert!(InnoSetupEngine::detect(&path));
    }

    #[test]
    fn innosetup_detect_returns_false_for_plain_exe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("normal.exe");
        fs::write(&path, b"this is not an InnoSetup installer").unwrap();
        assert!(!InnoSetupEngine::detect(&path));
    }

    // ---- decompress_zlib_block test -----------------------------------------

    #[test]
    fn decompress_zlib_block_roundtrips() {
        let original = b"hello world this is a test of zlib compression";
        // Compress using flate2
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_zlib_block(&compressed).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn decompress_zlib_block_errors_on_garbage() {
        let garbage = b"this is not zlib compressed data";
        assert!(decompress_zlib_block(garbage).is_err());
    }

    // ---- Install engine tests -----------------------------------------------

    #[test]
    fn installshield_install_registers_files_and_registry() {
        let dir = tempfile::tempdir().unwrap();
        let installer_path = dir.path().join("setup.exe");

        // Build a minimal valid CAB with MSCF magic and 0 files.
        // CAB header (CFHEADER) is 36 bytes.
        let mut cab = Vec::new();
        cab.extend_from_slice(b"MSCF");                     // 0-3:  magic
        cab.extend_from_slice(&[0u8; 4]);                   // 4-7:  reserved1
        cab.extend_from_slice(&44u32.to_le_bytes());        // 8-11: cab size
        cab.extend_from_slice(&[0u8; 4]);                   // 12-15: reserved2
        cab.extend_from_slice(&36u32.to_le_bytes());        // 16-19: file_offset
        cab.extend_from_slice(&[0u8; 4]);                   // 20-23: reserved3
        cab.extend_from_slice(&[1u8, 4]);                   // 24-25: version (1.4)
        cab.extend_from_slice(&0u16.to_le_bytes());         // 26-27: folder_count = 0
        cab.extend_from_slice(&0u16.to_le_bytes());         // 28-29: file_count = 0
        cab.extend_from_slice(&0u16.to_le_bytes());         // 30-31: flags = 0
        cab.extend_from_slice(&0u16.to_le_bytes());         // 32-33: set_id
        cab.extend_from_slice(&0u16.to_le_bytes());         // 34-35: cab_idx

        // Embed the CAB after "ISc(" prefix
        let mut data = Vec::new();
        data.extend_from_slice(b"ISc(");   // InstallShield CAB marker
        data.extend_from_slice(&cab);      // CAB content
        fs::write(&installer_path, &data).unwrap();

        let engine = InstallShieldEngine {
            installer_path: installer_path.clone(),
            cab_data: Vec::new(), // will be extracted from the file
        };

        let mut state = InstallerEngine::new();
        let result = engine.install(&mut state).unwrap();

        assert!(result.contains("Program Files"));
        // Check registry was written
        let registry = state.registry();
        assert!(registry.values().any(|v| v == "1.0.0"));
    }

    #[test]
    fn nsis_install_registers_files_and_registry() {
        let dir = tempfile::tempdir().unwrap();

        // Build NSIS overlay with one stored (uncompressed) entry.
        // Layout (offsets relative to overlay start):
        //   0-3:   "nsis" magic
        //   4-7:   first_header (u32 LE, relative offset to first entry)
        //   8-11:  next_header (u32 LE, 0 = end of chain)
        //   12-15: uncompressed_size (u32 LE)
        //   16-19: compressed_size (u32 LE, bit31=0 = stored)
        //   20-28: "test.txt\0" (null-terminated filename, 9 bytes)
        //   29-31: padding to 4-byte boundary
        //   32-36: "hello" (5 bytes of file data)
        let mut overlay = Vec::new();
        overlay.extend_from_slice(b"nsis");                    // 0-3:   magic
        overlay.extend_from_slice(&8u32.to_le_bytes());        // 4-7:   first_header = 8
        overlay.extend_from_slice(&0u32.to_le_bytes());        // 8-11:  next_header = 0 (end)
        overlay.extend_from_slice(&5u32.to_le_bytes());        // 12-15: uncompressed_size = 5
        overlay.extend_from_slice(&0u32.to_le_bytes());        // 16-19: compressed_size = 0 (stored)
        overlay.extend_from_slice(b"test.txt\x00");             // 20-28: filename (9 bytes)
        overlay.resize(32, 0);                                 // 29-31: padding to 4-byte boundary
        overlay.extend_from_slice(b"hello");                    // 32-36: file data (5 bytes)

        let (installer_path, _pe) = create_minimal_pe(dir.path(), "nsis_installer.exe", Some(&overlay));

        let engine = NsisEngine {
            installer_path: installer_path.clone(),
            extract_dir: dir.path().join("extract"),
        };

        let mut state = InstallerEngine::new();
        let result = engine.install(&mut state).unwrap();
        assert!(result.contains("Program Files"));
        assert!(!state.files().is_empty());
    }

    #[test]
    fn innosetup_install_registers_files_and_registry() {
        let dir = tempfile::tempdir().unwrap();

        // Build decompressed data that extract_innosetup_entries can parse
        // via the fallback path (scanning for '/' or '\').
        // Layout:
        //   0-3:   "zbin" magic
        //   4-7:   zero padding
        //   8-15:  data_offset=0, data_size=0  -> triggers fallback scan
        //   16-31: padding text
        //   32-46: "dir/hello.txt\0"  -> fallback finds '/' and extracts filename
        let mut decompressed = Vec::new();
        decompressed.extend_from_slice(b"zbin");
        decompressed.extend_from_slice(&[0u8; 4]);
        decompressed.extend_from_slice(&[0u8; 8]);  // data_offset=0, data_size=0
        decompressed.extend_from_slice(b"0123456789abcdef");
        decompressed.extend_from_slice(b"dir/hello.txt\x00");

        // Compress with zlib
        use flate2::Compression;
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&decompressed).unwrap();
        let compressed = encoder.finish().unwrap();

        // Build overlay: "Inno" magic + 20-byte header + compressed data
        let mut overlay = Vec::new();
        overlay.extend_from_slice(b"Inno");                              // 0-3:   magic
        overlay.extend_from_slice(&20u32.to_le_bytes());                 // 4-7:   header_size = 20
        overlay.extend_from_slice(&20u32.to_le_bytes());                 // 8-11:  comp_offset = 20 (right after header)
        overlay.extend_from_slice(&(compressed.len() as u32).to_le_bytes()); // 12-15: comp_size
        overlay.extend_from_slice(&(decompressed.len() as u32).to_le_bytes());// 16-19: uncomp_size
        overlay.extend_from_slice(&compressed);                          // 20+:   compressed data

        let (installer_path, _pe) = create_minimal_pe(dir.path(), "innosetup_installer.exe", Some(&overlay));

        let engine = InnoSetupEngine {
            installer_path: installer_path.clone(),
            extract_dir: dir.path().join("extract"),
        };

        let mut state = InstallerEngine::new();
        let result = engine.install(&mut state).unwrap();
        assert!(result.contains("Program Files"));
        assert!(!state.files().is_empty());
    }

    // ---- Uninstall tests ----------------------------------------------------

    #[test]
    fn installshield_uninstall_cleans_up() {
        let mut state = InstallerEngine::new();
        let dir = tempfile::tempdir().unwrap();
        let installer_path = dir.path().join("MyApp.exe");

        // Simulate prior install
        state.files.insert(
            "c:/program files/installshield/myapp/main.exe".to_string(),
            vec![1, 2, 3],
        );
        state.registry.insert(
            "hklm/software/microsoft/windows/currentversion/uninstall/myapp/displayname"
                .to_string(),
            "MyApp".to_string(),
        );

        let engine = InstallShieldEngine {
            installer_path,
            cab_data: Vec::new(),
        };

        engine.uninstall(&mut state).unwrap();
        assert!(state.files().is_empty());
        assert!(state.registry().is_empty());
    }

    #[test]
    fn nsis_uninstall_cleans_up() {
        let mut state = InstallerEngine::new();
        let dir = tempfile::tempdir().unwrap();
        let installer_path = dir.path().join("MyNSISApp.exe");

        state.files.insert(
            "c:/program files/mynsisapp/main.exe".to_string(),
            vec![1, 2, 3],
        );
        state.registry.insert(
            "hklm/software/microsoft/windows/currentversion/uninstall/mynsisapp/displayname"
                .to_string(),
            "MyNSISApp".to_string(),
        );

        let engine = NsisEngine {
            installer_path,
            extract_dir: dir.path().join("extract"),
        };

        engine.uninstall(&mut state).unwrap();
        assert!(state.files().is_empty());
        assert!(state.registry().is_empty());
    }

    #[test]
    fn innosetup_uninstall_cleans_up() {
        let mut state = InstallerEngine::new();
        let dir = tempfile::tempdir().unwrap();
        let installer_path = dir.path().join("MyInnoApp.exe");

        state.files.insert(
            "c:/program files/myinnoapp/app.exe".to_string(),
            vec![1, 2, 3],
        );
        state.files.insert(
            "c:/program files/myinnoapp/unins000.exe".to_string(),
            vec![4, 5, 6],
        );
        state.registry.insert(
            "hklm/software/microsoft/windows/currentversion/uninstall/myinnoapp/displayname"
                .to_string(),
            "MyInnoApp".to_string(),
        );

        let engine = InnoSetupEngine {
            installer_path,
            extract_dir: dir.path().join("extract"),
        };

        engine.uninstall(&mut state).unwrap();
        assert!(state.files().is_empty());
        assert!(state.registry().is_empty());
    }

    // ---- Detection dispatch test --------------------------------------------

    #[test]
    fn detect_installer_type_dispatch() {
        let dir = tempfile::tempdir().unwrap();

        // MSI
        let msi_path = dir.path().join("test.msi");
        fs::write(&msi_path, b"MSI!\x05product\x00\x00").unwrap();
        assert_eq!(detect_installer_type(&msi_path), InstallerFramework::Msi);

        // Custom
        let custom_path = dir.path().join("custom.exe");
        fs::write(&custom_path, b"unknown data").unwrap();
        assert_eq!(
            detect_installer_type(&custom_path),
            InstallerFramework::Custom
        );
    }

    // ---- register_installed_app test ----------------------------------------

    #[test]
    fn register_installed_app_writes_registry() {
        let mut state = InstallerEngine::new();
        register_installed_app(&mut state, "TestApp", "C:/TestApp", "C:/TestApp/uninstall.exe")
            .unwrap();

        let reg = state.registry();
        assert!(reg.contains_key(
            "hklm/software/microsoft/windows/currentversion/uninstall/testapp/displayname"
        ));
        assert_eq!(
            reg.get(
                "hklm/software/microsoft/windows/currentversion/uninstall/testapp/installlocation"
            ),
            Some(&"C:/TestApp".to_string())
        );
        assert_eq!(
            reg.get(
                "hklm/software/microsoft/windows/currentversion/uninstall/testapp/uninstallstring"
            ),
            Some(&"C:/TestApp/uninstall.exe".to_string())
        );
    }

    // ---- PE version string reading test -------------------------------------

    #[test]
    fn read_pe_version_string_returns_none_for_non_pe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not_a_pe.bin");
        fs::write(&path, b"random data").unwrap();
        assert!(read_pe_version_string(&path, "FileDescription")
            .unwrap()
            .is_none());
    }
}
