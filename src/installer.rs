use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum InstallerFramework {
    Nsis,
    InnoSetup,
    WixBundle,
    Msi,
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
            InstallerFramework::InnoSetup => vec!["/VERYSILENT".to_string(), "/SUPPRESSMSGBOXES".to_string()],
            InstallerFramework::WixBundle => vec!["/quiet".to_string(), "/norestart".to_string()],
            InstallerFramework::Msi => vec!["/qn".to_string(), "/norestart".to_string()],
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

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn stable_pairs(env: &BTreeMap<String, String>) -> String {
    env.iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

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