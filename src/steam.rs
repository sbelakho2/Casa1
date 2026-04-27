use crate::audio::AudioSubsystem;
use crate::error::{AppError, AppResult};
use crate::ge::{GameEnvironment, RegistryView};
use crate::installer::{GuiWindowPlan, InstallerEngine, InstallerFramework, InstallerSpec, InstallerTelemetry, RuntimeAssembly};
use crate::network::{Certificate, NetworkStack};
use crate::reason::ReasonCode;
use crate::security::{detect_driver_requirement_paths, driver_requirement_error};
use crate::user32::{
    KeyboardDevice, KeyboardLayoutId, KeyModifiers, MessageKind, MouseDevice, User32Subsystem,
};
use crate::util;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

const OFFICIAL_STEAM_SETUP_NAME: &str = "steamsetup.exe";
const NATIVE_STEAM_INSTALL_ROOT: &str = "C:/Steam";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SteamBootResult {
    pub login_window_title: String,
    pub steam_exe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SteamUpdatePlan {
    pub files: BTreeMap<String, Vec<u8>>,
    pub fail_after_write: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SteamLoginResult {
    pub cipher_suite: String,
    pub store_window_title: String,
    pub rendered_html_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeSteamInstallResult {
    pub install_root: String,
    pub file_list: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpcRoundtrip {
    pub pipe_name: String,
    pub shared_region: String,
    pub response: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepotManifest {
    pub app_id: u32,
    pub game_name: String,
    pub install_dir: String,
    pub launch_exe: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library_root: Option<String>,
    #[serde(default)]
    pub prerequisites: Vec<SteamGamePrerequisite>,
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SteamGamePrerequisite {
    DirectX { dll: String },
    DotNet { version: String },
    VisualCpp { version: String, dlls: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepotInstallResult {
    pub normalized_tree_hash: String,
    pub file_list: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SteamZeroTouchLaunchResult {
    pub install_telemetry: InstallerTelemetry,
    pub boot: SteamBootResult,
    pub login: SteamLoginResult,
    pub depot_install: DepotInstallResult,
    pub launch: GameLaunchResult,
    pub app_manifest_path: String,
    pub prerequisite_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GameLaunchResult {
    pub executable: String,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub window_title: String,
    pub checkpoint_hash: String,
    pub input_ok: bool,
    pub audio_ok: bool,
    pub network_ok: bool,
}

#[derive(Debug, Clone)]
struct InstalledDepot {
    manifest: DepotManifest,
    library_root: String,
    install_root: String,
    app_manifest_path: String,
    normalized_tree_hash: String,
    file_list: Vec<String>,
}

#[derive(Debug, Clone)]
struct IpcChannel {
    response: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SteamClient {
    ge_root: String,
    library_roots: Vec<String>,
    files: BTreeMap<String, Vec<u8>>,
    path_case: BTreeMap<String, String>,
    logs: Vec<String>,
    installer: InstallerEngine,
    ui: User32Subsystem,
    network: NetworkStack,
    audio: AudioSubsystem,
    logged_in: bool,
    installed_depots: BTreeMap<u32, InstalledDepot>,
    ipc_channels: BTreeMap<(String, String), IpcChannel>,
    steamworks_ready: BTreeSet<u32>,
    overlay_active: BTreeSet<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VdfNode {
    String(String),
    Object(BTreeMap<String, VdfNode>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VdfToken {
    String(String),
    OpenBrace,
    CloseBrace,
}

impl SteamClient {
    pub fn new(ge_root: &str) -> Self {
        Self::with_install_state(ge_root, true)
    }

    pub fn new_uninstalled(ge_root: &str) -> Self {
        Self::with_install_state(ge_root, false)
    }

    fn with_install_state(ge_root: &str, installed: bool) -> Self {
        let ge_root = normalize_path(ge_root);
        let mut network = NetworkStack::new();
        network.add_route(
            "https",
            "api.example.com",
            "/store/home",
            200,
            BTreeMap::from([("content-type".to_string(), "text/html".to_string())]),
            b"<html><body><div id=store>Steam Store</div></body></html>",
            Vec::new(),
            Vec::new(),
        );
        network.add_route(
            "http",
            "launcher.example.com",
            "/presence",
            200,
            BTreeMap::from([("content-type".to_string(), "application/json".to_string())]),
            br#"{"presence":"ok"}"#,
            Vec::new(),
            Vec::new(),
        );

        let mut client = Self {
            ge_root: ge_root.clone(),
            library_roots: vec![ge_root.clone()],
            files: BTreeMap::new(),
            path_case: BTreeMap::new(),
            logs: Vec::new(),
            installer: InstallerEngine::new(),
            ui: User32Subsystem::new(KeyboardLayoutId::Us),
            network,
            audio: AudioSubsystem::new(),
            logged_in: false,
            installed_depots: BTreeMap::new(),
            ipc_channels: BTreeMap::new(),
            steamworks_ready: BTreeSet::new(),
            overlay_active: BTreeSet::new(),
        };
        if installed {
            client.seed_steam_installation();
        }
        client
    }

    pub fn network_mut(&mut self) -> &mut NetworkStack {
        &mut self.network
    }

    pub fn logs(&self) -> &[String] {
        &self.logs
    }

    pub fn file_list(&self) -> Vec<String> {
        self.path_case.values().cloned().collect()
    }

    pub fn has_file(&self, path: &str) -> bool {
        self.files.contains_key(&normalize_path(path))
    }

    pub fn has_directx_component(&self, dll_name: &str) -> bool {
        self.installer.has_directx_component(dll_name)
    }

    pub fn has_vc_runtime(&self, version: &str, dlls: &[&str]) -> bool {
        self.installer.activate_vc_runtime(version, dlls)
    }

    pub fn supports_dotnet(&self, version: &str) -> bool {
        self.installer.require_dotnet(version).is_ok()
    }

    pub fn register_library_folder(&mut self, path: &str) {
        let normalized = normalize_library_root(path);
        if self
            .library_roots
            .iter()
            .any(|existing| normalize_library_root(existing) == normalized)
        {
            self.refresh_libraryfolders_file();
            return;
        }

        self.library_roots.push(normalized.clone());
        self.library_roots.sort();
        if let Some(primary_index) = self
            .library_roots
            .iter()
            .position(|path| path == &self.ge_root)
        {
            self.library_roots.swap(0, primary_index);
        }
        self.logs.push(format!("library-folder:{normalized}"));
        self.refresh_libraryfolders_file();
    }

    pub fn materialize_into_ge(&self, ge: &mut GameEnvironment, dtm: bool) -> AppResult<()> {
        let mut files = self.installer.files().clone();
        for (path, bytes) in &self.files {
            files.insert(path.clone(), bytes.clone());
        }

        for (path, bytes) in files {
            let windows_path = self
                .path_case
                .get(&path)
                .cloned()
                .unwrap_or(path.replace('\\', "/"));
            materialize_windows_file(ge, &windows_path, &bytes, dtm)?;
        }

        for (entry_path, value) in self.installer.registry() {
            let (hive, key, value_name) = split_registry_entry(entry_path)?;
            ge.registry_set_value(
                &hive,
                &key,
                &value_name,
                "REG_SZ",
                Value::String(value.clone()),
                RegistryView::Native,
            )?;
        }

        Ok(())
    }

    pub fn app_manifest_path(&self, app_id: u32) -> String {
        self.installed_depots
            .get(&app_id)
            .map(|depot| depot.app_manifest_path.clone())
            .unwrap_or_else(|| app_manifest_path_for_library(&self.ge_root, app_id))
    }

    pub fn install_downloaded_steam_executable(
        &mut self,
        downloaded_installer_path: &str,
        installer_bytes: &[u8],
    ) -> AppResult<InstallerTelemetry> {
        let normalized_download = normalize_path(downloaded_installer_path);
        if !normalized_download.ends_with(".exe") {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("unsupported Steam installer payload: {downloaded_installer_path}"),
            ));
        }

        let installer_spec = InstallerSpec {
            id: "steam-setup".to_string(),
            executable_name: file_name(downloaded_installer_path),
            framework: InstallerFramework::Nsis,
            gui_windows: vec![GuiWindowPlan {
                title: "Steam Setup".to_string(),
                modal: true,
                controls: vec!["Install".to_string(), "Cancel".to_string()],
            }],
            files: steam_install_files(&self.ge_root),
            registry: BTreeMap::from([
                (
                    "HKCU/Software/Valve/Steam/SteamExe".to_string(),
                    format!("{}/steam.exe", self.ge_root),
                ),
                (
                    "HKCU/Software/Valve/Steam/SteamPath".to_string(),
                    self.ge_root.clone(),
                ),
            ]),
            logs: vec![
                format!("downloaded-installer:{normalized_download}"),
                format!("installer-sha256:{}", util::sha256_bytes(installer_bytes)),
            ],
        };
        let result = self.installer.run_gui_installer(&installer_spec, None)?;
        for (path, bytes) in &installer_spec.files {
            self.write_file(path, bytes.clone());
        }
        self.logs.push(format!("steam-install:{normalized_download}"));
        self.logs.push(format!(
            "steam-install-silent:{}",
            result.telemetry.silent_flags.join(" ")
        ));
        Ok(result.telemetry)
    }

    pub fn zero_touch_install_and_launch(
        &mut self,
        downloaded_installer_path: &str,
        installer_bytes: &[u8],
        update_plan: &SteamUpdatePlan,
        certificate_chain: &[Certificate],
        depot: DepotManifest,
    ) -> AppResult<SteamZeroTouchLaunchResult> {
        let install_telemetry =
            self.install_downloaded_steam_executable(downloaded_installer_path, installer_bytes)?;
        let _ = self.boot()?;
        self.self_update(update_plan)?;
        let boot = self.boot()?;
        if let Some(root) = certificate_chain.last().cloned() {
            self.network.import_certificate(root);
        }
        let login = self.login(certificate_chain)?;
        let app_id = depot.app_id;
        let depot_install = self.install_depot(depot)?;
        let launch = self.launch_game(app_id)?;
        Ok(SteamZeroTouchLaunchResult {
            install_telemetry,
            boot,
            login,
            depot_install,
            launch,
            app_manifest_path: self.app_manifest_path(app_id),
            prerequisite_actions: self
                .logs
                .iter()
                .filter(|entry| entry.starts_with(&format!("prereq:{app_id}:")))
                .cloned()
                .collect(),
        })
    }

    pub fn boot(&mut self) -> AppResult<SteamBootResult> {
        if !self.files.contains_key(&format!("{}/steam.exe", self.ge_root)) {
            return Err(AppError::new(
                ReasonCode::RcSteamUpdateFailed,
                "Steam.exe missing after update",
            ));
        }
        self.ui.register_class_ex_w("SteamMainWindow");
        let title = if self.logged_in { "Steam" } else { "Steam Login" };
        let hwnd = self.ui.create_window_ex_w(
            "SteamMainWindow",
            title,
            1280,
            720,
            true,
            false,
            None,
            1,
        )?;
        let state = self.ui.window_state(hwnd)?;
        self.logs.push(format!("boot:{}", state.title));
        Ok(SteamBootResult {
            login_window_title: state.title,
            steam_exe: self.path_case[&format!("{}/steam.exe", self.ge_root)].clone(),
        })
    }

    pub fn self_update(&mut self, plan: &SteamUpdatePlan) -> AppResult<()> {
        let files_snapshot = self.files.clone();
        let path_case_snapshot = self.path_case.clone();
        for (path, bytes) in &plan.files {
            let normalized = normalize_path(path);
            if !normalized.starts_with(&self.ge_root) {
                self.files = files_snapshot;
                self.path_case = path_case_snapshot;
                self.logs.push(format!(
                    "steam-update-failed:{}:{}",
                    ReasonCode::RcSteamUpdateFailed.name(),
                    normalized
                ));
                return Err(AppError::new(
                    ReasonCode::RcSteamUpdateFailed,
                    format!("update attempted to escape GE root: {path}"),
                ));
            }
            self.write_file(path, bytes.clone());
            self.logs.push(format!("update-write:{normalized}"));
            if plan.fail_after_write.as_deref() == Some(path) {
                self.files = files_snapshot;
                self.path_case = path_case_snapshot;
                self.logs.push(format!(
                    "steam-update-failed:{}:{}",
                    ReasonCode::RcSteamUpdateFailed.name(),
                    normalized
                ));
                return Err(AppError::new(
                    ReasonCode::RcSteamUpdateFailed,
                    format!("update failed while writing {path}"),
                ));
            }
        }
        self.logs.push("update-success".to_string());
        Ok(())
    }

    pub fn prime_ipc_channel(&mut self, pipe_name: &str, shared_region: &str, response: &[u8]) {
        self.ipc_channels.insert(
            (pipe_name.to_string(), shared_region.to_string()),
            IpcChannel {
                response: response.to_vec(),
            },
        );
    }

    pub fn ipc_roundtrip(&mut self, pipe_name: &str, shared_region: &str, payload: &[u8]) -> AppResult<IpcRoundtrip> {
        let key = (pipe_name.to_string(), shared_region.to_string());
        let channel = self.ipc_channels.get(&key).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("steam IPC hang on {pipe_name}"))
        })?;
        self.logs.push(format!(
            "ipc:{}:{}:{}",
            pipe_name,
            shared_region,
            util::sha256_bytes(payload)
        ));
        Ok(IpcRoundtrip {
            pipe_name: pipe_name.to_string(),
            shared_region: shared_region.to_string(),
            response: channel.response.clone(),
        })
    }

    pub fn login(&mut self, certificate_chain: &[Certificate]) -> AppResult<SteamLoginResult> {
        let cipher = self
            .network
            .validate_server_certificate("api.example.com", certificate_chain, true)?;
        self.network.add_route(
            "https",
            "api.example.com",
            "/login",
            200,
            BTreeMap::from([("x-casa1-route".to_string(), "login".to_string())]),
            br#"{"ok":true}"#,
            Vec::new(),
            certificate_chain.to_vec(),
        );
        self.network.add_route(
            "https",
            "api.example.com",
            "/store/home",
            200,
            BTreeMap::from([("content-type".to_string(), "text/html".to_string())]),
            b"<html><body><div id=store>Steam Store</div></body></html>",
            Vec::new(),
            certificate_chain.to_vec(),
        );
        let session = self.network.win_http_open("Steam Client");
        let connection = self
            .network
            .win_http_connect(session, "api.example.com", 443, true)?;
        let request = self
            .network
            .win_http_open_request(connection, "POST", "/login")?;
        self.network
            .win_http_send_request(request, BTreeMap::new(), b"user=steam")?;
        self.network.win_http_receive_response(request)?;
        let store_request = self
            .network
            .win_http_open_request(connection, "GET", "/store/home")?;
        self.network
            .win_http_send_request(store_request, BTreeMap::new(), &[])?;
        self.network.win_http_receive_response(store_request)?;
        let body = self.network.win_http_read_data(store_request, 8192)?;
        self.network.close_handle(store_request);
        self.network.close_handle(request);
        self.network.close_handle(connection);
        self.network.close_handle(session);

        self.logged_in = true;
        self.ui.register_class_ex_w("SteamWebView");
        let hwnd = self.ui.create_window_ex_w(
            "SteamWebView",
            "Steam Store",
            1280,
            720,
            true,
            false,
            None,
            1,
        )?;
        let state = self.ui.window_state(hwnd)?;
        self.logs.push("login-success".to_string());
        Ok(SteamLoginResult {
            cipher_suite: cipher,
            store_window_title: state.title,
            rendered_html_hash: util::sha256_bytes(&body),
        })
    }

    pub fn install_depot(&mut self, manifest: DepotManifest) -> AppResult<DepotInstallResult> {
        let mut manifest = manifest;
        let library_root = self.resolve_library_root(manifest.library_root.as_deref());
        manifest.library_root = Some(library_root.clone());
        let install_root = install_root_for_library(&library_root, &manifest.install_dir);
        let mut staged: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut staged_case: BTreeMap<String, String> = BTreeMap::new();
        for (relative_path, bytes) in &manifest.files {
            let full_original = join_path(&install_root, relative_path);
            let normalized = normalize_path(&full_original);
            if let Some(existing) = staged.get(&normalized) {
                if existing != bytes {
                    return Err(AppError::new(
                        ReasonCode::RcIo,
                        format!("case-collision corruption for {relative_path}"),
                    ));
                }
                continue;
            }
            staged.insert(normalized.clone(), bytes.clone());
            staged_case.insert(normalized, full_original);
        }
        for (path, bytes) in &staged {
            self.files.insert(path.clone(), bytes.clone());
        }
        for (normalized, original) in &staged_case {
            self.path_case.insert(normalized.clone(), original.clone());
        }
        let app_manifest_path = app_manifest_path_for_library(&library_root, manifest.app_id);
        self.write_file(&app_manifest_path, steam_app_manifest_bytes(&manifest));
        let file_list = {
            let mut entries = staged_case.values().cloned().collect::<Vec<_>>();
            entries.push(app_manifest_path.clone());
            entries.sort();
            entries
        };
        let normalized_tree_hash = tree_hash(&staged);
        let app_id = manifest.app_id;
        self.installed_depots.insert(
            app_id,
            InstalledDepot {
                manifest,
                library_root,
                install_root,
                app_manifest_path: app_manifest_path.clone(),
                normalized_tree_hash: normalized_tree_hash.clone(),
                file_list: file_list.clone(),
            },
        );
        self.logs.push(format!("depot-install:{app_id}"));
        self.logs.push(format!("appmanifest-write:{app_id}:{app_manifest_path}"));
        self.refresh_libraryfolders_file();
        Ok(DepotInstallResult {
            normalized_tree_hash,
            file_list,
        })
    }

    pub fn verify_integrity(&self, app_id: u32) -> AppResult<DepotInstallResult> {
        let depot = self.installed_depots.get(&app_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown depot {app_id}"))
        })?;
        let normalized_install_root = normalize_path(&depot.install_root);
        let actual = self
            .files
            .iter()
            .filter(|(path, _)| path.starts_with(&normalized_install_root))
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect::<BTreeMap<_, _>>();
        let actual_hash = tree_hash(&actual);
        if actual_hash != depot.normalized_tree_hash {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("integrity mismatch for depot {app_id}"),
            ));
        }
        Ok(DepotInstallResult {
            normalized_tree_hash: actual_hash,
            file_list: depot.file_list.clone(),
        })
    }

    pub fn launch_game(&mut self, app_id: u32) -> AppResult<GameLaunchResult> {
        let depot = self.installed_depots.get(&app_id).cloned().ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown depot {app_id}"))
        })?;
        self.ensure_depot_prerequisites(&depot.manifest)?;
        let executable = join_path(&depot.install_root, &depot.manifest.launch_exe);
        let executable_normalized = normalize_path(&executable);
        if !self.files.contains_key(&executable_normalized) {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("launch target missing: {}", depot.manifest.launch_exe),
            ));
        }
        if let Some(report) = detect_driver_requirement_paths(
            &executable,
            self.path_case.values().map(String::as_str),
        ) {
            return Err(driver_requirement_error(&report));
        }
        self.ui.register_class_ex_w("SteamGameWindow");
        let hwnd = self.ui.create_window_ex_w(
            "SteamGameWindow",
            &format!("{} - Main Menu", depot.manifest.game_name),
            1920,
            1080,
            true,
            false,
            None,
            1,
        )?;
        let keyboard_id = self.ui.register_keyboard_device(&KeyboardDevice {
            vendor_id: 0x045e,
            product_id: 0x0001,
            serial: format!("steam-kbd-{app_id}"),
        });
        let mouse_id = self.ui.register_mouse_device(&MouseDevice {
            vendor_id: 0x045e,
            product_id: 0x0002,
            serial: format!("steam-mouse-{app_id}"),
        });
        self.ui.inject_keyboard_input(
            hwnd,
            &keyboard_id,
            0x10,
            KeyModifiers {
                shift: false,
                altgr: false,
            },
        )?;
        self.ui.inject_mouse_input(hwnd, &mouse_id, 12, 8, &[], 0, 0)?;
        let mut input_ok = false;
        while let Some(message) = self.ui.get_message_w() {
            if matches!(message.kind, MessageKind::KeyDown | MessageKind::MouseMove) {
                input_ok = true;
            }
        }

        let audio_ok = !self.audio.devices().is_empty();

        let session = self.network.win_http_open("Steam Game Runtime");
        let connection = self
            .network
            .win_http_connect(session, "launcher.example.com", 80, false)?;
        let request = self
            .network
            .win_http_open_request(connection, "GET", "/presence")?;
        self.network
            .win_http_send_request(request, BTreeMap::new(), &[])?;
        self.network.win_http_receive_response(request)?;
        let body = self.network.win_http_read_data(request, 4096)?;
        let network_ok = body == br#"{"presence":"ok"}"#;
        self.network.close_handle(request);
        self.network.close_handle(connection);
        self.network.close_handle(session);

        self.steamworks_ready.insert(app_id);
        let window_title = self.ui.window_state(hwnd)?.title;
        let checkpoint_hash = util::sha256_bytes(
            format!("{executable}|{}|{window_title}|{}", parent_dir(&executable), util::sha256_bytes(&body))
                .as_bytes(),
        );
        Ok(GameLaunchResult {
            executable,
            cwd: parent_dir(&self.path_case[&executable_normalized]),
            env: BTreeMap::from([
                ("SteamAppId".to_string(), app_id.to_string()),
                ("SteamGameId".to_string(), app_id.to_string()),
                ("SteamPath".to_string(), self.path_case[&format!("{}/steam.exe", self.ge_root)].clone()),
                ("SteamLibraryPath".to_string(), depot.library_root.clone()),
            ]),
            window_title,
            checkpoint_hash,
            input_ok,
            audio_ok,
            network_ok,
        })
    }

    pub fn steam_api_init(&self, app_id: u32) -> bool {
        self.steamworks_ready.contains(&app_id)
    }

    pub fn overlay_command(&mut self, app_id: u32, command: &str) -> AppResult<i32> {
        if !self.installed_depots.contains_key(&app_id) {
            return Err(AppError::new(ReasonCode::RcIo, format!("unknown depot {app_id}")));
        }
        match command {
            "activate" => {
                self.overlay_active.insert(app_id);
                Ok(0)
            }
            "deactivate" => {
                self.overlay_active.remove(&app_id);
                Ok(0)
            }
            "pump" => Ok(if self.overlay_active.contains(&app_id) { 1 } else { 0 }),
            other => Err(AppError::new(
                ReasonCode::RcIo,
                format!("unknown overlay command {other}"),
            )),
        }
    }

    pub fn overlay_active(&self, app_id: u32) -> bool {
        self.overlay_active.contains(&app_id)
    }

    fn seed_steam_installation(&mut self) {
        for (path, bytes) in steam_install_files(&self.ge_root) {
            self.write_file(&path, bytes);
        }
        self.refresh_libraryfolders_file();
    }

    fn ensure_depot_prerequisites(&mut self, manifest: &DepotManifest) -> AppResult<()> {
        for prerequisite in &manifest.prerequisites {
            match prerequisite {
                SteamGamePrerequisite::DirectX { dll } => {
                    if !self.installer.has_directx_component(dll) {
                        self.installer.provide_directx_component(dll);
                        self.logs.push(format!(
                            "prereq:{}:directx:{}",
                            manifest.app_id,
                            dll.to_ascii_lowercase()
                        ));
                    }
                }
                SteamGamePrerequisite::DotNet { version } => {
                    self.installer.require_dotnet(version)?;
                    self.logs
                        .push(format!("prereq:{}:dotnet:{version}", manifest.app_id));
                }
                SteamGamePrerequisite::VisualCpp { version, dlls } => {
                    let required = dlls.iter().map(String::as_str).collect::<Vec<_>>();
                    if !self.installer.activate_vc_runtime(version, &required) {
                        self.installer.install_vc_runtime(RuntimeAssembly {
                            version: version.clone(),
                            manifest: format!("steam-redist-{version}"),
                            dlls: dlls.clone(),
                        });
                        self.logs.push(format!(
                            "prereq:{}:vcredist:{}:{}",
                            manifest.app_id,
                            version,
                            dlls.join(",")
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn write_file(&mut self, path: &str, bytes: Vec<u8>) {
        let normalized = normalize_path(path);
        self.files.insert(normalized.clone(), bytes);
        self.path_case.insert(normalized, path.replace('\\', "/"));
    }

    fn refresh_libraryfolders_file(&mut self) {
        self.write_file(
            &format!("{}/steamapps/libraryfolders.vdf", self.ge_root),
            steam_libraryfolders_bytes(&self.library_roots, &self.installed_depots),
        );
    }

    fn resolve_library_root(&mut self, requested: Option<&str>) -> String {
        let selected = requested
            .map(normalize_library_root)
            .unwrap_or_else(|| self.ge_root.clone());
        self.register_library_folder(&selected);
        selected
    }
}

pub fn is_official_steam_setup(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case(OFFICIAL_STEAM_SETUP_NAME))
        .unwrap_or(false)
}

pub fn install_official_steam_setup_into_ge(
    ge: &mut GameEnvironment,
    installer_path: &Path,
    dtm: bool,
) -> AppResult<NativeSteamInstallResult> {
    if !is_official_steam_setup(installer_path) {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!(
                "unsupported native Steam installer recovery target {}",
                installer_path.display()
            ),
        ));
    }

    let extraction_root = create_native_steam_extract_dir()?;
    let result = (|| {
        extract_archive_with_7z(installer_path, &extraction_root)?;
        let mut file_list = Vec::new();
        let mut saw_steam_exe = false;
        for entry in WalkDir::new(&extraction_root)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
        {
            let relative = entry.path().strip_prefix(&extraction_root).map_err(|error| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!(
                        "failed to resolve extracted Steam payload path {}",
                        entry.path().display()
                    ),
                )
                .with_hint(error.to_string())
            })?;
            let relative = normalize_relative(&relative.to_string_lossy());
            let Some(target_path) = steam_install_target_path(&relative) else {
                continue;
            };
            let bytes = fs::read(entry.path()).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to read extracted Steam payload {}", entry.path().display()),
                    &error,
                )
            })?;
            materialize_windows_file(ge, &target_path, &bytes, dtm)?;
            if relative.eq_ignore_ascii_case("Steam.exe") {
                saw_steam_exe = true;
            }
            file_list.push(target_path);
        }

        if !saw_steam_exe {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!(
                    "native Steam extraction did not produce Steam.exe from {}",
                    installer_path.display()
                ),
            ));
        }

        let steam_root_backslashes = NATIVE_STEAM_INSTALL_ROOT.replace('/', "\\");
        ge.registry_set_value(
            "HKCU",
            "Software\\Valve\\Steam",
            "SteamExe",
            "REG_SZ",
            Value::String(format!("{steam_root_backslashes}\\Steam.exe")),
            RegistryView::Native,
        )?;
        ge.registry_set_value(
            "HKCU",
            "Software\\Valve\\Steam",
            "SteamPath",
            "REG_SZ",
            Value::String(steam_root_backslashes),
            RegistryView::Native,
        )?;

        file_list.sort();
        Ok(NativeSteamInstallResult {
            install_root: NATIVE_STEAM_INSTALL_ROOT.to_string(),
            file_list,
        })
    })();
    let _ = fs::remove_dir_all(&extraction_root);
    result
}

pub fn load_update_plan(path: &Path) -> AppResult<SteamUpdatePlan> {
    load_json_file(path, "Steam update plan")
}

pub fn load_certificate_chain(path: &Path) -> AppResult<Vec<Certificate>> {
    load_json_file(path, "Steam certificate chain")
}

pub fn load_depot_manifest_from_disk(
    appmanifest_path: &Path,
    installscript_path: &Path,
    payload_root: &Path,
    libraryfolders_path: Option<&Path>,
) -> AppResult<DepotManifest> {
    let appmanifest_text = fs::read_to_string(appmanifest_path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", appmanifest_path.display()),
            &error,
        )
    })?;
    let installscript_text = fs::read_to_string(installscript_path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", installscript_path.display()),
            &error,
        )
    })?;

    let appmanifest = parse_appmanifest(&appmanifest_text)?;
    let installscript = parse_installscript(&installscript_text)?;
    let library_root = load_library_root_from_libraryfolders(appmanifest.app_id, libraryfolders_path)?;

    Ok(DepotManifest {
        app_id: appmanifest.app_id,
        game_name: appmanifest.game_name,
        install_dir: appmanifest.install_dir,
        launch_exe: installscript.launch_exe,
        library_root,
        prerequisites: installscript.prerequisites,
        files: collect_payload_files(payload_root)?,
    })
}

fn steam_install_files(ge_root: &str) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            format!("{}/steam.exe", ge_root),
            b"steam-bootstrap".to_vec(),
        ),
        (
            format!("{}/package/steamui.dll", ge_root),
            b"steam-ui".to_vec(),
        ),
        (
            format!("{}/logs/bootstrap.log", ge_root),
            b"boot".to_vec(),
        ),
        (
            format!("{}/steamapps/libraryfolders.vdf", ge_root),
            steam_libraryfolders_bytes(&[ge_root.to_string()], &BTreeMap::new()),
        ),
    ])
}

fn steam_libraryfolders_bytes(
    library_roots: &[String],
    installed_depots: &BTreeMap<u32, InstalledDepot>,
) -> Vec<u8> {
    let mut bytes = String::from("\"libraryfolders\"\n{\n");
    for (index, library_root) in library_roots.iter().enumerate() {
        bytes.push_str(&format!(
            "\t\"{index}\"\n\t{{\n\t\t\"path\"\t\"{}\"\n",
            library_root.replace('/', "\\\\")
        ));
        let mut app_ids = installed_depots
            .values()
            .filter(|depot| depot.library_root == *library_root)
            .map(|depot| depot.manifest.app_id)
            .collect::<Vec<_>>();
        app_ids.sort_unstable();
        if !app_ids.is_empty() {
            bytes.push_str("\t\t\"apps\"\n\t\t{\n");
            for app_id in app_ids {
                bytes.push_str(&format!("\t\t\t\"{app_id}\"\t\"1\"\n"));
            }
            bytes.push_str("\t\t}\n");
        }
        bytes.push_str("\t}\n");
    }
    bytes.push_str("}\n");
    bytes.into_bytes()
}

fn steam_app_manifest_bytes(manifest: &DepotManifest) -> Vec<u8> {
    let prerequisites = manifest
        .prerequisites
        .iter()
        .map(|prerequisite| match prerequisite {
            SteamGamePrerequisite::DirectX { dll } => format!("dx:{dll}"),
            SteamGamePrerequisite::DotNet { version } => format!("dotnet:{version}"),
            SteamGamePrerequisite::VisualCpp { version, dlls } => {
                format!("vc:{version}:{}", dlls.join(","))
            }
        })
        .collect::<Vec<_>>()
        .join(";");
    format!(
        "\"AppState\"\n{{\n\t\"appid\"\t\"{}\"\n\t\"name\"\t\"{}\"\n\t\"installdir\"\t\"{}\"\n\t\"launch\"\t\"{}\"\n\t\"prerequisites\"\t\"{}\"\n}}\n",
        manifest.app_id,
        manifest.game_name,
        manifest.install_dir,
        manifest.launch_exe,
        prerequisites,
    )
    .into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAppManifest {
    app_id: u32,
    game_name: String,
    install_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedInstallScript {
    launch_exe: String,
    prerequisites: Vec<SteamGamePrerequisite>,
}

fn load_json_file<T>(path: &Path, description: &str) -> AppResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    let contents = fs::read_to_string(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    serde_json::from_str(&contents).map_err(|error| {
        AppError::new(
            ReasonCode::RcIo,
            format!("failed to parse {description} {}", path.display()),
        )
        .with_hint(error.to_string())
    })
}

fn parse_appmanifest(contents: &str) -> AppResult<ParsedAppManifest> {
    let root = parse_vdf_document(contents)?;
    let app_state = object_field(&root, "AppState")?;
    let app_id = string_field(app_state, "appid")?.parse::<u32>().map_err(|error| {
        AppError::new(ReasonCode::RcIo, "Steam appmanifest appid must be numeric")
            .with_hint(error.to_string())
    })?;
    Ok(ParsedAppManifest {
        app_id,
        game_name: string_field(app_state, "name")?.to_string(),
        install_dir: string_field(app_state, "installdir")?.to_string(),
    })
}

fn parse_installscript(contents: &str) -> AppResult<ParsedInstallScript> {
    let root = parse_vdf_document(contents)?;
    let script = object_field(&root, "InstallScript")?;
    let launch = object_field(script, "Launch")?;
    let redistributables = object_field(script, "Redistributables")?;
    let mut prerequisites = Vec::new();

    if let Ok(directx) = object_field(redistributables, "DirectX") {
        prerequisites.push(SteamGamePrerequisite::DirectX {
            dll: string_field(directx, "Dll")?.to_string(),
        });
    }
    if let Ok(visual_cpp) = object_field(redistributables, "VisualCpp") {
        let dlls = string_field(visual_cpp, "Dlls")?
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        prerequisites.push(SteamGamePrerequisite::VisualCpp {
            version: string_field(visual_cpp, "Version")?.to_string(),
            dlls,
        });
    }
    if let Ok(dotnet) = object_field(redistributables, "DotNet") {
        prerequisites.push(SteamGamePrerequisite::DotNet {
            version: string_field(dotnet, "Version")?.to_string(),
        });
    }

    Ok(ParsedInstallScript {
        launch_exe: string_field(launch, "Executable")?.to_string(),
        prerequisites,
    })
}

fn load_library_root_from_libraryfolders(app_id: u32, path: Option<&Path>) -> AppResult<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let contents = fs::read_to_string(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    parse_libraryfolders_for_app(&contents, app_id)
}

fn parse_libraryfolders_for_app(contents: &str, app_id: u32) -> AppResult<Option<String>> {
    let root = parse_vdf_document(contents)?;
    let libraryfolders = object_field(&root, "libraryfolders")?;
    let app_id_key = app_id.to_string();
    for entry in libraryfolders.values() {
        let VdfNode::Object(folder) = entry else {
            continue;
        };
        let Ok(apps) = object_field(folder, "apps") else {
            continue;
        };
        if !apps.contains_key(&app_id_key) {
            continue;
        }
        return Ok(Some(normalize_library_root(string_field(folder, "path")?)));
    }
    Ok(None)
}

fn collect_payload_files(payload_root: &Path) -> AppResult<BTreeMap<String, Vec<u8>>> {
    if !payload_root.is_dir() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("Steam payload root missing: {}", payload_root.display()),
        ));
    }

    let mut files = BTreeMap::new();
    for entry in WalkDir::new(payload_root) {
        let entry = entry.map_err(|error| {
            AppError::new(
                ReasonCode::RcIo,
                format!("failed to walk {}", payload_root.display()),
            )
            .with_hint(error.to_string())
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(payload_root).map_err(|error| {
            AppError::new(
                ReasonCode::RcIo,
                format!("failed to normalize payload file {}", entry.path().display()),
            )
            .with_hint(error.to_string())
        })?;
        let relative_path = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("/");
        let bytes = fs::read(entry.path()).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to read {}", entry.path().display()),
                &error,
            )
        })?;
        files.insert(relative_path, bytes);
    }
    Ok(files)
}

fn parse_vdf_document(contents: &str) -> AppResult<BTreeMap<String, VdfNode>> {
    let tokens = tokenize_vdf(contents)?;
    let mut index = 0;
    let document = parse_vdf_map(&tokens, &mut index)?;
    if index != tokens.len() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            "unexpected trailing tokens in Steam metadata",
        ));
    }
    Ok(document)
}

fn tokenize_vdf(contents: &str) -> AppResult<Vec<VdfToken>> {
    let bytes = contents.as_bytes();
    let mut index = 0;
    let mut tokens = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\r' | b'\n' => index += 1,
            b'/' if index + 1 < bytes.len() && bytes[index + 1] == b'/' => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'{' => {
                tokens.push(VdfToken::OpenBrace);
                index += 1;
            }
            b'}' => {
                tokens.push(VdfToken::CloseBrace);
                index += 1;
            }
            b'"' => {
                index += 1;
                let start = index;
                while index < bytes.len() && bytes[index] != b'"' {
                    index += 1;
                }
                if index >= bytes.len() {
                    return Err(AppError::new(
                        ReasonCode::RcIo,
                        "unterminated quoted string in Steam metadata",
                    ));
                }
                tokens.push(VdfToken::String(contents[start..index].to_string()));
                index += 1;
            }
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    "unsupported token in Steam metadata",
                )
                .with_hint(format!("byte offset {index}")));
            }
        }
    }
    Ok(tokens)
}

fn parse_vdf_map(tokens: &[VdfToken], index: &mut usize) -> AppResult<BTreeMap<String, VdfNode>> {
    let mut map = BTreeMap::new();
    while *index < tokens.len() {
        match &tokens[*index] {
            VdfToken::CloseBrace => {
                *index += 1;
                return Ok(map);
            }
            VdfToken::OpenBrace => {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    "unexpected object start in Steam metadata",
                ));
            }
            VdfToken::String(key) => {
                let key = key.clone();
                *index += 1;
                let Some(next) = tokens.get(*index) else {
                    return Err(AppError::new(
                        ReasonCode::RcIo,
                        format!("missing value for Steam metadata key {key}"),
                    ));
                };
                match next {
                    VdfToken::String(value) => {
                        map.insert(key, VdfNode::String(value.clone()));
                        *index += 1;
                    }
                    VdfToken::OpenBrace => {
                        *index += 1;
                        map.insert(key, VdfNode::Object(parse_vdf_map(tokens, index)?));
                    }
                    VdfToken::CloseBrace => {
                        return Err(AppError::new(
                            ReasonCode::RcIo,
                            format!("missing value for Steam metadata key {key}"),
                        ));
                    }
                }
            }
        }
    }
    Ok(map)
}

fn object_field<'a>(map: &'a BTreeMap<String, VdfNode>, key: &str) -> AppResult<&'a BTreeMap<String, VdfNode>> {
    match map.get(key) {
        Some(VdfNode::Object(object)) => Ok(object),
        Some(VdfNode::String(_)) => Err(AppError::new(
            ReasonCode::RcIo,
            format!("Steam metadata field {key} must be an object"),
        )),
        None => Err(AppError::new(
            ReasonCode::RcIo,
            format!("missing Steam metadata field {key}"),
        )),
    }
}

fn string_field<'a>(map: &'a BTreeMap<String, VdfNode>, key: &str) -> AppResult<&'a str> {
    match map.get(key) {
        Some(VdfNode::String(value)) => Ok(value),
        Some(VdfNode::Object(_)) => Err(AppError::new(
            ReasonCode::RcIo,
            format!("Steam metadata field {key} must be a string"),
        )),
        None => Err(AppError::new(
            ReasonCode::RcIo,
            format!("missing Steam metadata field {key}"),
        )),
    }
}

fn materialize_windows_file(
    ge: &mut GameEnvironment,
    windows_path: &str,
    contents: &[u8],
    dtm: bool,
) -> AppResult<()> {
    ensure_ge_drive_mapping(ge, windows_path)?;
    let host_path = ge.host_path_for_windows_path(windows_path)?;
    if let Some(parent) = host_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", parent.display()),
                &error,
            )
        })?;
    }
    ge.write_file_overwrite(windows_path, contents, dtm)?;
    Ok(())
}

fn ensure_ge_drive_mapping(ge: &mut GameEnvironment, windows_path: &str) -> AppResult<()> {
    let parsed = ge.parse_windows_path(windows_path, None)?;
    let Some(drive) = parsed.drive else {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("unsupported Windows path {windows_path}"),
        ));
    };

    if ge
        .active_drive_mappings()
        .iter()
        .any(|mapping| mapping.drive == drive)
    {
        return Ok(());
    }

    let target = ge.root.join(format!("drive_{}", drive.to_ascii_lowercase()));
    ge.add_drive_mapping(&drive, &target, false, false)
}

fn split_registry_entry(entry_path: &str) -> AppResult<(String, String, String)> {
    let parts = entry_path
        .replace('/', "\\")
        .split('\\')
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if parts.len() < 3 {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("invalid Steam registry entry {entry_path}"),
        ));
    }
    let hive = parts.first().cloned().expect("validated");
    let value_name = parts.last().cloned().expect("validated");
    let key = parts[1..parts.len() - 1].join("\\");
    Ok((hive, key, value_name))
}

fn create_native_steam_extract_dir() -> AppResult<PathBuf> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            AppError::new(ReasonCode::RcIo, "system clock is before the Unix epoch")
                .with_hint(error.to_string())
        })?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("casa1-steamsetup-{unique}"));
    fs::create_dir_all(&path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to create {}", path.display()),
            &error,
        )
    })?;
    Ok(path)
}

fn extract_archive_with_7z(installer_path: &Path, extraction_root: &Path) -> AppResult<()> {
    let archive_tool = locate_7z_binary()?;
    let output = Command::new(&archive_tool)
        .arg("x")
        .arg("-y")
        .arg(format!("-o{}", extraction_root.display()))
        .arg(installer_path)
        .output()
        .map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to run {}", archive_tool.display()),
                &error,
            )
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::new(
            ReasonCode::RcIo,
            format!(
                "{} failed to extract {}",
                archive_tool.display(),
                installer_path.display()
            ),
        )
        .with_hint(String::from_utf8_lossy(&output.stdout).trim().to_string())
        .with_hint(String::from_utf8_lossy(&output.stderr).trim().to_string()))
    }
}

fn locate_7z_binary() -> AppResult<PathBuf> {
    for candidate in [PathBuf::from("7z"), PathBuf::from("7zz"), PathBuf::from("/opt/homebrew/bin/7z")] {
        match Command::new(&candidate).arg("-h").output() {
            Ok(_) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to probe {}", candidate.display()),
                    &error,
                ));
            }
        }
    }
    Err(AppError::new(
        ReasonCode::RcIo,
        "native Steam extraction requires 7z on the host",
    ))
}

fn steam_install_target_path(relative_path: &str) -> Option<String> {
    let normalized = normalize_relative(relative_path.trim_start_matches('/'));
    if normalized.is_empty() || normalized.starts_with("$PLUGINSDIR/") {
        return None;
    }
    Some(join_path(NATIVE_STEAM_INSTALL_ROOT, &normalized))
}

fn file_name(path: &str) -> String {
    path.replace('\\', "/")
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("SteamSetup.exe")
        .to_string()
}

fn app_manifest_path_for_library(library_root: &str, app_id: u32) -> String {
    format!(
        "{}/steamapps/appmanifest_{app_id}.acf",
        normalize_library_root(library_root)
    )
}

fn install_root_for_library(library_root: &str, install_dir: &str) -> String {
    format!(
        "{}/steamapps/common/{}",
        normalize_library_root(library_root),
        normalize_relative(install_dir)
    )
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn normalize_library_root(path: &str) -> String {
    let mut normalized = normalize_path(path);
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    normalized.trim_end_matches('/').to_string()
}

fn normalize_relative(path: &str) -> String {
    path.replace('\\', "/")
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn join_path(left: &str, right: &str) -> String {
    format!("{}/{}", left.trim_end_matches('/'), normalize_relative(right))
}

fn tree_hash(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut entries = files
        .iter()
        .map(|(path, bytes)| format!("{path}|{}", util::sha256_bytes(bytes)))
        .collect::<Vec<_>>();
    entries.sort();
    util::sha256_bytes(entries.join("\n").as_bytes())
}

fn parent_dir(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_else(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::steam_install_target_path;

    #[test]
    fn steam_install_target_path_maps_payload_files_into_install_root() {
        assert_eq!(
            steam_install_target_path("bin/SteamService.exe"),
            Some("C:/Steam/bin/SteamService.exe".to_string())
        );
        assert_eq!(
            steam_install_target_path("/public/steambootstrapper_english.txt"),
            Some("C:/Steam/public/steambootstrapper_english.txt".to_string())
        );
    }

    #[test]
    fn steam_install_target_path_skips_nsis_plugin_payloads() {
        assert_eq!(steam_install_target_path("$PLUGINSDIR/System.dll"), None);
    }
}