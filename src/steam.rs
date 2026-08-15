use crate::audio::AudioSubsystem;
use crate::error::{AppError, AppResult};
use crate::ge::{GameEnvironment, RegistryView};
use crate::installer::{
    GuiWindowPlan, InstallerEngine, InstallerFramework, InstallerSpec, InstallerTelemetry,
    RuntimeAssembly,
};
use crate::network::{Certificate, NetworkStack, SimpleHttpResponse};
use crate::reason::ReasonCode;
use crate::security::{detect_driver_requirement_paths, driver_requirement_error};
use crate::steam_protocol::{
    self as steam_proto, ChunkInfo, ContentServerRecord as ProtoContentServerRecord,
    DepotManifest as ProtoDepotManifest,
};
use crate::user32::{
    KeyModifiers, KeyboardDevice, KeyboardLayoutId, MessageKind, MouseDevice, User32Subsystem,
};
use crate::util;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

#[derive(Debug)]
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
    content_manager: ContentManager,
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

        let content_manager = ContentManager::new(network.clone());
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
            content_manager,
        };
        if installed {
            client.seed_steam_installation();
        }
        client
    }

    pub fn network_mut(&mut self) -> &mut NetworkStack {
        &mut self.network
    }

    pub fn content_manager_mut(&mut self) -> &mut ContentManager {
        &mut self.content_manager
    }

    pub fn content_manager(&self) -> &ContentManager {
        &self.content_manager
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
        self.logs
            .push(format!("steam-install:{normalized_download}"));
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
        // Warm-up boot: initializes the environment before self-update.
        // The full boot result is obtained after self_update below.
        self.boot()?;
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
        if !self
            .files
            .contains_key(&format!("{}/steam.exe", self.ge_root))
        {
            return Err(AppError::new(
                ReasonCode::RcSteamUpdateFailed,
                "Steam.exe missing after update",
            ));
        }
        self.ui.register_class_ex_w("SteamMainWindow");
        let title = if self.logged_in {
            "Steam"
        } else {
            "Steam Login"
        };
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

    pub fn ipc_roundtrip(
        &mut self,
        pipe_name: &str,
        shared_region: &str,
        payload: &[u8],
    ) -> AppResult<IpcRoundtrip> {
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
        let cipher =
            self.network
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
        self.logs
            .push(format!("appmanifest-write:{app_id}:{app_manifest_path}"));
        self.refresh_libraryfolders_file();
        Ok(DepotInstallResult {
            normalized_tree_hash,
            file_list,
        })
    }

    pub fn verify_integrity(&self, app_id: u32) -> AppResult<DepotInstallResult> {
        let depot = self
            .installed_depots
            .get(&app_id)
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, format!("unknown depot {app_id}")))?;
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
        let depot =
            self.installed_depots.get(&app_id).cloned().ok_or_else(|| {
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
        self.ui
            .inject_mouse_input(hwnd, &mouse_id, 12, 8, &[], 0, 0)?;
        let mut input_ok = false;
        while let Some(message) = self.ui.get_message_w() {
            if matches!(message.kind, MessageKind::KeyDown | MessageKind::MouseMove) {
                input_ok = true;
            }
        }

        let audio_ok = !self.audio.devices().is_empty();

        let session = self.network.win_http_open("Steam Game Runtime");
        let connection =
            self.network
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
            format!(
                "{executable}|{}|{window_title}|{}",
                parent_dir(&executable),
                util::sha256_bytes(&body)
            )
            .as_bytes(),
        );
        Ok(GameLaunchResult {
            executable,
            cwd: parent_dir(&self.path_case[&executable_normalized]),
            env: BTreeMap::from([
                ("SteamAppId".to_string(), app_id.to_string()),
                ("SteamGameId".to_string(), app_id.to_string()),
                (
                    "SteamPath".to_string(),
                    self.path_case[&format!("{}/steam.exe", self.ge_root)].clone(),
                ),
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
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("unknown depot {app_id}"),
            ));
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
            "pump" => Ok(if self.overlay_active.contains(&app_id) {
                1
            } else {
                0
            }),
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
            let relative = entry
                .path()
                .strip_prefix(&extraction_root)
                .map_err(|error| {
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
                    format!(
                        "failed to read extracted Steam payload {}",
                        entry.path().display()
                    ),
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
    if let Err(e) = fs::remove_dir_all(&extraction_root) {
        eprintln!(
            "install_official_steam_setup_into_ge: failed to remove extraction dir {}: {e}",
            extraction_root.display()
        );
    }
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
    let library_root =
        load_library_root_from_libraryfolders(appmanifest.app_id, libraryfolders_path)?;

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
        (format!("{}/logs/bootstrap.log", ge_root), b"boot".to_vec()),
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
    let app_id = string_field(app_state, "appid")?
        .parse::<u32>()
        .map_err(|error| {
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

fn load_library_root_from_libraryfolders(
    app_id: u32,
    path: Option<&Path>,
) -> AppResult<Option<String>> {
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
                format!(
                    "failed to normalize payload file {}",
                    entry.path().display()
                ),
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
                return Err(
                    AppError::new(ReasonCode::RcIo, "unsupported token in Steam metadata")
                        .with_hint(format!("byte offset {index}")),
                );
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

fn object_field<'a>(
    map: &'a BTreeMap<String, VdfNode>,
    key: &str,
) -> AppResult<&'a BTreeMap<String, VdfNode>> {
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

    let target = ge
        .root
        .join(format!("drive_{}", drive.to_ascii_lowercase()));
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

/// Produce a short summary from registry entry path data (useful for fuzzing).
///
/// Returns `"ok:hive:key:vname"` on success or `"err:code:msg"` on failure.
pub fn registry_path_fuzz_summary(data: &[u8]) -> String {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return "err:utf8:invalid_utf8".into(),
    };
    match split_registry_entry(s) {
        Ok((hive, key, value)) => format!("ok:{hive}:{key}:{value}"),
        Err(e) => format!("err:{}:{}", e.code.as_u32(), e.message),
    }
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
    for candidate in [
        PathBuf::from("7z"),
        PathBuf::from("7zz"),
        PathBuf::from("/opt/homebrew/bin/7z"),
    ] {
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
    format!(
        "{}/{}",
        left.trim_end_matches('/'),
        normalize_relative(right)
    )
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

// ---------------------------------------------------------------------------
// Content Server / CDN Integration (Phase 3.3)
// ---------------------------------------------------------------------------

/// Default Steam content server hostnames for round-robin discovery.
const DEFAULT_CONTENT_SERVERS: &[&str] = &[
    "content1.steampowered.com",
    "content2.steampowered.com",
    "content3.steampowered.com",
    "content4.steampowered.com",
    "content5.steampowered.com",
    "content6.steampowered.com",
    "content7.steampowered.com",
    "content8.steampowered.com",
];

/// CDN routing endpoint for geo-located content server discovery.
const CDN_ROUTING_URL: &str = "https://api.steampowered.com/ICMService/GetContentServerRouting/v1";

/// How long (seconds) a content server list is cached before re-fetching.
const CONTENT_SERVER_TTL_SECS: u64 = 900; // 15 min

/// Default chunk size used for downloading depot content (1 MiB).
const DEFAULT_CHUNK_SIZE: u32 = 1_048_576;

/// Maximum concurrent chunk downloads per session.
const MAX_CONCURRENT_CHUNKS: usize = 4;

/// Maximum retries for downloading a single chunk.
const MAX_CHUNK_RETRIES: u32 = 3;

/// Base delay (ms) for exponential backoff when retrying chunks.
const RETRY_BASE_DELAY_MS: u64 = 1000;

// ---------------------------------------------------------------------------
// Content server tracking
// ---------------------------------------------------------------------------

/// A content server record with health tracking for load-balancing and failover.
#[derive(Debug, Clone)]
pub struct ContentServerRecord {
    /// Protocol-level content server record (host, port, https, cell, weight).
    pub proto: ProtoContentServerRecord,
    /// Whether the server is currently reachable.
    pub healthy: bool,
    /// Latency in milliseconds (None if not yet measured).
    pub latency_ms: Option<u64>,
    /// Timestamp (UNIX seconds) of the last successful health check.
    pub last_checked: u64,
    /// Consecutive failure count for failover.
    pub consecutive_failures: u32,
}

impl ContentServerRecord {
    pub fn from_proto(proto: ProtoContentServerRecord) -> Self {
        Self {
            proto,
            healthy: true,
            latency_ms: None,
            last_checked: 0,
            consecutive_failures: 0,
        }
    }

    /// Returns the base URL for this content server (e.g. `https://content1.steampowered.com`).
    pub fn base_url(&self) -> String {
        let scheme = if self.proto.https { "https" } else { "http" };
        format!("{}://{}:{}", scheme, self.proto.host, self.proto.port)
    }
}

/// A list of content servers with TTL caching, round-robin, and latency-aware selection.
#[derive(Debug, Clone)]
pub struct ContentServerList {
    /// All known content servers (healthy and unhealthy).
    servers: Vec<ContentServerRecord>,
    /// Current round-robin index.
    rr_index: usize,
    /// Timestamp (UNIX seconds) when this list was last fetched.
    fetched_at: u64,
}

impl ContentServerList {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            rr_index: 0,
            fetched_at: 0,
        }
    }

    /// Returns true if the cached list is still within its TTL.
    pub fn is_fresh(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.fetched_at) < CONTENT_SERVER_TTL_SECS
    }

    /// Populate the server list from protocol-level records.
    pub fn populate(&mut self, records: Vec<ProtoContentServerRecord>) {
        self.servers = records
            .into_iter()
            .map(ContentServerRecord::from_proto)
            .collect();
        self.fetched_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }

    /// Seed with the default hardcoded content servers (fallback when CDN routing is unavailable).
    pub fn seed_defaults(&mut self) {
        let records: Vec<ProtoContentServerRecord> = DEFAULT_CONTENT_SERVERS
            .iter()
            .enumerate()
            .map(|(_i, host)| ProtoContentServerRecord {
                host: host.to_string(),
                port: 443,
                https: true,
                cell_id: 0,
                weight: 1,
            })
            .collect();
        self.populate(records);
    }

    /// Returns the next healthy server using round-robin, skipping unhealthy servers.
    pub fn next_healthy(&mut self) -> Option<&ContentServerRecord> {
        let len = self.servers.len();
        if len == 0 {
            return None;
        }
        for _ in 0..len {
            let idx = self.rr_index % len;
            self.rr_index = (self.rr_index + 1) % len;
            if self.servers[idx].healthy {
                return Some(&self.servers[idx]);
            }
        }
        None
    }

    /// Mark a server as healthy or unhealthy, updating failure count.
    pub fn report_health(&mut self, host: &str, healthy: bool, latency_ms: Option<u64>) {
        if let Some(record) = self.servers.iter_mut().find(|r| r.proto.host == host) {
            record.healthy = healthy;
            record.latency_ms = latency_ms;
            record.last_checked = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if healthy {
                record.consecutive_failures = 0;
            } else {
                record.consecutive_failures += 1;
            }
        }
    }

    /// Returns the number of healthy servers.
    pub fn healthy_count(&self) -> usize {
        self.servers.iter().filter(|s| s.healthy).count()
    }

    /// Returns all servers for inspection.
    pub fn all_servers(&self) -> &[ContentServerRecord] {
        &self.servers
    }

    /// Select the best server based on latency (lowest latency among healthy servers).
    pub fn best_server(&self) -> Option<&ContentServerRecord> {
        self.servers
            .iter()
            .filter(|s| s.healthy)
            .min_by_key(|s| s.latency_ms.unwrap_or(u64::MAX))
    }
}

impl Default for ContentServerList {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Download data types
// ---------------------------------------------------------------------------

/// State of a single file download.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadState {
    Pending,
    Downloading,
    Verifying,
    Paused,
    Completed,
    Failed,
}

/// Progress metrics for a single file or an entire depot download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadProgress {
    /// Total bytes to download.
    pub total_bytes: u64,
    /// Bytes downloaded so far.
    pub downloaded_bytes: u64,
    /// Current download speed in bytes/second.
    pub speed_bps: u64,
    /// Estimated time remaining in seconds.
    pub eta_secs: u64,
    /// Download progress as a percentage (0.0 – 100.0).
    pub percent: f64,
    /// Current state of the download.
    pub state: DownloadState,
}

impl DownloadProgress {
    pub fn new(total_bytes: u64) -> Self {
        Self {
            total_bytes,
            downloaded_bytes: 0,
            speed_bps: 0,
            eta_secs: 0,
            percent: 0.0,
            state: DownloadState::Pending,
        }
    }

    pub fn update(&mut self, downloaded: u64, elapsed: Duration) {
        self.downloaded_bytes = downloaded;
        self.percent = if self.total_bytes > 0 {
            (downloaded as f64 / self.total_bytes as f64) * 100.0
        } else {
            0.0
        };
        let secs = elapsed.as_secs_f64();
        if secs > 0.0 {
            self.speed_bps = (downloaded as f64 / secs) as u64;
            let remaining = self.total_bytes.saturating_sub(downloaded);
            if self.speed_bps > 0 {
                self.eta_secs = remaining / self.speed_bps;
            }
        }
    }
}

/// Tracks the download state of a single file within a depot.
#[derive(Debug, Clone)]
pub struct FileDownload {
    /// File path relative to the depot install root.
    pub filename: String,
    /// Total file size in bytes.
    pub size: u64,
    /// SHA-1 checksum of the entire file.
    pub checksum: [u8; 20],
    /// List of chunks composing this file (from depot manifest).
    pub chunks: Vec<ChunkInfo>,
    /// Bytes downloaded so far.
    pub downloaded_bytes: u64,
    /// Current state.
    pub state: DownloadState,
    /// Accumulated file data (in-memory staging).
    pub data: Vec<u8>,
}

impl FileDownload {
    pub fn new(filename: String, size: u64, checksum: [u8; 20], chunks: Vec<ChunkInfo>) -> Self {
        let data = Vec::with_capacity(size as usize);
        Self {
            filename,
            size,
            checksum,
            chunks,
            downloaded_bytes: 0,
            state: DownloadState::Pending,
            data,
        }
    }
}

/// Tracks the download session for a single depot.
#[derive(Debug, Clone)]
pub struct DownloadSession {
    /// Steam app ID being downloaded.
    pub app_id: u32,
    /// Depot ID (may differ from app_id for multi-depot titles).
    pub depot_id: u32,
    /// All files composing this depot.
    pub files: Vec<FileDownload>,
    /// Aggregate download progress.
    pub progress: DownloadProgress,
    /// Current state of the download session.
    pub state: DownloadState,
    /// Start time of the download (for ETA calculation).
    pub start_time: Option<SystemTime>,
    /// Content server host being used.
    pub active_server: Option<String>,
    /// Whether the session is paused.
    pub paused: bool,
    /// Number of chunks currently being downloaded concurrently.
    pub active_chunks: usize,
}

impl DownloadSession {
    pub fn new(app_id: u32, depot_id: u32, total_bytes: u64) -> Self {
        Self {
            app_id,
            depot_id,
            files: Vec::new(),
            progress: DownloadProgress::new(total_bytes),
            state: DownloadState::Pending,
            start_time: None,
            active_server: None,
            paused: false,
            active_chunks: 0,
        }
    }

    /// Add a file to this download session.
    pub fn add_file(&mut self, file: FileDownload) {
        self.progress.total_bytes += file.size;
        self.files.push(file);
    }

    /// Returns total downloaded bytes across all files.
    pub fn total_downloaded(&self) -> u64 {
        self.files.iter().map(|f| f.downloaded_bytes).sum()
    }

    /// Returns overall progress percentage.
    pub fn overall_progress(&self) -> f64 {
        if self.progress.total_bytes > 0 {
            self.total_downloaded() as f64 / self.progress.total_bytes as f64 * 100.0
        } else {
            0.0
        }
    }

    /// Check whether all files have been downloaded.
    pub fn is_complete(&self) -> bool {
        self.files
            .iter()
            .all(|f| f.state == DownloadState::Completed)
    }

    /// Check whether any file has failed.
    pub fn has_failed(&self) -> bool {
        self.files.iter().any(|f| f.state == DownloadState::Failed)
    }
}

// ---------------------------------------------------------------------------
// SteamPipe format types
// ---------------------------------------------------------------------------

/// A single entry in a SteamPipe content manifest (.csm).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamPipeManifestEntry {
    /// File path relative to the install root.
    pub filename: String,
    /// Uncompressed file size.
    pub size: u64,
    /// SHA-1 hash of the uncompressed content.
    pub sha_hash: [u8; 20],
    /// CRC32 checksum.
    pub crc: u32,
    /// Flags (compression, encryption, etc.).
    pub flags: u32,
}

/// SteamPipe content data file (.csd) header and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamPipeContentData {
    /// Version of the content data format.
    pub version: u32,
    /// Depot ID this data belongs to.
    pub depot_id: u32,
    /// Total size of content data in bytes.
    pub data_size: u64,
    /// Chunk size used when packing the data.
    pub chunk_size: u32,
    /// Raw content data bytes.
    pub data: Vec<u8>,
}

/// SteamPipe content manifest file (.csm).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamPipeContentManifest {
    /// Version of the manifest format.
    pub version: u32,
    /// Depot ID this manifest belongs to.
    pub depot_id: u32,
    /// Total number of files described.
    pub file_count: u32,
    /// List of file entries.
    pub entries: Vec<SteamPipeManifestEntry>,
}

/// SteamPipe content bundle file (.csb) — a container for multiple depots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamPipeContentBundle {
    /// Version of the bundle format.
    pub version: u32,
    /// App ID this bundle belongs to.
    pub app_id: u32,
    /// Depot IDs contained in this bundle.
    pub depot_ids: Vec<u32>,
    /// Content data for each depot.
    pub depots: BTreeMap<u32, SteamPipeContentData>,
    /// Content manifest for each depot.
    pub manifests: BTreeMap<u32, SteamPipeContentManifest>,
}

// ---------------------------------------------------------------------------
// ContentManager
// ---------------------------------------------------------------------------

/// The main content manager for Steam CDN interactions.
///
/// Manages content server discovery, depot downloading with chunk-based
/// verification, download sessions, SteamPipe format support, and content
/// integrity verification.
#[derive(Debug, Clone)]
pub struct ContentManager {
    /// Content server list with health tracking and failover.
    pub server_list: ContentServerList,
    /// Active download sessions, keyed by app_id.
    pub downloads: BTreeMap<u32, DownloadSession>,
    /// Completed download records (app_id → timestamp).
    pub completed: BTreeMap<u32, u64>,
    /// Content verification state (app_id → whether integrity check passed).
    pub verified_content: BTreeMap<u32, bool>,
    /// Reference to the network stack for HTTP operations.
    network: NetworkStack,
}

impl ContentManager {
    /// Create a new ContentManager with the given network stack.
    pub fn new(network: NetworkStack) -> Self {
        Self {
            server_list: ContentServerList::new(),
            downloads: BTreeMap::new(),
            completed: BTreeMap::new(),
            verified_content: BTreeMap::new(),
            network,
        }
    }

    // -----------------------------------------------------------------------
    // Content server discovery
    // -----------------------------------------------------------------------

    /// Discover content servers from the Steam CDN routing endpoint.
    /// Falls back to default hardcoded servers if the CDN routing request fails.
    pub fn discover_content_servers(&mut self) -> AppResult<()> {
        if self.server_list.is_fresh() {
            return Ok(());
        }

        // Try fetching from the CDN routing endpoint
        match self.http_get_with_retry(CDN_ROUTING_URL, 2) {
            Ok(response) if response.status == 200 => {
                let body_str = String::from_utf8_lossy(&response.body);
                // Parse the CDN routing XML response using the protocol parser
                let proto_stack = steam_proto::SteamProtocolStack::new();
                match proto_stack.parse_cdn_routing(&body_str) {
                    Ok(records) => {
                        self.server_list.populate(records);
                        return Ok(());
                    }
                    Err(_) => {
                        // Fall through to default servers
                    }
                }
            }
            _ => {
                // Fall through to default servers
            }
        }

        // Fallback: seed with default hardcoded content servers
        self.server_list.seed_defaults();
        Ok(())
    }

    /// Ensure content servers are populated (discover if needed).
    pub fn ensure_content_servers(&mut self) -> AppResult<()> {
        if self.server_list.all_servers().is_empty() {
            self.discover_content_servers()?;
        }
        Ok(())
    }

    /// Check latency to a specific content server by hostname.
    pub fn check_server_latency(&mut self, host: &str) -> AppResult<u64> {
        let url = format!("https://{}/", host);
        let start = SystemTime::now();
        let result = self.http_get_with_retry(&url, 1);
        let elapsed = start.elapsed().unwrap_or(Duration::from_secs(30));
        let latency_ms = elapsed.as_millis() as u64;

        match result {
            Ok(_) => {
                self.server_list.report_health(host, true, Some(latency_ms));
                Ok(latency_ms)
            }
            Err(_) => {
                self.server_list.report_health(host, false, None);
                Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("content server {host} unreachable"),
                ))
            }
        }
    }

    /// Select the best content server based on latency, falling back to round-robin.
    pub fn select_best_server(&mut self) -> AppResult<String> {
        self.ensure_content_servers()?;

        // Try the best server by latency first
        if let Some(best) = self.server_list.best_server() {
            if best.latency_ms.unwrap_or(9999) < 500 {
                return Ok(best.base_url());
            }
        }

        // Fall back to round-robin
        self.server_list
            .next_healthy()
            .map(|s| s.base_url())
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, "no healthy content servers available"))
    }

    // -----------------------------------------------------------------------
    // Manifest fetching and parsing
    // -----------------------------------------------------------------------

    /// Fetch a depot manifest from the content server.
    pub fn fetch_depot_manifest(
        &mut self,
        _app_id: u32,
        depot_id: u32,
        manifest_id: u64,
        depot_key: Option<&[u8; 32]>,
    ) -> AppResult<Vec<ProtoDepotManifest>> {
        let base_url = self.select_best_server()?;
        let url = format!(
            "{}/depot/{depot_id}/manifest/{manifest_id}",
            base_url.trim_end_matches('/')
        );

        let response = self.http_get_with_retry(&url, MAX_CHUNK_RETRIES)?;
        if response.status != 200 {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("failed to fetch depot manifest: HTTP {}", response.status),
            ));
        }

        // Use the protocol-level parser to decode the manifest
        let proto_stack = steam_proto::SteamProtocolStack::new();
        let manifests = proto_stack.parse_depot_manifest(&response.body, depot_key)?;
        Ok(manifests)
    }

    // -----------------------------------------------------------------------
    // Chunk downloading
    // -----------------------------------------------------------------------

    /// Download a single chunk of data from a content server.
    pub fn download_chunk(
        &mut self,
        server_url: &str,
        depot_id: u32,
        chunk: &ChunkInfo,
    ) -> AppResult<Vec<u8>> {
        let chunk_hex = hex::encode(chunk.chunk_id);
        let url = format!(
            "{}/depot/{depot_id}/chunk/{chunk_hex}",
            server_url.trim_end_matches('/')
        );

        let response = self.http_get_with_retry(&url, MAX_CHUNK_RETRIES)?;
        if response.status != 200 {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("failed to download chunk: HTTP {}", response.status),
            ));
        }

        let data = response.body;
        let compressed_size = chunk.compressed_size;
        let expected_size = if compressed_size > 0 {
            compressed_size as usize
        } else {
            chunk.size as usize
        };

        // Verify chunk size
        if data.len() != expected_size {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!(
                    "chunk size mismatch: expected {expected_size}, got {}",
                    data.len()
                ),
            ));
        }

        // For compressed chunks, decompression would use the SteamPipe
        // format (Oodle or zlib). For now, pass through raw data.
        // In a full implementation, compressed_size != chunk.size would
        // trigger Oodle/zlib decompression.
        let chunk_data = data;

        // Verify SHA-1 hash of the chunk data
        let actual_hash = crate::network::sha1_hash(&chunk_data);
        if actual_hash.as_slice() != chunk.chunk_id {
            return Err(AppError::new(ReasonCode::RcIo, "chunk SHA-1 hash mismatch"));
        }

        Ok(chunk_data)
    }

    /// Download all chunks of a single file and assemble them.
    pub fn download_file_chunks(
        &mut self,
        server_url: &str,
        depot_id: u32,
        file: &mut FileDownload,
    ) -> AppResult<Vec<u8>> {
        file.state = DownloadState::Downloading;
        let mut assembled = Vec::with_capacity(file.size as usize);

        for chunk in &file.chunks {
            let chunk_data = self.download_chunk(server_url, depot_id, chunk)?;
            let offset = assembled.len() as u64;
            if offset != chunk.offset {
                // Pad to correct offset if needed (e.g., sparse files)
                let pad = (chunk.offset - offset) as usize;
                assembled.extend(std::iter::repeat(0u8).take(pad));
            }
            assembled.extend_from_slice(&chunk_data);
            file.downloaded_bytes += chunk_data.len() as u64;
        }

        // Verify the complete file checksum
        file.state = DownloadState::Verifying;
        let file_hash = crate::network::sha1_hash(&assembled);
        if file_hash.as_slice() != file.checksum {
            file.state = DownloadState::Failed;
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("file SHA-1 mismatch for {}", file.filename),
            ));
        }

        file.state = DownloadState::Completed;
        file.data = assembled.clone();
        Ok(assembled)
    }

    /// Helper for [`process_downloads`] that downloads chunks and verifies
    /// checksum without holding a mutable borrow on `self.downloads`.
    fn download_file_chunks_ext(
        &mut self,
        server_url: &str,
        depot_id: u32,
        chunks: &[ChunkInfo],
        checksum: [u8; 20],
        file_size: u64,
    ) -> AppResult<Vec<u8>> {
        let mut assembled = Vec::with_capacity(file_size as usize);

        for chunk in chunks {
            let chunk_data = self.download_chunk(server_url, depot_id, chunk)?;
            let offset = assembled.len() as u64;
            if offset != chunk.offset {
                let pad = (chunk.offset - offset) as usize;
                assembled.extend(std::iter::repeat(0u8).take(pad));
            }
            assembled.extend_from_slice(&chunk_data);
        }

        // Verify the complete file checksum
        let file_hash = crate::network::sha1_hash(&assembled);
        if file_hash.as_slice() != checksum {
            return Err(AppError::new(ReasonCode::RcIo, "file SHA-1 mismatch"));
        }

        Ok(assembled)
    }

    // -----------------------------------------------------------------------
    // Download session management
    // -----------------------------------------------------------------------

    /// Start a new download session for a depot.
    pub fn start_download(
        &mut self,
        app_id: u32,
        depot_id: u32,
        manifests: Vec<ProtoDepotManifest>,
    ) -> AppResult<()> {
        let total_bytes: u64 = manifests.iter().map(|m| m.size).sum();
        let mut session = DownloadSession::new(app_id, depot_id, total_bytes);

        for manifest in manifests {
            let file = FileDownload::new(
                manifest.filename.clone(),
                manifest.size,
                manifest.checksum,
                manifest.chunks.clone(),
            );
            session.add_file(file);
        }

        session.start_time = Some(SystemTime::now());
        session.state = DownloadState::Downloading;
        self.downloads.insert(app_id, session);
        Ok(())
    }

    /// Process pending downloads — download queued files/chunks.
    pub fn process_downloads(&mut self) -> AppResult<()> {
        let app_ids: Vec<u32> = self.downloads.keys().copied().collect();

        for app_id in app_ids {
            let server_url = self.select_best_server()?;
            let depot_id;
            let file_indices: Vec<usize>;

            // Scope the borrow of self.downloads
            {
                let session = self.downloads.get(&app_id).ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcIo,
                        format!("no active session for app {app_id}"),
                    )
                })?;

                if session.paused || session.is_complete() {
                    continue;
                }

                depot_id = session.depot_id;
                file_indices = session
                    .files
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| {
                        matches!(f.state, DownloadState::Pending | DownloadState::Failed)
                    })
                    .map(|(i, _)| i)
                    .collect();
            }

            for idx in file_indices {
                // Remove the file from the session to avoid borrow conflicts,
                // then process it and put it back.
                let file = self
                    .downloads
                    .get_mut(&app_id)
                    .and_then(|s| s.files.get_mut(idx))
                    .ok_or_else(|| {
                        AppError::new(ReasonCode::RcIo, format!("file index {idx} out of range"))
                    })?;

                if file.state == DownloadState::Completed {
                    continue;
                }

                // Extract the chunk info we need for downloading
                let file_chunks = file.chunks.clone();
                let file_checksum = file.checksum;
                let file_size = file.size;
                let _filename = file.filename.clone();

                // Call the download method - this borrows self mutably again
                // To avoid the conflict, we use a temporary extraction pattern
                match self.download_file_chunks_ext(
                    &server_url,
                    depot_id,
                    &file_chunks,
                    file_checksum,
                    file_size,
                ) {
                    Ok(data) => {
                        // Re-borrow to update the file
                        if let Some(session) = self.downloads.get_mut(&app_id) {
                            if let Some(f) = session.files.get_mut(idx) {
                                f.data = data;
                                f.downloaded_bytes = f.size;
                                f.state = DownloadState::Completed;
                            }
                        }
                    }
                    Err(e) => {
                        if let Some(session) = self.downloads.get_mut(&app_id) {
                            if let Some(f) = session.files.get_mut(idx) {
                                f.state = DownloadState::Failed;
                            }
                        }
                        self.server_list.report_health(&server_url, false, None);
                        return Err(e);
                    }
                }
            }

            // Check if session is complete
            let session = self.downloads.get(&app_id).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("session vanished for app {app_id}"),
                )
            })?;

            if session.is_complete() {
                if let Some(session_mut) = self.downloads.get_mut(&app_id) {
                    session_mut.state = DownloadState::Completed;
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                self.completed.insert(app_id, now);
            }
        }

        Ok(())
    }

    /// Pause an active download session.
    pub fn pause_download(&mut self, app_id: u32) -> AppResult<()> {
        let session = self.downloads.get_mut(&app_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcIo,
                format!("no active download for app {app_id}"),
            )
        })?;
        session.paused = true;
        session.state = DownloadState::Paused;
        Ok(())
    }

    /// Resume a paused download session.
    pub fn resume_download(&mut self, app_id: u32) -> AppResult<()> {
        let session = self.downloads.get_mut(&app_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcIo,
                format!("no active download for app {app_id}"),
            )
        })?;
        session.paused = false;
        session.state = DownloadState::Downloading;
        Ok(())
    }

    /// Cancel and remove a download session.
    pub fn cancel_download(&mut self, app_id: u32) {
        self.downloads.remove(&app_id);
        self.completed.remove(&app_id);
        self.verified_content.remove(&app_id);
    }

    // -----------------------------------------------------------------------
    // Content verification
    // -----------------------------------------------------------------------

    /// Verify that installed content matches the depot manifest.
    pub fn verify_installed_content(
        &mut self,
        app_id: u32,
        files: &BTreeMap<String, Vec<u8>>,
        manifests: &[ProtoDepotManifest],
    ) -> AppResult<bool> {
        for manifest in manifests {
            let Some(content) = files.get(&manifest.filename) else {
                self.verified_content.insert(app_id, false);
                return Ok(false);
            };

            // Verify file size
            if content.len() as u64 != manifest.size {
                self.verified_content.insert(app_id, false);
                return Ok(false);
            }

            // Verify SHA-1 checksum
            let hash = crate::network::sha1_hash(content);
            if hash.as_slice() != manifest.checksum {
                self.verified_content.insert(app_id, false);
                return Ok(false);
            }
        }

        self.verified_content.insert(app_id, true);
        Ok(true)
    }

    /// Check whether a previously verified app is still valid.
    pub fn is_content_verified(&self, app_id: u32) -> Option<bool> {
        self.verified_content.get(&app_id).copied()
    }

    // -----------------------------------------------------------------------
    // SteamPipe format support
    // -----------------------------------------------------------------------

    /// Parse a SteamPipe content data file (.csd) from raw bytes.
    pub fn parse_steampipe_csd(&self, data: &[u8]) -> AppResult<SteamPipeContentData> {
        if data.len() < 20 {
            return Err(AppError::new(
                ReasonCode::RcIo,
                "SteamPipe .csd file too short",
            ));
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let depot_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let data_size = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let chunk_size = u32::from_le_bytes(data[16..20].try_into().unwrap());

        let content_data = if data.len() > 20 {
            data[20..].to_vec()
        } else {
            Vec::new()
        };

        Ok(SteamPipeContentData {
            version,
            depot_id,
            data_size,
            chunk_size,
            data: content_data,
        })
    }

    /// Parse a SteamPipe content manifest file (.csm) from raw bytes.
    pub fn parse_steampipe_csm(&self, data: &[u8]) -> AppResult<SteamPipeContentManifest> {
        if data.len() < 12 {
            return Err(AppError::new(
                ReasonCode::RcIo,
                "SteamPipe .csm file too short",
            ));
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let depot_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let file_count = u32::from_le_bytes(data[8..12].try_into().unwrap());

        let mut entries = Vec::with_capacity(file_count as usize);
        let mut offset = 12usize;

        for _ in 0..file_count {
            if offset + 44 > data.len() {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    "SteamPipe .csm file truncated",
                ));
            }

            // Read fixed-size fields (filename hash placeholder, size, sha, crc, flags)
            let size = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let mut sha_hash = [0u8; 20];
            sha_hash.copy_from_slice(&data[offset..offset + 20]);
            offset += 20;
            let crc = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let flags = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let name_len =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + name_len > data.len() {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    "SteamPipe .csm filename truncated",
                ));
            }

            let filename = String::from_utf8_lossy(&data[offset..offset + name_len]).to_string();
            offset += name_len;

            // Pad to 4-byte alignment
            let padding = (4 - (name_len % 4)) % 4;
            offset += padding;

            entries.push(SteamPipeManifestEntry {
                filename,
                size,
                sha_hash,
                crc,
                flags,
            });
        }

        Ok(SteamPipeContentManifest {
            version,
            depot_id,
            file_count,
            entries,
        })
    }

    /// Parse a SteamPipe content bundle file (.csb) from raw bytes.
    pub fn parse_steampipe_csb(&self, data: &[u8]) -> AppResult<SteamPipeContentBundle> {
        if data.len() < 12 {
            return Err(AppError::new(
                ReasonCode::RcIo,
                "SteamPipe .csb file too short",
            ));
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let app_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let depot_count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;

        let mut offset = 12usize;
        let mut depot_ids = Vec::with_capacity(depot_count);

        for _ in 0..depot_count {
            if offset + 8 > data.len() {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    "SteamPipe .csb depot list truncated",
                ));
            }
            let depot_id = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            let data_size = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
            offset += 8;
            depot_ids.push((depot_id, data_size as usize));
        }

        let mut depots = BTreeMap::new();
        let mut manifests = BTreeMap::new();

        for (depot_id, data_size) in &depot_ids {
            if offset + data_size > data.len() {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("SteamPipe .csb data truncated for depot {depot_id}"),
                ));
            }

            // Try parsing as .csd first
            let depot_data = data[offset..offset + data_size].to_vec();
            let mut chunk_offset = offset + data_size;

            // Try to parse as content data
            match self.parse_steampipe_csd(&depot_data) {
                Ok(csd) => {
                    depots.insert(*depot_id, csd);
                }
                Err(_) => {
                    // Not a valid .csd, store raw
                    depots.insert(
                        *depot_id,
                        SteamPipeContentData {
                            version: 0,
                            depot_id: *depot_id,
                            data_size: *data_size as u64,
                            chunk_size: 0,
                            data: depot_data,
                        },
                    );
                }
            }

            // Check for manifest data (.csm) after content data
            if chunk_offset + 12 <= data.len() {
                // Probe for manifest header
                let remaining = data[chunk_offset..].to_vec();
                match self.parse_steampipe_csm(&remaining) {
                    Ok(csm) => {
                        manifests.insert(*depot_id, csm);
                        // Advance offset past the manifest
                        chunk_offset = data.len();
                    }
                    Err(_) => {}
                }
            }

            offset = chunk_offset;
        }

        Ok(SteamPipeContentBundle {
            version,
            app_id,
            depot_ids: depot_ids.iter().map(|(id, _)| *id).collect(),
            depots,
            manifests,
        })
    }

    // -----------------------------------------------------------------------
    // Staging and commit
    // -----------------------------------------------------------------------

    /// Stage a downloaded file into the content manager's temporary storage.
    pub fn stage_downloaded_file(&mut self, app_id: u32, filename: &str, data: Vec<u8>) {
        if let Some(session) = self.downloads.get_mut(&app_id) {
            if let Some(file) = session.files.iter_mut().find(|f| f.filename == filename) {
                file.data = data;
                file.state = DownloadState::Completed;
            }
        }
    }

    /// Commit a completed download — convert to a [`DepotManifest`] (app-level)
    /// suitable for [`SteamClient::install_depot`].
    pub fn commit_staged_file(
        &mut self,
        app_id: u32,
        game_name: &str,
        install_dir: &str,
        launch_exe: &str,
    ) -> AppResult<Option<DepotManifest>> {
        let session = self.downloads.get(&app_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcIo,
                format!("no download session for app {app_id}"),
            )
        })?;

        if !session.is_complete() {
            return Ok(None);
        }

        let mut files = BTreeMap::new();
        for file in &session.files {
            if !file.data.is_empty() {
                files.insert(file.filename.clone(), file.data.clone());
            }
        }

        if files.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("no files committed for app {app_id}"),
            ));
        }

        Ok(Some(DepotManifest {
            app_id,
            game_name: game_name.to_string(),
            install_dir: install_dir.to_string(),
            launch_exe: launch_exe.to_string(),
            library_root: None,
            prerequisites: Vec::new(),
            files,
        }))
    }

    // -----------------------------------------------------------------------
    // Install manifest creation
    // -----------------------------------------------------------------------

    /// Create an install manifest from a depot manifest, suitable for
    /// SteamClient. This maps protocol-level [`ProtoDepotManifest`] entries
    /// into a high-level [`DepotManifest`] that the installer can consume.
    pub fn create_install_manifest(
        &self,
        app_id: u32,
        game_name: &str,
        install_dir: &str,
        launch_exe: &str,
        _depot_manifests: &[ProtoDepotManifest],
        downloaded_files: &BTreeMap<String, Vec<u8>>,
    ) -> DepotManifest {
        DepotManifest {
            app_id,
            game_name: game_name.to_string(),
            install_dir: install_dir.to_string(),
            launch_exe: launch_exe.to_string(),
            library_root: None,
            prerequisites: Vec::new(),
            files: downloaded_files.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // HTTP helpers
    // -----------------------------------------------------------------------

    /// Perform an HTTP GET request with retry and exponential backoff.
    fn http_get_with_retry(
        &mut self,
        url: &str,
        max_retries: u32,
    ) -> AppResult<SimpleHttpResponse> {
        let mut last_error = None;

        for attempt in 0..=max_retries {
            match self.network.http_get(url) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < max_retries {
                        let delay = Duration::from_millis(RETRY_BASE_DELAY_MS * (1u64 << attempt));
                        std::thread::sleep(delay);
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            AppError::new(
                ReasonCode::RcIo,
                format!("HTTP GET failed after {max_retries} retries: {url}"),
            )
        }))
    }
}

impl Default for ContentManager {
    fn default() -> Self {
        Self::new(NetworkStack::new())
    }
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
