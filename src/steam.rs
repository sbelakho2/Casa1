use crate::audio::AudioSubsystem;
use crate::error::{AppError, AppResult};
use crate::network::{Certificate, NetworkStack};
use crate::reason::ReasonCode;
use crate::security::{detect_driver_requirement_paths, driver_requirement_error};
use crate::user32::{
    KeyboardDevice, KeyboardLayoutId, KeyModifiers, MessageKind, MouseDevice, User32Subsystem,
};
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepotInstallResult {
    pub normalized_tree_hash: String,
    pub file_list: Vec<String>,
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
    files: BTreeMap<String, Vec<u8>>,
    path_case: BTreeMap<String, String>,
    logs: Vec<String>,
    ui: User32Subsystem,
    network: NetworkStack,
    audio: AudioSubsystem,
    logged_in: bool,
    installed_depots: BTreeMap<u32, InstalledDepot>,
    ipc_channels: BTreeMap<(String, String), IpcChannel>,
    steamworks_ready: BTreeSet<u32>,
    overlay_active: BTreeSet<u32>,
}

impl SteamClient {
    pub fn new(ge_root: &str) -> Self {
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
            files: BTreeMap::new(),
            path_case: BTreeMap::new(),
            logs: Vec::new(),
            ui: User32Subsystem::new(KeyboardLayoutId::Us),
            network,
            audio: AudioSubsystem::new(),
            logged_in: false,
            installed_depots: BTreeMap::new(),
            ipc_channels: BTreeMap::new(),
            steamworks_ready: BTreeSet::new(),
            overlay_active: BTreeSet::new(),
        };
        client.write_file(
            &format!("{}/steam.exe", ge_root),
            b"steam-bootstrap".to_vec(),
        );
        client.write_file(
            &format!("{}/package/steamui.dll", ge_root),
            b"steam-ui".to_vec(),
        );
        client.write_file(
            &format!("{}/logs/bootstrap.log", ge_root),
            b"boot".to_vec(),
        );
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
        let install_root = format!("{}/steamapps/common/{}", self.ge_root, normalize_relative(&manifest.install_dir));
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
        let file_list = {
            let mut entries = staged_case.values().cloned().collect::<Vec<_>>();
            entries.sort();
            entries
        };
        let normalized_tree_hash = tree_hash(&staged);
        let app_id = manifest.app_id;
        self.installed_depots.insert(
            app_id,
            InstalledDepot {
                manifest,
                normalized_tree_hash: normalized_tree_hash.clone(),
                file_list: file_list.clone(),
            },
        );
        self.logs.push(format!("depot-install:{app_id}"));
        Ok(DepotInstallResult {
            normalized_tree_hash,
            file_list,
        })
    }

    pub fn verify_integrity(&self, app_id: u32) -> AppResult<DepotInstallResult> {
        let depot = self.installed_depots.get(&app_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown depot {app_id}"))
        })?;
        let install_root = normalize_path(&format!(
            "{}/steamapps/common/{}",
            self.ge_root,
            normalize_relative(&depot.manifest.install_dir)
        ));
        let actual = self
            .files
            .iter()
            .filter(|(path, _)| path.starts_with(&install_root))
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
        let depot = self.installed_depots.get(&app_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown depot {app_id}"))
        })?;
        let executable = join_path(
            &format!(
                "{}/steamapps/common/{}",
                self.ge_root,
                normalize_relative(&depot.manifest.install_dir)
            ),
            &depot.manifest.launch_exe,
        );
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

    fn write_file(&mut self, path: &str, bytes: Vec<u8>) {
        let normalized = normalize_path(path);
        self.files.insert(normalized.clone(), bytes);
        self.path_case.insert(normalized, path.replace('\\', "/"));
    }
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
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