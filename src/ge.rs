use crate::canonical::{FileManifestDelta, NormalizedTimes, RegistryDelta};
use crate::error::{AppError, AppResult};
use crate::pe;
use crate::reason::ReasonCode;
use crate::util;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum GeArch {
    #[value(name = "x64")]
    X64,
    #[value(name = "x86")]
    X86,
}

impl GeArch {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::X86 => "x86",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriveMapping {
    pub drive: String,
    pub target: String,
    pub read_only: bool,
    pub enabled: bool,
    pub requires_permission: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FsEntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsMetadataRecord {
    pub kind: FsEntryKind,
    pub original_case: String,
    pub attributes: Vec<String>,
    pub creation_time_ticks: u64,
    pub last_access_time_ticks: u64,
    pub last_write_time_ticks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReparseKind {
    Junction,
    Symlink,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReparsePoint {
    pub kind: ReparseKind,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GeFsState {
    pub entries: BTreeMap<String, FsMetadataRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reparse_points: BTreeMap<String, ReparsePoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverrideMatchRule {
    ExeSha256 { sha256: String },
    ProductVersion { product_name: String, file_version: String },
    InstallPathWildcard { pattern: String },
    DefaultProfile,
}

impl OverrideMatchRule {
    pub const fn priority(&self) -> u8 {
        match self {
            Self::ExeSha256 { .. } => 0,
            Self::ProductVersion { .. } => 1,
            Self::InstallPathWildcard { .. } => 2,
            Self::DefaultProfile => 3,
        }
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ExeSha256 { .. } => "exe_sha256",
            Self::ProductVersion { .. } => "product_version",
            Self::InstallPathWildcard { .. } => "install_path_wildcard",
            Self::DefaultProfile => "default_profile",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrySetOverride {
    pub hive: String,
    pub key: String,
    pub value: String,
    #[serde(rename = "type")]
    pub value_type: String,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryDeleteOverride {
    pub hive: String,
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DllOverrideMode {
    Builtin,
    Native,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DllOverride {
    pub name: String,
    pub mode: DllOverrideMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuProfile {
    pub cpuid_mask: String,
    pub dbt_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GfxProfile {
    pub feature_masks: Vec<String>,
    pub shader_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputProfile {
    pub layout_id: String,
    pub deadzone: u32,
    pub mappings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    AllowAll,
    DenyAll,
    AllowOnlyWhitelist,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkProfile {
    pub policy: NetworkPolicy,
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsProfile {
    pub case_mode: String,
    pub long_paths_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OverridePayload {
    pub env_add: BTreeMap<String, String>,
    pub env_remove: Vec<String>,
    pub reg_set: Vec<RegistrySetOverride>,
    pub reg_delete: Vec<RegistryDeleteOverride>,
    pub dll_override: Vec<DllOverride>,
    pub cpu_profile: Option<CpuProfile>,
    pub gfx_profile: Option<GfxProfile>,
    pub input_profile: Option<InputProfile>,
    pub network_profile: Option<NetworkProfile>,
    pub fs_profile: Option<FsProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverrideProfile {
    pub id: String,
    pub match_rule: OverrideMatchRule,
    pub payload: OverridePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeConfig {
    pub schema_version: u32,
    pub name: String,
    pub arch: GeArch,
    pub winver: String,
    #[serde(default = "default_user_name")]
    pub user_name: String,
    #[serde(default)]
    pub long_paths_enabled: bool,
    #[serde(default = "default_drive_mappings")]
    pub drive_mappings: Vec<DriveMapping>,
    #[serde(default)]
    pub override_profiles: Vec<OverrideProfile>,
    #[serde(default)]
    pub fs_state: GeFsState,
}

#[derive(Debug, Clone)]
pub struct GameEnvironment {
    pub root: PathBuf,
    pub config: GeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshotEntry {
    pub path_norm: String,
    pub sha256: String,
    pub size: u64,
    pub times_norm: NormalizedTimes,
    pub attrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredRegistryValue {
    #[serde(rename = "type")]
    pub value_type: String,
    pub data: Value,
}

pub type RegistryDb = BTreeMap<String, BTreeMap<String, StoredRegistryValue>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySnapshotEntry {
    pub hive: String,
    pub key_norm: String,
    pub value: String,
    pub value_type: String,
    pub data_norm: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryView {
    Native,
    Wow6432,
    Native64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedWindowsPath {
    pub drive: Option<String>,
    pub normalized_path: String,
    pub components: Vec<String>,
    pub verbatim: bool,
    pub device_namespace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWindowsPath {
    pub normalized_path: String,
    pub host_path: PathBuf,
    pub existed: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileAccess {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

impl FileAccess {
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            delete: false,
        }
    }

    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            delete: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareMode {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

impl ShareMode {
    pub const fn all() -> Self {
        Self {
            read: true,
            write: true,
            delete: true,
        }
    }

    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            delete: false,
        }
    }

    pub const fn none() -> Self {
        Self {
            read: false,
            write: false,
            delete: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle {
    pub id: u64,
    pub normalized_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableIdentity {
    pub sha256: String,
    pub product_name: Option<String>,
    pub file_version: Option<String>,
    pub normalized_install_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppliedOverride {
    pub profile_id: String,
    pub match_rule: String,
    pub normalized_diff: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionSidecar {
    product_name: Option<String>,
    file_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SharedOpenFileState {
    handle_id: u64,
    owner_pid: u32,
    normalized_path: String,
    desired_access: FileAccess,
    share_mode: ShareMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SharedByteRangeLock {
    handle_id: u64,
    owner_pid: u32,
    normalized_path: String,
    offset: u64,
    length: u64,
    exclusive: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SharedFileRuntimeState {
    next_handle: u64,
    open_handles: Vec<SharedOpenFileState>,
    locks: Vec<SharedByteRangeLock>,
}

#[derive(Debug)]
struct RegistryWatcherInner {
    ge_root: String,
    hive: String,
    key_norm: String,
    recursive: bool,
    sequence: Mutex<u64>,
    condvar: Condvar,
}

#[derive(Debug)]
pub struct RegistryWatcher {
    inner: Arc<RegistryWatcherInner>,
    observed_sequence: u64,
}

impl RegistryWatcher {
    pub fn wait_for_change(&mut self, timeout: Duration) -> AppResult<bool> {
        let mut sequence = self.inner.sequence.lock().expect("registry watcher lock poisoned");
        if *sequence > self.observed_sequence {
            self.observed_sequence = *sequence;
            return Ok(true);
        }

        let (updated_sequence, wait_result) = self
            .inner
            .condvar
            .wait_timeout(sequence, timeout)
            .expect("registry watcher condvar poisoned");
        sequence = updated_sequence;
        if *sequence > self.observed_sequence {
            self.observed_sequence = *sequence;
            Ok(true)
        } else if wait_result.timed_out() {
            Ok(false)
        } else {
            Ok(false)
        }
    }
}

impl GameEnvironment {
    pub fn create(name: &str, arch: GeArch, winver: &str) -> AppResult<Self> {
        let current = std::env::current_dir().map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to resolve current directory", &error)
        })?;
        // When CASA1_GES_ROOT is set, that root is authoritative: the caller has
        // explicitly chosen where game environments live, so we must NOT fall
        // back to scanning the workspace for like-named environments (which
        // exists only to disambiguate when no explicit root was provided).
        let env_root_explicit = std::env::var_os("CASA1_GES_ROOT").is_some();
        let candidate_roots = base_root_candidates_from_env_or(&current)?;
        let root = candidate_roots[0].join(name);
        let existing_root = candidate_roots
            .iter()
            .map(|candidate| candidate.join(name))
            .find(|candidate| candidate.exists());
        let existing_root = match existing_root {
            Some(found) => Some(found),
            None if env_root_explicit => None,
            None => find_named_ge_in_workspace(&current, name, &candidate_roots)?,
        };
        if let Some(existing_root) = existing_root {
            return Err(AppError::new(
                ReasonCode::RcGeExists,
                format!("game environment {name} already exists at {}", existing_root.display()),
            ));
        }
        Self::create_in_root(root, name, arch, winver)
    }

    pub fn create_in(base_root: impl AsRef<Path>, name: &str, arch: GeArch, winver: &str) -> AppResult<Self> {
        let root = base_root.as_ref().join(name);
        Self::create_in_root(root, name, arch, winver)
    }

    fn create_in_root(root: PathBuf, name: &str, arch: GeArch, winver: &str) -> AppResult<Self> {
        if root.exists() {
            return Err(AppError::new(
                ReasonCode::RcGeExists,
                format!("game environment {name} already exists"),
            ));
        }

        let config = GeConfig {
            schema_version: 2,
            name: name.to_string(),
            arch,
            winver: winver.to_string(),
            user_name: default_user_name(),
            long_paths_enabled: false,
            drive_mappings: default_drive_mappings(),
            override_profiles: Vec::new(),
            fs_state: GeFsState::default(),
        };
        let ge = Self { root, config };
        ge.ensure_layout()?;
        ge.write_config()?;
        Ok(ge)
    }

    pub fn open(name: &str) -> AppResult<Self> {
        let current = std::env::current_dir().map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to resolve current directory", &error)
        })?;
        let candidate_roots = base_root_candidates_from_env_or(&current)?;
        for candidate in &candidate_roots {
            let root = candidate.join(name);
            if root.join("ge.json").is_file() {
                return Self::from_root(root);
            }
        }
        if let Some(root) = find_named_ge_in_workspace(&current, name, &candidate_roots)? {
            return Self::from_root(root);
        }
        Self::from_root(candidate_roots[0].join(name))
    }

    pub fn from_root(root: PathBuf) -> AppResult<Self> {
        let config_path = root.join("ge.json");
        let contents = fs::read_to_string(&config_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcGeNotFound,
                format!("failed to open {}", config_path.display()),
                &error,
            )
        })?;
        let config = serde_json::from_str::<GeConfig>(&contents).map_err(|error| {
            AppError::new(
                ReasonCode::RcGeNotFound,
                format!("failed to parse {}", config_path.display()),
            )
            .with_hint(error.to_string())
        })?;
        let mut config = config;
        let embedded_reparse_points = std::mem::take(&mut config.fs_state.reparse_points);
        let sidecar_reparse_points = load_reparse_db(&root.join("fs/reparse.db.json"))?;
        config.fs_state.reparse_points = if sidecar_reparse_points.is_empty() {
            embedded_reparse_points
        } else {
            sidecar_reparse_points
        };
        Ok(Self { root, config })
    }

    pub fn save_config(&self) -> AppResult<()> {
        self.write_config()
    }

    pub fn drive_c(&self) -> PathBuf {
        self.root.join("drive_c")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn traces_dir(&self) -> PathBuf {
        self.root.join("traces")
    }

    pub fn reports_dir(&self) -> PathBuf {
        self.root.join("reports")
    }

    pub fn diagnostics_dir(&self) -> PathBuf {
        self.root.join("diagnostics")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    pub fn registry_file(&self, hive: &str) -> PathBuf {
        self.root.join("registry").join(format!("{hive}.db"))
    }

    fn reparse_db_file(&self) -> PathBuf {
        self.root.join("fs").join("reparse.db.json")
    }

    pub fn report_path(&self, test_id: &str) -> PathBuf {
        self.reports_dir().join(format!("{test_id}.json"))
    }

    pub fn trace_path(&self, test_id: &str) -> PathBuf {
        self.traces_dir().join(format!("{test_id}.json"))
    }

    pub fn guest_trace_path(&self, test_id: &str) -> PathBuf {
        self.traces_dir().join(format!("{test_id}-guest.json"))
    }

    pub fn job_path(&self, test_id: &str) -> PathBuf {
        self.tmp_dir().join(format!("{test_id}-job.json"))
    }

    pub fn log_path(&self, test_id: &str, pid: u32) -> PathBuf {
        self.logs_dir().join(format!("{test_id}-guest-{pid}.jsonl"))
    }

    pub fn active_drive_mappings(&self) -> Vec<DriveMapping> {
        self.config
            .drive_mappings
            .iter()
            .filter(|mapping| mapping.enabled)
            .cloned()
            .collect()
    }

    pub fn add_drive_mapping(
        &mut self,
        drive: &str,
        target: &Path,
        read_only: bool,
        requires_permission: bool,
    ) -> AppResult<()> {
        let normalized_drive = normalize_drive_letter(drive)?;
        self.config.drive_mappings.retain(|mapping| mapping.drive != normalized_drive);
        self.config.drive_mappings.push(DriveMapping {
            drive: normalized_drive,
            target: target.display().to_string(),
            read_only,
            enabled: true,
            requires_permission,
        });
        self.config.drive_mappings.sort_by(|left, right| left.drive.cmp(&right.drive));
        self.save_config()
    }

    pub fn host_path_for_windows_path(&self, windows_path: &str) -> AppResult<PathBuf> {
        let parsed = self.parse_windows_path(windows_path, None)?;
        if parsed.device_namespace {
            return Ok(PathBuf::from(parsed.normalized_path));
        }

        let drive = parsed.drive.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("missing drive designator in {windows_path}"),
            )
        })?;
        let mapping = self.resolve_drive_mapping(&drive)?;
        let mut host_path = self.resolve_drive_target(&mapping);
        for component in parsed.components {
            host_path.push(component);
        }
        Ok(host_path)
    }

    pub fn normalize_host_path(&self, path: &Path) -> String {
        for mapping in self.active_drive_mappings() {
            let drive_root = self.resolve_drive_target(&mapping);
            if let Ok(relative) = path.strip_prefix(&drive_root) {
                return windows_path_for_drive(&mapping.drive, relative);
            }
        }
        util::normalize_windows_path(&self.root, path)
    }

    pub fn set_override_profiles(&mut self, profiles: Vec<OverrideProfile>) -> AppResult<()> {
        self.config.override_profiles = profiles;
        self.save_config()
    }

    pub fn snapshot_files(&self, dtm: bool, epoch: SystemTime) -> AppResult<BTreeMap<String, FileSnapshotEntry>> {
        let mut paths = Vec::new();
        let mut roots = self
            .active_drive_mappings()
            .into_iter()
            .filter(|mapping| !mapping.read_only)
            .map(|mapping| self.resolve_drive_target(&mapping))
            .collect::<Vec<_>>();
        roots.sort();
        roots.dedup();

        for root in roots {
            if !root.exists() {
                continue;
            }
            for entry in WalkDir::new(&root).sort_by_file_name() {
                let entry = entry.map_err(|error| {
                    AppError::new(ReasonCode::RcIo, "failed to walk GE drive snapshot")
                        .with_hint(error.to_string())
                })?;
                if entry.path() == root {
                    continue;
                }
                paths.push(entry.into_path());
            }
        }

        if paths.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut snapshot = BTreeMap::new();
        for path in paths {
            let metadata = fs::metadata(&path).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to stat {}", path.display()),
                    &error,
                )
            })?;
            let path_norm = self.normalize_host_path(&path);
            let mut attrs = Vec::new();
            if let Some(record) = self.config.fs_state.entries.get(&path_norm) {
                attrs = record.attributes.clone();
                if record.kind == FsEntryKind::Directory && !attrs.iter().any(|value| value == "directory") {
                    attrs.push("directory".to_string());
                }
            } else {
                if metadata.is_dir() {
                    attrs.push("directory".to_string());
                }
                if metadata.permissions().readonly() {
                    attrs.push("readonly".to_string());
                }
            }
            attrs.sort();
            attrs.dedup();
            let times_norm = if let Some(record) = self.config.fs_state.entries.get(&path_norm) {
                NormalizedTimes {
                    created_ms: if dtm { 0 } else { record.creation_time_ticks / 10_000 },
                    accessed_ms: if dtm { 0 } else { record.last_access_time_ticks / 10_000 },
                    modified_ms: if dtm { 0 } else { record.last_write_time_ticks / 10_000 },
                }
            } else {
                NormalizedTimes {
                    created_ms: util::elapsed_offset_ms(epoch, metadata.created().ok(), dtm),
                    accessed_ms: util::elapsed_offset_ms(epoch, metadata.accessed().ok(), dtm),
                    modified_ms: util::elapsed_offset_ms(epoch, metadata.modified().ok(), dtm),
                }
            };
            snapshot.insert(
                path_norm.clone(),
                FileSnapshotEntry {
                    path_norm,
                    sha256: if metadata.is_dir() {
                        util::sha256_bytes(b"directory")
                    } else {
                        util::sha256_file(&path)?
                    },
                    size: if metadata.is_dir() { 0 } else { metadata.len() },
                    times_norm,
                    attrs,
                },
            );
        }
        Ok(snapshot)
    }

    pub fn snapshot_registry(&self) -> AppResult<BTreeMap<String, RegistrySnapshotEntry>> {
        let mut snapshot = BTreeMap::new();
        for hive in ["HKCR", "HKCU", "HKLM"] {
            let database = load_registry_db(&self.registry_file(hive))?;
            for (key, values) in database {
                for (value_name, value) in values {
                    let entry = RegistrySnapshotEntry {
                        hive: hive.to_string(),
                        key_norm: key.replace('/', "\\"),
                        value: value_name,
                        value_type: value.value_type,
                        data_norm: normalize_registry_data(&value.data),
                    };
                    let snapshot_key = format!("{}\\{}\\{}", entry.hive, entry.key_norm, entry.value);
                    snapshot.insert(snapshot_key, entry);
                }
            }
        }
        Ok(snapshot)
    }

    pub fn parse_windows_path(
        &self,
        input: &str,
        long_paths_override: Option<bool>,
    ) -> AppResult<ParsedWindowsPath> {
        parse_windows_path_impl(self, input, long_paths_override)
    }

    pub fn create_directory(&mut self, windows_path: &str, dtm: bool) -> AppResult<String> {
        let (parent, requested_name, normalized_path) = self.resolve_parent_for_create(windows_path, None)?;
        let target = parent.host_path.join(&requested_name);
        fs::create_dir(&target).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", target.display()),
                &error,
            )
        })?;
        self.upsert_fs_entry(&normalized_path, &requested_name, FsEntryKind::Directory, dtm)?;
        Ok(normalized_path)
    }

    pub fn write_file(&mut self, windows_path: &str, contents: &[u8], dtm: bool) -> AppResult<String> {
        let (parent, requested_name, normalized_path) = self.resolve_parent_for_create(windows_path, None)?;
        let target = parent.host_path.join(&requested_name);
        fs::write(&target, contents).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to write {}", target.display()),
                &error,
            )
        })?;
        self.upsert_fs_entry(&normalized_path, &requested_name, FsEntryKind::File, dtm)?;
        Ok(normalized_path)
    }

    pub fn write_file_overwrite(&mut self, windows_path: &str, contents: &[u8], dtm: bool) -> AppResult<String> {
        match self.resolve_existing_path(windows_path, None, 0) {
            Ok(resolved) => {
                fs::write(&resolved.host_path, contents).map_err(|error| {
                    AppError::from_io(
                        ReasonCode::RcIo,
                        format!("failed to write {}", resolved.host_path.display()),
                        &error,
                    )
                })?;
                let requested_name = self
                    .parse_windows_path(windows_path, None)?
                    .components
                    .last()
                    .cloned()
                    .unwrap_or_else(|| {
                        resolved
                            .host_path
                            .file_name()
                            .map(|value| value.to_string_lossy().to_string())
                            .unwrap_or_else(|| "file".to_string())
                    });
                self.upsert_fs_entry(&resolved.normalized_path, &requested_name, FsEntryKind::File, dtm)?;
                Ok(resolved.normalized_path)
            }
            Err(error) if error.code == ReasonCode::RcFsNotFound => {
                self.write_file(windows_path, contents, dtm)
            }
            Err(error) => Err(error),
        }
    }

    pub fn enumerate_directory(&self, windows_path: &str) -> AppResult<Vec<String>> {
        let resolved = self.resolve_existing_path(windows_path, None, 0)?;
        let mut entries = fs::read_dir(&resolved.host_path)
            .map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcFsNotFound,
                    format!("failed to enumerate {}", resolved.host_path.display()),
                    &error,
                )
            })?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        entries.sort();
        Ok(entries)
    }

    pub fn set_file_attributes(&mut self, windows_path: &str, attrs: &[&str]) -> AppResult<()> {
        let resolved = self.resolve_existing_path(windows_path, None, 0)?;
        if let Some(entry) = self.config.fs_state.entries.get_mut(&resolved.normalized_path) {
            entry.attributes = attrs.iter().map(|value| (*value).to_string()).collect();
            entry.attributes.sort();
            entry.attributes.dedup();
        }
        self.save_config()
    }

    pub fn set_file_times(
        &mut self,
        windows_path: &str,
        creation_time_ticks: Option<u64>,
        last_access_time_ticks: Option<u64>,
        last_write_time_ticks: Option<u64>,
    ) -> AppResult<()> {
        let resolved = self.resolve_existing_path(windows_path, None, 0)?;
        let host_metadata = fs::metadata(&resolved.host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to stat {}", resolved.host_path.display()),
                &error,
            )
        })?;
        let kind = if host_metadata.is_dir() {
            FsEntryKind::Directory
        } else {
            FsEntryKind::File
        };
        let original_case = resolved
            .host_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_string();
        let fallback_ticks = creation_time_ticks
            .or(last_access_time_ticks)
            .or(last_write_time_ticks)
            .unwrap_or_else(|| current_windows_ticks(false));
        let entry = self
            .config
            .fs_state
            .entries
            .entry(resolved.normalized_path)
            .or_insert_with(|| FsMetadataRecord {
                kind: kind.clone(),
                original_case,
                attributes: if kind == FsEntryKind::Directory {
                    vec!["directory".to_string()]
                } else {
                    Vec::new()
                },
                creation_time_ticks: fallback_ticks,
                last_access_time_ticks: fallback_ticks,
                last_write_time_ticks: fallback_ticks,
            });
        if let Some(value) = creation_time_ticks {
            entry.creation_time_ticks = value;
        }
        if let Some(value) = last_access_time_ticks {
            entry.last_access_time_ticks = value;
        }
        if let Some(value) = last_write_time_ticks {
            entry.last_write_time_ticks = value;
        }
        self.save_config()
    }

    pub fn get_file_metadata(&self, windows_path: &str) -> AppResult<FsMetadataRecord> {
        let resolved = self.resolve_existing_path(windows_path, None, 0)?;
        self.config
            .fs_state
            .entries
            .get(&resolved.normalized_path)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!("missing metadata for {}", resolved.normalized_path),
                )
            })
    }

    pub fn create_reparse_point(
        &mut self,
        windows_path: &str,
        target: &str,
        kind: ReparseKind,
        dtm: bool,
    ) -> AppResult<()> {
        let normalized_path = if self.resolve_existing_path(windows_path, None, 0).is_ok() {
            self.parse_windows_path(windows_path, None)?.normalized_path
        } else {
            self.create_directory(windows_path, dtm)?
        };
        self.config.fs_state.reparse_points.insert(
            normalized_path.clone(),
            ReparsePoint {
                kind,
                target: target.to_string(),
            },
        );
        if let Some(entry) = self.config.fs_state.entries.get_mut(&normalized_path) {
            if !entry.attributes.iter().any(|value| value == "reparse_point") {
                entry.attributes.push("reparse_point".to_string());
                entry.attributes.sort();
            }
        }
        self.save_config()
    }

    pub fn resolve_sandboxed_path(&self, windows_path: &str) -> AppResult<String> {
        Ok(self.resolve_existing_path(windows_path, None, 0)?.normalized_path)
    }

    pub fn open_file(
        &self,
        windows_path: &str,
        desired_access: FileAccess,
        share_mode: ShareMode,
    ) -> AppResult<FileHandle> {
        let resolved = self.resolve_existing_path(windows_path, None, 0)?;
        let pid = std::process::id();
        self.with_shared_file_runtime(|runtime| {
            for existing in &runtime.open_handles {
                if existing.normalized_path == resolved.normalized_path
                    && share_conflict(existing, desired_access, share_mode)
                {
                    return Err(AppError::new(
                        ReasonCode::RcFsSharingViolation,
                        format!("sharing violation for {}", resolved.normalized_path),
                    ));
                }
            }
            runtime.next_handle += 1;
            let handle = FileHandle {
                id: runtime.next_handle,
                normalized_path: resolved.normalized_path.clone(),
            };
            runtime.open_handles.push(SharedOpenFileState {
                handle_id: handle.id,
                owner_pid: pid,
                normalized_path: resolved.normalized_path.clone(),
                desired_access,
                share_mode,
            });
            Ok(handle)
        })
    }

    pub fn close_file_handle(&self, handle: &FileHandle) -> AppResult<()> {
        let pid = std::process::id();
        self.with_shared_file_runtime(|runtime| {
            runtime
                .open_handles
                .retain(|state| !(state.handle_id == handle.id && state.owner_pid == pid));
            runtime
                .locks
                .retain(|lock| !(lock.handle_id == handle.id && lock.owner_pid == pid));
            Ok(())
        })
    }

    pub fn lock_file_range(
        &self,
        handle: &FileHandle,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> AppResult<()> {
        let pid = std::process::id();
        self.with_shared_file_runtime(|runtime| {
            let normalized_path = runtime
                .open_handles
                .iter()
                .find(|open_handle| open_handle.handle_id == handle.id && open_handle.owner_pid == pid)
                .map(|open_handle| open_handle.normalized_path.clone())
                .ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcFsLockViolation,
                        format!("unknown handle {}", handle.id),
                    )
                })?;
            for lock in &runtime.locks {
                if lock.normalized_path == normalized_path
                    && !(lock.handle_id == handle.id && lock.owner_pid == pid)
                    && ranges_overlap(lock.offset, lock.length, offset, length)
                    && (lock.exclusive || exclusive)
                {
                    return Err(AppError::new(
                        ReasonCode::RcFsLockViolation,
                        format!("byte-range lock conflict for {}", normalized_path),
                    ));
                }
            }
            runtime.locks.push(SharedByteRangeLock {
                handle_id: handle.id,
                owner_pid: pid,
                normalized_path,
                offset,
                length,
                exclusive,
            });
            Ok(())
        })
    }

    pub fn registry_set_value(
        &self,
        hive: &str,
        key: &str,
        value_name: &str,
        value_type: &str,
        data: Value,
        view: RegistryView,
    ) -> AppResult<()> {
        validate_registry_value_type(value_type)?;
        let (actual_hive, actual_key) = self.redirect_registry_path(hive, key, view, true)?;
        let path = self.registry_file(&actual_hive);
        let mut db = load_registry_db(&path)?;
        let values = db.entry(actual_key.clone()).or_insert_with(BTreeMap::new);
        values.insert(
            value_name.to_string(),
            StoredRegistryValue {
                value_type: value_type.to_string(),
                data,
            },
        );
        store_registry_db(&path, &db)?;
        self.notify_registry_watchers(&actual_hive, &actual_key);
        Ok(())
    }

    pub fn registry_get_value(
        &self,
        hive: &str,
        key: &str,
        value_name: &str,
        view: RegistryView,
    ) -> AppResult<Option<StoredRegistryValue>> {
        if normalize_hive(hive)? == "HKCR" {
            for (merged_hive, merged_key) in self.hkcr_merged_keys(key, view)? {
                let db = load_registry_db(&self.registry_file(&merged_hive))?;
                if let Some(values) = db.get(&merged_key) {
                    if let Some(value) = values.get(value_name) {
                        return Ok(Some(value.clone()));
                    }
                }
            }
            return Ok(None);
        }

        let (actual_hive, actual_key) = self.redirect_registry_path(hive, key, view, false)?;
        let db = load_registry_db(&self.registry_file(&actual_hive))?;
        Ok(db.get(&actual_key).and_then(|values| values.get(value_name)).cloned())
    }

    pub fn registry_key_exists(&self, hive: &str, key: &str, view: RegistryView) -> AppResult<bool> {
        if normalize_hive(hive)? == "HKCR" {
            for (merged_hive, merged_key) in self.hkcr_merged_keys(key, view)? {
                let db = load_registry_db(&self.registry_file(&merged_hive))?;
                if db.contains_key(&merged_key) {
                    return Ok(true);
                }
                let prefix = format!("{}\\", normalize_registry_key(&merged_key));
                if db.keys().any(|existing| existing.starts_with(&prefix)) {
                    return Ok(true);
                }
            }
            return Ok(false);
        }

        let (actual_hive, actual_key) = self.redirect_registry_path(hive, key, view, false)?;
        let db = load_registry_db(&self.registry_file(&actual_hive))?;
        if db.contains_key(&actual_key) {
            return Ok(true);
        }
        let prefix = format!("{}\\", normalize_registry_key(&actual_key));
        Ok(db.keys().any(|existing| existing.starts_with(&prefix)))
    }

    pub fn registry_create_key(&self, hive: &str, key: &str, view: RegistryView) -> AppResult<bool> {
        let (actual_hive, actual_key) = self.redirect_registry_path(hive, key, view, true)?;
        let path = self.registry_file(&actual_hive);
        let mut db = load_registry_db(&path)?;
        let existing = db.remove(&actual_key);
        let created = existing.is_none();
        db.insert(actual_key.clone(), existing.unwrap_or_default());
        if created {
            store_registry_db(&path, &db)?;
            self.notify_registry_watchers(&actual_hive, &actual_key);
        }
        Ok(created)
    }

    pub fn registry_delete_value(
        &self,
        hive: &str,
        key: &str,
        value_name: &str,
        view: RegistryView,
    ) -> AppResult<()> {
        let (actual_hive, actual_key) = self.redirect_registry_path(hive, key, view, true)?;
        let path = self.registry_file(&actual_hive);
        let mut db = load_registry_db(&path)?;
        let values = db.get_mut(&actual_key).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcRegistryNotFound,
                format!("missing registry key {}\\{}", actual_hive, actual_key),
            )
        })?;
        values.remove(value_name);
        if values.is_empty() {
            db.remove(&actual_key);
        }
        store_registry_db(&path, &db)?;
        self.notify_registry_watchers(&actual_hive, &actual_key);
        Ok(())
    }

    pub fn registry_delete_key(&self, hive: &str, key: &str, view: RegistryView) -> AppResult<()> {
        let (actual_hive, actual_key) = self.redirect_registry_path(hive, key, view, true)?;
        let path = self.registry_file(&actual_hive);
        let mut db = load_registry_db(&path)?;
        let prefix = format!("{}\\", actual_key);
        let keys_to_remove = db
            .keys()
            .filter(|existing| *existing == &actual_key || existing.starts_with(&prefix))
            .cloned()
            .collect::<Vec<_>>();
        if keys_to_remove.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcRegistryNotFound,
                format!("missing registry key {}\\{}", actual_hive, actual_key),
            ));
        }
        for key_to_remove in keys_to_remove {
            db.remove(&key_to_remove);
        }
        store_registry_db(&path, &db)?;
        self.notify_registry_watchers(&actual_hive, &actual_key);
        Ok(())
    }

    pub fn registry_enum_keys(&self, hive: &str, key: &str, view: RegistryView) -> AppResult<Vec<String>> {
        let normalized_hive = normalize_hive(hive)?;
        if normalized_hive == "HKCR" {
            let mut merged = BTreeSet::new();
            for (merged_hive, merged_key) in self.hkcr_merged_keys(key, view)? {
                for child in enumerate_subkeys(&load_registry_db(&self.registry_file(&merged_hive))?, &merged_key) {
                    merged.insert(child);
                }
            }
            return Ok(merged.into_iter().collect());
        }

        let (actual_hive, actual_key) = self.redirect_registry_path(hive, key, view, false)?;
        Ok(enumerate_subkeys(
            &load_registry_db(&self.registry_file(&actual_hive))?,
            &actual_key,
        ))
    }

    pub fn registry_enum_values(&self, hive: &str, key: &str, view: RegistryView) -> AppResult<Vec<String>> {
        let normalized_hive = normalize_hive(hive)?;
        if normalized_hive == "HKCR" {
            let mut merged = BTreeSet::new();
            for (merged_hive, merged_key) in self.hkcr_merged_keys(key, view)? {
                let db = load_registry_db(&self.registry_file(&merged_hive))?;
                if let Some(values) = db.get(&merged_key) {
                    for name in values.keys() {
                        merged.insert(name.clone());
                    }
                }
            }
            return Ok(merged.into_iter().collect());
        }

        let (actual_hive, actual_key) = self.redirect_registry_path(hive, key, view, false)?;
        let db = load_registry_db(&self.registry_file(&actual_hive))?;
        let mut values = db
            .get(&actual_key)
            .map(|entries| entries.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        values.sort();
        Ok(values)
    }

    pub fn registry_watch(&self, hive: &str, key: &str, recursive: bool, view: RegistryView) -> AppResult<RegistryWatcher> {
        let (actual_hive, actual_key) = self.redirect_registry_path(hive, key, view, false)?;
        let watcher = Arc::new(RegistryWatcherInner {
            ge_root: self.root.display().to_string(),
            hive: actual_hive,
            key_norm: normalize_registry_key(&actual_key),
            recursive,
            sequence: Mutex::new(0),
            condvar: Condvar::new(),
        });
        registry_watchers()
            .lock()
            .expect("registry watchers lock poisoned")
            .push(Arc::downgrade(&watcher));
        Ok(RegistryWatcher {
            inner: watcher,
            observed_sequence: 0,
        })
    }

    pub fn executable_identity(&self, program: &Path) -> AppResult<ExecutableIdentity> {
        let normalized_install_path = self.normalize_host_path(program);
        let pe_version = pe::maybe_version_info_from_file(program)?;
        let version_sidecar = read_version_sidecar(program)?;
        let product_name = pe_version
            .as_ref()
            .and_then(|version| version.product_name.clone())
            .or_else(|| version_sidecar.as_ref().and_then(|sidecar| sidecar.product_name.clone()));
        let file_version = pe_version
            .as_ref()
            .and_then(|version| version.file_version.clone())
            .or_else(|| version_sidecar.as_ref().and_then(|sidecar| sidecar.file_version.clone()));
        Ok(ExecutableIdentity {
            sha256: util::sha256_file(program)?,
            product_name,
            file_version,
            normalized_install_path,
        })
    }

    pub fn match_override_for_identity(&self, identity: &ExecutableIdentity) -> Option<&OverrideProfile> {
        self.config
            .override_profiles
            .iter()
            .enumerate()
            .filter(|(_, profile)| override_matches(&profile.match_rule, identity))
            .min_by_key(|(index, profile)| (profile.match_rule.priority(), *index))
            .map(|(_, profile)| profile)
    }

    pub fn apply_overrides_for_program(
        &mut self,
        program: &Path,
        env: &mut BTreeMap<String, String>,
    ) -> AppResult<Option<AppliedOverride>> {
        let identity = self.executable_identity(program)?;
        let Some(profile) = self.match_override_for_identity(&identity).cloned() else {
            return Ok(None);
        };

        for (key, value) in &profile.payload.env_add {
            env.insert(key.clone(), value.clone());
        }
        for key in &profile.payload.env_remove {
            env.remove(key);
        }
        for set in &profile.payload.reg_set {
            self.registry_set_value(
                &set.hive,
                &set.key,
                &set.value,
                &set.value_type,
                set.data.clone(),
                RegistryView::Native,
            )?;
        }
        for delete in &profile.payload.reg_delete {
            if let Some(value_name) = &delete.value {
                let _ = self.registry_delete_value(&delete.hive, &delete.key, value_name, RegistryView::Native);
            } else {
                let _ = self.registry_delete_key(&delete.hive, &delete.key, RegistryView::Native);
            }
        }
        if let Some(fs_profile) = &profile.payload.fs_profile {
            env.insert(
                "CASA1_EFFECTIVE_LONG_PATHS_ENABLED".to_string(),
                if fs_profile.long_paths_enabled { "1" } else { "0" }.to_string(),
            );
            env.insert(
                "CASA1_EFFECTIVE_CASE_MODE".to_string(),
                fs_profile.case_mode.clone(),
            );
        }
        env.insert(
            "CASA1_ACTIVE_OVERRIDE_PAYLOAD".to_string(),
            util::stable_json(&profile.payload)?,
        );
        env.insert("CASA1_ACTIVE_OVERRIDE_ID".to_string(), profile.id.clone());

        Ok(Some(AppliedOverride {
            profile_id: profile.id,
            match_rule: profile.match_rule.kind().to_string(),
            normalized_diff: serde_json::to_value(&profile.payload).unwrap_or(Value::Null),
        }))
    }

    fn ensure_layout(&self) -> AppResult<()> {
        let mut directories = vec![
            self.drive_c().join("Windows/System32"),
            self.drive_c().join("Program Files"),
            self.drive_c().join(format!("users/{}/AppData/Roaming", self.config.user_name)),
            self.drive_c().join(format!("users/{}/AppData/Local", self.config.user_name)),
            self.drive_c().join(format!("users/{}/AppData/LocalLow", self.config.user_name)),
            self.root.join("fs"),
            self.root.join("registry"),
            self.root.join("cache/dbt"),
            self.root.join("cache/shader"),
            self.root.join("cache/pso"),
            self.root.join("cache/dxgi"),
            self.root.join("cache/http"),
            self.tmp_dir(),
            self.logs_dir(),
            self.traces_dir(),
            self.reports_dir(),
            self.diagnostics_dir(),
        ];
        if self.config.arch == GeArch::X86 {
            directories.push(self.drive_c().join("Windows/SysWOW64"));
            directories.push(self.drive_c().join("Program Files (x86)"));
        }
        for directory in directories {
            fs::create_dir_all(&directory).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to create {}", directory.display()),
                    &error,
                )
            })?;
        }
        for hive in ["HKLM", "HKCU", "HKCR"] {
            let path = self.registry_file(hive);
            if !path.exists() {
                util::write_string(&path, "{}")?;
            }
        }
        let reparse_db = self.reparse_db_file();
        if !reparse_db.exists() {
            util::write_string(&reparse_db, "{}")?;
        }
        Ok(())
    }

    fn write_config(&self) -> AppResult<()> {
        write_reparse_db(&self.reparse_db_file(), &self.config.fs_state.reparse_points)?;
        let mut persisted_config = self.config.clone();
        persisted_config.fs_state.reparse_points.clear();
        let contents = util::stable_json(&persisted_config)?;
        util::write_string(&self.root.join("ge.json"), &contents)
    }

    fn resolve_parent_for_create(
        &self,
        windows_path: &str,
        long_paths_override: Option<bool>,
    ) -> AppResult<(ResolvedWindowsPath, String, String)> {
        let parsed = self.parse_windows_path(windows_path, long_paths_override)?;
        if parsed.device_namespace {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("device namespace path {windows_path} cannot be materialized in the GE"),
            ));
        }
        let drive = parsed.drive.clone().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("missing drive designator in {windows_path}"),
            )
        })?;
        let requested_name = parsed.components.last().cloned().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("path {windows_path} does not identify a file-system entry"),
            )
        })?;
        let parent_components = parsed.components[..parsed.components.len() - 1].to_vec();
        let parent_path = build_drive_path(&drive, &parent_components);
        let parent = self.resolve_existing_path(&parent_path, long_paths_override, 0)?;
        if find_existing_child_case_insensitive(&parent.host_path, &requested_name)?.is_some() {
            return Err(AppError::new(
                ReasonCode::RcFsAlreadyExists,
                format!("{} already exists", build_drive_path(&drive, &parsed.components)),
            ));
        }
        let normalized_path = build_drive_path(
            &drive,
            &parsed
                .components
                .iter()
                .map(|component| component.to_lowercase())
                .collect::<Vec<_>>(),
        );
        Ok((parent, requested_name, normalized_path))
    }

    fn resolve_existing_path(
        &self,
        windows_path: &str,
        long_paths_override: Option<bool>,
        depth: u8,
    ) -> AppResult<ResolvedWindowsPath> {
        if depth > 8 {
            return Err(AppError::new(
                ReasonCode::RcFsSandboxEscape,
                format!("reparse-point resolution exceeded the depth limit for {windows_path}"),
            ));
        }

        let parsed = self.parse_windows_path(windows_path, long_paths_override)?;
        if parsed.device_namespace {
            let normalized_path = parsed.normalized_path.clone();
            return Ok(ResolvedWindowsPath {
                normalized_path,
                host_path: PathBuf::from(parsed.normalized_path),
                existed: true,
            });
        }

        let drive = parsed.drive.clone().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("missing drive designator in {windows_path}"),
            )
        })?;
        let mapping = self.resolve_drive_mapping(&drive)?;
        let mut current_host = self.resolve_drive_target(&mapping);
        let mut walked_components = Vec::new();

        for (index, component) in parsed.components.iter().enumerate() {
            let prefix_components = parsed.components[..=index].to_vec();
            let existing_child = find_existing_child_case_insensitive(&current_host, component)?.ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!("{} was not found", build_drive_path(&drive, &prefix_components)),
                )
            })?;
            current_host.push(&existing_child);
            walked_components.push(existing_child.clone());
            let normalized_prefix = build_drive_path(
                &drive,
                &walked_components
                    .iter()
                    .map(|item| item.to_lowercase())
                    .collect::<Vec<_>>(),
            );
            if let Some(reparse_point) = self.config.fs_state.reparse_points.get(&normalized_prefix) {
                let redirected_path = build_reparse_redirect(
                    &drive,
                    &walked_components[..walked_components.len() - 1],
                    reparse_point,
                    &parsed.components[index + 1..],
                );
                let redirected = self
                    .resolve_existing_path(&redirected_path, long_paths_override, depth + 1)
                    .map_err(|error| {
                        if matches!(error.code, ReasonCode::RcFsPathInvalid | ReasonCode::RcFsNotFound)
                        {
                            AppError::new(
                                ReasonCode::RcFsSandboxEscape,
                                format!("reparse target {} escaped the GE sandbox", redirected_path),
                            )
                            .with_hint(error.message)
                        } else {
                            error
                        }
                    })?;
                self.ensure_within_allowed_roots(&redirected.host_path)?;
                return Ok(redirected);
            }
        }

        self.ensure_within_allowed_roots(&current_host)?;
        Ok(ResolvedWindowsPath {
            normalized_path: build_drive_path(
                &drive,
                &walked_components
                    .iter()
                    .map(|item| item.to_lowercase())
                    .collect::<Vec<_>>(),
            ),
            host_path: current_host,
            existed: true,
        })
    }

    fn resolve_drive_mapping(&self, drive: &str) -> AppResult<DriveMapping> {
        let normalized_drive = normalize_drive_letter(drive)?;
        self.config
            .drive_mappings
            .iter()
            .find(|mapping| mapping.drive == normalized_drive && mapping.enabled)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcFsPathInvalid,
                    format!("drive {}: is not mapped in this GE", normalized_drive),
                )
            })
    }

    fn resolve_drive_target(&self, mapping: &DriveMapping) -> PathBuf {
        if mapping.target == "<GE>" {
            self.root.clone()
        } else if let Some(suffix) = mapping.target.strip_prefix("<GE>/") {
            self.root.join(suffix)
        } else {
            PathBuf::from(&mapping.target)
        }
    }

    fn ensure_within_allowed_roots(&self, path: &Path) -> AppResult<()> {
        let allowed_roots = self
            .active_drive_mappings()
            .into_iter()
            .map(|mapping| self.resolve_drive_target(&mapping))
            .collect::<Vec<_>>();
        if allowed_roots.iter().any(|root| path.starts_with(root)) {
            Ok(())
        } else {
            Err(AppError::new(
                ReasonCode::RcFsSandboxEscape,
                format!("{} escapes the GE sandbox", path.display()),
            ))
        }
    }

    fn with_shared_file_runtime<T>(
        &self,
        operation: impl FnOnce(&mut SharedFileRuntimeState) -> AppResult<T>,
    ) -> AppResult<T> {
        let lock_path = self.tmp_dir().join("fs_runtime.lock");
        let state_path = self.tmp_dir().join("fs_runtime.json");
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to open {}", lock_path.display()),
                    &error,
                )
            })?;
        flock_exclusive(&lock_file)?;
        let operation_result = (|| {
            let mut runtime = load_shared_file_runtime(&state_path)?;
            cleanup_stale_runtime(&mut runtime);
            let result = operation(&mut runtime)?;
            persist_shared_file_runtime(&state_path, &mut runtime)?;
            Ok(result)
        })();
        let unlock_result = flock_unlock(&lock_file);
        match (operation_result, unlock_result) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn upsert_fs_entry(
        &mut self,
        normalized_path: &str,
        original_case: &str,
        kind: FsEntryKind,
        dtm: bool,
    ) -> AppResult<()> {
        let ticks = current_windows_ticks(dtm);
        self.config.fs_state.entries.insert(
            normalized_path.to_string(),
            FsMetadataRecord {
                kind: kind.clone(),
                original_case: original_case.to_string(),
                attributes: if kind == FsEntryKind::Directory {
                    vec!["directory".to_string()]
                } else {
                    Vec::new()
                },
                creation_time_ticks: ticks,
                last_access_time_ticks: ticks,
                last_write_time_ticks: ticks,
            },
        );
        self.save_config()
    }

    fn redirect_registry_path(
        &self,
        hive: &str,
        key: &str,
        view: RegistryView,
        allow_hkcr_write: bool,
    ) -> AppResult<(String, String)> {
        let normalized_hive = normalize_hive(hive)?;
        let normalized_key = normalize_registry_key(key);
        if normalized_hive == "HKCR" {
            if allow_hkcr_write {
                return Ok((
                    "HKCU".to_string(),
                    join_registry_key("Software\\Classes", &normalized_key),
                ));
            }
            return Ok((normalized_hive, normalized_key));
        }

        let redirected_key = if self.config.arch == GeArch::X86
            && view == RegistryView::Wow6432
            && normalized_hive == "HKLM"
            && starts_with_registry_segment(&normalized_key, "Software")
            && !starts_with_registry_segment(&normalized_key, "Software\\Classes")
        {
            join_registry_key(
                "Software\\WOW6432Node",
                normalized_key
                    .strip_prefix("Software\\")
                    .unwrap_or(normalized_key.as_str()),
            )
        } else {
            normalized_key
        };
        Ok((normalized_hive, redirected_key))
    }

    fn hkcr_merged_keys(&self, key: &str, view: RegistryView) -> AppResult<Vec<(String, String)>> {
        let normalized_key = normalize_registry_key(key);
        Ok(vec![
            (
                "HKCU".to_string(),
                join_registry_key("Software\\Classes", &normalized_key),
            ),
            self.redirect_registry_path(
                "HKLM",
                &join_registry_key("Software\\Classes", &normalized_key),
                view,
                false,
            )?,
        ])
    }

    fn notify_registry_watchers(&self, hive: &str, key: &str) {
        let normalized_key = normalize_registry_key(key);
        let ge_root = self.root.display().to_string();
        let mut registry_watchers = registry_watchers()
            .lock()
            .expect("registry watchers lock poisoned");
        registry_watchers.retain(|watcher| watcher.upgrade().is_some());
        for watcher in registry_watchers.iter().filter_map(Weak::upgrade) {
            if watcher.ge_root != ge_root || watcher.hive != hive {
                continue;
            }
            if normalized_key == watcher.key_norm
                || (watcher.recursive
                    && normalized_key.starts_with(&format!("{}\\", watcher.key_norm)))
            {
                let mut sequence = watcher.sequence.lock().expect("registry watcher sequence poisoned");
                *sequence += 1;
                watcher.condvar.notify_all();
            }
        }
    }
}

pub fn diff_file_snapshots(
    before: &BTreeMap<String, FileSnapshotEntry>,
    after: &BTreeMap<String, FileSnapshotEntry>,
) -> Vec<FileManifestDelta> {
    let mut keys = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();

    let mut deltas = Vec::new();
    for key in keys {
        match (before.get(&key), after.get(&key)) {
            (None, Some(entry)) => deltas.push(FileManifestDelta {
                op: "create".to_string(),
                path_norm: entry.path_norm.clone(),
                sha256: entry.sha256.clone(),
                size: entry.size,
                times_norm: entry.times_norm.clone(),
                attrs: entry.attrs.clone(),
            }),
            (Some(entry), None) => deltas.push(FileManifestDelta {
                op: "delete".to_string(),
                path_norm: entry.path_norm.clone(),
                sha256: entry.sha256.clone(),
                size: entry.size,
                times_norm: entry.times_norm.clone(),
                attrs: entry.attrs.clone(),
            }),
            (Some(before_entry), Some(after_entry)) if before_entry != after_entry => {
                deltas.push(FileManifestDelta {
                    op: "modify".to_string(),
                    path_norm: after_entry.path_norm.clone(),
                    sha256: after_entry.sha256.clone(),
                    size: after_entry.size,
                    times_norm: after_entry.times_norm.clone(),
                    attrs: after_entry.attrs.clone(),
                });
            }
            _ => {}
        }
    }
    deltas
}

pub fn diff_registry_snapshots(
    before: &BTreeMap<String, RegistrySnapshotEntry>,
    after: &BTreeMap<String, RegistrySnapshotEntry>,
) -> Vec<RegistryDelta> {
    let mut keys = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();

    let mut deltas = Vec::new();
    for key in keys {
        match (before.get(&key), after.get(&key)) {
            (None, Some(entry)) => deltas.push(RegistryDelta {
                op: "set".to_string(),
                hive: entry.hive.clone(),
                key_norm: entry.key_norm.clone(),
                value: entry.value.clone(),
                value_type: entry.value_type.clone(),
                data_norm: entry.data_norm.clone(),
            }),
            (Some(entry), None) => deltas.push(RegistryDelta {
                op: "delete".to_string(),
                hive: entry.hive.clone(),
                key_norm: entry.key_norm.clone(),
                value: entry.value.clone(),
                value_type: entry.value_type.clone(),
                data_norm: entry.data_norm.clone(),
            }),
            (Some(before_entry), Some(after_entry)) if before_entry != after_entry => {
                deltas.push(RegistryDelta {
                    op: "set".to_string(),
                    hive: after_entry.hive.clone(),
                    key_norm: after_entry.key_norm.clone(),
                    value: after_entry.value.clone(),
                    value_type: after_entry.value_type.clone(),
                    data_norm: after_entry.data_norm.clone(),
                });
            }
            _ => {}
        }
    }
    deltas
}

pub fn load_registry_db(path: &Path) -> AppResult<RegistryDb> {
    if !path.exists() {
        return Ok(RegistryDb::new());
    }
    let contents = fs::read_to_string(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    if contents.trim().is_empty() {
        return Ok(RegistryDb::new());
    }
    serde_json::from_str(&contents).map_err(|error| {
        AppError::new(
            ReasonCode::RcIo,
            format!("failed to parse {}", path.display()),
        )
        .with_hint(error.to_string())
    })
}

pub fn store_registry_db(path: &Path, db: &RegistryDb) -> AppResult<()> {
    let contents = util::stable_json(db)?;
    util::write_string(path, &contents)
}

fn default_user_name() -> String {
    "casa1".to_string()
}

fn default_drive_mappings() -> Vec<DriveMapping> {
    vec![
        DriveMapping {
            drive: "C".to_string(),
            target: "<GE>/drive_c".to_string(),
            read_only: false,
            enabled: true,
            requires_permission: false,
        },
        DriveMapping {
            drive: "Z".to_string(),
            target: "/".to_string(),
            read_only: true,
            enabled: false,
            requires_permission: true,
        },
    ]
}

fn windows_path_for_drive(prefix: &str, relative: &Path) -> String {
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

fn parse_windows_path_impl(
    ge: &GameEnvironment,
    input: &str,
    long_paths_override: Option<bool>,
) -> AppResult<ParsedWindowsPath> {
    let mut raw = input.replace('/', "\\");
    let mut verbatim = false;
    let mut device_namespace = false;
    if let Some(rest) = raw.strip_prefix("\\\\?\\") {
        verbatim = true;
        raw = rest.to_string();
    } else if let Some(rest) = raw.strip_prefix("\\\\.\\") {
        device_namespace = true;
        raw = rest.to_string();
    }

    if device_namespace {
        return Ok(ParsedWindowsPath {
            drive: None,
            normalized_path: format!("\\\\.\\{}", raw),
            components: raw
                .split('\\')
                .filter(|component| !component.is_empty())
                .map(|component| component.to_string())
                .collect(),
            verbatim,
            device_namespace,
        });
    }

    if raw.len() < 2 || !raw.as_bytes()[0].is_ascii_alphabetic() || raw.as_bytes()[1] != b':' {
        return Err(AppError::new(
            ReasonCode::RcFsPathInvalid,
            format!("expected an absolute drive path, got {input}"),
        ));
    }
    let drive = raw[0..1].to_ascii_uppercase();
    let mut remainder = raw[2..].to_string();
    if remainder.is_empty() {
        remainder.push('\\');
    }
    let long_paths_enabled = long_paths_override.unwrap_or(ge.config.long_paths_enabled);
    let mut components = Vec::new();
    for component in remainder.split('\\') {
        if component.is_empty() {
            continue;
        }
        let normalized_component = if verbatim {
            component.to_string()
        } else if component == "." {
            continue;
        } else if component == ".." {
            components.pop();
            continue;
        } else {
            let trimmed = component.trim_end_matches([' ', '.']);
            if trimmed.is_empty() {
                continue;
            }
            if is_reserved_dos_name(trimmed) {
                return Err(AppError::new(
                    ReasonCode::RcFsReservedName,
                    format!("{} is a reserved DOS device name", trimmed),
                ));
            }
            trimmed.to_string()
        };
        components.push(normalized_component);
    }
    let normalized_path = if verbatim {
        format!("\\\\?\\{}", build_drive_path(&drive, &components))
    } else {
        build_drive_path(
            &drive,
            &components
                .iter()
                .map(|component| component.to_lowercase())
                .collect::<Vec<_>>(),
        )
    };
    if !verbatim && !long_paths_enabled && normalized_path.len() > 260 {
        return Err(AppError::new(
            ReasonCode::RcFsPathTooLong,
            format!("{} exceeds the 260-character Win32 path limit", normalized_path),
        ));
    }

    Ok(ParsedWindowsPath {
        drive: Some(drive),
        normalized_path,
        components,
        verbatim,
        device_namespace,
    })
}

fn normalize_registry_data(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()),
    }
}

fn base_root_candidates_from_env_or(current: &Path) -> AppResult<Vec<PathBuf>> {
    match std::env::var("CASA1_GES_ROOT") {
        Ok(root) => Ok(vec![PathBuf::from(root)]),
        Err(_) => Ok(base_root_candidates_from(current)),
    }
}

fn base_root_candidates_from(current: &Path) -> Vec<PathBuf> {
    let primary = resolve_base_root(current);
    let legacy = current.join("ges");
    if legacy == primary {
        vec![primary]
    } else {
        vec![primary, legacy]
    }
}

fn resolve_base_root(current: &Path) -> PathBuf {
    find_workspace_root(current)
        .unwrap_or_else(|| current.to_path_buf())
        .join("ges")
}

fn find_workspace_root(current: &Path) -> Option<PathBuf> {
    let mut cursor = current;
    loop {
        if cursor.join("Cargo.toml").is_file() {
            return Some(cursor.to_path_buf());
        }
        cursor = cursor.parent()?;
    }
}

fn find_named_ge_in_workspace(
    current: &Path,
    name: &str,
    exclude_roots: &[PathBuf],
) -> AppResult<Option<PathBuf>> {
    let Some(workspace_root) = find_workspace_root(current) else {
        return Ok(None);
    };
    let mut matches = Vec::new();
    for entry in WalkDir::new(&workspace_root)
        .follow_links(false)
        .min_depth(3)
        .max_depth(6)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() || entry.file_name() != "ge.json" {
            continue;
        }
        let Some(ge_root) = entry.path().parent() else {
            continue;
        };
        let Some(ges_root) = ge_root.parent() else {
            continue;
        };
        if ge_root.file_name().and_then(|value| value.to_str()) != Some(name)
            || ges_root.file_name().and_then(|value| value.to_str()) != Some("ges")
        {
            continue;
        }
        if exclude_roots.iter().any(|root| root == ges_root) {
            continue;
        }
        matches.push(ge_root.to_path_buf());
    }
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.into_iter().next()),
        _ => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!(
                "multiple game environments named {name} were found in the workspace; set CASA1_GES_ROOT explicitly"
            ),
        )),
    }
}

fn current_windows_ticks(dtm: bool) -> u64 {
    if dtm {
        0
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .div_euclid(100) as u64
    }
}

fn build_drive_path(drive: &str, components: &[String]) -> String {
    if components.is_empty() {
        format!("{}:\\", drive.to_ascii_uppercase())
    } else {
        format!("{}:\\{}", drive.to_ascii_uppercase(), components.join("\\"))
    }
}

fn normalize_drive_letter(drive: &str) -> AppResult<String> {
    let trimmed = drive.trim_end_matches(':').trim();
    if trimmed.len() == 1 && trimmed.as_bytes()[0].is_ascii_alphabetic() {
        Ok(trimmed.to_ascii_uppercase())
    } else {
        Err(AppError::new(
            ReasonCode::RcFsPathInvalid,
            format!("invalid drive designator {drive}"),
        ))
    }
}

fn is_reserved_dos_name(component: &str) -> bool {
    let base = component.split('.').next().unwrap_or(component).to_ascii_uppercase();
    matches!(
        base.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn find_existing_child_case_insensitive(parent: &Path, requested: &str) -> AppResult<Option<String>> {
    if !parent.exists() {
        return Ok(None);
    }
    let requested_folded = windows_casefold_key(requested);
    for entry in fs::read_dir(parent).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to enumerate {}", parent.display()),
            &error,
        )
    })? {
        let entry = entry.map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to enumerate {}", parent.display()),
                &error,
            )
        })?;
        let child_name = entry.file_name().to_string_lossy().to_string();
        if windows_casefold_key(&child_name) == requested_folded {
            return Ok(Some(child_name));
        }
    }
    Ok(None)
}

fn build_reparse_redirect(
    drive: &str,
    parent_components: &[String],
    reparse_point: &ReparsePoint,
    remaining_components: &[String],
) -> String {
    let target = reparse_point.target.replace('/', "\\");
    let base_path = if target.starts_with("\\\\?\\") || target.starts_with("\\\\.\\") {
        target
    } else if target.len() >= 2 && target.as_bytes()[1] == b':' {
        target
    } else if target.starts_with('\\') {
        format!("{}:{}", drive.to_ascii_uppercase(), target)
    } else {
        let mut components = parent_components.to_vec();
        for component in target.split('\\').filter(|component| !component.is_empty()) {
            match component {
                "." => {}
                ".." => {
                    components.pop();
                }
                value => components.push(value.to_string()),
            }
        }
        build_drive_path(drive, &components)
    };
    if remaining_components.is_empty() {
        base_path
    } else {
        format!("{}\\{}", base_path.trim_end_matches('\\'), remaining_components.join("\\"))
    }
}

fn starts_with_registry_segment(value: &str, prefix: &str) -> bool {
    value == prefix || value.starts_with(&format!("{}\\", prefix))
}

fn normalize_hive(hive: &str) -> AppResult<String> {
    match hive.to_ascii_uppercase().as_str() {
        "HKLM" => Ok("HKLM".to_string()),
        "HKCU" => Ok("HKCU".to_string()),
        "HKCR" => Ok("HKCR".to_string()),
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry hive {other}"),
        )),
    }
}

fn normalize_registry_key(key: &str) -> String {
    key.replace('/', "\\")
        .split('\\')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("\\")
}

fn join_registry_key(base: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        normalize_registry_key(base)
    } else if base.is_empty() {
        normalize_registry_key(suffix)
    } else {
        format!("{}\\{}", normalize_registry_key(base), normalize_registry_key(suffix))
    }
}

fn enumerate_subkeys(db: &RegistryDb, key: &str) -> Vec<String> {
    let prefix = if key.is_empty() {
        String::new()
    } else {
        format!("{}\\", normalize_registry_key(key))
    };
    let mut subkeys = BTreeSet::new();
    for existing_key in db.keys() {
        if prefix.is_empty() {
            if let Some(segment) = existing_key.split('\\').next() {
                if !segment.is_empty() {
                    subkeys.insert(segment.to_string());
                }
            }
        } else if let Some(remainder) = existing_key.strip_prefix(&prefix) {
            if let Some(segment) = remainder.split('\\').next() {
                if !segment.is_empty() {
                    subkeys.insert(segment.to_string());
                }
            }
        }
    }
    subkeys.into_iter().collect()
}

fn validate_registry_value_type(value_type: &str) -> AppResult<()> {
    match value_type {
        "REG_SZ"
        | "REG_EXPAND_SZ"
        | "REG_MULTI_SZ"
        | "REG_DWORD"
        | "REG_QWORD"
        | "REG_BINARY" => Ok(()),
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry value type {other}"),
        )),
    }
}

fn read_version_sidecar(program: &Path) -> AppResult<Option<VersionSidecar>> {
    let sidecar_path = program.with_extension("casa1-version.json");
    if !sidecar_path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&sidecar_path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", sidecar_path.display()),
            &error,
        )
    })?;
    let sidecar = serde_json::from_str::<VersionSidecar>(&contents).map_err(|error| {
        AppError::new(
            ReasonCode::RcIo,
            format!("failed to parse {}", sidecar_path.display()),
        )
        .with_hint(error.to_string())
    })?;
    Ok(Some(sidecar))
}

fn override_matches(rule: &OverrideMatchRule, identity: &ExecutableIdentity) -> bool {
    match rule {
        OverrideMatchRule::ExeSha256 { sha256 } => sha256.eq_ignore_ascii_case(&identity.sha256),
        OverrideMatchRule::ProductVersion {
            product_name,
            file_version,
        } => identity.product_name.as_ref() == Some(product_name)
            && identity.file_version.as_ref() == Some(file_version),
        OverrideMatchRule::InstallPathWildcard { pattern } => wildcard_match(
            &pattern.to_lowercase(),
            &identity.normalized_install_path.to_lowercase(),
        ),
        OverrideMatchRule::DefaultProfile => true,
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern_chars = pattern.chars().collect::<Vec<_>>();
    let value_chars = value.chars().collect::<Vec<_>>();
    let mut dp = vec![vec![false; value_chars.len() + 1]; pattern_chars.len() + 1];
    dp[0][0] = true;
    for pattern_index in 1..=pattern_chars.len() {
        if pattern_chars[pattern_index - 1] == '*' {
            dp[pattern_index][0] = dp[pattern_index - 1][0];
        }
    }
    for pattern_index in 1..=pattern_chars.len() {
        for value_index in 1..=value_chars.len() {
            dp[pattern_index][value_index] = match pattern_chars[pattern_index - 1] {
                '*' => dp[pattern_index - 1][value_index] || dp[pattern_index][value_index - 1],
                '?' => dp[pattern_index - 1][value_index - 1],
                current => {
                    current == value_chars[value_index - 1] && dp[pattern_index - 1][value_index - 1]
                }
            };
        }
    }
    dp[pattern_chars.len()][value_chars.len()]
}

fn registry_watchers() -> &'static Mutex<Vec<Weak<RegistryWatcherInner>>> {
    static REGISTRY_WATCHERS: OnceLock<Mutex<Vec<Weak<RegistryWatcherInner>>>> = OnceLock::new();
    REGISTRY_WATCHERS.get_or_init(|| Mutex::new(Vec::new()))
}

fn share_conflict(existing: &SharedOpenFileState, desired_access: FileAccess, share_mode: ShareMode) -> bool {
    (desired_access.read && !existing.share_mode.read)
        || (desired_access.write && !existing.share_mode.write)
        || (desired_access.delete && !existing.share_mode.delete)
        || (existing.desired_access.read && !share_mode.read)
        || (existing.desired_access.write && !share_mode.write)
        || (existing.desired_access.delete && !share_mode.delete)
}

fn ranges_overlap(left_offset: u64, left_length: u64, right_offset: u64, right_length: u64) -> bool {
    let left_end = left_offset.saturating_add(left_length);
    let right_end = right_offset.saturating_add(right_length);
    left_offset < right_end && right_offset < left_end
}

fn load_shared_file_runtime(path: &Path) -> AppResult<SharedFileRuntimeState> {
    if !path.exists() {
        return Ok(SharedFileRuntimeState::default());
    }
    let contents = fs::read_to_string(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    if contents.trim().is_empty() {
        return Ok(SharedFileRuntimeState::default());
    }
    serde_json::from_str(&contents).map_err(|error| {
        AppError::new(
            ReasonCode::RcIo,
            format!("failed to parse {}", path.display()),
        )
        .with_hint(error.to_string())
    })
}

fn load_reparse_db(path: &Path) -> AppResult<BTreeMap<String, ReparsePoint>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let contents = fs::read_to_string(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcGeNotFound,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    if contents.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str::<BTreeMap<String, ReparsePoint>>(&contents).map_err(|error| {
        AppError::new(
            ReasonCode::RcGeNotFound,
            format!("failed to parse {}", path.display()),
        )
        .with_hint(error.to_string())
    })
}

fn write_reparse_db(path: &Path, reparse_points: &BTreeMap<String, ReparsePoint>) -> AppResult<()> {
    util::write_string(path, &util::stable_json(reparse_points)?)
}

fn persist_shared_file_runtime(path: &Path, runtime: &mut SharedFileRuntimeState) -> AppResult<()> {
    runtime
        .open_handles
        .sort_by(|left, right| (left.owner_pid, left.handle_id).cmp(&(right.owner_pid, right.handle_id)));
    runtime.locks.sort_by(|left, right| {
        (left.owner_pid, left.handle_id, left.offset, left.length).cmp(&(
            right.owner_pid,
            right.handle_id,
            right.offset,
            right.length,
        ))
    });
    let contents = util::stable_json(runtime)?;
    util::write_string(path, &contents)
}

fn cleanup_stale_runtime(runtime: &mut SharedFileRuntimeState) {
    runtime.open_handles.retain(|state| process_alive(state.owner_pid));
    runtime.locks.retain(|lock| {
        runtime
            .open_handles
            .iter()
            .any(|state| state.owner_pid == lock.owner_pid && state.handle_id == lock.handle_id)
    });
}

fn windows_casefold_key(value: &str) -> String {
    let mut folded = String::new();
    for character in value.chars() {
        folded.push(simple_windows_casefold_char(character));
    }
    folded
}

fn simple_windows_casefold_char(character: char) -> char {
    let mut uppercase = character.to_uppercase();
    match (uppercase.next(), uppercase.next()) {
        (Some(folded), None) => folded,
        _ => {
            let mut lowercase = character.to_lowercase();
            match (lowercase.next(), lowercase.next()) {
                (Some(folded), None) => folded,
                _ => character,
            }
        }
    }
}

fn process_alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    let result = unsafe { libc::kill(pid as i32, 0) };
    if result == 0 {
        true
    } else {
        matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM))
    }
}

fn flock_exclusive(file: &std::fs::File) -> AppResult<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result == 0 {
        Ok(())
    } else {
        Err(AppError::from_io(
            ReasonCode::RcIo,
            "failed to acquire shared file-runtime lock",
            &std::io::Error::last_os_error(),
        ))
    }
}

fn flock_unlock(file: &std::fs::File) -> AppResult<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if result == 0 {
        Ok(())
    } else {
        Err(AppError::from_io(
            ReasonCode::RcIo,
            "failed to release shared file-runtime lock",
            &std::io::Error::last_os_error(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn resolve_base_root_prefers_nearest_cargo_manifest() {
        let temp_dir = TempDir::new().expect("temp dir");
        let workspace_root = temp_dir.path().join("workspace");
        let nested = workspace_root.join("games/windows_tetris");
        fs::create_dir_all(&nested).expect("create nested workspace dirs");
        fs::write(
            workspace_root.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .expect("write cargo manifest");

        assert_eq!(resolve_base_root(&nested), workspace_root.join("ges"));
    }

    #[test]
    fn base_root_candidates_include_legacy_cwd_path_when_different() {
        let temp_dir = TempDir::new().expect("temp dir");
        let workspace_root = temp_dir.path().join("workspace");
        let nested = workspace_root.join("games/windows_tetris");
        fs::create_dir_all(&nested).expect("create nested workspace dirs");
        fs::write(
            workspace_root.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .expect("write cargo manifest");

        assert_eq!(
            base_root_candidates_from(&nested),
            vec![workspace_root.join("ges"), nested.join("ges")]
        );
    }

    #[test]
    fn find_named_ge_in_workspace_discovers_legacy_subdirectory_ge() {
        let temp_dir = TempDir::new().expect("temp dir");
        let workspace_root = temp_dir.path().join("workspace");
        let current = workspace_root.join("games/windows_tetris");
        let legacy_ge = current.join("ges/casa1-live-tetris");
        fs::create_dir_all(&legacy_ge).expect("create legacy ge dirs");
        fs::write(
            workspace_root.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .expect("write cargo manifest");
        fs::write(legacy_ge.join("ge.json"), "{}\n").expect("write ge.json");

        let found = find_named_ge_in_workspace(&workspace_root, "casa1-live-tetris", &[workspace_root.join("ges")])
            .expect("find ge");

        assert_eq!(found, Some(legacy_ge));
    }

    #[test]
    fn find_named_ge_in_workspace_errors_on_ambiguous_legacy_matches() {
        let temp_dir = TempDir::new().expect("temp dir");
        let workspace_root = temp_dir.path().join("workspace");
        let first = workspace_root.join("games/one/ges/casa1-live-tetris");
        let second = workspace_root.join("games/two/ges/casa1-live-tetris");
        fs::create_dir_all(&first).expect("create first legacy ge dirs");
        fs::create_dir_all(&second).expect("create second legacy ge dirs");
        fs::write(
            workspace_root.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .expect("write cargo manifest");
        fs::write(first.join("ge.json"), "{}\n").expect("write first ge.json");
        fs::write(second.join("ge.json"), "{}\n").expect("write second ge.json");

        let error = find_named_ge_in_workspace(&workspace_root, "casa1-live-tetris", &[workspace_root.join("ges")])
            .expect_err("ambiguous legacy ge lookup should fail");

        assert_eq!(error.code, ReasonCode::RcCliInvalid);
    }

    #[test]
    fn resolve_base_root_falls_back_to_current_directory_without_manifest() {
        let temp_dir = TempDir::new().expect("temp dir");
        let nested = temp_dir.path().join("games/windows_tetris");
        fs::create_dir_all(&nested).expect("create nested dirs");

        assert_eq!(resolve_base_root(&nested), nested.join("ges"));
    }
}