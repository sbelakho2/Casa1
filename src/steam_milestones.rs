//! Steam run instrumentation: provenance, milestones, first-failure recording.
//!
//! Pure instrumentation for Steam.exe bootstrap runs.  Nothing in this module
//! changes emulation behavior: it only records what happened, for the
//! `<short-sha>-steam-bootstrap.{json,log}` run artifacts written by the
//! runner.  All counters live in a process-wide static so the Win32 file layer
//! (which has no access to the PE runtime) can record milestones without
//! plumbing.  The PE runtime snapshots the static at the end of a run and
//! carries it in `PeExecutionResult`.
//!
//! The `*_in` functions below operate on a `&mut SteamMilestones` and are
//! pure (no statics); the static wrappers apply them to `MILESTONES`.  Tests
//! exercise the `*_in` variants on local values so they stay deterministic
//! and parallel-safe.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Process-wide statics
// ---------------------------------------------------------------------------

/// Shared milestone state.  The Win32 file layer, CEF bridge, Metal backend
/// and PE runtime all update this static; the PE runtime snapshots it at the
/// end of a run.
pub static MILESTONES: LazyLock<Mutex<SteamMilestones>> =
    LazyLock::new(|| Mutex::new(SteamMilestones::default()));

/// DXGI `Present` calls observed by the DXGI Present thunk.
pub static DXGI_PRESENTS: AtomicU64 = AtomicU64::new(0);

/// CEF software paints (`CefRenderHandler::OnPaint`).
pub static CEF_SOFTWARE_PAINTS: AtomicU64 = AtomicU64::new(0);

/// CEF accelerated paints (`CefRenderHandler::OnAcceleratedPaint`).
pub static CEF_ACCELERATED_PAINTS: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// First-failure recording
// ---------------------------------------------------------------------------

/// One first-failure record per subsystem; only the FIRST failure per
/// category is kept.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FirstFailure {
    /// Guest program counter at the failure site (`0` when host-side).
    pub guest_pc: u32,
    /// Guest thread id at the failure site (`0` when host-side).
    pub thread_id: u32,
    /// API name, e.g. `CreateFileW` / `connect`.
    pub api: Option<String>,
    /// Guest-visible error code (GetLastError / WSAGetLastError / errno).
    pub guest_error: Option<u32>,
    /// The Windows path involved (file failures), when known.
    pub windows_path: Option<String>,
    /// Compact JSON of the failing call's parameters (CreateFileW's
    /// path/desired_access/share_mode/disposition/...), when known.
    pub params: Option<String>,
    /// Short human-readable detail string.
    pub detail: String,
}

/// Subsystem categories that keep an independent first-failure record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCategory {
    Fs,
    Crt,
    Thread,
    Network,
    Cef,
    Gfx,
}

impl FailureCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Crt => "crt",
            Self::Thread => "thread",
            Self::Network => "network",
            Self::Cef => "cef",
            Self::Gfx => "gfx",
        }
    }
}

/// First-failure slots, one per subsystem category.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FirstFailureGroup {
    pub fs: Option<FirstFailure>,
    pub crt: Option<FirstFailure>,
    pub thread: Option<FirstFailure>,
    pub network: Option<FirstFailure>,
    pub cef: Option<FirstFailure>,
    pub gfx: Option<FirstFailure>,
}

/// Record `failure` into `slot` only when the category slot is still empty.
///
/// Pure: callers may apply it to a local struct or to the shared static.
#[allow(clippy::too_many_arguments)]
pub fn record_first_failure_in(
    milestones: &mut SteamMilestones,
    category: FailureCategory,
    guest_pc: u32,
    thread_id: u32,
    api: Option<String>,
    guest_error: Option<u32>,
    detail: String,
    path_value: Option<String>,
    params: Option<String>,
) -> bool {
    let slot = match category {
        FailureCategory::Fs => &mut milestones.first_failures.fs,
        FailureCategory::Crt => &mut milestones.first_failures.crt,
        FailureCategory::Thread => &mut milestones.first_failures.thread,
        FailureCategory::Network => &mut milestones.first_failures.network,
        FailureCategory::Cef => &mut milestones.first_failures.cef,
        FailureCategory::Gfx => &mut milestones.first_failures.gfx,
    };
    if slot.is_some() {
        return false;
    }
    *slot = Some(FirstFailure {
        guest_pc,
        thread_id,
        api,
        guest_error,
        detail,
        windows_path: path_value,
        params,
    });
    true
}

/// Record the first failure for `category` into the shared static.
#[allow(clippy::too_many_arguments)]
pub fn record_first_failure(
    category: FailureCategory,
    guest_pc: u32,
    thread_id: u32,
    api: Option<String>,
    guest_error: Option<u32>,
    detail: String,
    path_value: Option<String>,
    params: Option<String>,
) -> bool {
    with_milestones(|milestones| {
        record_first_failure_in(
            milestones,
            category,
            guest_pc,
            thread_id,
            api,
            guest_error,
            detail,
            path_value,
            params,
        )
    })
    .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Milestone groups
// ---------------------------------------------------------------------------

/// Steam bootstrap milestones (steam group).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SteamMilestoneGroup {
    /// Set at the first block dispatch of the PE main loop.
    pub bootstrap_started: bool,
    /// A file open of the manifest (`...\package\steam_client_win32.installed`).
    pub manifest_opened: bool,
    /// Approximation: the manifest was opened AND at least one full read of
    /// the manifest file completed.
    pub manifest_verified: bool,
    /// An open-for-write of `C:\package` or a `C:\*.crash` path.
    pub package_writability_probe: bool,
    /// First `CreateThread` from the initial synthetic process after
    /// bootstrap started.
    pub client_main_started: bool,
    /// `CreateProcess` calls whose application/command line contains
    /// `steamwebhelper` (case-insensitive).
    pub webhelper_processes: u32,
    /// A CEF browser has been created (set on the first successful paint).
    pub cef_browser_created: bool,
    /// The first CEF paint (software or accelerated) was observed.
    pub cef_first_paint: bool,
    /// `CefRenderHandler::OnPaint` calls.
    pub cef_software_paints: u32,
    /// `CefRenderHandler::OnAcceleratedPaint` calls.
    pub cef_accelerated_paints: u32,
}

/// Graphics frame counters (graphics group).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GraphicsMilestoneGroup {
    /// GfxFrames whose metadata source maps to a host placeholder.
    pub host_placeholder_frames: u32,
    /// GfxFrames whose metadata source maps to GDI.
    pub gdi_frames: u32,
    /// GfxFrames whose metadata source maps to CEF software rendering.
    pub cef_software_frames: u32,
    /// GfxFrames whose metadata source maps to CEF accelerated rendering.
    pub cef_accelerated_frames: u32,
    /// DXGI `Present` thunk calls (atomic counter folded in at snapshot).
    pub dxgi_presents: u32,
    /// Metal `present_drawable` calls (atomic counter folded in at snapshot).
    pub metal_presented_frames: u32,
}

/// Guest thread lifecycle counters (threads group).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ThreadMilestoneGroup {
    /// Guest-visible thread creations (`CreateThread` / `_beginthread`).
    pub created: u32,
    /// Clean exits: `ExitThread` / `_endthreadex` / `_endthread` / thread
    /// procedure return.
    pub normal_exits: u32,
    /// `TerminateThread` calls.
    pub terminated: u32,
    /// Host-side refusal to run a guest thread (should be 0 on Steam x86).
    pub illegal_host_terminations: u32,
    /// `created - normal_exits - terminated`, computed at end of run.
    pub live_at_process_exit: u32,
}

/// Full milestone set carried in `PeExecutionResult` and written to the
/// steam-bootstrap artifact.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SteamMilestones {
    pub steam: SteamMilestoneGroup,
    pub graphics: GraphicsMilestoneGroup,
    pub threads: ThreadMilestoneGroup,
    pub first_failures: FirstFailureGroup,
}

// ---------------------------------------------------------------------------
// Pure milestone transitions
// ---------------------------------------------------------------------------

/// Case-insensitive manifest-path test: the normalized path contains
/// `package` and ends with `steam_client_win32.installed`.
pub fn is_manifest_path(normalized_path: &str) -> bool {
    let lower = normalized_path.to_ascii_lowercase();
    lower.contains("package") && lower.ends_with("steam_client_win32.installed")
}

/// The Steam package-writability probe paths: `C:\package` itself or any
/// `C:\*.crash` file, tolerating the `\\?\` extended-length prefix.
pub fn is_package_writability_probe_path(normalized_path: &str) -> bool {
    let stripped = normalized_path.trim_start_matches("\\\\?\\");
    let lower = stripped.to_ascii_lowercase();
    lower == "c:\\package" || (lower.starts_with("c:\\") && lower.ends_with(".crash"))
}

/// Record a successful manifest open into `milestones`.
pub fn note_manifest_path_in(milestones: &mut SteamMilestones, normalized_path: &str) {
    if is_manifest_path(normalized_path) {
        milestones.steam.manifest_opened = true;
    }
}

/// Record a successful full read of the manifest into `milestones`; the read
/// proves the manifest was opened, so both flags are set.
pub fn note_manifest_read_in(milestones: &mut SteamMilestones, normalized_path: &str) {
    if is_manifest_path(normalized_path) {
        milestones.steam.manifest_opened = true;
        milestones.steam.manifest_verified = true;
    }
}

/// Record a package-writability probe into `milestones` when a write access
/// was requested for a probe path.
pub fn note_package_writability_probe_in(
    milestones: &mut SteamMilestones,
    normalized_path: &str,
    write_requested: bool,
) {
    if write_requested && is_package_writability_probe_path(normalized_path) {
        milestones.steam.package_writability_probe = true;
    }
}

/// Record the first block dispatch (bootstrap started).
pub fn note_bootstrap_started_in(milestones: &mut SteamMilestones) {
    milestones.steam.bootstrap_started = true;
}

/// Record a guest thread creation.  `is_initial_process` marks a
/// `CreateThread` issued by the initial synthetic main process (main thread);
/// the first such call after bootstrap sets `client_main_started`.
pub fn note_thread_created_in(milestones: &mut SteamMilestones, is_initial_process: bool) {
    milestones.threads.created = milestones.threads.created.saturating_add(1);
    if is_initial_process
        && milestones.steam.bootstrap_started
        && !milestones.steam.client_main_started
    {
        milestones.steam.client_main_started = true;
    }
}

/// Record a clean thread exit (`ExitThread` / `_endthreadex` / `_endthread` /
/// thread procedure return).
pub fn note_thread_normal_exit_in(milestones: &mut SteamMilestones) {
    milestones.threads.normal_exits = milestones.threads.normal_exits.saturating_add(1);
}

/// Record a `TerminateThread` call.
pub fn note_thread_terminated_in(milestones: &mut SteamMilestones) {
    milestones.threads.terminated = milestones.threads.terminated.saturating_add(1);
}

/// Record a host-side refusal to run a guest thread.
pub fn note_illegal_host_termination_in(milestones: &mut SteamMilestones) {
    milestones.threads.illegal_host_terminations = milestones
        .threads
        .illegal_host_terminations
        .saturating_add(1);
}

/// Record a `CreateProcess` whose application/command line names
/// `steamwebhelper` (case-insensitive).
pub fn note_webhelper_process_in(milestones: &mut SteamMilestones) {
    milestones.steam.webhelper_processes = milestones.steam.webhelper_processes.saturating_add(1);
}

/// Pure test of whether a CreateProcess application/command line targets
/// `steamwebhelper`.
pub fn command_line_is_webhelper(application: &str, command_line: &str) -> bool {
    format!("{application} {command_line}")
        .to_ascii_lowercase()
        .contains("steamwebhelper")
}

/// Count a GfxFrame push whose metadata carries its source.
pub fn note_gfx_frame_in(milestones: &mut SteamMilestones, metadata: &BTreeMap<String, String>) {
    match frame_category_for_metadata(metadata) {
        FrameCategory::HostPlaceholder => {
            milestones.graphics.host_placeholder_frames = milestones
                .graphics
                .host_placeholder_frames
                .saturating_add(1);
        }
        FrameCategory::Gdi => {
            milestones.graphics.gdi_frames = milestones.graphics.gdi_frames.saturating_add(1);
        }
        FrameCategory::CefSoftware => {
            milestones.graphics.cef_software_frames =
                milestones.graphics.cef_software_frames.saturating_add(1);
        }
        FrameCategory::CefAccelerated => {
            milestones.graphics.cef_accelerated_frames =
                milestones.graphics.cef_accelerated_frames.saturating_add(1);
        }
        FrameCategory::Other => {}
    }
}

/// Count a CEF paint (software or accelerated) and set the browser-created /
/// first-paint flags (a paint proves a browser existed).
pub fn note_cef_paint_in(milestones: &mut SteamMilestones, accelerated: bool) {
    if accelerated {
        milestones.steam.cef_accelerated_paints =
            milestones.steam.cef_accelerated_paints.saturating_add(1);
    } else {
        milestones.steam.cef_software_paints =
            milestones.steam.cef_software_paints.saturating_add(1);
    }
    milestones.steam.cef_first_paint = true;
    milestones.steam.cef_browser_created = true;
}

/// Frame categories counted from GfxFrame metadata sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameCategory {
    HostPlaceholder,
    Gdi,
    CefSoftware,
    CefAccelerated,
    /// DXGI/Vulkan/OpenGL presents — not counted by category (they are
    /// tracked by the `dxgi_presents` / `metal_presented_frames` counters).
    Other,
}

/// Map a metadata `source` value to its frame category.
pub fn frame_category_for_source(source: &str) -> FrameCategory {
    match source.to_ascii_lowercase().as_str() {
        "host_placeholder" | "placeholder" | "host-placeholder" => FrameCategory::HostPlaceholder,
        "gdi" | "gdi32" => FrameCategory::Gdi,
        "cef_software" | "cef-software" | "cef" | "cef_sw" => FrameCategory::CefSoftware,
        "cef_accelerated" | "cef-accelerated" | "cef_gpu" => FrameCategory::CefAccelerated,
        _ => FrameCategory::Other,
    }
}

/// Map a GfxFrame metadata map to its frame category via the `source` key.
pub fn frame_category_for_metadata(metadata: &BTreeMap<String, String>) -> FrameCategory {
    metadata
        .get("source")
        .map(String::as_str)
        .map(frame_category_for_source)
        .unwrap_or(FrameCategory::Other)
}

// ---------------------------------------------------------------------------
// Static wrappers
// ---------------------------------------------------------------------------

fn with_milestones<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut SteamMilestones) -> R,
{
    MILESTONES
        .lock()
        .ok()
        .map(|mut milestones| f(&mut milestones))
}

pub fn snapshot_milestones() -> SteamMilestones {
    let mut milestones = MILESTONES.lock().map(|m| m.clone()).unwrap_or_default();
    milestones.graphics.dxgi_presents = DXGI_PRESENTS.load(Ordering::Relaxed) as u32;
    milestones.graphics.metal_presented_frames =
        crate::metal_backend::METAL_PRESENTED_FRAMES.load(Ordering::Relaxed) as u32;
    milestones.steam.cef_software_paints = CEF_SOFTWARE_PAINTS.load(Ordering::Relaxed) as u32;
    milestones.steam.cef_accelerated_paints = CEF_ACCELERATED_PAINTS.load(Ordering::Relaxed) as u32;
    milestones.threads.live_at_process_exit = milestones
        .threads
        .created
        .saturating_sub(milestones.threads.normal_exits)
        .saturating_sub(milestones.threads.terminated);
    milestones
}

/// Reset the shared static (tests and between jobs in a long-lived process).
pub fn reset_milestones() {
    if let Ok(mut milestones) = MILESTONES.lock() {
        *milestones = SteamMilestones::default();
    }
    DXGI_PRESENTS.store(0, Ordering::Relaxed);
    CEF_SOFTWARE_PAINTS.store(0, Ordering::Relaxed);
    CEF_ACCELERATED_PAINTS.store(0, Ordering::Relaxed);
    crate::metal_backend::METAL_PRESENTED_FRAMES.store(0, Ordering::Relaxed);
}

pub fn note_manifest_path(normalized_path: &str) {
    with_milestones(|milestones| note_manifest_path_in(milestones, normalized_path));
}

pub fn note_manifest_read(normalized_path: &str) {
    with_milestones(|milestones| note_manifest_read_in(milestones, normalized_path));
}

pub fn note_package_writability_probe(normalized_path: &str, write_requested: bool) {
    with_milestones(|milestones| {
        note_package_writability_probe_in(milestones, normalized_path, write_requested);
    });
}

pub fn note_bootstrap_started() {
    with_milestones(note_bootstrap_started_in);
}

pub fn note_thread_created(is_initial_process: bool) {
    with_milestones(|milestones| note_thread_created_in(milestones, is_initial_process));
}

pub fn note_thread_normal_exit() {
    with_milestones(note_thread_normal_exit_in);
}

pub fn note_thread_terminated() {
    with_milestones(note_thread_terminated_in);
}

pub fn note_illegal_host_termination() {
    with_milestones(note_illegal_host_termination_in);
}

pub fn note_webhelper_process(application: &str, command_line: &str) {
    if command_line_is_webhelper(application, command_line) {
        with_milestones(note_webhelper_process_in);
    }
}

pub fn note_gfx_frame(metadata: &BTreeMap<String, String>) {
    with_milestones(|milestones| note_gfx_frame_in(milestones, metadata));
}

/// Count one DXGI `Present` (atomic; folded into the snapshot).
pub fn note_dxgi_present() {
    DXGI_PRESENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn note_cef_paint(accelerated: bool) {
    if accelerated {
        CEF_ACCELERATED_PAINTS.fetch_add(1, Ordering::Relaxed);
    } else {
        CEF_SOFTWARE_PAINTS.fetch_add(1, Ordering::Relaxed);
    }
    with_milestones(|milestones| note_cef_paint_in(milestones, accelerated));
}

// ---------------------------------------------------------------------------
// Run provenance
// ---------------------------------------------------------------------------

/// Self-identifying run header written into the steam-bootstrap artifact.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RunProvenance {
    /// `CASA1_COMMIT_SHA` build-time env (`git rev-parse HEAD`, `unknown`
    /// when git is unavailable).
    pub commit_sha: String,
    /// `CASA1_DIRTY` build-time env: any uncommitted change at build time.
    pub dirty_tree: bool,
    /// SHA-256 over the sorted GE root files (relative path + size +
    /// per-file hash).
    pub fixture_hash: String,
    /// SHA-256 of the GE config (`<ge_root>/ge.json`).
    pub ge_hash: String,
    /// SHA-256 of the Steam executable run by the job.
    pub steam_executable_hash: String,
    /// RFC 3339 UTC timestamp of artifact collection.
    pub timestamp_utc_rfc3339: String,
    /// Host OS (`std::env::consts::OS`).
    pub host_os: String,
    /// Host architecture (`std::env::consts::ARCH`).
    pub host_arch: String,
}

impl RunProvenance {
    /// Env-only fields: commit sha, dirty tree, host identity, timestamp.
    /// Hash fields stay empty (no filesystem access).  Cheap enough for the
    /// PE runtime to attach to every result.
    pub fn from_env() -> Self {
        Self {
            commit_sha: option_env!("CASA1_COMMIT_SHA")
                .unwrap_or("unknown")
                .to_string(),
            dirty_tree: option_env!("CASA1_DIRTY").unwrap_or("true") == "true",
            timestamp_utc_rfc3339: utc_rfc3339_now(),
            host_os: std::env::consts::OS.to_string(),
            host_arch: std::env::consts::ARCH.to_string(),
            ..Self::default()
        }
    }

    /// Full provenance: env fields plus the fixture / GE / Steam executable
    /// content hashes.  Computed by the runner for Steam.exe jobs.
    pub fn collect(ge_root: &Path, steam_executable: &Path) -> Self {
        let mut provenance = Self::from_env();
        provenance.fixture_hash = dir_content_hash(ge_root);
        provenance.ge_hash = file_content_hash(&ge_root.join("ge.json"));
        provenance.steam_executable_hash = file_content_hash(steam_executable);
        provenance
    }
}

/// RFC 3339 UTC timestamp of the current instant.
pub fn utc_rfc3339_now() -> String {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::gmtime_r(&now, &mut tm);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}

/// SHA-256 hex of a file's contents; `"unavailable"` when the file cannot be
/// read (an honest marker, never a fabricated hash).
pub fn file_content_hash(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let Ok(bytes) = std::fs::read(path) else {
        return "unavailable".to_string();
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

/// SHA-256 over the sorted regular files under `root`: for each file, hash
/// `relative_path \0 file_size \0 sha256(file contents)`, then hash the
/// concatenation.  Deterministic and independent of host path details.
pub fn dir_content_hash(root: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut entries: Vec<(String, u64, String)> = Vec::new();
    if !root.exists() {
        return "unavailable".to_string();
    }
    for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(root) else {
            continue;
        };
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let hash = file_content_hash(entry.path());
        entries.push((
            relative.to_string_lossy().into_owned(),
            metadata.len(),
            hash,
        ));
    }
    entries.sort();
    let mut hasher = Sha256::new();
    for (relative, size, hash) in entries {
        hasher.update(relative.as_bytes());
        hasher.update([0_u8]);
        hasher.update(size.to_le_bytes());
        hasher.update(hash.as_bytes());
        hasher.update([0_u8]);
    }
    hex::encode(hasher.finalize())
}

/// Best-effort numeric id for the calling host thread (used by host-side
/// first-failure records that have no guest context).
pub fn host_thread_id() -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    hasher.finish() as u32
}
