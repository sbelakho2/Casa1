//! Host CLR (.NET) metadata.
//!
//! Casa1 runs managed images on the host-installed CoreCLR (`dotnet exec`),
//! so the CLR metadata surface must describe what is *really installed on the
//! host*: the versioned directories under
//! `<dotnet-root>/shared/Microsoft.NETCore.App`, their real version strings,
//! and the real PE CLI metadata of managed assemblies.
//!
//! This module is deliberately host-pure: it reads the filesystem and PE
//! images, never guesses a version, and never spawns `dotnet`.  The guest COM
//! model built on top of it lives in `runtime::dispatch::mscoree`.
//!
//! .NET Framework CLR directories (`Microsoft.NET\\Framework*`) are not
//! enumerated: the host genuinely has no Framework CLR, and conflating the
//! CoreCLR shared framework with the Framework contract would make
//! `CorBindToRuntime*` lie (see `mscoree.rs`).

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::pe::{self, DataDirectory};

/// `CLR_E_SHIM_RUNTIMELOAD` — the shim could not load a CLR for the file or
/// runtime contract requested (used for files without CLI metadata).
pub(crate) const CLR_E_SHIM_RUNTIMELOAD: u32 = 0x8013_1700;
/// `CLR_E_SHIM_RUNTIMENOTFOUND` — the requested runtime version is not
/// installed.  This is the real shim failure for an absent runtime.
pub(crate) const CLR_E_SHIM_RUNTIMENOTFOUND: u32 = 0x8013_1701;
/// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`.
pub(crate) const HRESULT_FILE_NOT_FOUND: u32 = 0x8007_0002;
/// `HRESULT_FROM_WIN32(ERROR_BAD_FORMAT)`.
pub(crate) const HRESULT_BAD_FORMAT: u32 = 0x8007_000B;
/// `HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND)`.
pub(crate) const HRESULT_MOD_NOT_FOUND: u32 = 0x8007_007E;
/// `HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND)`.
pub(crate) const HRESULT_PROC_NOT_FOUND: u32 = 0x8007_007F;
/// `HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)`.
pub(crate) const HRESULT_INSUFFICIENT_BUFFER: u32 = 0x8007_007A;
/// `HRESULT_FROM_WIN32(ERROR_GEN_FAILURE)`.
pub(crate) const HRESULT_GEN_FAILURE: u32 = 0x8007_001F;

/// The CLI metadata signature (`BSJB`).
pub(crate) const METADATA_SIGNATURE: u32 = 0x424A_5342;

/// A parsed runtime version.
///
/// Real versions are dotted decimal with two to four components (`8.0.31`,
/// `4.0.30319`, `10.0.4`).  Parsing rejects everything else so a malformed
/// guest request can never be silently rounded to an installed runtime.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ClrVersion {
    components: Vec<u16>,
}

impl ClrVersion {
    /// Parse a guest-facing version string.  A single leading `v`/`V` is the
    /// documented CLR form (`v4.0.30319`); whitespace and signs are rejected.
    pub(crate) fn parse_request(input: &str) -> Option<Self> {
        let body = match input.strip_prefix('v').or_else(|| input.strip_prefix('V')) {
            Some(body) => body,
            None => input,
        };
        Self::parse_components(body)
    }

    /// Parse a runtime directory name.  Directory names are bare versions and
    /// must not carry the `v` prefix.
    pub(crate) fn parse_directory_name(input: &str) -> Option<Self> {
        if input.starts_with('v') || input.starts_with('V') {
            return None;
        }
        Self::parse_components(input)
    }

    fn parse_components(body: &str) -> Option<Self> {
        if body.is_empty() || body.trim() != body {
            return None;
        }
        let parts: Vec<&str> = body.split('.').collect();
        if !(2..=4).contains(&parts.len()) {
            return None;
        }
        let mut components = Vec::with_capacity(parts.len());
        for part in parts {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            if part.len() > 1 && part.starts_with('0') {
                return None;
            }
            components.push(part.parse::<u16>().ok()?);
        }
        Some(Self { components })
    }

    /// Number of dotted components.
    pub(crate) fn component_count(&self) -> usize {
        self.components.len()
    }

    /// The canonical dotted form (`8.0.31`).
    pub(crate) fn as_string(&self) -> String {
        self.components
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }

    fn starts_with(&self, prefix: &[u16]) -> bool {
        self.components.len() >= prefix.len() && self.components[..prefix.len()] == *prefix
    }
}

/// One real installed CoreCLR shared framework.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClrRuntime {
    /// The runtime version taken from the real directory name.
    pub(crate) version: ClrVersion,
    /// The real runtime directory (absolute, canonical where possible).
    pub(crate) directory: PathBuf,
}

impl ClrRuntime {
    pub(crate) fn version_string(&self) -> String {
        self.version.as_string()
    }

    /// The CoreCLR library inside this runtime directory, if present.
    pub(crate) fn coreclr_library(&self) -> Option<PathBuf> {
        for name in ["libcoreclr.dylib", "coreclr.dll", "libcoreclr.so"] {
            let candidate = self.directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }

    /// The hostfxr library inside this runtime directory, if present.
    pub(crate) fn hostfxr_library(&self) -> Option<PathBuf> {
        for name in ["libhostfxr.dylib", "hostfxr.dll", "libhostfxr.so"] {
            let candidate = self.directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}

/// The roots the host `dotnet` install can live in.  `DOTNET_ROOT` wins, then
/// the machine-wide location, then Homebrew (opt symlinks and Cellar kegs),
/// then the per-user install.  Only roots that exist are returned.
pub(crate) fn dotnet_roots() -> Vec<PathBuf> {
    dotnet_roots_from(
        std::env::var_os("DOTNET_ROOT").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

/// The pure root-discovery rule, with the two environment inputs injected so
/// the precedence rule is testable without mutating the process environment.
pub(crate) fn dotnet_roots_from(
    dotnet_root: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut push = |candidate: PathBuf| {
        if candidate.is_dir() {
            let canonical = candidate.canonicalize().unwrap_or(candidate);
            if !roots.contains(&canonical) {
                roots.push(canonical);
            }
        }
    };

    if let Some(root) = dotnet_root {
        push(root);
    }
    push(PathBuf::from("/usr/local/share/dotnet"));
    push(PathBuf::from("/opt/homebrew/opt/dotnet/libexec"));
    push(PathBuf::from("/opt/homebrew/opt/dotnet@8/libexec"));
    push(PathBuf::from("/usr/local/share/dotnet/x64"));
    if let Some(home) = home {
        push(home.join(".dotnet"));
    }

    // Versioned Homebrew formulae (`dotnet@8`, `dotnet@9`, ...) and Cellar
    // kegs.  These are the real installation layouts on macOS.
    for base in ["/opt/homebrew/opt", "/usr/local/opt"] {
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("dotnet@") {
                    push(entry.path().join("libexec"));
                }
            }
        }
    }
    for base in ["/opt/homebrew/Cellar", "/usr/local/Cellar"] {
        if let Ok(formulae) = std::fs::read_dir(base) {
            for formula in formulae.flatten() {
                let formula_name = formula.file_name();
                let formula_name = formula_name.to_string_lossy();
                if formula_name.starts_with("dotnet") {
                    for keg in std::fs::read_dir(formula.path())
                        .into_iter()
                        .flatten()
                        .flatten()
                    {
                        push(keg.path().join("libexec"));
                    }
                }
            }
        }
    }

    roots
}

/// Enumerate the real CoreCLR shared frameworks under one `dotnet` root.
/// Layout: `<root>/shared/Microsoft.NETCore.App/<version>/`.
pub(crate) fn runtimes_under_root(root: &Path) -> Vec<ClrRuntime> {
    let shared = root.join("shared").join("Microsoft.NETCore.App");
    let Ok(entries) = std::fs::read_dir(&shared) else {
        return Vec::new();
    };
    let mut runtimes = Vec::new();
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(version) = ClrVersion::parse_directory_name(&name) else {
            continue;
        };
        let directory = entry.path();
        let runtime = ClrRuntime { version, directory };
        // A shared-framework directory without the CLR library is not a
        // usable runtime; it must not be advertised to the guest.
        if runtime.coreclr_library().is_none() {
            continue;
        }
        runtimes.push(runtime);
    }
    runtimes.sort();
    runtimes
}

/// Enumerate every real installed CoreCLR shared framework on this host,
/// highest version first, with duplicates (Homebrew opt/Cellar symlinks)
/// collapsed by canonical directory.
pub(crate) fn installed_runtimes() -> Vec<ClrRuntime> {
    let mut seen = BTreeSet::new();
    let mut runtimes = Vec::new();
    for root in dotnet_roots() {
        for runtime in runtimes_under_root(&root) {
            let canonical = runtime
                .directory
                .canonicalize()
                .unwrap_or_else(|_| runtime.directory.clone());
            if seen.insert(canonical.clone()) {
                runtimes.push(ClrRuntime {
                    version: runtime.version,
                    directory: canonical,
                });
            }
        }
    }
    runtimes.sort_by(|left, right| right.version.cmp(&left.version));
    runtimes
}

/// Select the installed runtime that satisfies a guest version request.
///
/// `v8.0` selects the highest installed `8.0.x`; a fully specified request
/// (`8.0.31`) requires an exact version.  A request with more components than
/// any installed version never matches.
pub(crate) fn select_runtime<'a>(
    requested: &ClrVersion,
    runtimes: &'a [ClrRuntime],
) -> Option<&'a ClrRuntime> {
    runtimes
        .iter()
        .filter(|runtime| {
            if requested.component_count() >= runtime.version.component_count() {
                runtime.version == *requested
            } else {
                runtime.version.starts_with(&requested.components)
            }
        })
        .max_by(|left, right| left.version.cmp(&right.version))
}

/// Errors from reading a guest file's CLI metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClrMetaError {
    /// The file could not be read (already mapped to a Win32 HRESULT).
    Io(u32),
    /// The file is not a valid PE image.
    InvalidPe,
    /// The PE image carries no CLI metadata.
    NotManaged,
    /// The CLI metadata root is truncated or corrupt.
    InvalidMetadata,
}

impl ClrMetaError {
    pub(crate) fn hresult(self) -> u32 {
        match self {
            Self::Io(hresult) => hresult,
            Self::InvalidPe | Self::InvalidMetadata => HRESULT_BAD_FORMAT,
            Self::NotManaged => CLR_E_SHIM_RUNTIMELOAD,
        }
    }
}

fn io_hresult(error: &std::io::Error) -> u32 {
    if error.kind() == std::io::ErrorKind::NotFound {
        HRESULT_FILE_NOT_FOUND
    } else {
        HRESULT_GEN_FAILURE
    }
}

/// Parse the CLI metadata root and return its runtime version string.
///
/// Layout (ECMA-335 II.24.2.1): signature `BSJB`, major/minor, reserved,
/// length-prefixed UTF-8 version string (NUL-terminated).
pub(crate) fn metadata_version_from_root(root: &[u8]) -> Result<String, ClrMetaError> {
    if root.len() < 16 {
        return Err(ClrMetaError::InvalidMetadata);
    }
    let signature = u32::from_le_bytes([root[0], root[1], root[2], root[3]]);
    if signature != METADATA_SIGNATURE {
        return Err(ClrMetaError::InvalidMetadata);
    }
    let length = u32::from_le_bytes([root[12], root[13], root[14], root[15]]) as usize;
    if length == 0 || length > 4096 || 16 + length > root.len() {
        return Err(ClrMetaError::InvalidMetadata);
    }
    let raw = &root[16..16 + length];
    let nul = raw
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ClrMetaError::InvalidMetadata)?;
    let text = std::str::from_utf8(&raw[..nul]).map_err(|_| ClrMetaError::InvalidMetadata)?;
    if text.is_empty() {
        return Err(ClrMetaError::InvalidMetadata);
    }
    Ok(text.to_string())
}

/// Map an RVA to a file offset using the real section table.
fn rva_to_file_offset(bytes: &[u8], sections: &[pe::PeSection], rva: u32) -> Option<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_data_size);
        let end = section.virtual_address.saturating_add(span);
        if rva >= section.virtual_address && rva < end {
            let delta = rva - section.virtual_address;
            let offset = section.raw_data_ptr as usize + delta as usize;
            if offset < bytes.len() {
                return Some(offset);
            }
        }
    }
    None
}

fn version_from_parsed(bytes: &[u8], parsed: &pe::ParsedPe) -> Result<String, ClrMetaError> {
    let header = parsed.clr_header.as_ref().ok_or(ClrMetaError::NotManaged)?;
    let metadata: DataDirectory = header.metadata;
    let offset = rva_to_file_offset(bytes, &parsed.sections, metadata.virtual_address)
        .ok_or(ClrMetaError::InvalidMetadata)?;
    let size = (metadata.size as usize).min(bytes.len().saturating_sub(offset));
    metadata_version_from_root(&bytes[offset..offset + size])
}

/// Read the real PE CLI metadata runtime version of a file.
pub(crate) fn version_from_file(path: &Path) -> Result<String, ClrMetaError> {
    let bytes = std::fs::read(path).map_err(|error| ClrMetaError::Io(io_hresult(&error)))?;
    let parsed = pe::parse(&bytes).map_err(|_| ClrMetaError::InvalidPe)?;
    if !parsed.is_dotnet {
        return Err(ClrMetaError::NotManaged);
    }
    version_from_parsed(&bytes, &parsed)
}

/// Whether `symbol` is exported by the runtime directory's CoreCLR or hostfxr
/// dylib.  The library is loaded from the real runtime directory for the
/// check and unloaded again; GetProcAddress hands the guest a thunk that
/// re-resolves the symbol when called.
pub(crate) fn native_export_available(runtime: &ClrRuntime, symbol: &str) -> bool {
    if symbol.is_empty() {
        return false;
    }
    let mut libraries = Vec::new();
    if let Some(library) = runtime.coreclr_library() {
        libraries.push(library);
    }
    if let Some(library) = runtime.hostfxr_library() {
        libraries.push(library);
    }
    for library in libraries {
        // SAFETY: loading a shared library runs its initializers.  These are
        // the host's own signed CoreCLR libraries, already used by `dotnet
        // exec`, and the handle is dropped before returning.
        let Ok(library) = (unsafe { libloading::Library::new(&library) }) else {
            continue;
        };
        // SAFETY: the symbol type is only used to test presence; it is never
        // called here.
        let found = unsafe { library.get::<*mut c_void>(symbol.as_bytes()) }.is_ok();
        if found {
            return true;
        }
    }
    false
}

// ── Guest COM object table ────────────────────────────────────────────────
//
// The mscoree COM objects live in guest memory, but their host state is kept
// here: the runtime (`PeHostRuntime`) does not own a CLR field yet, so the
// table is process-global and keyed by the guest pid, which is unique per
// runtime instance.  All access goes through one mutex, so concurrent guest
// threads (and concurrent test enumerations) observe atomic refcounts.

/// The kind of enumerator behind an `IEnumUnknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClrEnumKind {
    Installed,
    Loaded,
}

/// A guest COM object's host-side state.
#[derive(Debug, Clone)]
pub(crate) enum ClrObject {
    MetaHost {
        refcount: u32,
    },
    RuntimeInfo {
        refcount: u32,
        runtime: ClrRuntime,
        load_error: u32,
    },
    Enumerator {
        refcount: u32,
        kind: ClrEnumKind,
        runtimes: Vec<ClrRuntime>,
        cursor: usize,
    },
}

impl ClrObject {
    #[allow(dead_code)] // pinned refcount assertions in the adversarial tests
    pub(crate) fn refcount(&self) -> u32 {
        match self {
            Self::MetaHost { refcount }
            | Self::RuntimeInfo { refcount, .. }
            | Self::Enumerator { refcount, .. } => *refcount,
        }
    }

    fn set_refcount(&mut self, value: u32) {
        match self {
            Self::MetaHost { refcount }
            | Self::RuntimeInfo { refcount, .. }
            | Self::Enumerator { refcount, .. } => *refcount = value,
        }
    }
}

/// One runtime-load notification callback and its thread pin/unpin state.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // read by the loaded-runtime callback path and its tests
pub(crate) struct ClrLoadedCallback {
    pub(crate) callback: u64,
    pub(crate) thread_pinned: bool,
}

#[derive(Debug, Default)]
struct ClrObjectTable {
    objects: std::collections::HashMap<(u32, u64), ClrObject>,
    callbacks: std::collections::HashMap<u32, ClrLoadedCallback>,
    loaded: std::collections::HashMap<u32, BTreeSet<String>>,
}

/// Process-global CLR COM state.
#[derive(Debug, Default)]
pub(crate) struct ClrHostObjects {
    table: Mutex<ClrObjectTable>,
}

impl ClrHostObjects {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn insert_meta_host(&self, pid: u32, address: u64) {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        table
            .objects
            .insert((pid, address), ClrObject::MetaHost { refcount: 1 });
    }

    pub(crate) fn insert_runtime_info(&self, pid: u32, address: u64, runtime: ClrRuntime) {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        table.objects.insert(
            (pid, address),
            ClrObject::RuntimeInfo {
                refcount: 1,
                runtime,
                load_error: 0,
            },
        );
    }

    pub(crate) fn insert_enumerator(
        &self,
        pid: u32,
        address: u64,
        kind: ClrEnumKind,
        runtimes: Vec<ClrRuntime>,
        cursor: usize,
    ) {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        table.objects.insert(
            (pid, address),
            ClrObject::Enumerator {
                refcount: 1,
                kind,
                runtimes,
                cursor,
            },
        );
    }

    /// Add one reference.  Returns the new count, or `None` for an unknown
    /// object (the guest passed a pointer that is not a CLR object).
    pub(crate) fn add_ref(&self, pid: u32, address: u64) -> Option<u32> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let object = table.objects.get_mut(&(pid, address))?;
        let next = object.refcount().saturating_add(1);
        object.set_refcount(next);
        Some(next)
    }

    /// Release one reference.  Returns the new count (`Some(0)` when the
    /// object was destroyed), or `None` for an unknown object.
    pub(crate) fn release(&self, pid: u32, address: u64) -> Option<u32> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let object = table.objects.get_mut(&(pid, address))?;
        let next = object.refcount().saturating_sub(1);
        if next == 0 {
            table.objects.remove(&(pid, address));
        } else {
            object.set_refcount(next);
        }
        Some(next)
    }

    #[allow(dead_code)] // refcount assertions in the adversarial tests
    pub(crate) fn refcount(&self, pid: u32, address: u64) -> Option<u32> {
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        table.objects.get(&(pid, address)).map(ClrObject::refcount)
    }

    /// Run `body` with the runtime behind a runtime-info object and record
    /// `error` as that object's last load/status error.
    pub(crate) fn with_runtime_info<R>(
        &self,
        pid: u32,
        address: u64,
        error: u32,
        body: impl FnOnce(&ClrRuntime) -> R,
    ) -> Option<R> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let object = table.objects.get_mut(&(pid, address))?;
        match object {
            ClrObject::RuntimeInfo {
                runtime,
                load_error,
                ..
            } => {
                *load_error = error;
                Some(body(runtime))
            }
            _ => None,
        }
    }

    pub(crate) fn load_error(&self, pid: u32, address: u64) -> Option<u32> {
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match table.objects.get(&(pid, address)) {
            Some(ClrObject::RuntimeInfo { load_error, .. }) => Some(*load_error),
            _ => None,
        }
    }

    /// Snapshot the next enumerator item and advance the cursor.
    pub(crate) fn next_enum_item(&self, pid: u32, address: u64) -> Option<ClrRuntime> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let object = table.objects.get_mut(&(pid, address))?;
        match object {
            ClrObject::Enumerator {
                runtimes, cursor, ..
            } => {
                let runtime = runtimes.get(*cursor)?.clone();
                *cursor += 1;
                Some(runtime)
            }
            _ => None,
        }
    }

    /// Skip `count` enumerator items; returns how many were actually skipped.
    pub(crate) fn skip_enum_items(&self, pid: u32, address: u64, count: usize) -> Option<usize> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let object = table.objects.get_mut(&(pid, address))?;
        match object {
            ClrObject::Enumerator {
                runtimes, cursor, ..
            } => {
                let remaining = runtimes.len().saturating_sub(*cursor);
                let skipped = remaining.min(count);
                *cursor += skipped;
                Some(skipped)
            }
            _ => None,
        }
    }

    pub(crate) fn reset_enum(&self, pid: u32, address: u64) -> Option<()> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let object = table.objects.get_mut(&(pid, address))?;
        match object {
            ClrObject::Enumerator { cursor, .. } => {
                *cursor = 0;
                Some(())
            }
            _ => None,
        }
    }

    /// Clone an enumerator (same item snapshot and cursor, independent
    /// refcount).
    pub(crate) fn clone_enum(
        &self,
        pid: u32,
        address: u64,
    ) -> Option<(ClrEnumKind, Vec<ClrRuntime>, usize)> {
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match table.objects.get(&(pid, address)) {
            Some(ClrObject::Enumerator {
                kind,
                runtimes,
                cursor,
                ..
            }) => Some((*kind, runtimes.clone(), *cursor)),
            _ => None,
        }
    }

    #[allow(dead_code)] // kind assertions in the adversarial tests
    pub(crate) fn enum_kind(&self, pid: u32, address: u64) -> Option<ClrEnumKind> {
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match table.objects.get(&(pid, address)) {
            Some(ClrObject::Enumerator { kind, .. }) => Some(*kind),
            _ => None,
        }
    }

    /// Register the process-wide runtime-loaded callback.  Returns `false`
    /// when a callback is already registered (the CLR allows exactly one).
    pub(crate) fn register_loaded_callback(&self, pid: u32, callback: u64) -> bool {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if table.callbacks.contains_key(&pid) {
            return false;
        }
        table.callbacks.insert(
            pid,
            ClrLoadedCallback {
                callback,
                thread_pinned: false,
            },
        );
        true
    }

    pub(crate) fn loaded_callback(&self, pid: u32) -> Option<u64> {
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        table.callbacks.get(&pid).map(|entry| entry.callback)
    }

    /// Mark a runtime as loaded for this process and report whether it was
    /// newly loaded (the callback is invoked only for a real transition).
    pub(crate) fn mark_loaded(&self, pid: u32, version: &str) -> bool {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        table
            .loaded
            .entry(pid)
            .or_default()
            .insert(version.to_string())
    }

    pub(crate) fn is_loaded(&self, pid: u32, version: &str) -> bool {
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        table
            .loaded
            .get(&pid)
            .is_some_and(|versions| versions.contains(version))
    }

    pub(crate) fn loaded_versions(&self, pid: u32) -> Vec<String> {
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        table
            .loaded
            .get(&pid)
            .map(|versions| versions.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn set_thread_pinned(&self, pid: u32, pinned: bool) -> bool {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match table.callbacks.get_mut(&pid) {
            Some(entry) => {
                entry.thread_pinned = pinned;
                true
            }
            None => false,
        }
    }

    #[allow(dead_code)] // thread pin/unpin assertions in the adversarial tests
    pub(crate) fn thread_pinned(&self, pid: u32) -> Option<bool> {
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        table.callbacks.get(&pid).map(|entry| entry.thread_pinned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_runtime(dir: &Path, version: &str) -> ClrRuntime {
        ClrRuntime {
            version: ClrVersion::parse_directory_name(version).expect("parse version"),
            directory: dir.to_path_buf(),
        }
    }

    #[test]
    fn runtime_root_precedence_rejects_missing_duplicate_and_relative_roots() {
        let temp = tempfile::TempDir::new().expect("temp");
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&first).expect("first root");
        std::fs::create_dir_all(&second).expect("second root");
        std::fs::create_dir_all(&home).expect("home root");
        let roots = dotnet_roots_from(Some(first.clone()), Some(home.clone()));
        assert_eq!(
            roots.first(),
            Some(&first.canonicalize().expect("canonical"))
        );
        assert_eq!(
            roots.contains(&home.join(".dotnet")),
            false,
            "a home directory without .dotnet is not a CLR root"
        );
        let missing = temp.path().join("missing");
        assert_eq!(
            dotnet_roots_from(Some(missing), None)
                .contains(&first.canonicalize().expect("canonical")),
            false
        );
        let duplicate = dotnet_roots_from(Some(first.clone()), Some(first.clone()));
        let canonical = first.canonicalize().expect("canonical");
        assert_eq!(
            duplicate.iter().filter(|root| **root == canonical).count(),
            1,
            "a canonical root is never enumerated twice"
        );
    }

    #[test]
    fn rva_mapping_rejects_unbacked_and_out_of_range_sections() {
        let section = pe::PeSection {
            name: ".text".to_string(),
            virtual_address: 0x2000,
            virtual_size: 0x100,
            raw_data_ptr: 0x100,
            raw_data_size: 0x100,
            characteristics: 0,
        };
        let bytes = vec![0_u8; 0x200];
        assert_eq!(
            rva_to_file_offset(&bytes, &[section.clone()], 0x2010),
            Some(0x110)
        );
        assert_eq!(
            rva_to_file_offset(&bytes, &[section.clone()], 0x1050),
            None,
            "an RVA outside every section maps to no file offset"
        );
        let huge = pe::PeSection {
            raw_data_ptr: 0xFFFF_FFFF,
            ..section
        };
        assert_eq!(
            rva_to_file_offset(&bytes, &[huge], 0x2000),
            None,
            "an unbacked section never yields an offset"
        );
    }

    #[test]
    fn malformed_version_strings_are_rejected_without_guessing() {
        for malformed in [
            "",
            "v",
            "8",
            "v8",
            "8.",
            ".8",
            "8.0.",
            "8..0",
            "8.0.x",
            "-8.0",
            "+8.0",
            " 8.0",
            "8.0 ",
            "v 8.0",
            "8.0.31-rc1",
            "8.0.31.0.1",
            "08.0",
            "8.00",
            "65536.0",
        ] {
            assert_eq!(
                ClrVersion::parse_request(malformed),
                None,
                "malformed version {malformed:?} must be rejected"
            );
        }
        assert_eq!(ClrVersion::parse_directory_name("v8.0.31"), None);
        assert_eq!(ClrVersion::parse_directory_name("v"), None);
    }

    #[test]
    fn version_parsing_real_directory_forms_and_edge_components() {
        let version = ClrVersion::parse_request("v8.0.31").expect("valid request");
        assert_eq!(version.as_string(), "8.0.31");
        assert_eq!(version.component_count(), 3);
        assert_eq!(
            ClrVersion::parse_directory_name("8.0.31").expect("valid dir"),
            version
        );
        assert_eq!(
            ClrVersion::parse_request("4.0.30319")
                .expect("framework form")
                .as_string(),
            "4.0.30319"
        );
        assert_eq!(
            ClrVersion::parse_request("10.0")
                .expect("two components")
                .as_string(),
            "10.0"
        );
        assert_eq!(
            ClrVersion::parse_request("10.0.4.1")
                .expect("four components")
                .as_string(),
            "10.0.4.1"
        );
    }

    #[test]
    fn malformed_or_absent_runtime_requests_never_match_installed_dirs() {
        let temp = tempfile::TempDir::new().expect("temp");
        let dir = temp.path().join("8.0.31");
        std::fs::create_dir_all(&dir).expect("runtime dir");
        std::fs::write(dir.join("libcoreclr.dylib"), b"").expect("coreclr stub file");
        let installed = vec![valid_runtime(&dir, "8.0.31")];

        assert_eq!(
            select_runtime(
                &ClrVersion::parse_request("v999.0.0").expect("valid"),
                &installed
            ),
            None
        );
        assert_eq!(
            select_runtime(
                &ClrVersion::parse_request("8.0.32").expect("valid"),
                &installed
            ),
            None
        );
        assert_eq!(
            select_runtime(
                &ClrVersion::parse_request("8.0.31.1").expect("valid"),
                &installed
            ),
            None,
            "a request with more components than the installed runtime never matches"
        );
        let exact = select_runtime(
            &ClrVersion::parse_request("8.0.31").expect("valid"),
            &installed,
        )
        .expect("exact match");
        assert_eq!(exact.version_string(), "8.0.31");
        let floating = select_runtime(
            &ClrVersion::parse_request("v8.0").expect("valid"),
            &installed,
        )
        .expect("floating match");
        assert_eq!(floating.version_string(), "8.0.31");
    }

    #[test]
    fn discovery_rejects_non_runtime_dirs_and_unparseable_names() {
        let temp = tempfile::TempDir::new().expect("temp");
        let shared = temp.path().join("shared").join("Microsoft.NETCore.App");
        let good = shared.join("8.0.31");
        std::fs::create_dir_all(&good).expect("good dir");
        std::fs::write(good.join("libcoreclr.dylib"), b"").expect("coreclr file");
        let no_clr = shared.join("9.0.1");
        std::fs::create_dir_all(&no_clr).expect("no-clr dir");
        let malformed = shared.join("nightly");
        std::fs::create_dir_all(&malformed).expect("malformed dir");
        std::fs::write(malformed.join("libcoreclr.dylib"), b"").expect("coreclr file");
        std::fs::write(shared.join("8.0.31-file"), b"").expect("plain file");

        let runtimes = runtimes_under_root(temp.path());
        assert_eq!(runtimes, vec![valid_runtime(&good, "8.0.31")]);
        assert_eq!(
            runtimes_under_root(&temp.path().join("missing")),
            Vec::new()
        );
    }

    #[test]
    fn installed_runtimes_match_real_directories_without_duplicate_versions() {
        let runtimes = installed_runtimes();
        assert!(
            !runtimes.is_empty(),
            "the host must expose at least one real CoreCLR shared framework"
        );
        for runtime in &runtimes {
            let library = runtime
                .coreclr_library()
                .expect("every advertised runtime has a real CoreCLR library");
            assert!(
                library.is_file(),
                "runtime {runtime:?} advertises a missing CoreCLR library"
            );
            assert_eq!(
                runtime
                    .directory
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
                Some(runtime.version_string()),
                "the version must be the real directory name"
            );
        }
        let mut versions: Vec<String> = runtimes.iter().map(ClrRuntime::version_string).collect();
        let sorted = {
            let mut copy = versions.clone();
            copy.sort_by(|left, right| {
                let left = ClrVersion::parse_directory_name(left).expect("version");
                let right = ClrVersion::parse_directory_name(right).expect("version");
                right.cmp(&left)
            });
            copy
        };
        assert_eq!(versions, sorted, "runtime enumeration is highest-first");
        versions.dedup();
        assert_eq!(
            versions.len(),
            runtimes.len(),
            "duplicate Homebrew kegs collapse to one runtime per directory"
        );
    }

    #[test]
    fn metadata_root_errors_are_exact() {
        let mut root = Vec::new();
        root.extend(METADATA_SIGNATURE.to_le_bytes());
        root.extend(1_u16.to_le_bytes());
        root.extend(1_u16.to_le_bytes());
        root.extend(0_u32.to_le_bytes());
        let version = b"v4.0.30319\0";
        root.extend((version.len() as u32).to_le_bytes());
        root.extend(version);
        assert_eq!(
            metadata_version_from_root(&root),
            Ok("v4.0.30319".to_string())
        );

        assert_eq!(
            metadata_version_from_root(&root[..8]),
            Err(ClrMetaError::InvalidMetadata)
        );

        let mut bad_signature = root.clone();
        bad_signature[0] = 0;
        assert_eq!(
            metadata_version_from_root(&bad_signature),
            Err(ClrMetaError::InvalidMetadata)
        );

        let mut zero_length = root.clone();
        zero_length[12..16].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            metadata_version_from_root(&zero_length),
            Err(ClrMetaError::InvalidMetadata)
        );

        let mut oversized = root.clone();
        oversized[12..16].copy_from_slice(&4097_u32.to_le_bytes());
        assert_eq!(
            metadata_version_from_root(&oversized),
            Err(ClrMetaError::InvalidMetadata)
        );

        let mut truncated = root.clone();
        truncated.truncate(20);
        assert_eq!(
            metadata_version_from_root(&truncated),
            Err(ClrMetaError::InvalidMetadata)
        );

        let mut unterminated = root.clone();
        let last = unterminated.len() - 1;
        unterminated[last] = b'x';
        assert_eq!(
            metadata_version_from_root(&unterminated),
            Err(ClrMetaError::InvalidMetadata)
        );

        let mut empty_version = root.clone();
        let empty_offset = empty_version.len() - version.len();
        empty_version[empty_offset] = 0;
        assert_eq!(
            metadata_version_from_root(&empty_version),
            Err(ClrMetaError::InvalidMetadata)
        );

        let mut bad_utf8 = root;
        let invalid_offset = bad_utf8.len() - version.len();
        bad_utf8[invalid_offset] = 0xFF;
        assert_eq!(
            metadata_version_from_root(&bad_utf8),
            Err(ClrMetaError::InvalidMetadata)
        );
    }

    #[test]
    fn real_managed_assembly_metadata_matches_and_non_pe_is_rejected() {
        let runtimes = installed_runtimes();
        let runtime = runtimes.first().expect("a real runtime is installed");
        let assembly = runtime.directory.join("System.Runtime.dll");
        assert!(
            assembly.is_file(),
            "the real shared framework contains System.Runtime.dll"
        );
        assert_eq!(
            version_from_file(&assembly),
            Ok("v4.0.30319".to_string()),
            "CoreCLR assemblies carry the real CLI metadata version"
        );

        let temp = tempfile::TempDir::new().expect("temp");
        let text = temp.path().join("not-pe.txt");
        std::fs::write(&text, b"this is not a PE image\n").expect("write text");
        assert_eq!(version_from_file(&text), Err(ClrMetaError::InvalidPe));

        // A real native Windows PE with no CLI header is the truthful
        // "non-managed file" case: it parses as PE but has no runtime version.
        let native_pe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("ges/steam-live-run-x86/drive_c/nsExec.dll");
        assert_eq!(
            version_from_file(&native_pe),
            Err(ClrMetaError::NotManaged),
            "a native PE has no CLI metadata runtime version"
        );

        let missing = temp.path().join("missing.dll");
        assert_eq!(
            version_from_file(&missing),
            Err(ClrMetaError::Io(HRESULT_FILE_NOT_FOUND))
        );
        assert_eq!(
            ClrMetaError::Io(HRESULT_FILE_NOT_FOUND).hresult(),
            HRESULT_FILE_NOT_FOUND
        );
        let directory = temp.path().join("a-directory");
        std::fs::create_dir_all(&directory).expect("directory");
        assert_eq!(
            version_from_file(&directory),
            Err(ClrMetaError::Io(HRESULT_GEN_FAILURE)),
            "a non-file read failure is a generic host I/O failure"
        );

        let native = runtime.coreclr_library().expect("real coreclr library");
        assert_eq!(version_from_file(&native), Err(ClrMetaError::InvalidPe));
    }

    #[test]
    fn native_export_resolution_rejects_absent_symbols_and_empty_dirs() {
        let runtimes = installed_runtimes();
        let runtime = runtimes.first().expect("a real runtime is installed");
        assert_eq!(native_export_available(runtime, "coreclr_initialize"), true);
        assert_eq!(
            native_export_available(runtime, "casa1_no_such_clr_export_42"),
            false
        );
        assert_eq!(native_export_available(runtime, ""), false);

        let temp = tempfile::TempDir::new().expect("temp");
        let empty = valid_runtime(temp.path(), "1.0.0");
        assert_eq!(
            native_export_available(&empty, "coreclr_initialize"),
            false,
            "a directory without a real CLR library exports nothing"
        );

        // A runtime directory that only carries hostfxr (a valid alternate
        // layout) is searched, and an unloadable library exports nothing.
        let hostfxr_dir = temp.path().join("hostfxr-only");
        std::fs::create_dir_all(&hostfxr_dir).expect("hostfxr dir");
        std::fs::write(hostfxr_dir.join("libhostfxr.dylib"), b"not a dylib").expect("hostfxr file");
        assert_eq!(
            native_export_available(
                &valid_runtime(&hostfxr_dir, "1.0.0"),
                "hostfxr_initialize_for_runtime_config"
            ),
            false
        );
    }

    #[test]
    fn concurrent_enumeration_and_refcounts_are_atomic() {
        let runtimes = installed_runtimes();
        let baseline = runtimes.clone();
        let mut workers = Vec::new();
        for _ in 0..4 {
            let expected = baseline.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..8 {
                    assert_eq!(installed_runtimes(), expected);
                }
            }));
        }
        for worker in workers {
            worker.join().expect("enumeration worker");
        }

        let objects = std::sync::Arc::new(ClrHostObjects::new());
        objects.insert_meta_host(4242, 0x1000);
        let mut workers = Vec::new();
        for _ in 0..8 {
            let objects = objects.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    // Concurrent AddRef/Release pairs interleave; the
                    // atomic invariant is the net refcount, which the
                    // joining thread pins exactly below.
                    assert!(objects.add_ref(4242, 0x1000).is_some());
                    assert!(objects.release(4242, 0x1000).is_some());
                }
            }));
        }
        for worker in workers {
            worker.join().expect("refcount worker");
        }
        assert_eq!(objects.refcount(4242, 0x1000), Some(1));
        assert_eq!(objects.release(4242, 0x1000), Some(0));
        assert_eq!(
            objects.release(4242, 0x1000),
            None,
            "an object cannot be released twice"
        );
    }

    #[test]
    fn unknown_object_operations_are_rejected() {
        let objects = ClrHostObjects::new();
        objects.insert_meta_host(1, 0x1000);
        assert_eq!(
            objects.with_runtime_info(1, 0x1000, 0, |_| ()),
            None,
            "a meta host is not a runtime info object"
        );
        assert_eq!(objects.next_enum_item(1, 0x1000), None);
        assert_eq!(objects.skip_enum_items(1, 0x1000, 1), None);
        assert_eq!(objects.reset_enum(1, 0x1000), None);
        assert_eq!(objects.clone_enum(1, 0x1000), None);
        assert_eq!(objects.load_error(1, 0x1000), None);
        assert_eq!(objects.add_ref(1, 0xDEAD), None);
        assert_eq!(objects.release(1, 0xDEAD), None);
        assert_eq!(objects.refcount(1, 0xDEAD), None);
        assert_eq!(objects.with_runtime_info(1, 0xDEAD, 0, |_| ()), None);
        assert_eq!(objects.next_enum_item(1, 0xDEAD), None);
        assert_eq!(objects.skip_enum_items(1, 0xDEAD, 1), None);
        assert_eq!(objects.reset_enum(1, 0xDEAD), None);
        assert_eq!(objects.clone_enum(1, 0xDEAD), None);
        assert_eq!(objects.enum_kind(1, 0xDEAD), None);
        assert_eq!(objects.load_error(1, 0xDEAD), None);
        assert_eq!(objects.thread_pinned(1), None);
        assert_eq!(objects.loaded_callback(1), None);
        assert_eq!(objects.loaded_versions(1), Vec::<String>::new());
        assert_eq!(objects.is_loaded(1, "8.0.31"), false);
        assert_eq!(objects.set_thread_pinned(1, true), false);
    }

    #[test]
    fn enumerator_state_edges_are_exact() {
        let objects = ClrHostObjects::new();
        let runtime = valid_runtime(Path::new("/tmp/clr"), "8.0.31");
        objects.insert_enumerator(7, 0x2000, ClrEnumKind::Installed, vec![runtime.clone()], 0);
        assert_eq!(objects.enum_kind(7, 0x2000), Some(ClrEnumKind::Installed));
        assert_eq!(objects.next_enum_item(7, 0x2000), Some(runtime.clone()));
        assert_eq!(
            objects.next_enum_item(7, 0x2000),
            None,
            "a drained enumerator yields no more items"
        );
        assert_eq!(objects.skip_enum_items(7, 0x2000, 4), Some(0));
        assert_eq!(objects.reset_enum(7, 0x2000), Some(()));
        assert_eq!(objects.next_enum_item(7, 0x2000), Some(runtime.clone()));
        assert_eq!(
            objects.skip_enum_items(7, 0x2000, 4),
            Some(0),
            "skipping past the end only skips what remains"
        );
        objects.reset_enum(7, 0x2000);
        assert_eq!(objects.skip_enum_items(7, 0x2000, 1), Some(1));
        let (kind, items, cursor) = objects.clone_enum(7, 0x2000).expect("clone state");
        assert_eq!(kind, ClrEnumKind::Installed);
        assert_eq!(items, vec![runtime.clone()]);
        assert_eq!(cursor, 1, "a clone keeps the source cursor");
        assert_eq!(objects.loaded_versions(9), Vec::<String>::new());
        assert_eq!(objects.mark_loaded(9, "8.0.31"), true);
        assert_eq!(objects.mark_loaded(9, "8.0.31"), false);
        assert_eq!(objects.is_loaded(9, "8.0.31"), true);
        assert_eq!(objects.is_loaded(9, "10.0.11"), false);
        assert_eq!(objects.loaded_versions(9), vec!["8.0.31".to_string()]);
    }
}
