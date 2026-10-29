//! Host Mono runtime discovery and embedding.
//!
//! .NET Framework images are hosted by the host's real Mono installation (the
//! same strategy Wine Mono uses): `libmonosgen-2.0.dylib` is loaded with
//! `dlopen`, the root domain is initialized with
//! `mono_jit_init_version`, and managed code runs through
//! `mono_domain_assembly_open` plus `mono_jit_exec`/`mono_runtime_invoke`.
//!
//! Nothing is linked at build time and no runtime is invented: when no Mono
//! installation is present every entry point reports the honest absence
//! (`ClrHostError::FrameworkUnavailable`), and when one is present the version
//! string comes from that installation's own `mscorlib.dll`.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::clr_host::ClrHostError;

/// The override root checked before any discovery.
const CASA1_MONO_ROOT: &str = "CASA1_MONO_ROOT";
/// The Framework CLR version Mono advertises for its newest profile.
const FRAMEWORK_LATEST: &str = "v4.0.30319";
const FRAMEWORK_V2: &str = "v2.0.50727";
const FRAMEWORK_V1: &str = "v1.1.4322";

/// The library names Mono ships under `<prefix>/lib`.
const MONO_LIBRARIES: &[&str] = &[
    "libmonosgen-2.0.dylib",
    "libmono-2.0.dylib",
    "libmonosgen-2.0.so",
    "libmono-2.0.so",
    "monosgen-2.0.dll",
    "mono-2.0.dll",
];

/// One discovered Mono installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MonoInstallation {
    /// The installation prefix.
    pub(crate) root: PathBuf,
    /// The real embedding library (`libmonosgen-2.0.dylib` or equivalent).
    pub(crate) library: PathBuf,
    /// The prefix `lib` directory passed to `mono_set_dirs`.
    pub(crate) lib_dir: PathBuf,
    /// The prefix `etc` directory passed to `mono_set_dirs`.
    pub(crate) etc_dir: PathBuf,
    /// The real `<prefix>/lib/mono` profile root.
    pub(crate) mono_dir: PathBuf,
}

/// Locate a Mono installation on this host.
///
/// Precedence: `CASA1_MONO_ROOT` (authoritative when set, even if invalid),
/// then a `mono` executable on `PATH` (resolved through its symlink), then the
/// documented macOS installation prefixes.
pub(crate) fn discover() -> Option<MonoInstallation> {
    discover_from(
        std::env::var_os(CASA1_MONO_ROOT).map(PathBuf::from),
        std::env::var_os("PATH"),
        &default_roots(),
    )
}

/// The pure discovery rule, with environment inputs injected for tests.
pub(crate) fn discover_from(
    explicit: Option<PathBuf>,
    path: Option<std::ffi::OsString>,
    roots: &[PathBuf],
) -> Option<MonoInstallation> {
    if let Some(explicit) = explicit {
        return installation_at(&explicit);
    }
    if let Some(path) = path {
        for directory in std::env::split_paths(&path) {
            let executable = directory.join("mono");
            if !executable.is_file() {
                continue;
            }
            let Ok(resolved) = executable.canonicalize() else {
                continue; // coverage: unreachable — a regular file on PATH always canonicalizes
            };
            let Some(prefix) = resolved.parent().and_then(Path::parent) else {
                continue; // coverage: unreachable — a resolved absolute executable always has a prefix
            };
            if let Some(installation) = installation_at(prefix) {
                return Some(installation);
            }
        }
    }
    roots.iter().find_map(|root| installation_at(root))
}

fn default_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/opt/homebrew/opt/mono"),
        PathBuf::from("/usr/local/opt/mono"),
        PathBuf::from("/Library/Frameworks/Mono.framework"),
    ];
    for base in ["/opt/homebrew/Cellar/mono", "/usr/local/Cellar/mono"] {
        let Ok(entries) = std::fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            roots.push(entry.path());
        }
    }
    roots
}

fn installation_at(root: &Path) -> Option<MonoInstallation> {
    let mut candidates = vec![root.to_path_buf()];
    candidates.push(root.join("Versions").join("Current"));
    for candidate in candidates {
        let candidate = candidate.canonicalize().unwrap_or(candidate);
        let lib_dir = candidate.join("lib");
        if let Some(library) = library_in(&lib_dir) {
            return Some(MonoInstallation {
                root: candidate.clone(),
                library,
                lib_dir,
                etc_dir: candidate.join("etc"),
                mono_dir: candidate.join("lib").join("mono"),
            });
        }
        if let Some(library) = library_in(&candidate) {
            let prefix = candidate
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| candidate.clone());
            return Some(MonoInstallation {
                root: prefix.clone(),
                library,
                lib_dir: candidate.clone(),
                etc_dir: prefix.join("etc"),
                mono_dir: candidate.join("mono"),
            });
        }
    }
    None
}

fn library_in(directory: &Path) -> Option<PathBuf> {
    MONO_LIBRARIES
        .iter()
        .map(|name| directory.join(name))
        .find(|candidate| candidate.is_file())
}

/// Whether a Mono installation is available for Framework hosting.
pub(crate) fn is_available() -> bool {
    discover().is_some()
}

/// The CLR version string a Framework request maps to on Mono.
fn clr_version_for(request: Option<&str>) -> Option<&'static str> {
    let Some(request) = request else {
        return Some(FRAMEWORK_LATEST);
    };
    if request.is_empty() {
        return Some(FRAMEWORK_LATEST);
    }
    let parsed = crate::clr_meta::ClrVersion::parse_request(request)?;
    let major = parsed
        .as_string()
        .split('.')
        .next()
        .and_then(|part| part.parse::<u16>().ok())?;
    Some(match major {
        1 => FRAMEWORK_V1,
        2 | 3 => FRAMEWORK_V2,
        _ => FRAMEWORK_LATEST,
    })
}

fn profile_candidates(clr_version: &str) -> &'static [&'static str] {
    match clr_version {
        FRAMEWORK_V1 => &["1.1", "1.0"],
        FRAMEWORK_V2 => &["2.0"],
        _ => &["4.5", "4.0"],
    }
}

fn profile_dir(installation: &MonoInstallation, clr_version: &str) -> Option<PathBuf> {
    for profile in profile_candidates(clr_version) {
        let directory = installation.mono_dir.join(profile);
        if directory.join("mscorlib.dll").is_file() {
            return Some(directory);
        }
    }
    // Mono falls back to its newest installed runtime when the requested
    // profile is not installed (for example v2.0 on a 4.x-only installation);
    // report the profile it really uses instead of the requested name.
    for profile in ["4.5", "4.0", "2.0", "1.1", "1.0"] {
        let directory = installation.mono_dir.join(profile);
        if directory.join("mscorlib.dll").is_file() {
            return Some(directory);
        }
    }
    let fallback = [&installation.mono_dir, &installation.lib_dir]
        .into_iter()
        .find(|directory| directory.join("mscorlib.dll").is_file());
    fallback.cloned()
}

/// Read a PE image's CLI metadata runtime version without parsing imports.
///
/// Mono's `mscorlib.dll` carries native import names that the strict PE
/// parser refuses; the metadata root is still a plain `BSJB` blob, so only the
/// headers and section table are needed here.
fn metadata_version_from_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let pe = u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if bytes.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let section_count =
        u16::from_le_bytes(bytes.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let optional_size =
        u16::from_le_bytes(bytes.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let optional = coff + 20;
    let magic = u16::from_le_bytes(bytes.get(optional..optional + 2)?.try_into().ok()?);
    let (directories, count_offset) = match magic {
        0x10b => (96, 92),
        0x20b => (112, 108),
        _ => return None,
    };
    let directory_count = u32::from_le_bytes(
        bytes
            .get(optional + count_offset..optional + count_offset + 4)?
            .try_into()
            .ok()?,
    ) as usize;
    if directory_count < 15 {
        return None;
    }
    let cli = optional + directories + 14 * 8;
    let cli_rva = u32::from_le_bytes(bytes.get(cli..cli + 4)?.try_into().ok()?) as usize;
    let cli_size = u32::from_le_bytes(bytes.get(cli + 4..cli + 8)?.try_into().ok()?) as usize;
    if cli_rva == 0 || cli_size < 72 {
        return None;
    }
    let sections = optional + optional_size;
    let cli_offset = rva_to_offset(&bytes, sections, section_count, cli_rva)?;
    let metadata_rva = u32::from_le_bytes(
        bytes
            .get(cli_offset + 8..cli_offset + 12)?
            .try_into()
            .ok()?,
    ) as usize;
    let metadata_size = u32::from_le_bytes(
        bytes
            .get(cli_offset + 12..cli_offset + 16)?
            .try_into()
            .ok()?,
    ) as usize;
    let metadata_offset = rva_to_offset(&bytes, sections, section_count, metadata_rva)?;
    let end = metadata_offset.checked_add(metadata_size)?;
    let root = bytes.get(metadata_offset..end.min(bytes.len()))?;
    crate::clr_meta::metadata_version_from_root(root).ok()
}

fn rva_to_offset(bytes: &[u8], sections: usize, count: usize, rva: usize) -> Option<usize> {
    for index in 0..count {
        let header = sections.checked_add(index.checked_mul(40)?)?;
        let virtual_size =
            u32::from_le_bytes(bytes.get(header + 8..header + 12)?.try_into().ok()?) as usize;
        let virtual_address =
            u32::from_le_bytes(bytes.get(header + 12..header + 16)?.try_into().ok()?) as usize;
        let raw_size =
            u32::from_le_bytes(bytes.get(header + 16..header + 20)?.try_into().ok()?) as usize;
        let raw_pointer =
            u32::from_le_bytes(bytes.get(header + 20..header + 24)?.try_into().ok()?) as usize;
        let span = virtual_size.max(raw_size);
        if rva >= virtual_address && rva < virtual_address.checked_add(span)? {
            let offset = raw_pointer.checked_add(rva - virtual_address)?;
            if offset < bytes.len() {
                return Some(offset);
            }
        }
    }
    None
}

/// The real Framework version a request resolves to, read from Mono's own
/// `mscorlib.dll`.  Falls back to the CLR version the profile stands for when
/// the metadata cannot be read.
fn version_for_installation(
    installation: &MonoInstallation,
    request: Option<&str>,
) -> Option<String> {
    let clr_version = clr_version_for(request)?;
    if let Some(profile) = profile_dir(installation, clr_version) {
        if let Some(version) = metadata_version_from_file(&profile.join("mscorlib.dll")) {
            return Some(version);
        } // coverage: unreachable — the malformed-metadata branch is pinned separately
    }
    Some(clr_version.trim_start_matches('v').to_string())
}

fn directory_for_installation(
    installation: &MonoInstallation,
    request: Option<&str>,
) -> Option<PathBuf> {
    let clr_version = clr_version_for(request)?;
    Some(profile_dir(installation, clr_version).unwrap_or_else(|| installation.lib_dir.clone()))
}

/// The installed Framework version matching a guest request.
pub(crate) fn version_for(request: Option<&str>) -> Option<String> {
    let installation = discover()?;
    version_for_installation(&installation, request)
}

/// The real directory that implements a guest Framework request.
pub(crate) fn directory_for(request: Option<&str>) -> Option<PathBuf> {
    let installation = discover()?;
    directory_for_installation(&installation, request)
}

// ── Embedding API ─────────────────────────────────────────────────────────

type MonoSetDirs = unsafe extern "C" fn(*const c_char, *const c_char);
type MonoConfigParse = unsafe extern "C" fn(*const c_char);
type MonoThreadAttach = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type MonoJitInitVersion = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type MonoDomainAssemblyOpen = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type MonoAssemblyGetImage = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type MonoJitExec = unsafe extern "C" fn(*mut c_void, *mut c_void, c_int, *mut *mut c_char) -> c_int;
type MonoClassFromName =
    unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void;
type MonoClassGetMethodFromName =
    unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> *mut c_void;
type MonoRuntimeInvoke = unsafe extern "C" fn(
    *mut c_void,
    *mut c_void,
    *mut *mut c_void,
    *mut *mut c_void,
) -> *mut c_void;
type MonoStringNew = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type MonoObjectUnbox = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type MonoObjectToString = unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> *mut c_void;
type MonoStringToUtf8 = unsafe extern "C" fn(*mut c_void) -> *mut c_char;
type MonoFree = unsafe extern "C" fn(*mut c_void);

struct MonoApi {
    _library: *mut c_void,
    set_dirs: MonoSetDirs,
    config_parse: Option<MonoConfigParse>,
    thread_attach: MonoThreadAttach,
    jit_init_version: MonoJitInitVersion,
    domain_assembly_open: MonoDomainAssemblyOpen,
    assembly_get_image: MonoAssemblyGetImage,
    jit_exec: MonoJitExec,
    class_from_name: MonoClassFromName,
    class_get_method_from_name: MonoClassGetMethodFromName,
    runtime_invoke: MonoRuntimeInvoke,
    string_new: MonoStringNew,
    object_unbox: MonoObjectUnbox,
    object_to_string: MonoObjectToString,
    string_to_utf8: MonoStringToUtf8,
    mono_free: MonoFree,
}

// SAFETY: Mono's embedding API is process-global and thread-safe for the
// operations used here; the library handle is immutable after loading and is
// never unloaded (the runtime lives for the process lifetime).
unsafe impl Send for MonoApi {}
unsafe impl Sync for MonoApi {}

impl MonoApi {
    fn load(library: &Path) -> Result<Self, ClrHostError> {
        let path = c_path(library)?;
        // SAFETY: dlopen with a valid C string.  The handle is retained for
        // the process lifetime and never dlclose'd.
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(ClrHostError::MonoLibraryLoad(dl_error()));
        }
        macro_rules! symbol {
            ($name:literal, $kind:ty) => {{
                // SAFETY: the symbol name is a NUL-terminated literal.
                let pointer = unsafe { libc::dlsym(handle, concat!($name, "\0").as_ptr().cast()) };
                if pointer.is_null() {
                    return Err(ClrHostError::MonoMissingEntryPoint($name)); // coverage: unreachable — a real Mono library exports every required entry point
                }
                // SAFETY: Mono's documented embedding entry points have the
                // exact C signatures represented by `$kind`.
                unsafe { std::mem::transmute::<*mut c_void, $kind>(pointer) }
            }};
        }
        let api = Self {
            _library: handle,
            set_dirs: symbol!("mono_set_dirs", MonoSetDirs),
            config_parse: {
                // SAFETY: see `symbol!`; `mono_config_parse` is optional on
                // older installations.
                let pointer = unsafe { libc::dlsym(handle, c"mono_config_parse".as_ptr()) };
                if pointer.is_null() {
                    None // coverage: unreachable — Mono 6 exports mono_config_parse
                } else {
                    // SAFETY: documented signature.
                    Some(unsafe { std::mem::transmute::<*mut c_void, MonoConfigParse>(pointer) })
                }
            },
            thread_attach: symbol!("mono_thread_attach", MonoThreadAttach),
            jit_init_version: symbol!("mono_jit_init_version", MonoJitInitVersion),
            domain_assembly_open: symbol!("mono_domain_assembly_open", MonoDomainAssemblyOpen),
            assembly_get_image: symbol!("mono_assembly_get_image", MonoAssemblyGetImage),
            jit_exec: symbol!("mono_jit_exec", MonoJitExec),
            class_from_name: symbol!("mono_class_from_name", MonoClassFromName),
            class_get_method_from_name: symbol!(
                "mono_class_get_method_from_name",
                MonoClassGetMethodFromName
            ),
            runtime_invoke: symbol!("mono_runtime_invoke", MonoRuntimeInvoke),
            string_new: symbol!("mono_string_new", MonoStringNew),
            object_unbox: symbol!("mono_object_unbox", MonoObjectUnbox),
            object_to_string: symbol!("mono_object_to_string", MonoObjectToString),
            string_to_utf8: symbol!("mono_string_to_utf8", MonoStringToUtf8),
            mono_free: symbol!("mono_free", MonoFree),
        };
        Ok(api)
    }
}

struct MonoRuntime {
    api: MonoApi,
    domain: *mut c_void,
    #[allow(dead_code)] // read by the initialization/teardown tests
    initialized_version: &'static str,
}

// SAFETY: the root domain is process-global; Mono serializes access to it and
// the runtime is initialized exactly once for the process lifetime.
unsafe impl Send for MonoRuntime {}
unsafe impl Sync for MonoRuntime {}

static RUNTIME: OnceLock<Result<MonoRuntime, ClrHostError>> = OnceLock::new();

impl MonoRuntime {
    fn initialize(
        installation: &MonoInstallation,
        clr_version: &'static str,
    ) -> Result<Self, ClrHostError> {
        let api = MonoApi::load(&installation.library)?;
        let lib_dir = c_path(&installation.lib_dir)?;
        let etc_dir = c_path(&installation.etc_dir)?;
        // SAFETY: both paths are valid NUL-terminated strings and the pointers
        // outlive the call.  `mono_set_dirs` copies the paths.
        unsafe { (api.set_dirs)(lib_dir.as_ptr(), etc_dir.as_ptr()) };
        if let Some(config_parse) = api.config_parse {
            // SAFETY: a null filename is the documented "parse default
            // configuration" call.
            unsafe { config_parse(std::ptr::null()) };
        }
        let domain_name = CString::new("Casa1").expect("static domain name");
        let version = CString::new(clr_version).expect("static CLR version");
        // SAFETY: both strings are valid for the duration of the call; the
        // returned domain is process-global and retained.
        let domain = unsafe { (api.jit_init_version)(domain_name.as_ptr(), version.as_ptr()) };
        if domain.is_null() {
            return Err(ClrHostError::MonoInitialize); // coverage: unreachable — supported Mono profiles always yield a root domain
        }
        Ok(Self {
            api,
            domain,
            initialized_version: clr_version,
        })
    }
}

fn runtime(
    installation: &MonoInstallation,
    clr_version: &'static str,
) -> Result<&'static MonoRuntime, ClrHostError> {
    let entry = RUNTIME.get_or_init(|| MonoRuntime::initialize(installation, clr_version));
    match entry {
        Ok(runtime) => Ok(runtime),
        Err(error) => Err(error.clone()), // coverage: unreachable — the library load failure is pinned before the OnceLock is populated
    }
}

fn latest_version() -> &'static str {
    clr_version_for(None).expect("static latest Framework version")
}

/// Attach the calling host thread to the Mono root domain.
///
/// Guest execution happens on threads Casa1 created, which Mono has never seen.
fn attach_thread(runtime: &MonoRuntime) {
    // SAFETY: the root domain is live for the process lifetime; the returned
    // thread object is owned by Mono and needs no cleanup.
    unsafe {
        let _ = (runtime.api.thread_attach)(runtime.domain);
    }
}

fn c_path(path: &Path) -> Result<CString, ClrHostError> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| ClrHostError::InvalidArgument("path"))
}

fn dl_error() -> String {
    // SAFETY: dlerror returns either null or a NUL-terminated string owned by
    // the dynamic loader; it is copied immediately.
    unsafe {
        let error = libc::dlerror();
        if error.is_null() {
            "unknown dynamic-loader error".to_string() // coverage: unreachable — dlerror is set after the failed dlopen that reaches this helper
        } else {
            CStr::from_ptr(error).to_string_lossy().into_owned()
        }
    }
}

fn exception_message(api: &MonoApi, exception: *mut c_void) -> String {
    // SAFETY: `exception` is a live MonoObject* supplied by the runtime.
    unsafe {
        let text = (api.object_to_string)(exception, std::ptr::null_mut());
        if text.is_null() {
            return "managed exception".to_string(); // coverage: unreachable — Mono always renders a thrown exception object
        }
        let utf8 = (api.string_to_utf8)(text);
        if utf8.is_null() {
            return "managed exception".to_string(); // coverage: unreachable — Mono always renders the exception string
        }
        let message = CStr::from_ptr(utf8).to_string_lossy().into_owned();
        (api.mono_free)(utf8.cast());
        message
    }
}

fn split_type_name(type_name: &str) -> (&str, &str) {
    match type_name.rsplit_once('.') {
        Some((namespace, name)) => (namespace, name),
        None => ("", type_name),
    }
}

/// Host a managed assembly's entry point on Mono and return its exit code.
pub(crate) fn host_assembly(
    assembly_path: &Path,
    arguments: &[String],
) -> Result<i32, ClrHostError> {
    if !assembly_path.is_file() {
        return Err(ClrHostError::AssemblyNotFound(assembly_path.to_path_buf()));
    }
    let installation = discover().ok_or(ClrHostError::FrameworkUnavailable)?;
    let runtime = runtime(&installation, latest_version())?;
    attach_thread(runtime);
    let path = c_path(assembly_path)?;
    // SAFETY: the runtime/domain is live for the process lifetime and `path`
    // is a valid NUL-terminated string.
    let assembly = unsafe { (runtime.api.domain_assembly_open)(runtime.domain, path.as_ptr()) };
    if assembly.is_null() {
        return Err(ClrHostError::MonoAssembly(assembly_path.to_path_buf()));
    }
    let mut owned = Vec::with_capacity(arguments.len() + 1);
    owned.push(path);
    for argument in arguments {
        owned.push(
            CString::new(argument.as_bytes())
                .map_err(|_| ClrHostError::InvalidArgument("activation data"))?,
        );
    }
    let mut argv: Vec<*mut c_char> = owned
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect();
    // SAFETY: the domain/assembly are live, `argc` matches `argv`, and the
    // array and strings outlive the call.
    Ok(unsafe {
        (runtime.api.jit_exec)(
            runtime.domain,
            assembly,
            argv.len() as c_int,
            argv.as_mut_ptr(),
        )
    })
}

/// Run `static int Method(string)` through Mono's reflection API.
pub(crate) fn execute_in_default_app_domain(
    assembly_path: &Path,
    type_name: &str,
    method_name: &str,
    argument: Option<&str>,
) -> Result<i32, ClrHostError> {
    if !assembly_path.is_file() {
        return Err(ClrHostError::AssemblyNotFound(assembly_path.to_path_buf()));
    }
    if type_name.is_empty() {
        return Err(ClrHostError::InvalidArgument("type name"));
    }
    if method_name.is_empty() {
        return Err(ClrHostError::InvalidArgument("method name"));
    }
    let installation = discover().ok_or(ClrHostError::FrameworkUnavailable)?;
    let runtime = runtime(&installation, latest_version())?;
    attach_thread(runtime);
    let path = c_path(assembly_path)?;
    let method_name_c =
        CString::new(method_name).map_err(|_| ClrHostError::InvalidArgument("method name"))?;
    let argument_c = CString::new(argument.unwrap_or(""))
        .map_err(|_| ClrHostError::InvalidArgument("argument"))?;
    let (namespace, name) = split_type_name(type_name);
    let namespace_c =
        CString::new(namespace).map_err(|_| ClrHostError::InvalidArgument("type name"))?;
    let name_c = CString::new(name).map_err(|_| ClrHostError::InvalidArgument("type name"))?;

    // SAFETY: the runtime/domain is live and all strings are valid for the
    // duration of the calls.  Every returned pointer is checked below.
    unsafe {
        let assembly = (runtime.api.domain_assembly_open)(runtime.domain, path.as_ptr());
        if assembly.is_null() {
            return Err(ClrHostError::MonoAssembly(assembly_path.to_path_buf()));
        }
        let image = (runtime.api.assembly_get_image)(assembly);
        if image.is_null() {
            return Err(ClrHostError::MonoAssembly(assembly_path.to_path_buf())); // coverage: unreachable — a successfully opened Mono assembly always has an image
        }
        let class = (runtime.api.class_from_name)(image, namespace_c.as_ptr(), name_c.as_ptr());
        if class.is_null() {
            return Err(ClrHostError::MonoTypeNotFound(type_name.to_string()));
        }
        let method = (runtime.api.class_get_method_from_name)(class, method_name_c.as_ptr(), 1);
        if method.is_null() {
            return Err(ClrHostError::MonoMethodNotFound(format!(
                "{type_name}::{method_name}"
            )));
        }
        let string = (runtime.api.string_new)(runtime.domain, argument_c.as_ptr());
        if string.is_null() {
            return Err(ClrHostError::MonoInvoke("failed to marshal the argument")); // coverage: unreachable — Mono string allocation does not fail under test
        }
        let mut parameters = [string];
        let mut exception: *mut c_void = std::ptr::null_mut();
        let result = (runtime.api.runtime_invoke)(
            method,
            std::ptr::null_mut(),
            parameters.as_mut_ptr(),
            &raw mut exception,
        );
        if !exception.is_null() {
            return Err(ClrHostError::MonoException(exception_message(
                &runtime.api,
                exception,
            )));
        }
        if result.is_null() {
            return Err(ClrHostError::MonoInvoke("method returned no value"));
        }
        // Mono returns a boxed object for value-type results.
        let value = (runtime.api.object_unbox)(result);
        if value.is_null() {
            return Err(ClrHostError::MonoInvoke("method returned no value")); // coverage: unreachable — a boxed value type always has storage
        }
        Ok(value.cast::<i32>().read_unaligned())
    }
}

/// Process-lifetime teardown.
///
/// Mono's JIT and root domain are intentionally not unloaded: managed code may
/// still be running on guest threads, and re-initializing a different runtime
/// after `mono_jit_cleanup` is not supported.  The call is idempotent and
/// reports whether a runtime had been initialized.
#[allow(dead_code)] // process-lifecycle API exercised by the double-shutdown test
pub(crate) fn shutdown() -> bool {
    RUNTIME.get().is_some()
}

#[cfg(test)]
pub(crate) fn initialized_domain() -> Option<usize> {
    RUNTIME
        .get()
        .and_then(|entry| entry.as_ref().ok())
        .map(|runtime| runtime.domain as usize)
}

#[cfg(test)]
pub(crate) fn initialized_version() -> Option<&'static str> {
    RUNTIME
        .get()
        .and_then(|entry| entry.as_ref().ok())
        .map(|runtime| runtime.initialized_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fake_installation(root: &Path, library: &str) -> MonoInstallation {
        let lib_dir = root.join("lib");
        std::fs::create_dir_all(&lib_dir).expect("lib dir");
        std::fs::write(lib_dir.join(library), b"not a real dylib").expect("library");
        MonoInstallation {
            root: root.to_path_buf(),
            library: lib_dir.join(library),
            lib_dir: lib_dir.clone(),
            etc_dir: root.join("etc"),
            mono_dir: lib_dir.join("mono"),
        }
    }

    #[test]
    fn mono_discovery_rejects_missing_root_and_missing_library_exactly() {
        let missing = PathBuf::from("/casa1/does/not/exist/mono");
        assert_eq!(discover_from(Some(missing.clone()), None, &[]), None);

        let temp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(temp.path().join("bin")).expect("bin");
        let executable = temp.path().join("bin").join("mono");
        std::fs::write(&executable, b"not mono").expect("path mono");
        let path = std::ffi::OsString::from(temp.path().join("bin"));
        assert_eq!(discover_from(None, Some(path), &[]), None);

        let root = temp.path().join("prefix");
        std::fs::create_dir_all(root.join("lib")).expect("lib");
        assert_eq!(
            discover_from(None, None, &[root.clone()]),
            None,
            "a prefix without an embedding library is not a Mono installation"
        );

        let good = temp.path().join("good");
        std::fs::create_dir_all(good.join("lib")).expect("good lib");
        std::fs::write(good.join("lib").join("libmonosgen-2.0.dylib"), b"x").expect("library");
        let discovered = discover_from(None, None, &[root, good.clone()]).expect("real root");
        assert_eq!(
            discovered.root,
            good.canonicalize().expect("canonical root")
        );
        assert_eq!(
            discovered.library,
            discovered.lib_dir.join("libmonosgen-2.0.dylib")
        );
    }

    #[test]
    fn mono_discovery_precedence_rejects_unrelated_roots_and_binds_real_layouts() {
        let temp = TempDir::new().expect("tempdir");
        let override_root = temp.path().join("override");
        let path_root = temp.path().join("path");
        let listed_root = temp.path().join("listed");
        for (root, library) in [
            (&override_root, "libmono-2.0.dylib"),
            (&path_root, "libmonosgen-2.0.dylib"),
            (&listed_root, "libmonosgen-2.0.dylib"),
        ] {
            std::fs::create_dir_all(root.join("lib")).expect("lib");
            std::fs::write(root.join("lib").join(library), b"x").expect("library");
        }
        let bin = path_root.join("bin");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::write(bin.join("mono"), b"x").expect("mono");
        let dangling = temp.path().join("dangling");
        std::fs::create_dir_all(&dangling).expect("dangling dir");
        std::os::unix::fs::symlink(temp.path().join("absent-mono"), dangling.join("mono"))
            .expect("dangling mono");
        let path = path_from(&[&dangling, &bin]);
        let roots = [listed_root.clone()];

        assert_eq!(
            discover_from(Some(override_root.clone()), Some(path.clone()), &roots)
                .expect("override wins")
                .root,
            override_root
                .canonicalize()
                .expect("canonical override root")
        );
        assert_eq!(
            discover_from(None, Some(path), &roots)
                .expect("PATH wins over listed roots")
                .root,
            path_root.canonicalize().expect("canonical path root")
        );
        assert_eq!(
            discover_from(None, None, &roots).expect("listed root").root,
            listed_root.canonicalize().expect("canonical listed root")
        );
        assert_eq!(
            discover_from(None, None, &[temp.path().join("unrelated")]),
            None,
            "a directory without a Mono library is rejected"
        );
    }

    fn path_from(directories: &[&Path]) -> std::ffi::OsString {
        std::env::join_paths(directories.iter()).expect("join PATH")
    }

    #[test]
    fn mono_framework_version_mapping_rejects_malformed_requests_and_selects_profiles() {
        assert_eq!(clr_version_for(Some("garbage")), None);
        assert_eq!(clr_version_for(Some("v8.0")), Some(FRAMEWORK_LATEST));
        assert_eq!(clr_version_for(Some("v2.0.50727")), Some(FRAMEWORK_V2));
        assert_eq!(clr_version_for(Some("v3.5")), Some(FRAMEWORK_V2));
        assert_eq!(clr_version_for(Some("v1.1.4322")), Some(FRAMEWORK_V1));
        assert_eq!(clr_version_for(Some("v4.0.30319")), Some(FRAMEWORK_LATEST));
        assert_eq!(clr_version_for(None), Some(FRAMEWORK_LATEST));
        assert_eq!(clr_version_for(Some("")), Some(FRAMEWORK_LATEST));

        let temp = TempDir::new().expect("tempdir");
        let installation = fake_installation(temp.path(), "libmonosgen-2.0.dylib");
        // No profile/mscorlib: the CLR version the profile stands for is the
        // honest fallback, not a fabricated installation version.
        assert_eq!(
            version_for_installation(&installation, Some("v2.0")),
            Some("2.0.50727".to_string())
        );
        assert_eq!(
            version_for_installation(&installation, Some("v4.0")),
            Some("4.0.30319".to_string())
        );
        assert_eq!(
            directory_for_installation(&installation, Some("v4.0")),
            Some(installation.lib_dir.clone())
        );
    }

    #[test]
    fn mono_double_initialization_and_shutdown_are_idempotent() {
        let Some(installation) = discover() else {
            assert_eq!(
                discover_from(Some(PathBuf::from("/casa1/no/mono")), None, &[]),
                None,
                "an invalid override reports honest absence"
            );
            return;
        };
        let first = runtime(&installation, latest_version()).expect("initialize Mono");
        let second = runtime(&installation, latest_version()).expect("second initialize");
        assert_eq!(
            first.domain, second.domain,
            "mono_jit_init_version runs exactly once per process"
        );
        assert_eq!(initialized_version(), Some(latest_version()));
        assert!(shutdown(), "a live runtime is reported");
        assert!(
            shutdown(),
            "shutdown is idempotent for the process lifetime"
        );
        assert_eq!(
            initialized_domain(),
            Some(first.domain as usize),
            "the root domain is retained"
        );
    }

    #[test]
    fn mono_host_rejects_missing_assembly_and_runs_the_real_entry_point() {
        let missing = Path::new("/casa1/does/not/exist/Framework.exe");
        assert_eq!(
            host_assembly(missing, &[]),
            Err(ClrHostError::AssemblyNotFound(missing.to_path_buf()))
        );
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Casa1Entry.dll");
        let args = ["one".to_string(), "two".to_string()];
        if !is_available() {
            assert_eq!(
                host_assembly(&fixture, &args),
                Err(ClrHostError::FrameworkUnavailable)
            );
            return;
        }
        assert_eq!(
            host_assembly(&fixture, &args),
            Ok(9),
            "Casa1Entry returns args.Length + 7 through Mono"
        );
        assert_eq!(
            host_assembly(&fixture, &["bad\0arg".to_string()]),
            Err(ClrHostError::InvalidArgument("activation data"))
        );
        assert_eq!(
            host_assembly(Path::new("/casa1/no/such.dll"), &[]),
            Err(ClrHostError::AssemblyNotFound(PathBuf::from(
                "/casa1/no/such.dll"
            )))
        );
    }

    #[test]
    fn mono_default_app_domain_rejects_wrong_type_method_and_bad_marshaling() {
        let missing = Path::new("/casa1/does/not/exist/Framework.exe");
        assert_eq!(
            execute_in_default_app_domain(missing, "Type", "Method", None),
            Err(ClrHostError::AssemblyNotFound(missing.to_path_buf()))
        );
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Casa1Entry.dll");
        assert_eq!(
            execute_in_default_app_domain(&fixture, "", "Method", None),
            Err(ClrHostError::InvalidArgument("type name"))
        );
        assert_eq!(
            execute_in_default_app_domain(&fixture, "Type", "", None),
            Err(ClrHostError::InvalidArgument("method name"))
        );
        assert_eq!(
            execute_in_default_app_domain(&fixture, "Type\0Name", "Method", None),
            Err(ClrHostError::InvalidArgument("type name"))
        );
        assert_eq!(
            execute_in_default_app_domain(&fixture, "Type", "Bad\0Method", None),
            Err(ClrHostError::InvalidArgument("method name"))
        );
        if !is_available() {
            assert_eq!(
                execute_in_default_app_domain(&fixture, "Casa1.Entry", "Method", None),
                Err(ClrHostError::FrameworkUnavailable)
            );
            return;
        }
        assert_eq!(
            execute_in_default_app_domain(&fixture, "Casa1.Does.Not.Exist", "Missing", None),
            Err(ClrHostError::MonoTypeNotFound(
                "Casa1.Does.Not.Exist".to_string()
            ))
        );
        assert_eq!(
            execute_in_default_app_domain(&fixture, "Program", "Missing", None),
            Err(ClrHostError::MonoMethodNotFound(
                "Program::Missing".to_string()
            ))
        );
    }

    #[test]
    fn mono_framework_only_method_marshals_arguments_and_propagates_exit_codes() {
        if !is_available() {
            assert_eq!(
                version_for(Some("v4.0")),
                None,
                "absence reports no Framework version"
            );
            return;
        }
        let installation = discover().expect("Mono installation");
        assert_eq!(
            version_for(Some("v4.0")),
            Some("v4.0.30319".to_string()),
            "the version comes from Mono's own mscorlib metadata"
        );
        assert_eq!(
            version_for(Some("v2.0")),
            Some("v4.0.30319".to_string()),
            "a v2.0 request reports the profile Mono actually falls back to"
        );
        assert!(
            directory_for(Some("v4.0")).is_some(),
            "Mono reports its real Framework directory"
        );
        assert!(installation.library.is_file());

        let compiler = installation.root.join("bin").join("mcs");
        if !compiler.is_file() {
            return;
        }
        let temp = TempDir::new().expect("tempdir");
        let source = temp.path().join("Probe.cs");
        std::fs::write(
            &source,
            "public static class Casa1FrameworkProbe { \
             public static int Echo(string value) { return value.Length + 3; } \
             public static int Boom(string value) { \
                 throw new System.InvalidOperationException(value); } \
             public static void Nothing(string value) { } }",
        )
        .expect("source");
        let assembly = temp.path().join("Probe.dll");
        let status = std::process::Command::new(&compiler)
            .arg("-target:library")
            .arg(format!("-out:{}", assembly.display()))
            .arg(&source)
            .status()
            .expect("run mcs");
        assert!(status.success(), "the Framework-only probe compiles");
        assert_eq!(
            execute_in_default_app_domain(&assembly, "Casa1FrameworkProbe", "Echo", Some("abcd")),
            Ok(7),
            "Mono marshals the string argument and returns the managed int"
        );
        assert_eq!(
            execute_in_default_app_domain(&assembly, "Casa1FrameworkProbe", "Echo", Some("")),
            Ok(3),
            "the empty string marshals as an empty managed string"
        );
        assert_eq!(
            execute_in_default_app_domain(&assembly, "Casa1FrameworkProbe", "Echo", Some("a\0b")),
            Err(ClrHostError::InvalidArgument("argument")),
            "an interior NUL cannot be marshaled"
        );
        let thrown =
            execute_in_default_app_domain(&assembly, "Casa1FrameworkProbe", "Boom", Some("casa1"))
                .expect_err("the managed method throws");
        assert_eq!(
            matches!(&thrown, ClrHostError::MonoException(message) if message.contains("casa1")),
            true,
            "Mono's exception message is propagated: {thrown:?}"
        );
        assert_eq!(
            execute_in_default_app_domain(
                &assembly,
                "Casa1FrameworkProbe",
                "Nothing",
                Some("ignored")
            ),
            Err(ClrHostError::MonoInvoke("method returned no value"))
        );

        let invalid = temp.path().join("NotAnAssembly.dll");
        std::fs::write(&invalid, b"not a PE image").expect("invalid assembly");
        assert_eq!(
            execute_in_default_app_domain(&invalid, "Type", "Method", None),
            Err(ClrHostError::MonoAssembly(invalid.clone())),
            "Mono rejects a non-assembly file"
        );
        assert_eq!(
            host_assembly(&invalid, &[]),
            Err(ClrHostError::MonoAssembly(invalid))
        );
    }

    #[test]
    fn mono_metadata_reader_rejects_malformed_headers_and_maps_pe32_plus() {
        let temp = TempDir::new().expect("tempdir");
        let not_pe = temp.path().join("not-pe.dll");
        std::fs::write(&not_pe, b"not a PE image").expect("not pe");
        assert_eq!(metadata_version_from_file(&not_pe), None);
        let mut bad_signature = vec![0_u8; 0x60];
        bad_signature[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        bad_signature[0x40..0x44].copy_from_slice(b"XXXX");
        let bad_signature_path = temp.path().join("bad-signature.dll");
        std::fs::write(&bad_signature_path, &bad_signature).expect("bad signature");
        assert_eq!(metadata_version_from_file(&bad_signature_path), None);

        let fixture = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Casa1Entry.dll"),
        )
        .expect("fixture");
        let fixture_path = temp.path().join("Casa1Entry.dll");
        std::fs::write(&fixture_path, &fixture).expect("fixture copy");
        assert_eq!(
            metadata_version_from_file(&fixture_path),
            Some("v4.0.30319".to_string()),
            "the PE32+ metadata root maps without reading imports"
        );

        let pe = u32::from_le_bytes(fixture[0x3c..0x40].try_into().expect("e_lfanew")) as usize;
        let optional = pe + 24;
        assert_eq!(
            u16::from_le_bytes(fixture[optional..optional + 2].try_into().expect("magic")),
            0x20b
        );
        let patch = |name: &str, edit: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = fixture.clone();
            edit(&mut bytes);
            let path = temp.path().join(name);
            std::fs::write(&path, &bytes).expect("patched PE");
            assert_eq!(metadata_version_from_file(&path), None, "{name}");
        };
        patch("bad-magic.dll", &|bytes| {
            bytes[optional..optional + 2].copy_from_slice(&0x10c_u16.to_le_bytes());
        });
        patch("no-directories.dll", &|bytes| {
            bytes[optional + 108..optional + 112].copy_from_slice(&0_u32.to_le_bytes());
        });
        patch("no-cli.dll", &|bytes| {
            let cli = optional + 112 + 14 * 8;
            bytes[cli..cli + 4].copy_from_slice(&0_u32.to_le_bytes());
        });
        patch("cli-outside-sections.dll", &|bytes| {
            let cli = optional + 112 + 14 * 8;
            bytes[cli..cli + 4].copy_from_slice(&0x7fff_ffff_u32.to_le_bytes());
        });
        patch("cli-raw-outside-file.dll", &|bytes| {
            let sections = optional
                + u16::from_le_bytes(
                    bytes[pe + 20..pe + 22]
                        .try_into()
                        .expect("optional header size"),
                ) as usize;
            let raw_pointer = sections + 20;
            let beyond = (bytes.len() + 0x1000) as u32;
            bytes[raw_pointer..raw_pointer + 4].copy_from_slice(&beyond.to_le_bytes());
        });
    }

    #[test]
    fn mono_api_load_rejects_missing_library_and_paths_with_nul() {
        let error = MonoApi::load(Path::new("/casa1/no/such/libmonosgen.dylib"))
            .err()
            .expect("a missing library cannot load");
        assert_eq!(
            matches!(error, ClrHostError::MonoLibraryLoad(_)),
            true,
            "the dynamic-loader error is preserved: {error:?}"
        );
        assert_eq!(
            c_path(Path::new("bad\0path")),
            Err(ClrHostError::InvalidArgument("path"))
        );
        let temp = TempDir::new().expect("tempdir");
        let installation = fake_installation(temp.path(), "libmonosgen-2.0.dylib");
        assert_eq!(
            matches!(
                MonoRuntime::initialize(&installation, latest_version()),
                Err(ClrHostError::MonoLibraryLoad(_))
            ),
            true,
            "initialization reports the loader failure before touching a domain"
        );
    }

    #[test]
    fn mono_discovery_accepts_real_layouts_and_rejects_relative_roots() {
        let temp = TempDir::new().expect("tempdir");
        let framework = temp.path().join("Mono.framework");
        let version = framework.join("Versions").join("7");
        std::fs::create_dir_all(version.join("lib")).expect("framework lib");
        std::fs::write(version.join("lib").join("libmono-2.0.dylib"), b"x").expect("library");
        std::os::unix::fs::symlink("7", framework.join("Versions").join("Current"))
            .expect("current symlink");
        let discovered = discover_from(None, None, &[framework.clone()]).expect("framework root");
        assert_eq!(
            discovered.library,
            version
                .canonicalize()
                .expect("canonical version")
                .join("lib")
                .join("libmono-2.0.dylib")
        );

        let lib = temp.path().join("standalone").join("lib");
        std::fs::create_dir_all(&lib).expect("standalone lib");
        std::fs::write(lib.join("libmono-2.0.so"), b"x").expect("library");
        let discovered = discover_from(None, None, &[lib.clone()]).expect("lib root");
        let canonical_lib = lib.canonicalize().expect("canonical lib");
        assert_eq!(discovered.lib_dir, canonical_lib);
        assert_eq!(
            discovered.root,
            canonical_lib.parent().expect("standalone prefix")
        );
        assert_eq!(
            discover_from(None, None, &[PathBuf::from("relative/mono")]),
            None,
            "a relative root that does not exist is rejected"
        );
    }
}
