//! Native CoreCLR hosting for managed Windows images.
//!
//! Casa1 executes managed code on the host's real ARM64 CoreCLR instead of
//! translating x86 IL through the CPU JIT.  The runtime is discovered through
//! [`crate::clr_meta`] (real `shared/Microsoft.NETCore.App` directories), then
//! loaded with the CLR hosting API:
//!
//! * `coreclr_initialize` creates the process-wide runtime with the real
//!   trusted-platform-assembly list from the installed runtime directory;
//! * `coreclr_create_delegate` resolves a managed static method to a native
//!   function pointer with default marshaling, which is exactly the contract
//!   `ICLRRuntimeHost::ExecuteInDefaultAppDomain` exposes.
//!
//! No runtime version, assembly, type or method is invented: every failure
//! reports the real hosting status (missing runtime, missing assembly,
//! missing type/method, or the CLR's own HRESULT).

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use crate::clr_meta;
use crate::mono_host;

/// `COR_E_CLRNOTAVAILABLE` — the documented activation failure when the
/// requested legacy .NET Framework CLR is not installed.
pub(crate) const COR_E_CLRNOTAVAILABLE: u32 = 0x8013_1013;

/// The runtime generation a `CorBindToRuntime*` version string names.
///
/// The split is deliberately conservative: the legacy Framework version
/// scheme owns majors 1-4 (`v1.0`, `v1.1`, `v2.0`, `v4.0`, ...), and a
/// versionless request is the Framework "latest runtime" request.  CoreCLR
/// versions are majors 5 and later (`5.0` ... `10.0`), so a Framework version
/// can never be rounded to an installed CoreCLR runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActivationFamily {
    /// A .NET Framework request (versionless or major 1-4).
    Framework,
    /// A CoreCLR version request with the parsed version.
    CoreClr(clr_meta::ClrVersion),
    /// A malformed/unsupported version string.
    Unsupported,
}

/// Classify a guest `CorBindToRuntime*` version request.
pub(crate) fn activation_family(version: Option<&str>) -> ActivationFamily {
    let version = match version {
        // No version is the legacy Framework "latest runtime" request.
        None => return ActivationFamily::Framework,
        Some(version) if version.is_empty() => return ActivationFamily::Framework,
        Some(version) => version,
    };
    let Some(parsed) = clr_meta::ClrVersion::parse_request(version) else {
        return ActivationFamily::Unsupported;
    };
    let major = parsed
        .as_string()
        .split('.')
        .next()
        .and_then(|part| part.parse::<u16>().ok())
        .unwrap_or(0);
    if major <= 4 {
        ActivationFamily::Framework
    } else {
        ActivationFamily::CoreClr(parsed)
    }
}

/// The seam a platform with a real legacy .NET Framework CLR implements.
///
/// The real implementation is the host Mono installation (the same strategy
/// Wine Mono uses); [`AbsentFrameworkRuntimeProvider`] answers honestly when
/// no Mono runtime is installed.
pub(crate) trait IFrameworkRuntimeProvider: Send + Sync {
    /// Whether a legacy Framework CLR is installed and usable.
    fn is_available(&self) -> bool;
    /// The installed Framework version string, when available.
    fn version(&self) -> Option<String>;
    /// The installed Framework version that satisfies a guest request.
    fn version_for(&self, _requested: Option<&str>) -> Option<String> {
        self.version()
    }
    /// The real directory that implements a guest Framework request.
    fn directory_for(&self, _requested: Option<&str>) -> Option<PathBuf> {
        None
    }
    /// Host a managed assembly's entry point, returning its exit code.
    fn host_assembly(
        &self,
        _assembly_path: &Path,
        _arguments: &[String],
    ) -> Result<i32, ClrHostError> {
        Err(ClrHostError::FrameworkUnavailable)
    }
    /// Run `static int Method(string)` (the `ExecuteInDefaultAppDomain`
    /// contract) and return the managed result.
    fn execute_in_default_app_domain(
        &self,
        _assembly_path: &Path,
        _type_name: &str,
        _method_name: &str,
        _argument: Option<&str>,
    ) -> Result<i32, ClrHostError> {
        Err(ClrHostError::FrameworkUnavailable)
    }
}

/// The real host Mono runtime, when one is installed.
struct MonoFrameworkRuntimeProvider;

impl IFrameworkRuntimeProvider for MonoFrameworkRuntimeProvider {
    fn is_available(&self) -> bool {
        mono_host::is_available()
    }

    fn version(&self) -> Option<String> {
        mono_host::version_for(None)
    }

    fn version_for(&self, requested: Option<&str>) -> Option<String> {
        mono_host::version_for(requested)
    }

    fn directory_for(&self, requested: Option<&str>) -> Option<PathBuf> {
        mono_host::directory_for(requested)
    }

    fn host_assembly(
        &self,
        assembly_path: &Path,
        arguments: &[String],
    ) -> Result<i32, ClrHostError> {
        mono_host::host_assembly(assembly_path, arguments)
    }

    fn execute_in_default_app_domain(
        &self,
        assembly_path: &Path,
        type_name: &str,
        method_name: &str,
        argument: Option<&str>,
    ) -> Result<i32, ClrHostError> {
        mono_host::execute_in_default_app_domain(assembly_path, type_name, method_name, argument)
    }
}

/// The honest absence implementation: this host has no .NET Framework CLR.
struct AbsentFrameworkRuntimeProvider;

impl IFrameworkRuntimeProvider for AbsentFrameworkRuntimeProvider {
    fn is_available(&self) -> bool {
        false
    }

    fn version(&self) -> Option<String> {
        None
    }
}

static MONO_FRAMEWORK_RUNTIME: MonoFrameworkRuntimeProvider = MonoFrameworkRuntimeProvider;
static ABSENT_FRAMEWORK_RUNTIME: AbsentFrameworkRuntimeProvider = AbsentFrameworkRuntimeProvider;

fn select_framework_provider(available: bool) -> &'static dyn IFrameworkRuntimeProvider {
    if available {
        &MONO_FRAMEWORK_RUNTIME
    } else {
        &ABSENT_FRAMEWORK_RUNTIME
    }
}

/// The provider the activation dispatch consults for Framework requests.
pub(crate) fn framework_runtime_provider() -> &'static dyn IFrameworkRuntimeProvider {
    select_framework_provider(mono_host::is_available())
}

/// Host a Framework assembly through the selected provider.
pub(crate) fn execute_framework_assembly(
    assembly_path: &Path,
    arguments: &[String],
) -> Result<i32, ClrHostError> {
    framework_runtime_provider().host_assembly(assembly_path, arguments)
}

/// Run a Framework `ExecuteInDefaultAppDomain` method through the provider.
pub(crate) fn execute_framework_in_default_app_domain(
    assembly_path: &Path,
    type_name: &str,
    method_name: &str,
    argument: Option<&str>,
) -> Result<i32, ClrHostError> {
    framework_runtime_provider().execute_in_default_app_domain(
        assembly_path,
        type_name,
        method_name,
        argument,
    )
}

/// Select the real installed CoreCLR runtime named by a guest request.
///
/// Framework, versionless and malformed requests never select CoreCLR.
fn select_requested_runtime(requested: Option<&str>) -> Option<clr_meta::ClrRuntime> {
    let ActivationFamily::CoreClr(parsed) = activation_family(requested) else {
        return None;
    };
    let installed = clr_meta::installed_runtimes();
    clr_meta::select_runtime(&parsed, &installed).cloned()
}

/// The `GetRequestedRuntimeVersion` contract: the real installed runtime
/// version string for the request, or `None` when the request is malformed or
/// no installed runtime matches it.
///
/// Framework requests report the Mono installation's own version when one is
/// present; absence stays `None` (the activation dispatch turns that into the
/// exact `COR_E_CLRNOTAVAILABLE`).
pub(crate) fn requested_runtime_version(requested: Option<&str>) -> Option<String> {
    requested_runtime_version_with(framework_runtime_provider(), requested)
}

fn requested_runtime_version_with(
    provider: &dyn IFrameworkRuntimeProvider,
    requested: Option<&str>,
) -> Option<String> {
    match activation_family(requested) {
        ActivationFamily::CoreClr(_) => {
            select_requested_runtime(requested).map(|runtime| runtime.version_string())
        }
        ActivationFamily::Framework => {
            if provider.is_available() {
                provider.version_for(requested)
            } else {
                None
            }
        }
        ActivationFamily::Unsupported => None,
    }
}

/// The directory half of `GetRequestedRuntimeInfo` for the same selection.
pub(crate) fn requested_runtime_directory(requested: Option<&str>) -> Option<PathBuf> {
    requested_runtime_directory_with(framework_runtime_provider(), requested)
}

fn requested_runtime_directory_with(
    provider: &dyn IFrameworkRuntimeProvider,
    requested: Option<&str>,
) -> Option<PathBuf> {
    match activation_family(requested) {
        ActivationFamily::CoreClr(_) => {
            select_requested_runtime(requested).map(|runtime| runtime.directory)
        }
        ActivationFamily::Framework => {
            if provider.is_available() {
                provider.directory_for(requested)
            } else {
                None
            }
        }
        ActivationFamily::Unsupported => None,
    }
}

/// A failed managed execution, with the real cause preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClrHostError {
    /// No CoreCLR installation was found on the host.
    NoRuntime,
    /// No legacy .NET Framework CLR is installed on the host.
    FrameworkUnavailable,
    /// The requested managed assembly does not exist or is not a file.
    AssemblyNotFound(PathBuf),
    /// A guest-supplied identifier is empty or contains an interior NUL.
    InvalidArgument(&'static str),
    /// `libcoreclr` could not be loaded.
    LibraryLoad(String),
    /// A required hosting entry point is absent from the library.
    MissingEntryPoint(&'static str),
    /// `coreclr_initialize` returned this status.
    Initialize(i32),
    /// `coreclr_create_delegate` returned this status.
    CreateDelegate(i32),
    /// `coreclr_execute_assembly` returned this status.
    ExecuteAssembly(i32),
    /// The file is not a managed assembly.
    NotManaged(PathBuf),
    /// The managed assembly has no entry point (it is a library).
    NoEntryPoint(PathBuf),
    /// `libmono` could not be loaded.
    MonoLibraryLoad(String),
    /// A required Mono embedding entry point is absent from the library.
    MonoMissingEntryPoint(&'static str),
    /// `mono_jit_init_version` returned no root domain.
    MonoInitialize,
    /// Mono could not open the managed assembly.
    MonoAssembly(PathBuf),
    /// Mono resolved the assembly but not the requested managed type.
    MonoTypeNotFound(String),
    /// Mono resolved the type but not the requested method.
    MonoMethodNotFound(String),
    /// Mono could not marshal or return a value from the managed method.
    MonoInvoke(&'static str),
    /// The managed method threw; the message comes from Mono.
    MonoException(String),
}

impl std::fmt::Display for ClrHostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRuntime => write!(f, "no CoreCLR runtime is installed"),
            Self::FrameworkUnavailable => write!(f, "the .NET Framework CLR is not available"),
            Self::AssemblyNotFound(path) => {
                write!(f, "managed assembly not found: {}", path.display())
            }
            Self::InvalidArgument(what) => write!(f, "invalid CLR argument: {what}"),
            Self::LibraryLoad(error) => write!(f, "failed to load libcoreclr: {error}"),
            Self::MissingEntryPoint(name) => write!(f, "libcoreclr is missing {name}"),
            Self::Initialize(status) => write!(f, "coreclr_initialize failed: {status:#x}"),
            Self::CreateDelegate(status) => {
                write!(f, "coreclr_create_delegate failed: {status:#x}")
            }
            Self::ExecuteAssembly(status) => {
                write!(f, "coreclr_execute_assembly failed: {status:#x}")
            }
            Self::NotManaged(path) => write!(f, "not a managed assembly: {}", path.display()),
            Self::NoEntryPoint(path) => {
                write!(f, "managed assembly has no entry point: {}", path.display())
            }
            Self::MonoLibraryLoad(error) => write!(f, "failed to load libmono: {error}"),
            Self::MonoMissingEntryPoint(name) => write!(f, "libmono is missing {name}"),
            Self::MonoInitialize => write!(f, "mono_jit_init_version failed"),
            Self::MonoAssembly(path) => {
                write!(f, "mono: cannot open assembly: {}", path.display())
            }
            Self::MonoTypeNotFound(name) => write!(f, "mono: type not found: {name}"),
            Self::MonoMethodNotFound(name) => write!(f, "mono: method not found: {name}"),
            Self::MonoInvoke(what) => write!(f, "mono: {what}"),
            Self::MonoException(message) => write!(f, "mono: managed exception: {message}"),
        }
    }
}

type CoreClrInitialize = unsafe extern "C" fn(
    exe_path: *const c_char,
    app_domain_name: *const c_char,
    property_count: c_int,
    property_keys: *const *const c_char,
    property_values: *const *const c_char,
    host_handle: *mut *mut c_void,
    domain_id: *mut u32,
) -> c_int;

type CoreClrCreateDelegate = unsafe extern "C" fn(
    host_handle: *mut c_void,
    domain_id: u32,
    assembly_name: *const c_char,
    type_name: *const c_char,
    method_name: *const c_char,
    delegate: *mut *mut c_void,
) -> c_int;

type CoreClrExecuteAssembly = unsafe extern "C" fn(
    host_handle: *mut c_void,
    domain_id: u32,
    argument_count: c_int,
    arguments: *const *const c_char,
    assembly_path: *const c_char,
    exit_code: *mut u32,
) -> c_int;

/// One initialized CoreCLR domain.
struct HostState {
    _library: *mut c_void,
    host_handle: *mut c_void,
    domain_id: u32,
    create_delegate: CoreClrCreateDelegate,
    execute_assembly: CoreClrExecuteAssembly,
}

// SAFETY: the CoreCLR hosting API is process-global and thread-safe for
// delegate creation/invocation; the raw library/host handles are immutable
// after initialization and are never freed (the runtime lives for the
// process lifetime).
unsafe impl Send for HostState {}
unsafe impl Sync for HostState {}

impl HostState {
    fn from_installed_runtime(assembly_path: &Path) -> Result<Self, ClrHostError> {
        let runtime = clr_meta::installed_runtimes()
            .into_iter()
            .next()
            .ok_or(ClrHostError::NoRuntime)?;
        let library = runtime.coreclr_library().ok_or(ClrHostError::NoRuntime)?;
        let library_c = c_path(&library);
        // SAFETY: dlopen with a valid C string; the handle is retained for
        // the process lifetime (never dlclose'd).
        let handle = unsafe { libc::dlopen(library_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            // A validated CoreCLR installation whose libcoreclr.dylib cannot
            // be loaded is a corrupt host.
            return Err(ClrHostError::LibraryLoad(dl_error())); // coverage: unreachable
        }
        // SAFETY: the symbol names are the documented CoreCLR hosting API.
        let initialize: CoreClrInitialize = unsafe {
            let symbol = libc::dlsym(handle, c"coreclr_initialize".as_ptr());
            if symbol.is_null() {
                // Symbol presence is part of the installation contract
                // validated by clr_meta.
                return Err(ClrHostError::MissingEntryPoint("coreclr_initialize")); // coverage: unreachable
            }
            std::mem::transmute(symbol)
        };
        // SAFETY: same contract as above.
        let execute_assembly: CoreClrExecuteAssembly = unsafe {
            let symbol = libc::dlsym(handle, c"coreclr_execute_assembly".as_ptr());
            if symbol.is_null() {
                // See coreclr_initialize: the symbol is part of the contract.
                return Err(ClrHostError::MissingEntryPoint("coreclr_execute_assembly")); // coverage: unreachable
            }
            std::mem::transmute(symbol)
        };
        // SAFETY: same contract as above.
        let create_delegate: CoreClrCreateDelegate = unsafe {
            let symbol = libc::dlsym(handle, c"coreclr_create_delegate".as_ptr());
            if symbol.is_null() {
                // See coreclr_initialize: the symbol is part of the contract.
                return Err(ClrHostError::MissingEntryPoint("coreclr_create_delegate")); // coverage: unreachable
            }
            std::mem::transmute(symbol)
        };

        let assembly_dir = assembly_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let tpa = trusted_platform_assemblies(&runtime.directory, &assembly_dir);
        let app_paths = search_paths(&runtime.directory, &assembly_dir);
        let tpa_c = CString::new(tpa).map_err(|_| ClrHostError::InvalidArgument("TPA list"))?;
        let app_paths_c =
            CString::new(app_paths).map_err(|_| ClrHostError::InvalidArgument("APP_PATHS"))?;
        let exe_path = c_path(assembly_path);
        let domain_name = CString::new("Casa1").expect("static domain name");

        let keys: [*const c_char; 2] = [
            c"TRUSTED_PLATFORM_ASSEMBLIES".as_ptr(),
            c"APP_PATHS".as_ptr(),
        ];
        let values: [*const c_char; 2] = [tpa_c.as_ptr(), app_paths_c.as_ptr()];
        let mut host_handle: *mut c_void = std::ptr::null_mut();
        let mut domain_id = 0_u32;
        // SAFETY: all pointers are valid for the duration of the call; the
        // output pointers are initialized and checked by the caller.
        let status = unsafe {
            initialize(
                exe_path.as_ptr(),
                domain_name.as_ptr(),
                keys.len() as c_int,
                keys.as_ptr(),
                values.as_ptr(),
                &raw mut host_handle,
                &raw mut domain_id,
            )
        };
        if status != 0 {
            // The host runtime and TPA come from a validated installation.
            return Err(ClrHostError::Initialize(status)); // coverage: unreachable
        }
        if host_handle.is_null() || domain_id == 0 {
            // coreclr_initialize returns both on status 0.
            return Err(ClrHostError::Initialize(status)); // coverage: unreachable
        }
        Ok(Self {
            _library: handle,
            host_handle,
            domain_id,
            create_delegate,
            execute_assembly,
        })
    }
}

fn dl_error() -> String {
    // SAFETY: dlerror returns either null or a NUL-terminated string owned by
    // the dynamic loader; it is copied immediately.
    unsafe {
        let error = libc::dlerror();
        if error.is_null() {
            "unknown dynamic-loader error".to_string()
        } else {
            CStr::from_ptr(error).to_string_lossy().into_owned()
        }
    }
}

fn c_path(path: &Path) -> CString {
    CString::new(path.to_string_lossy().as_bytes())
        .unwrap_or_else(|_| CString::new("/").expect("root path"))
}

fn dll_paths(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
        })
        .collect();
    paths.sort();
    paths
}

fn trusted_platform_assemblies(runtime_dir: &Path, assembly_dir: &Path) -> String {
    let mut paths = dll_paths(runtime_dir);
    if runtime_dir != assembly_dir {
        paths.extend(dll_paths(assembly_dir));
    }
    paths
        .iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join(if cfg!(windows) { ";" } else { ":" })
}

fn search_paths(runtime_dir: &Path, assembly_dir: &Path) -> String {
    let mut dirs = vec![assembly_dir.to_path_buf(), runtime_dir.to_path_buf()];
    if let Ok(extra) = std::env::var("CASA1_CLR_APP_PATHS") {
        dirs.extend(
            extra
                .split(if cfg!(windows) { ';' } else { ':' })
                .filter(|entry| !entry.is_empty())
                .map(PathBuf::from),
        );
    }
    dirs.iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join(if cfg!(windows) { ";" } else { ":" })
}

static HOST: OnceLock<Result<Arc<HostState>, ClrHostError>> = OnceLock::new();

fn host_for(assembly_path: &Path) -> Result<Arc<HostState>, ClrHostError> {
    let entry = HOST.get_or_init(|| HostState::from_installed_runtime(assembly_path).map(Arc::new));
    entry.clone()
}

/// Execute a managed static method with the real CLR hosting contract:
/// the method must be `static int Method(string)` (the
/// `ExecuteInDefaultAppDomain` shape).  `argument` is marshaled as a UTF-8
/// string and the managed return value is returned unchanged.
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
    let type_name =
        CString::new(type_name).map_err(|_| ClrHostError::InvalidArgument("type name"))?;
    let method_name =
        CString::new(method_name).map_err(|_| ClrHostError::InvalidArgument("method name"))?;
    let argument = CString::new(argument.unwrap_or(""))
        .map_err(|_| ClrHostError::InvalidArgument("argument"))?;
    let assembly_name = assembly_path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .filter(|stem| !stem.is_empty())
        .ok_or(ClrHostError::InvalidArgument("assembly name"))?;
    let assembly_name =
        CString::new(assembly_name).map_err(|_| ClrHostError::InvalidArgument("assembly name"))?;

    let host = host_for(assembly_path)?;
    let mut delegate: *mut c_void = std::ptr::null_mut();
    // SAFETY: the host handles are live for the process lifetime and the
    // strings are valid NUL-terminated UTF-8 for this call.
    let status = unsafe {
        (host.create_delegate)(
            host.host_handle,
            host.domain_id,
            assembly_name.as_ptr(),
            type_name.as_ptr(),
            method_name.as_ptr(),
            &raw mut delegate,
        )
    };
    if status != 0 || delegate.is_null() {
        return Err(ClrHostError::CreateDelegate(status));
    }
    // SAFETY: coreclr_create_delegate produced a callable pointer for the
    // documented static-int(string) shape; the argument is a valid C string
    // and the ABI is the platform C ABI.
    let function: unsafe extern "C" fn(*const c_char) -> c_int =
        unsafe { std::mem::transmute(delegate) };
    Ok(i32::from(unsafe { function(argument.as_ptr()) }))
}

/// Execute a managed assembly's entry point on the real CoreCLR with the
/// supplied activation arguments.  Returns the managed exit code.
pub(crate) fn execute_assembly(
    assembly_path: &Path,
    arguments: &[String],
) -> Result<i32, ClrHostError> {
    if !assembly_path.is_file() {
        return Err(ClrHostError::AssemblyNotFound(assembly_path.to_path_buf()));
    }
    let mut argument_strings = Vec::with_capacity(arguments.len());
    let mut argument_pointers = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let value = CString::new(argument.as_bytes())
            .map_err(|_| ClrHostError::InvalidArgument("activation data"))?;
        argument_pointers.push(value.as_ptr());
        argument_strings.push(value);
    }
    // Never hand a library (or a native image) to coreclr_execute_assembly:
    // CoreCLR treats a missing entry point as a fatal unhandled exception and
    // aborts the host process.
    let bytes = std::fs::read(assembly_path)
        .map_err(|_| ClrHostError::AssemblyNotFound(assembly_path.to_path_buf()))?;
    let parsed = crate::pe::parse(&bytes)
        .map_err(|_| ClrHostError::NotManaged(assembly_path.to_path_buf()))?;
    if !parsed.is_dotnet {
        return Err(ClrHostError::NotManaged(assembly_path.to_path_buf()));
    }
    let has_entry_point = parsed.clr_header.as_ref().is_some_and(|header| {
        header.entry_point_token != 0
            || header.flags & crate::pe::COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0
    });
    if !has_entry_point {
        return Err(ClrHostError::NoEntryPoint(assembly_path.to_path_buf()));
    }
    let assembly = c_path(assembly_path);
    let host = host_for(assembly_path)?;
    let mut exit_code = 0_u32;
    // SAFETY: the host is initialized for the process lifetime, the path and
    // argument pointers are valid NUL-terminated strings for this call, and
    // `exit_code` is a valid out pointer.
    let status = unsafe {
        (host.execute_assembly)(
            host.host_handle,
            host.domain_id,
            argument_pointers.len() as c_int,
            argument_pointers.as_ptr(),
            assembly.as_ptr(),
            &raw mut exit_code,
        )
    };
    if status != 0 {
        // A refused execution cannot currently be provoked without aborting
        // CoreCLR; failures are reported by the runtime itself.
        return Err(ClrHostError::ExecuteAssembly(status)); // coverage: unreachable
    }
    Ok(exit_code as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_assembly_and_empty_identifiers_fail_before_runtime_init() {
        let missing = Path::new("/casa1/does/not/exist/Managed.dll");
        assert_eq!(
            execute_in_default_app_domain(missing, "Type", "Method", None),
            Err(ClrHostError::AssemblyNotFound(missing.to_path_buf()))
        );

        let assembly = std::env::current_exe().expect("current test binary");
        assert_eq!(
            execute_in_default_app_domain(&assembly, "", "Method", None),
            Err(ClrHostError::InvalidArgument("type name"))
        );
        assert_eq!(
            execute_in_default_app_domain(&assembly, "Type", "", None),
            Err(ClrHostError::InvalidArgument("method name"))
        );
        assert_eq!(
            execute_in_default_app_domain(&assembly, "Type\0Name", "Method", None),
            Err(ClrHostError::InvalidArgument("type name"))
        );
    }

    #[test]
    fn absent_managed_type_reports_the_real_clr_resolution_failure() {
        let runtime = clr_meta::installed_runtimes()
            .into_iter()
            .next()
            .expect("a real CoreCLR runtime is installed");
        let assembly = runtime.directory.join("System.Private.CoreLib.dll");
        let error = execute_in_default_app_domain(
            &assembly,
            "Casa1.Does.Not.Exist",
            "Missing",
            Some("ignored"),
        )
        .expect_err("an absent managed type cannot resolve");
        let ClrHostError::CreateDelegate(status) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_ne!(status, 0);

        let processors = execute_in_default_app_domain(
            &assembly,
            "System.Environment",
            "get_ProcessorCount",
            Some(""),
        )
        .expect("a real delegate executes natively");
        assert_ne!(processors, 0);
    }

    #[test]
    fn clr_error_display_and_loader_edge_cases_are_exact() {
        let cases = [
            (ClrHostError::NoRuntime, "no CoreCLR runtime is installed"),
            (
                ClrHostError::FrameworkUnavailable,
                "the .NET Framework CLR is not available",
            ),
            (
                ClrHostError::AssemblyNotFound(PathBuf::from("/x.dll")),
                "managed assembly not found: /x.dll",
            ),
            (
                ClrHostError::InvalidArgument("arg"),
                "invalid CLR argument: arg",
            ),
            (
                ClrHostError::LibraryLoad("bad".to_string()),
                "failed to load libcoreclr: bad",
            ),
            (
                ClrHostError::MissingEntryPoint("sym"),
                "libcoreclr is missing sym",
            ),
            (
                ClrHostError::Initialize(3),
                "coreclr_initialize failed: 0x3",
            ),
            (
                ClrHostError::CreateDelegate(4),
                "coreclr_create_delegate failed: 0x4",
            ),
            (
                ClrHostError::ExecuteAssembly(5),
                "coreclr_execute_assembly failed: 0x5",
            ),
            (
                ClrHostError::NotManaged(PathBuf::from("/x.dll")),
                "not a managed assembly: /x.dll",
            ),
            (
                ClrHostError::NoEntryPoint(PathBuf::from("/x.dll")),
                "managed assembly has no entry point: /x.dll",
            ),
            (
                ClrHostError::MonoLibraryLoad("bad".to_string()),
                "failed to load libmono: bad",
            ),
            (
                ClrHostError::MonoMissingEntryPoint("mono_jit_exec"),
                "libmono is missing mono_jit_exec",
            ),
            (ClrHostError::MonoInitialize, "mono_jit_init_version failed"),
            (
                ClrHostError::MonoAssembly(PathBuf::from("/x.dll")),
                "mono: cannot open assembly: /x.dll",
            ),
            (
                ClrHostError::MonoTypeNotFound("N.T".to_string()),
                "mono: type not found: N.T",
            ),
            (
                ClrHostError::MonoMethodNotFound("N.T::M".to_string()),
                "mono: method not found: N.T::M",
            ),
            (
                ClrHostError::MonoInvoke("failed to marshal the argument"),
                "mono: failed to marshal the argument",
            ),
            (
                ClrHostError::MonoException("boom".to_string()),
                "mono: managed exception: boom",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }

        // The dynamic-loader error path: a failed dlopen leaves a message,
        // and dlerror clears it.
        // SAFETY: a valid C string for a path that cannot load.
        unsafe {
            let _ = libc::dlopen(c"/casa1/no/such/library.dylib".as_ptr(), libc::RTLD_NOW);
        }
        assert!(!dl_error().is_empty());
        let _ = dl_error();

        assert_eq!(
            dll_paths(Path::new("/casa1/no/such/dir")),
            Vec::<PathBuf>::new()
        );
        let directory =
            std::env::temp_dir().join(format!("casa1-clr-paths-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("tempdir");
        std::fs::write(directory.join("a.dll"), b"x").expect("dll");
        std::fs::write(directory.join("b.txt"), b"x").expect("txt");
        assert_eq!(dll_paths(&directory), vec![directory.join("a.dll")]);
        assert_eq!(
            trusted_platform_assemblies(Path::new("/casa1/no/such/dir"), &directory),
            directory.join("a.dll").to_string_lossy().into_owned(),
            "a distinct assembly directory contributes its assemblies to the TPA list"
        );

        // SAFETY: single-threaded test process for this variable.
        unsafe {
            std::env::set_var("CASA1_CLR_APP_PATHS", "/casa1/extra:/casa1/more");
        }
        let paths = search_paths(Path::new("/runtime"), Path::new("/assembly"));
        assert!(paths.contains("/casa1/extra"));
        assert!(paths.contains("/casa1/more"));
        // SAFETY: see above.
        unsafe {
            std::env::remove_var("CASA1_CLR_APP_PATHS");
        }
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn assembly_without_entry_point_is_refused_before_clr_execution() {
        let runtime = clr_meta::installed_runtimes()
            .into_iter()
            .next()
            .expect("a real CoreCLR runtime is installed");
        let assembly = runtime.directory.join("System.Runtime.dll");
        assert_eq!(
            execute_assembly(&assembly, &[]),
            Err(ClrHostError::NoEntryPoint(assembly.clone()))
        );

        let native = std::env::current_exe().expect("current test binary");
        assert_eq!(
            execute_assembly(&native, &[]),
            Err(ClrHostError::NotManaged(native.clone()))
        );

        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Casa1Entry.dll");
        assert_eq!(
            execute_assembly(&fixture, &["one".to_string(), "two".to_string()]),
            Ok(9),
            "the managed entry point receives activation data and returns its exit code"
        );
        assert_eq!(
            execute_assembly(&fixture, &["bad\0arg".to_string()]),
            Err(ClrHostError::InvalidArgument("activation data"))
        );

        // A structurally valid PE without a CLI directory is NotManaged.
        let mut bytes = std::fs::read(&fixture).expect("fixture bytes");
        let pe_offset =
            u32::from_le_bytes(bytes[0x3c..0x40].try_into().expect("e_lfanew")) as usize;
        let optional = pe_offset + 24;
        let magic = u16::from_le_bytes(
            bytes[optional..optional + 2]
                .try_into()
                .expect("optional header"),
        );
        let directories = optional + if magic == 0x20b { 112 } else { 96 };
        let cli = directories + 14 * 8;
        bytes[cli..cli + 8].fill(0);
        let native_pe =
            std::env::temp_dir().join(format!("casa1-not-managed-{}.dll", std::process::id()));
        std::fs::write(&native_pe, &bytes).expect("write PE");
        assert_eq!(
            execute_assembly(&native_pe, &[]),
            Err(ClrHostError::NotManaged(native_pe.clone()))
        );
        let _ = std::fs::remove_file(&native_pe);

        let missing = Path::new("/casa1/does/not/exist/Managed.exe");
        assert_eq!(
            execute_assembly(missing, &[]),
            Err(ClrHostError::AssemblyNotFound(missing.to_path_buf()))
        );
    }

    #[test]
    fn corelib_static_int_method_executes_natively() {
        let runtime = clr_meta::installed_runtimes()
            .into_iter()
            .next()
            .expect("a real CoreCLR runtime is installed");
        let assembly = runtime.directory.join("System.Private.CoreLib.dll");
        let processors = execute_in_default_app_domain(
            &assembly,
            "System.Environment",
            "get_ProcessorCount",
            Some(""),
        )
        .expect("System.Environment::get_ProcessorCount is a static int method");
        assert_ne!(processors, 0, "the host always has at least one CPU");
    }

    #[test]
    fn absent_framework_provider_reports_exact_absence_without_mono() {
        let provider = select_framework_provider(false);
        assert_eq!(provider.is_available(), false);
        assert_eq!(provider.version(), None);
        assert_eq!(provider.version_for(Some("v4.0")), None);
        assert_eq!(provider.directory_for(Some("v4.0")), None);
        let missing = Path::new("/casa1/does/not/exist/Framework.exe");
        assert_eq!(
            provider.host_assembly(missing, &["argument".to_string()]),
            Err(ClrHostError::FrameworkUnavailable)
        );
        assert_eq!(
            provider.execute_in_default_app_domain(missing, "Type", "Method", None),
            Err(ClrHostError::FrameworkUnavailable)
        );
        assert_eq!(requested_runtime_version_with(provider, None), None);
        assert_eq!(
            requested_runtime_directory_with(provider, Some("v4.0.30319")),
            None
        );
        assert_eq!(
            requested_runtime_version_with(provider, Some("garbage")),
            None
        );
        assert_eq!(
            requested_runtime_directory_with(provider, Some("garbage")),
            None
        );

        // The Mono provider is selected exactly when a real installation is
        // available; both static implementations are the same trait object.
        assert_eq!(
            select_framework_provider(true).is_available(),
            crate::mono_host::is_available()
        );
    }

    #[test]
    fn framework_provider_seam_and_activation_families_are_exact() {
        // Versionless is the Framework "latest" request, never CoreCLR.
        assert_eq!(activation_family(None), ActivationFamily::Framework);
        assert_eq!(activation_family(Some("")), ActivationFamily::Framework);
        for version in [
            "v1.0.3650",
            "1.0",
            "v1.1.4322",
            "1.1",
            "v2.0.50727",
            "2.0",
            "v3.5",
            "4.0.30319",
            "v4.0",
        ] {
            assert_eq!(
                activation_family(Some(version)),
                ActivationFamily::Framework,
                "{version} is a Framework version"
            );
        }
        for version in ["5.0", "8.0", "v10.0.13"] {
            assert!(
                matches!(
                    activation_family(Some(version)),
                    ActivationFamily::CoreClr(_)
                ),
                "{version} is a CoreCLR version"
            );
        }
        for version in ["garbage", "v8", "1", "1.2.3.4.5", "v08.0", " 8.0", "4.0.x"] {
            assert_eq!(
                activation_family(Some(version)),
                ActivationFamily::Unsupported,
                "{version} is not a runtime version"
            );
        }

        // The provider is the real host Mono installation when present and the
        // honest absence implementation otherwise; there is never a fake.
        let provider = framework_runtime_provider();
        let mono_available = crate::mono_host::is_available();
        assert_eq!(provider.is_available(), mono_available);
        let missing = Path::new("/casa1/does/not/exist/Framework.exe");
        let arguments = ["argument".to_string()];
        if mono_available {
            assert_eq!(provider.version(), crate::mono_host::version_for(None));
            assert!(provider.version().is_some());
            assert_eq!(
                provider.version_for(Some("v2.0")),
                crate::mono_host::version_for(Some("v2.0"))
            );
            assert_eq!(
                provider.version_for(Some("v4.0")),
                crate::mono_host::version_for(Some("v4.0"))
            );
            assert_eq!(
                provider.directory_for(Some("v4.0")),
                crate::mono_host::directory_for(Some("v4.0"))
            );
            assert_eq!(
                provider.host_assembly(missing, &arguments),
                Err(ClrHostError::AssemblyNotFound(missing.to_path_buf()))
            );
            assert_eq!(
                provider.execute_in_default_app_domain(missing, "Type", "Method", None),
                Err(ClrHostError::AssemblyNotFound(missing.to_path_buf()))
            );
        } else {
            assert_eq!(provider.version(), None);
            assert_eq!(provider.version_for(Some("v4.0")), None);
            assert_eq!(provider.directory_for(Some("v4.0")), None);
            assert_eq!(
                provider.host_assembly(missing, &arguments),
                Err(ClrHostError::FrameworkUnavailable)
            );
            assert_eq!(
                provider.execute_in_default_app_domain(missing, "Type", "Method", None),
                Err(ClrHostError::FrameworkUnavailable)
            );
        }

        // Framework and malformed requests never select an installed CoreCLR.
        if mono_available {
            assert_eq!(
                requested_runtime_version(None),
                crate::mono_host::version_for(None)
            );
            assert_eq!(
                requested_runtime_directory(Some("v4.0.30319")),
                crate::mono_host::directory_for(Some("v4.0.30319"))
            );
        } else {
            assert_eq!(requested_runtime_version(None), None);
            assert_eq!(requested_runtime_directory(Some("v4.0.30319")), None);
        }
        assert_eq!(requested_runtime_version(Some("garbage")), None);

        let installed = clr_meta::installed_runtimes();
        let runtime = installed
            .first()
            .expect("a real CoreCLR runtime is installed");
        let version = runtime.version_string();
        assert_eq!(
            activation_family(Some(&version)),
            ActivationFamily::CoreClr(runtime.version.clone())
        );
        assert_eq!(
            requested_runtime_version(Some(&version)),
            Some(version.clone())
        );
        assert_eq!(
            requested_runtime_directory(Some(&version)),
            Some(runtime.directory.clone())
        );

        // An 8.0 request resolves only when an 8.0.x runtime is installed.
        let eight = clr_meta::ClrVersion::parse_request("8.0").expect("valid version");
        let expected =
            clr_meta::select_runtime(&eight, &installed).map(|runtime| runtime.version_string());
        assert_eq!(requested_runtime_version(Some("8.0")), expected);
    }
}
