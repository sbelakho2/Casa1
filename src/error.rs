use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Clone)]
pub struct AppError {
    pub code: ReasonCode,
    pub message: String,
    pub reproduction_hints: Vec<String>,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.name(), self.message)
    }
}

impl std::error::Error for AppError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub reason_code: u32,
    pub reason_name: String,
    pub message: String,
    pub reproduction_hints: Vec<String>,
}

impl AppError {
    pub fn new(code: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            reproduction_hints: Vec::new(),
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.reproduction_hints.push(hint.into());
        self
    }

    pub fn from_io(code: ReasonCode, message: impl Into<String>, source: &std::io::Error) -> Self {
        Self::new(code, message).with_hint(source.to_string())
    }

    /// Create an OOM (out of memory) error.
    pub fn oom(message: impl Into<String>) -> Self {
        Self::new(ReasonCode::RcOutOfMemory, message)
    }

    /// Create an invalid parameter error with the parameter name and expected value.
    pub fn invalid_param(name: &str, expected: &str) -> Self {
        Self::new(
            ReasonCode::RcInvalidParameter,
            format!("{name}: expected {expected}"),
        )
    }

    pub fn to_response(&self) -> ErrorResponse {
        ErrorResponse {
            reason_code: self.code.as_u32(),
            reason_name: self.code.name().to_string(),
            message: self.message.clone(),
            reproduction_hints: self.reproduction_hints.clone(),
        }
    }

    /// Returns a Windows-compatible last-error code (`GetLastError` value)
    /// that best represents this error.  Maps [`ReasonCode`] variants to
    /// their closest Win32 error equivalent.
    ///
    /// Every [`ReasonCode`] variant has an explicit mapping so the catch-all
    /// `_` branch is only hit for unexpected / future codes.
    #[allow(unreachable_patterns)]
    pub fn last_error(&self) -> u32 {
        match self.code {
            // ── Success ────────────────────────────────────────────────
            ReasonCode::Success => ERROR_SUCCESS,

            // ── CLI / Launcher (1000–1011) ─────────────────────────────
            ReasonCode::RcCliInvalid => ERROR_INVALID_PARAMETER,
            ReasonCode::RcGeExists => ERROR_ALREADY_EXISTS,
            ReasonCode::RcGeNotFound => ERROR_FILE_NOT_FOUND,
            ReasonCode::RcIo => ERROR_READ_FAULT,
            ReasonCode::RcRunnerSpawnFailed => ERROR_FILE_NOT_FOUND,
            ReasonCode::RcRunnerProtocolInvalid => ERROR_INVALID_PARAMETER,
            ReasonCode::RcTraceEnvMismatch => ERROR_INVALID_PARAMETER,
            ReasonCode::RcCompareMismatch => ERROR_INVALID_PARAMETER,
            ReasonCode::RcDiagnosticsExportFailed => ERROR_ACCESS_DENIED,
            ReasonCode::RcHelperPermissionDenied => ERROR_ACCESS_DENIED,
            ReasonCode::RcEntitlementAuditFailed => ERROR_ACCESS_DENIED,
            ReasonCode::RcEntitlementValidationError => ERROR_ACCESS_DENIED,

            // ── Filesystem (1100–1108) ─────────────────────────────────
            ReasonCode::RcFsPathInvalid => ERROR_INVALID_NAME,
            ReasonCode::RcFsAlreadyExists => ERROR_ALREADY_EXISTS,
            ReasonCode::RcFsNotFound => ERROR_FILE_NOT_FOUND,
            ReasonCode::RcFsReservedName => ERROR_INVALID_NAME,
            ReasonCode::RcFsPathTooLong => ERROR_INVALID_PARAMETER,
            ReasonCode::RcFsSharingViolation => ERROR_SHARING_VIOLATION,
            ReasonCode::RcFsLockViolation => ERROR_LOCK_VIOLATION,
            ReasonCode::RcFsSandboxEscape => ERROR_ACCESS_DENIED,
            ReasonCode::RcSandboxPathViolation => ERROR_ACCESS_DENIED,

            // ── Registry (1200) ────────────────────────────────────────
            ReasonCode::RcRegistryNotFound => ERROR_FILE_NOT_FOUND,

            // ── Win32 / COM (1300–1306) ────────────────────────────────
            ReasonCode::RcWin32InvalidHandle | ReasonCode::RcHandleStaleOrInvalid => {
                ERROR_INVALID_HANDLE
            }
            ReasonCode::RcWin32Timeout => ERROR_TIMEOUT,
            ReasonCode::RcComClassNotRegistered => ERROR_INVALID_PARAMETER,
            ReasonCode::RcMemoryAccessViolation => ERROR_NOACCESS,
            ReasonCode::RcPipeBusy => ERROR_ACCESS_DENIED,
            ReasonCode::RcComObjectError => ERROR_INVALID_PARAMETER,

            // ── PE / JIT / Loader (2000–2019) ──────────────────────────
            ReasonCode::RcPeParseInvalid => ERROR_BAD_FORMAT,
            ReasonCode::RcImportMissing => ERROR_PROC_NOT_FOUND,
            ReasonCode::RcUnimplInsn => ERROR_NOT_SUPPORTED,
            ReasonCode::RcD3dFeatureUnsupported => ERROR_NOT_SUPPORTED,
            ReasonCode::RcAnticheatDriverDetected => ERROR_ACCESS_DENIED,
            ReasonCode::RcTlsCertRejected => ERROR_ACCESS_DENIED,
            ReasonCode::RcMsiCustomActionServiceBlocked => ERROR_ACCESS_DENIED,
            ReasonCode::RcTlsValidationFailed => ERROR_ACCESS_DENIED,
            ReasonCode::RcBufferLimitExceeded => ERROR_INSUFFICIENT_BUFFER,
            ReasonCode::RcInvalidGuestEnum => ERROR_INVALID_PARAMETER,
            ReasonCode::RcJitCodeAllocFailed => ERROR_NOT_ENOUGH_MEMORY,
            ReasonCode::RcParserTruncation => ERROR_INVALID_PARAMETER,
            ReasonCode::RcUnsupportedPlatform => ERROR_NOT_SUPPORTED,
            ReasonCode::RcTlsCertificatePinMismatch => ERROR_ACCESS_DENIED,
            ReasonCode::RcUnsupportedPlatformApi => ERROR_NOT_SUPPORTED,
            ReasonCode::RcParserTruncated => ERROR_INVALID_PARAMETER,
            ReasonCode::RcJitCompilationError => ERROR_INVALID_PARAMETER,
            ReasonCode::RcExecutableMemoryExhausted => ERROR_NO_SYSTEM_RESOURCES,
            ReasonCode::RcGuestPointerOutOfRange => ERROR_NOACCESS,
            ReasonCode::RcGuestStringInvalid => ERROR_INVALID_PARAMETER,

            // ── Graphics / Input / Shaders (2100–2109) ─────────────────
            ReasonCode::RcInputUnsupported => ERROR_NOT_SUPPORTED,
            ReasonCode::RcDxilInvalid => ERROR_INVALID_PARAMETER,
            ReasonCode::RcDxilBindingAmbiguous => ERROR_INVALID_PARAMETER,
            ReasonCode::RcCacheCorrupt => ERROR_INVALID_PARAMETER,
            ReasonCode::RcD3dInvalidState => ERROR_INVALID_PARAMETER,
            ReasonCode::RcD3d9NotSupported => ERROR_NOT_SUPPORTED,
            ReasonCode::RcVulkanNotSupported => ERROR_NOT_SUPPORTED,
            ReasonCode::RcOpenGlNotSupported => ERROR_NOT_SUPPORTED,
            ReasonCode::RcInvalidState => ERROR_INVALID_PARAMETER,
            ReasonCode::RcNotFound => ERROR_FILE_NOT_FOUND,

            // ── Audio (2200–2201) ──────────────────────────────────────
            ReasonCode::RcAudioUnsupported => ERROR_NOT_SUPPORTED,
            ReasonCode::RcAudioBufferSizeMismatch => ERROR_INVALID_PARAMETER,

            // ── Network / Crypto (2300–2302) ───────────────────────────
            ReasonCode::RcWinsockWouldBlock => 10035, // WSAEWOULDBLOCK
            ReasonCode::RcDnsNotFound => 11001,       // WSAHOST_NOT_FOUND
            ReasonCode::RcCryptoInvalid => ERROR_ACCESS_DENIED,

            // ── .NET / Steam / Media (2400–2600) ───────────────────────
            ReasonCode::RcDotnetUnsupported => ERROR_NOT_SUPPORTED,
            ReasonCode::RcSteamUpdateFailed => ERROR_ACCESS_DENIED,
            ReasonCode::RcMediaInvalid => ERROR_INVALID_PARAMETER,

            // ── Network detailed (2700–2716) ───────────────────────────
            ReasonCode::RcNetworkUnreachable => ERROR_BAD_NETPATH,
            ReasonCode::RcNetworkProtocolInvalid => ERROR_INVALID_PARAMETER,
            ReasonCode::RcMsiInvalid => ERROR_INVALID_PARAMETER,
            ReasonCode::RcNetDnsResolutionFailed => 11001, // WSAHOST_NOT_FOUND
            ReasonCode::RcNetConnectionFailed => ERROR_BAD_NETPATH,
            ReasonCode::RcNetWriteFailed => ERROR_WRITE_FAULT,
            ReasonCode::RcNetReadFailed => ERROR_READ_FAULT,
            ReasonCode::RcNetProtocolError => ERROR_INVALID_PARAMETER,
            ReasonCode::RcNetHttpRequestFailed => ERROR_INVALID_PARAMETER,
            ReasonCode::RcNetHttpHeaderNotFound => ERROR_INVALID_PARAMETER,
            ReasonCode::RcNetSocketCreateFailed => ERROR_NETWORK_ACCESS_DENIED,
            ReasonCode::RcNetSendFailed => ERROR_WRITE_FAULT,
            ReasonCode::RcWebSocketFrameTooLarge => ERROR_INVALID_PARAMETER,
            ReasonCode::RcHttpHeaderLimitExceeded => ERROR_INVALID_PARAMETER,
            ReasonCode::RcPortParseError => ERROR_INVALID_PARAMETER,
            ReasonCode::RcRequestBodyTooLarge => ERROR_INVALID_PARAMETER,
            ReasonCode::RcSocketReceiveQueueFull => ERROR_INVALID_PARAMETER,

            // ── DRM (2800–2806) ────────────────────────────────────────
            ReasonCode::RcDrmInitFailed => ERROR_ACCESS_DENIED,
            ReasonCode::RcDrmDecryptFailed => ERROR_ACCESS_DENIED,
            ReasonCode::RcDrmIntegrityFailed => ERROR_ACCESS_DENIED,
            ReasonCode::RcDrmLicenseInvalid => ERROR_ACCESS_DENIED,
            ReasonCode::RcDrmPackUnsupported => ERROR_NOT_SUPPORTED,
            ReasonCode::RcDrmSectionNotFound => ERROR_FILE_NOT_FOUND,
            ReasonCode::RcDrmRegionNotFound => ERROR_FILE_NOT_FOUND,

            // ── WMI / Telemetry (2900–2903) ────────────────────────────
            ReasonCode::RcWmiParseError => ERROR_INVALID_PARAMETER,
            ReasonCode::RcWmiClassNotFound => ERROR_FILE_NOT_FOUND,
            ReasonCode::RcWmiObjectNotFound => ERROR_FILE_NOT_FOUND,
            ReasonCode::RcTelemetryRanking => ERROR_INVALID_PARAMETER,

            // ── SEH / Crash / Recovery (3000–3103) ─────────────────────
            ReasonCode::SehException => ERROR_NOACCESS,
            ReasonCode::VeHandlerUnhandled => ERROR_INVALID_PARAMETER,
            ReasonCode::RcCrashRecoveryError => ERROR_INVALID_PARAMETER,
            ReasonCode::Halted => ERROR_INVALID_PARAMETER,
            ReasonCode::RcSignalHandlerError => ERROR_INVALID_PARAMETER,

            // ── Parameter / OOM / Lock (3100–3300) ─────────────────────
            ReasonCode::RcInvalidParameter => ERROR_INVALID_PARAMETER,
            ReasonCode::RcOutOfMemory | ReasonCode::RcOutOfMemoryHint => ERROR_NOT_ENOUGH_MEMORY,
            ReasonCode::RcLockPoisoned => ERROR_INVALID_PARAMETER,

            // ── Catch-all for any future ReasonCode not yet mapped ─────
            _ => ERROR_INVALID_PARAMETER,
        }
    }

    /// Returns an `HRESULT` for this error.
    ///
    /// Uses `MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, code)` for custom
    /// Casa1 reason codes so they occupy a dedicated range that will never
    /// collide with system-defined HRESULTs.
    ///
    /// `Success` maps to `S_OK` (`0x00000000`).
    pub fn hresult(&self) -> u32 {
        match self.code {
            ReasonCode::Success => 0x0000_0000, // S_OK
            // FACILITY_ITF = 4; SEVERITY_ERROR = 1 (bit 31).
            // Mask to 16 bits so a future reason code >= 0x10000 cannot
            // bleed into the facility/severity bits.
            _ => 0x8004_0000 | (self.code.as_u32() & 0xFFFF),
        }
    }
}

// ─── Error Code Mapping ──────────────────────────────────────────────────────
//
// Comprehensive mappings between Windows error domains:
//   NTSTATUS (kernel)  ←→  DOS/Win32 error  ←→  POSIX errno  ←→  mach kern_return_t
//   HRESULT (COM)      ←→  NTSTATUS
//   WSAGetLastError    ←→  DOS/win32 error
//
// These are used by RtlNtStatusToDosError, GetLastError→errno translation,
// WSA error reporting, and COM HRESULT→NTSTATUS conversion.

/// Error constants used by the mapping functions.
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_TOO_MANY_OPEN_FILES: u32 = 4;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_BAD_FORMAT: u32 = 11;
pub const ERROR_OUTOFMEMORY: u32 = 14;
pub const ERROR_WRITE_FAULT: u32 = 29;
pub const ERROR_READ_FAULT: u32 = 30;
pub const ERROR_SHARING_VIOLATION: u32 = 32;
pub const ERROR_LOCK_VIOLATION: u32 = 33;
pub const ERROR_NOT_SUPPORTED: u32 = 50;
pub const ERROR_BAD_NETPATH: u32 = 53;
pub const ERROR_NETWORK_ACCESS_DENIED: u32 = 65;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_INVALID_NAME: u32 = 123;
pub const ERROR_MOD_NOT_FOUND: u32 = 126;
pub const ERROR_PROC_NOT_FOUND: u32 = 127;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_ENVVAR_NOT_FOUND: u32 = 203;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const ERROR_NOACCESS: u32 = 998;
pub const ERROR_TIMEOUT: u32 = 1460;
pub const ERROR_NO_SYSTEM_RESOURCES: u32 = 1450;

/// Expanded NTSTATUS → DOS error mapping.
/// Covers the most common NTSTATUS codes that guest binaries encounter.
pub fn ntstatus_to_dos_error(status: u32) -> u32 {
    match status {
        // Success
        0x0000_0000 => ERROR_SUCCESS,

        // Informational / Warning
        0x0000_0001 => ERROR_INVALID_PARAMETER, // STATUS_WAIT_1
        0x0000_0002 => ERROR_INVALID_PARAMETER, // STATUS_WAIT_2
        0x8000_0001 => ERROR_INVALID_PARAMETER, // STATUS_GUARD_PAGE_VIOLATION
        0x8000_0002 => ERROR_INVALID_PARAMETER, // STATUS_DATATYPE_MISALIGNMENT
        0x8000_0003 => ERROR_INVALID_PARAMETER, // STATUS_BREAKPOINT
        0x8000_0004 => ERROR_INVALID_PARAMETER, // STATUS_SINGLE_STEP

        // Memory / Access violations
        0xC000_0005 => ERROR_NOACCESS,       // STATUS_ACCESS_VIOLATION
        0xC000_0008 => ERROR_INVALID_HANDLE, // STATUS_INVALID_HANDLE
        0xC000_000D => ERROR_INVALID_PARAMETER, // STATUS_INVALID_PARAMETER
        0xC000_000E => ERROR_INVALID_PARAMETER, // STATUS_NO_SUCH_DEVICE
        0xC000_000F => ERROR_FILE_NOT_FOUND, // STATUS_NO_SUCH_FILE
        0xC000_0010 => ERROR_PATH_NOT_FOUND, // STATUS_INVALID_DEVICE_REQUEST
        0xC000_0011 => ERROR_INVALID_PARAMETER, // STATUS_END_OF_FILE
        0xC000_0012 => ERROR_INVALID_PARAMETER, // STATUS_WRONG_VOLUME
        0xC000_0013 => ERROR_INVALID_PARAMETER, // STATUS_NO_MEDIA_IN_DEVICE
        0xC000_0014 => ERROR_INVALID_PARAMETER, // STATUS_UNRECOGNIZED_VOLUME
        0xC000_0015 => ERROR_INVALID_PARAMETER, // STATUS_FILE_LOCK_CONFLICT
        0xC000_0016 => ERROR_INVALID_PARAMETER, // STATUS_SET_NOT_SUPPORTED
        0xC000_0017 => ERROR_NOT_ENOUGH_MEMORY, // STATUS_NO_MEMORY
        0xC000_0018 => ERROR_INVALID_PARAMETER, // STATUS_CONFLICTING_ADDRESSES
        0xC000_0019 => ERROR_INVALID_PARAMETER, // STATUS_NOT_MAPPED_VIEW
        0xC000_001A => ERROR_INVALID_PARAMETER, // STATUS_UNABLE_TO_FREE_VM
        0xC000_001B => ERROR_INVALID_PARAMETER, // STATUS_UNABLE_TO_DELETE_SECTION

        // File system
        0xC000_0022 => ERROR_ACCESS_DENIED, // STATUS_ACCESS_DENIED
        0xC000_0023 => ERROR_INSUFFICIENT_BUFFER, // STATUS_BUFFER_TOO_SMALL
        0xC000_0034 => ERROR_FILE_NOT_FOUND, // STATUS_OBJECT_NAME_NOT_FOUND
        0xC000_0035 => ERROR_ALREADY_EXISTS, // STATUS_OBJECT_NAME_COLLISION
        0xC000_0036 => ERROR_PATH_NOT_FOUND, // STATUS_OBJECT_PATH_NOT_FOUND
        0xC000_0037 => ERROR_INVALID_PARAMETER, // STATUS_OBJECT_PATH_INVALID
        0xC000_0038 => ERROR_INVALID_PARAMETER, // STATUS_OBJECT_PATH_SYNTAX_BAD
        0xC000_0039 => ERROR_INVALID_PARAMETER, // STATUS_DATA_OVERRUN
        0xC000_0040 => ERROR_INVALID_PARAMETER, // STATUS_DATA_LATE_ERROR
        0xC000_0041 => ERROR_INVALID_PARAMETER, // STATUS_DATA_ERROR
        0xC000_0043 => ERROR_SHARING_VIOLATION, // STATUS_SHARING_VIOLATION
        0xC000_0045 => ERROR_INVALID_PARAMETER, // STATUS_INVALID_PAGE_PROTECTION
        0xC000_0047 => ERROR_INVALID_PARAMETER, // STATUS_PAGEFILE_QUOTA
        0xC000_0054 => ERROR_INVALID_PARAMETER, // STATUS_TOO_MANY_LINKS
        0xC000_006D => ERROR_INVALID_PARAMETER, // STATUS_LOGON_FAILURE
        0xC000_007A => ERROR_INVALID_PARAMETER, // STATUS_BAD_IMPERSONATION_LEVEL
        0xC000_008B => ERROR_INVALID_PARAMETER, // STATUS_NOT_IMPLEMENTED
        0xC000_0090 => ERROR_INVALID_PARAMETER, // STATUS_NOT_IMPLEMENTED_2

        // Arithmetic
        0xC000_0094 => ERROR_INVALID_PARAMETER, // STATUS_INTEGER_DIVIDE_BY_ZERO
        0xC000_0095 => ERROR_INVALID_PARAMETER, // STATUS_INTEGER_OVERFLOW
        0xC000_0096 => ERROR_INVALID_PARAMETER, // STATUS_FLOAT_DIVIDE_BY_ZERO
        0xC000_0097 => ERROR_INVALID_PARAMETER, // STATUS_FLOAT_INEXACT_RESULT
        0xC000_0098 => ERROR_INVALID_PARAMETER, // STATUS_FLOAT_INVALID_OPERATION
        0xC000_0099 => ERROR_INVALID_PARAMETER, // STATUS_FLOAT_OVERFLOW
        0xC000_009A => ERROR_INVALID_PARAMETER, // STATUS_FLOAT_STACK_CHECK
        0xC000_009B => ERROR_INVALID_PARAMETER, // STATUS_FLOAT_UNDERFLOW

        // Image / PE loading
        0xC000_00BB => ERROR_NOT_SUPPORTED, // STATUS_NOT_SUPPORTED
        0xC000_0120 => ERROR_INVALID_PARAMETER, // STATUS_CANCELLED
        0xC000_0128 => ERROR_MOD_NOT_FOUND, // STATUS_ENTRYPOINT_NOT_FOUND
        0xC000_0135 => ERROR_MOD_NOT_FOUND, // STATUS_DLL_NOT_FOUND (alternate)
        0xC000_0139 => ERROR_PROC_NOT_FOUND, // STATUS_ORDINAL_NOT_FOUND
        0xC000_0142 => ERROR_PROC_NOT_FOUND, // STATUS_DLL_INIT_FAILED
        0xC000_0143 => ERROR_INVALID_PARAMETER, // STATUS_RESOURCE_NOT_FOUND
        0xC000_0225 => ERROR_INVALID_PARAMETER, // STATUS_NOT_FOUND

        // Stack / heap
        0xC000_00FD => ERROR_INVALID_PARAMETER, // STATUS_STACK_OVERFLOW
        0xC000_00FE => ERROR_INVALID_PARAMETER, // STATUS_INVALID_UNWIND_TARGET
        0xC000_0147 => ERROR_INVALID_PARAMETER, // STATUS_HEAP_CORRUPTION
        0xC000_0374 => ERROR_INVALID_PARAMETER, // STATUS_HEAP_CORRUPTION (alternate)

        // Registry
        0xC000_0030 => ERROR_FILE_NOT_FOUND, // STATUS_OBJECT_TYPE_MISMATCH

        // Fallback
        _ => ERROR_INVALID_PARAMETER,
    }
}

/// HRESULT → NTSTATUS conversion.
/// Many COM APIs return HRESULTs that guest code passes to NTSTATUS-aware
/// functions.  This mapping covers the most common codes.
pub fn hresult_to_ntstatus(hr: u32) -> u32 {
    match hr {
        // Success codes
        0x0000_0000 => 0x0000_0000, // S_OK → STATUS_SUCCESS
        0x0000_0001 => 0x0000_0000, // S_FALSE → STATUS_SUCCESS (partial success)

        // Common COM errors
        0x8000_0002 => 0xC000_0005, // E_UNEXPECTED → STATUS_ACCESS_VIOLATION
        0x8000_0005 => 0xC000_0008, // E_FAIL → STATUS_INVALID_HANDLE
        0x8000_000E => 0xC000_0017, // E_OUTOFMEMORY → STATUS_NO_MEMORY
        0x8000_0057 => 0xC000_000D, // E_INVALIDARG → STATUS_INVALID_PARAMETER
        0x8000_4002 => 0xC000_00BB, // E_NOINTERFACE → STATUS_NOT_SUPPORTED
        0x8000_4003 => 0xC000_0005, // E_POINTER → STATUS_ACCESS_VIOLATION
        0x8000_4004 => 0xC000_0120, // E_ABORT → STATUS_CANCELLED
        0x8000_4005 => 0xC000_0008, // E_HANDLE → STATUS_INVALID_HANDLE

        // Class / COM factory errors
        0x8000_4011 => 0xC000_000D, // CLASS_E_CLASSNOTAVAILABLE → STATUS_INVALID_PARAMETER
        0x8004_01F0 => 0xC000_000D, // CO_E_NOTINITIALIZED → STATUS_INVALID_PARAMETER
        0x8004_01F3 => 0xC000_000D, // CO_E_NOTINITIALIZED (alt) → STATUS_INVALID_PARAMETER

        // Storage errors
        0x8004_0001 => 0xC000_0022, // STG_E_INVALIDFUNCTION → STATUS_ACCESS_DENIED
        0x8004_0002 => 0xC000_0034, // STG_E_FILENOTFOUND → STATUS_OBJECT_NAME_NOT_FOUND
        0x8004_0003 => 0xC000_0035, // STG_E_PATHNOTFOUND → STATUS_OBJECT_PATH_NOT_FOUND
        0x8004_0004 => 0xC000_0035, // STG_E_TOOMANYOPENFILES → STATUS_OBJECT_NAME_COLLISION
        0x8004_0005 => 0xC000_0022, // STG_E_ACCESSDENIED → STATUS_ACCESS_DENIED
        0x8004_0011 => 0xC000_000D, // STG_E_INVALIDPARAMETER → STATUS_INVALID_PARAMETER
        0x8004_0010 => 0xC000_000D, // STG_E_INVALIDPOINTER → STATUS_INVALID_PARAMETER
        0x8004_0020 => 0xC000_000D, // STG_E_INVALIDFLAG → STATUS_INVALID_PARAMETER
        0x8004_0021 => 0xC000_000D, // STG_E_INVALIDPARAMETER → STATUS_INVALID_PARAMETER
        0x8004_0022 => 0xC000_0034, // STG_E_REGISTRY → STATUS_OBJECT_NAME_NOT_FOUND
        0x8000_FFFF => 0xC000_000D, // E_NOTIMPL → STATUS_INVALID_PARAMETER
        0x8004_0040 => 0xC000_000D, // STG_E_INVALIDHEADER → STATUS_INVALID_PARAMETER
        0x8004_0050 => 0xC000_0043, // STG_E_SHAREREQUIRED → STATUS_SHARING_VIOLATION
        0x8004_0051 => 0xC000_0043, // STG_E_SHAREVIOLATION → STATUS_SHARING_VIOLATION
        0x8004_0060 => 0xC000_0022, // STG_E_LOCKVIOLATION → STATUS_ACCESS_DENIED
        0x8004_0070 => 0xC000_000D, // STG_E_ABNORMALAPIEXIT → STATUS_INVALID_PARAMETER
        0x8004_0080 => 0xC000_000D, // STG_E_ABNORMALAPIEXIT → STATUS_INVALID_PARAMETER
        0x8004_0090 => 0xC000_000D, // STG_E_INVALIDCOMPLETION → STATUS_INVALID_PARAMETER

        // Security / trust errors
        0x800B_0100 => 0xC000_0022, // TRUST_E_NOSIGNATURE → STATUS_ACCESS_DENIED
        0x800B_010A => 0xC000_0022, // CERT_E_EXPIRED → STATUS_ACCESS_DENIED
        0x800B_0109 => 0xC000_0022, // CERT_E_UNTRUSTEDROOT → STATUS_ACCESS_DENIED
        0x800B_0110 => 0xC000_0022, // CERT_E_WRONG_USAGE → STATUS_ACCESS_DENIED
        0x8009_6001 => 0xC000_0022, // CRYPT_E_NO_MATCH → STATUS_ACCESS_DENIED

        // CO_E errors
        0x8007_0002 => 0xC000_0022, // CO_E_ACCESSDENIED → STATUS_ACCESS_DENIED
        0x8007_0013 => 0xC000_0008, // CO_E_CLASS_CREATE_FAILED → STATUS_INVALID_HANDLE
        0x8007_0015 => 0xC000_0017, // CO_E_OUTOFMEMORY → STATUS_NO_MEMORY
        0x8007_0008 => 0xC000_0022, // CO_E_ALREADYINITIALIZED → STATUS_ACCESS_DENIED
        0x8007_0009 => 0xC000_0022, // CO_E_CANTDETERMINECLASS → STATUS_ACCESS_DENIED
        0x8007_000A => 0xC000_0022, // CO_E_CLASSSTRING → STATUS_ACCESS_DENIED
        0x8007_000B => 0xC000_0022, // CO_E_APPNOTFOUND → STATUS_ACCESS_DENIED
        0x8007_000C => 0xC000_0022, // CO_E_APPSINGLEUSE → STATUS_ACCESS_DENIED
        0x8007_000D => 0xC000_0022, // CO_E_APPMODEL → STATUS_ACCESS_DENIED
        0x8007_000E => 0xC000_000D, // CO_E_CLASSNOTREG → STATUS_INVALID_PARAMETER

        // Network / URL errors
        0x800C_0002 => 0xC000_0034, // INET_E_INVALID_URL → STATUS_OBJECT_NAME_NOT_FOUND
        0x800C_000B => 0xC000_00AF, // INET_E_CANNOT_CONNECT → STATUS_HOST_UNREACHABLE
        0x800C_0005 => 0xC000_00C5, // INET_E_CONNECTION_TIMEOUT → STATUS_IO_TIMEOUT

        // Any unrecognized HRESULT: use the severity bit to decide mapping.
        // Failure HRESULTs (bit 31 set) map to STATUS_INVALID_PARAMETER;
        // success/warning HRESULTs map to STATUS_SUCCESS.
        hr if hr & 0x8000_0000 != 0 => 0xC000_000D, // failure HRESULT → STATUS_INVALID_PARAMETER
        _ => 0x0000_0000,                           // success HRESULT → STATUS_SUCCESS
    }
}

/// HRESULT → DOS error conversion (convenience: hresult → ntstatus → dos).
pub fn hresult_to_dos_error(hr: u32) -> u32 {
    ntstatus_to_dos_error(hresult_to_ntstatus(hr))
}

/// DOS/win32 error → POSIX errno.
/// Maps the most common GetLastError values to their POSIX errno equivalents.
pub fn dos_error_to_errno(error: u32) -> i32 {
    match error {
        0 => 0,                  // ERROR_SUCCESS
        2 => libc::ENOENT,       // ERROR_FILE_NOT_FOUND
        3 => libc::ENOENT,       // ERROR_PATH_NOT_FOUND
        4 => libc::EMFILE,       // ERROR_TOO_MANY_OPEN_FILES
        5 => libc::EACCES,       // ERROR_ACCESS_DENIED
        6 => libc::EBADF,        // ERROR_INVALID_HANDLE
        7 => libc::ENOMEM,       // ERROR_ARENA_TRASHED
        8 => libc::ENOMEM,       // ERROR_NOT_ENOUGH_MEMORY
        9 => libc::ENOMEM,       // ERROR_INVALID_BLOCK
        10 => libc::ENOMEM,      // ERROR_BAD_ENVIRONMENT
        11 => libc::EACCES,      // ERROR_BAD_FORMAT
        12 => libc::EACCES,      // ERROR_INVALID_ACCESS
        13 => libc::EACCES,      // ERROR_INVALID_DATA
        14 => libc::ENOMEM,      // ERROR_OUTOFMEMORY
        15 => libc::EACCES,      // ERROR_INVALID_DRIVE
        16 => libc::EACCES,      // ERROR_CURRENT_DIRECTORY
        17 => libc::EACCES,      // ERROR_NOT_SAME_DEVICE
        32 => libc::EACCES,      // ERROR_SHARING_VIOLATION
        33 => libc::EACCES,      // ERROR_LOCK_VIOLATION
        36 => libc::EACCES,      // ERROR_SHARING_BUFFER_EXCEEDED
        53 => libc::ENETDOWN,    // ERROR_BAD_NETPATH
        87 => libc::EINVAL,      // ERROR_INVALID_PARAMETER
        100 => libc::ENETDOWN,   // ERROR_NETWORK_PATH_NOT_FOUND
        111 => libc::EBUSY,      // ERROR_FILE_EXISTS
        122 => libc::ENOSPC,     // ERROR_INSUFFICIENT_BUFFER
        123 => libc::EINVAL,     // ERROR_INVALID_NAME
        126 => libc::ENOENT,     // ERROR_MOD_NOT_FOUND
        127 => libc::ENOENT,     // ERROR_PROC_NOT_FOUND
        130 => libc::EACCES,     // ERROR_DIRECT_ACCESS_HANDLE
        183 => libc::EEXIST,     // ERROR_ALREADY_EXISTS
        234 => libc::EAGAIN,     // ERROR_MORE_DATA
        259 => libc::EAGAIN,     // ERROR_NO_MORE_ITEMS
        998 => libc::EFAULT,     // ERROR_NOACCESS
        1300 => libc::EACCES,    // ERROR_NOT_ALL_ASSIGNED
        1450 => libc::ENOMEM,    // ERROR_NO_SYSTEM_RESOURCES
        1451 => libc::ENOMEM,    // ERROR_NOT_ENOUGH_QUOTA
        1460 => libc::ETIMEDOUT, // ERROR_TIMEOUT

        // Socket errors (WSA constants)
        10004 => libc::EINTR,           // WSAEINTR
        10013 => libc::EACCES,          // WSAEACCES
        10014 => libc::EFAULT,          // WSAEFAULT
        10022 => libc::EINVAL,          // WSAEINVAL
        10024 => libc::EMFILE,          // WSAEMFILE
        10035 => libc::EWOULDBLOCK,     // WSAEWOULDBLOCK
        10036 => libc::EINPROGRESS,     // WSAEINPROGRESS
        10037 => libc::EALREADY,        // WSAEALREADY
        10038 => libc::ENOTSOCK,        // WSAENOTSOCK
        10039 => libc::EDESTADDRREQ,    // WSAEDESTADDRREQ
        10040 => libc::EMSGSIZE,        // WSAEMSGSIZE
        10041 => libc::EPROTOTYPE,      // WSAEPROTOTYPE
        10042 => libc::EPROTONOSUPPORT, // WSAEPROTONOSUPPORT
        10043 => libc::ESOCKTNOSUPPORT, // WSAESOCKTNOSUPPORT
        10044 => libc::EOPNOTSUPP,      // WSAEOPNOTSUPP
        10045 => libc::EPFNOSUPPORT,    // WSAEPFNOSUPPORT
        10046 => libc::EAFNOSUPPORT,    // WSAEAFNOSUPPORT
        10047 => libc::EADDRINUSE,      // WSAEADDRINUSE
        10048 => libc::EADDRNOTAVAIL,   // WSAEADDRNOTAVAIL
        10049 => libc::ENETDOWN,        // WSAENETDOWN
        10050 => libc::ENETUNREACH,     // WSAENETUNREACH
        10051 => libc::ENETRESET,       // WSAENETRESET
        10052 => libc::ECONNABORTED,    // WSAECONNABORTED
        10053 => libc::ECONNRESET,      // WSAECONNRESET
        10054 => libc::ENOBUFS,         // WSAENOBUFS
        10055 => libc::EISCONN,         // WSAEISCONN
        10056 => libc::ENOTCONN,        // WSAENOTCONN
        10057 => libc::ESHUTDOWN,       // WSAESHUTDOWN
        10058 => libc::ETOOMANYREFS,    // WSAETOOMANYREFS
        10060 => libc::ETIMEDOUT,       // WSAETIMEDOUT
        10061 => libc::ECONNREFUSED,    // WSAECONNREFUSED
        10064 => libc::EHOSTDOWN,       // WSAEHOSTDOWN
        10065 => libc::EHOSTUNREACH,    // WSAEHOSTUNREACH
        11001 => libc::ENOENT,          // WSAHOST_NOT_FOUND
        11002 => libc::EAGAIN,          // WSATRY_AGAIN
        11003 => libc::ENOENT,          // WSANO_RECOVERY
        11004 => libc::ENOENT,          // WSANO_DATA

        _ => libc::EINVAL,
    }
}

/// POSIX errno → macOS / XNU kern_return_t.
/// The kernel uses mach/i386/kern_return.h values.
/// Only uses POSIX/BSD errno constants available on macOS.
/// Linux-specific errno values (> 43, not defined in macOS libc) are handled
/// by a cfg-gated guarded arm; on macOS those numeric values belong to real
/// constants (e.g. 44 is ESOCKTNOSUPPORT, 62 is ELOOP) and are matched by
/// the constant arms above.
pub fn errno_to_kern_return(errno: i32) -> u32 {
    match errno {
        0 => 0,                   // KERN_SUCCESS
        libc::EPERM => 1,         // KERN_INVALID_TASK
        libc::ENOENT => 2,        // KERN_INVALID_TASK
        libc::ESRCH => 3,         // KERN_INVALID_TASK
        libc::EINTR => 4,         // KERN_INVALID_ARGUMENT
        libc::EIO => 5,           // KERN_INVALID_ARGUMENT
        libc::ENXIO => 6,         // KERN_INVALID_ARGUMENT
        libc::E2BIG => 7,         // KERN_INVALID_ARGUMENT
        libc::ENOEXEC => 8,       // KERN_INVALID_ARGUMENT
        libc::EBADF => 9,         // KERN_INVALID_TASK
        libc::ECHILD => 10,       // KERN_INVALID_TASK
        libc::EAGAIN => 6,        // KERN_RESOURCE_SHORTAGE (EAGAIN == EWOULDBLOCK on macOS/Linux)
        libc::ENOMEM => 12,       // KERN_RESOURCE_SHORTAGE
        libc::EACCES => 13,       // KERN_INVALID_ARGUMENT
        libc::EFAULT => 14,       // KERN_INVALID_ARGUMENT
        libc::ENOTBLK => 15,      // KERN_INVALID_ARGUMENT
        libc::EBUSY => 16,        // KERN_FAILURE
        libc::EEXIST => 17,       // KERN_FAILURE
        libc::EXDEV => 18,        // KERN_INVALID_ARGUMENT
        libc::ENODEV => 19,       // KERN_INVALID_ARGUMENT
        libc::ENOTDIR => 20,      // KERN_INVALID_ARGUMENT
        libc::EISDIR => 21,       // KERN_INVALID_ARGUMENT
        libc::EINVAL => 22,       // KERN_INVALID_ARGUMENT
        libc::ENFILE => 23,       // KERN_RESOURCE_SHORTAGE
        libc::EMFILE => 24,       // KERN_RESOURCE_SHORTAGE
        libc::ENOTTY => 25,       // KERN_INVALID_ARGUMENT
        libc::ETXTBSY => 26,      // KERN_FAILURE
        libc::EFBIG => 27,        // KERN_FAILURE
        libc::ENOSPC => 28,       // KERN_RESOURCE_SHORTAGE
        libc::ESPIPE => 29,       // KERN_INVALID_ARGUMENT
        libc::EROFS => 30,        // KERN_FAILURE
        libc::EMLINK => 31,       // KERN_FAILURE
        libc::EPIPE => 32,        // KERN_FAILURE
        libc::EDOM => 33,         // KERN_INVALID_ARGUMENT
        libc::ERANGE => 34,       // KERN_INVALID_ARGUMENT
        libc::EDEADLK => 35,      // KERN_FAILURE
        libc::ENAMETOOLONG => 36, // KERN_FAILURE
        libc::ENOLCK => 37,       // KERN_RESOURCE_SHORTAGE
        libc::ENOSYS => 38,       // KERN_FAILURE
        libc::ENOTEMPTY => 39,    // KERN_FAILURE
        libc::ELOOP => 40,        // KERN_FAILURE
        libc::ENOMSG => 42,       // KERN_FAILURE
        libc::EIDRM => 43,        // KERN_FAILURE
        libc::EREMOTE => 66,         // KERN_FAILURE
        libc::ENOLINK => 67,         // KERN_FAILURE
        libc::EPROTO => 71,          // KERN_FAILURE
        libc::EMULTIHOP => 72,       // KERN_FAILURE
        libc::EBADMSG => 74,         // KERN_FAILURE
        libc::EOVERFLOW => 75,       // KERN_FAILURE
        libc::EILSEQ => 84,          // KERN_FAILURE
        libc::ENOTSOCK => 88,        // KERN_FAILURE
        libc::EDESTADDRREQ => 89,    // KERN_FAILURE
        libc::EMSGSIZE => 90,        // KERN_FAILURE
        libc::EPROTOTYPE => 91,      // KERN_FAILURE
        libc::ENOPROTOOPT => 92,     // KERN_FAILURE
        libc::EPROTONOSUPPORT => 93, // KERN_FAILURE
        libc::ESOCKTNOSUPPORT => 94, // KERN_FAILURE
        libc::EOPNOTSUPP => 95,      // KERN_FAILURE
        libc::EPFNOSUPPORT => 96,    // KERN_FAILURE
        libc::EAFNOSUPPORT => 97,    // KERN_FAILURE
        libc::EADDRINUSE => 98,      // KERN_FAILURE
        libc::EADDRNOTAVAIL => 99,   // KERN_FAILURE
        libc::ENETDOWN => 100,       // KERN_FAILURE
        libc::ENETUNREACH => 101,    // KERN_FAILURE
        libc::ENETRESET => 102,      // KERN_FAILURE
        libc::ECONNABORTED => 103,   // KERN_FAILURE
        libc::ECONNRESET => 104,     // KERN_FAILURE
        libc::ENOBUFS => 105,        // KERN_RESOURCE_SHORTAGE
        libc::EISCONN => 106,        // KERN_FAILURE
        libc::ENOTCONN => 107,       // KERN_FAILURE
        libc::ESHUTDOWN => 108,      // KERN_FAILURE
        libc::ETOOMANYREFS => 109,   // KERN_FAILURE
        libc::ETIMEDOUT => 110,      // KERN_FAILURE
        libc::ECONNREFUSED => 111,   // KERN_FAILURE
        libc::EHOSTDOWN => 112,      // KERN_FAILURE
        libc::EHOSTUNREACH => 113,   // KERN_FAILURE
        libc::EALREADY => 114,       // KERN_FAILURE
        libc::EINPROGRESS => 115,    // KERN_FAILURE
        libc::ESTALE => 116,         // KERN_FAILURE
        libc::EDQUOT => 122,         // KERN_RESOURCE_SHORTAGE
        // Linux-specific errno constants not available in macOS libc,
        // using raw integer values from Linux <asm-generic/errno.h>:
        //   ECHRNG=44, EL2NSYNC=45, EL3HLT=46, EL3RST=47, ELNRNG=48,
        //   EUNATCH=49, ENOCSI=50, EL2HLT=51, EBADE=52, EBADR=53, EXFULL=54,
        //   ENOANO=55, EBADRQC=56, EBADSLT=57, EDEADLOCK=58, EBFONT=59,
        //   ENOSTR=60, ENODATA=61, ETIME=62, ENOSR=63, ENONET=64, ENOPKG=65,
        //   EADV=68, ESRMNT=69, ECOMM=70, EDOTDOT=73, ENOTUNIQ=76, EBADFD=77,
        //   EREMCHG=78, ELIBACC=79, ELIBBAD=80, ELIBSCN=81, ELIBMAX=82,
        //   ELIBEXEC=83, ERESTART=85, ESTRPIPE=86, EUSERS=87, EUCLEAN=117,
        //   ENOTNAM=118, ENAVAIL=119, EISNAM=120, EREMOTEIO=121, ENOMEDIUM=123,
        //   EMEDIUMTYPE=124.
        // The guard keeps the values out of the constant arms on macOS, where
        // the same numbers are real errno constants matched above.
        #[cfg(target_os = "linux")]
        errno if linux_only_errno(errno) => 5, // KERN_FAILURE
        // Unknown errno values beyond the POSIX/Linux range map to KERN_FAILURE.
        _ => 5, // KERN_FAILURE
    }
}

/// Returns `true` for Linux-only errno values (44–124) that are not covered
/// by the constant arms above.  Compiles to nothing on non-Linux targets.
#[cfg(target_os = "linux")]
fn linux_only_errno(errno: i32) -> bool {
    matches!(errno, 44..=65 | 68..=70 | 73 | 76..=83 | 85..=87 | 117..=121 | 123..=124)
}

/// WSA error → DOS error mapping.
/// Converts WSAGetLastError() values to GetLastError() equivalents.
pub fn wsa_error_to_dos_error(wsa_error: u32) -> u32 {
    match wsa_error {
        0 => ERROR_SUCCESS,
        10004 => ERROR_TOO_MANY_OPEN_FILES, // WSAEINTR
        10013 => ERROR_ACCESS_DENIED,       // WSAEACCES
        10014 => ERROR_INVALID_PARAMETER,   // WSAEFAULT
        10022 => ERROR_INVALID_PARAMETER,   // WSAEINVAL
        10024 => ERROR_TOO_MANY_OPEN_FILES, // WSAEMFILE
        10035 => ERROR_INVALID_PARAMETER,   // WSAEWOULDBLOCK
        10036 => ERROR_INVALID_PARAMETER,   // WSAEINPROGRESS
        10037 => ERROR_INVALID_PARAMETER,   // WSAEALREADY
        10038 => ERROR_INVALID_HANDLE,      // WSAENOTSOCK
        10039 => ERROR_INVALID_PARAMETER,   // WSAEDESTADDRREQ
        10040 => ERROR_INVALID_PARAMETER,   // WSAEMSGSIZE
        10041 => ERROR_INVALID_PARAMETER,   // WSAEPROTOTYPE
        10042 => ERROR_INVALID_PARAMETER,   // WSAEPROTONOSUPPORT
        10043 => ERROR_INVALID_PARAMETER,   // WSAESOCKTNOSUPPORT
        10044 => ERROR_INVALID_PARAMETER,   // WSAEOPNOTSUPP
        10045 => ERROR_INVALID_PARAMETER,   // WSAEPFNOSUPPORT
        10046 => ERROR_INVALID_PARAMETER,   // WSAEAFNOSUPPORT
        10047 => ERROR_INVALID_PARAMETER,   // WSAEADDRINUSE
        10048 => ERROR_INVALID_PARAMETER,   // WSAEADDRNOTAVAIL
        10049 => ERROR_INVALID_PARAMETER,   // WSAENETDOWN
        10050 => ERROR_INVALID_PARAMETER,   // WSAENETUNREACH
        10051 => ERROR_INVALID_PARAMETER,   // WSAENETRESET
        10052 => ERROR_INVALID_PARAMETER,   // WSAECONNABORTED
        10053 => ERROR_INVALID_PARAMETER,   // WSAECONNRESET
        10054 => ERROR_INVALID_PARAMETER,   // WSAENOBUFS
        10055 => ERROR_INVALID_PARAMETER,   // WSAEISCONN
        10056 => ERROR_INVALID_PARAMETER,   // WSAENOTCONN
        10057 => ERROR_INVALID_PARAMETER,   // WSAESHUTDOWN
        10058 => ERROR_INVALID_PARAMETER,   // WSAETOOMANYREFS
        10060 => ERROR_TIMEOUT,             // WSAETIMEDOUT
        10061 => ERROR_ACCESS_DENIED,       // WSAECONNREFUSED
        10064 => ERROR_BAD_NETPATH,         // WSAEHOSTDOWN
        10065 => ERROR_BAD_NETPATH,         // WSAEHOSTUNREACH
        11001 => 11001,                     // WSAHOST_NOT_FOUND (passthrough)
        11002 => 11002,                     // WSATRY_AGAIN
        11003 => 11003,                     // WSANO_RECOVERY
        11004 => 11004,                     // WSANO_DATA
        _ => ERROR_INVALID_PARAMETER,
    }
}

/// Return a human-readable name for a DOS error code.
pub fn last_error_name(error: u32) -> &'static str {
    match error {
        0 => "ERROR_SUCCESS",
        2 => "ERROR_FILE_NOT_FOUND",
        3 => "ERROR_PATH_NOT_FOUND",
        4 => "ERROR_TOO_MANY_OPEN_FILES",
        5 => "ERROR_ACCESS_DENIED",
        6 => "ERROR_INVALID_HANDLE",
        7 => "ERROR_ARENA_TRASHED",
        8 => "ERROR_NOT_ENOUGH_MEMORY",
        32 => "ERROR_SHARING_VIOLATION",
        33 => "ERROR_LOCK_VIOLATION",
        53 => "ERROR_BAD_NETPATH",
        87 => "ERROR_INVALID_PARAMETER",
        122 => "ERROR_INSUFFICIENT_BUFFER",
        126 => "ERROR_MOD_NOT_FOUND",
        127 => "ERROR_PROC_NOT_FOUND",
        183 => "ERROR_ALREADY_EXISTS",
        203 => "ERROR_ENVVAR_NOT_FOUND",
        234 => "ERROR_MORE_DATA",
        259 => "ERROR_NO_MORE_ITEMS",
        998 => "ERROR_NOACCESS",
        1300 => "ERROR_NOT_ALL_ASSIGNED",
        1450 => "ERROR_NO_SYSTEM_RESOURCES",
        1460 => "ERROR_TIMEOUT",
        15700 => "APPMODEL_ERROR_NO_PACKAGE",
        _ => "ERROR_UNKNOWN",
    }
}

// ─── P1 — OOM Recovery ─────────────────────────────────────────────────────

/// Out-of-memory error type for wrapping critical allocations.
#[derive(Debug, Clone)]
pub struct OomError {
    pub size: usize,
    pub align: usize,
    pub message: String,
}

impl std::fmt::Display for OomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OOM: failed to allocate {} bytes (align {}): {}",
            self.size, self.align, self.message
        )
    }
}

impl std::error::Error for OomError {}

impl OomError {
    pub fn new(size: usize, align: usize, message: impl Into<String>) -> Self {
        Self {
            size,
            align,
            message: message.into(),
        }
    }
}

/// Try to allocate a Vec<T> with OOM error handling.
/// Returns an `OomError` instead of panicking on allocation failure.
pub fn try_vec<T>(capacity: usize) -> Result<Vec<T>, OomError> {
    let size = std::mem::size_of::<T>();
    let Some(total) = size.checked_mul(capacity) else {
        return Err(OomError::new(
            capacity,
            std::mem::align_of::<T>(),
            "Vec<T>: capacity overflows isize address space",
        ));
    };
    if total > isize::MAX as usize {
        return Err(OomError::new(
            capacity,
            std::mem::align_of::<T>(),
            "Vec<T>: capacity exceeds isize::MAX bytes",
        ));
    }
    let mut vec = Vec::new();
    vec.try_reserve_exact(capacity).map_err(|_| {
        OomError::new(
            capacity,
            std::mem::align_of::<T>(),
            "Vec<T>: allocation failed",
        )
    })?;
    Ok(vec)
}

/// Try to allocate a Box<T> with OOM error handling.
/// Returns an `OomError` instead of aborting the process on allocation failure.
pub fn try_box<T>(value: T) -> Result<Box<T>, OomError> {
    let layout = std::alloc::Layout::new::<T>();
    // SAFETY: `Layout::new::<T>()` is a valid layout for a single `T`.
    let ptr = unsafe { std::alloc::alloc(layout) };
    if ptr.is_null() {
        return Err(OomError::new(
            layout.size(),
            layout.align(),
            "Box<T>: allocation failed",
        ));
    }
    // SAFETY: `ptr` is non-null, aligned for `T` (per `Layout::new`), and we
    // write a fully initialized `T` before constructing the box.
    unsafe {
        std::ptr::write(ptr as *mut T, value);
        Ok(Box::from_raw(ptr as *mut T))
    }
}

/// Global OOM handler that logs the error instead of panicking.
/// This is a placeholder for the alloc error hook; on stable Rust
/// the default handler will abort.
pub fn handle_alloc_error(layout: std::alloc::Layout) {
    eprintln!(
        "Casa1 OOM: allocation failed — size={}, align={}",
        layout.size(),
        layout.align()
    );
}

/// Install the Casa1 OOM error hook.
///
/// Uses `std::alloc::set_alloc_error_hook` when available (nightly),
/// otherwise provides a no-op fallback.
pub fn install_oom_hook() {
    // The `set_alloc_error_hook` API is nightly-only. On stable Rust,
    // the default OOM handler will abort. We provide this function
    // as a future-compatible hook point.
    #[cfg(feature = "nightly_alloc_error_hook")]
    std::alloc::set_alloc_error_hook(|layout| {
        eprintln!(
            "Casa1 OOM: allocation failed — size={}, align={}. Graceful degradation attempted.",
            layout.size(),
            layout.align()
        );
        std::process::abort();
    });
}

// ─── P2 — Parameter Validation Macros ──────────────────────────────────────

/// Validate that a pointer is non-null. Returns `ERROR_INVALID_PARAMETER` if null.
#[macro_export]
macro_rules! validate_ptr {
    ($ptr:expr) => {
        if $ptr.is_null() {
            return $crate::error::ERROR_INVALID_PARAMETER as u32;
        }
    };
}

/// Validate that a handle is non-zero. Returns `ERROR_INVALID_HANDLE` if zero.
#[macro_export]
macro_rules! validate_handle {
    ($handle:expr) => {
        if $handle == 0 {
            return $crate::error::ERROR_INVALID_HANDLE as u32;
        }
    };
}

/// Validate that a buffer has sufficient size. Returns `ERROR_INSUFFICIENT_BUFFER` if too small.
#[macro_export]
macro_rules! validate_buffer_size {
    ($actual:expr, $required:expr) => {
        if $actual < $required {
            return $crate::error::ERROR_INSUFFICIENT_BUFFER as u32;
        }
    };
}

/// Validate that a value is within bounds. Returns `ERROR_INVALID_PARAMETER` if out of range.
#[macro_export]
macro_rules! validate_range {
    ($value:expr, $min:expr, $max:expr) => {
        if $value < $min || $value > $max {
            return $crate::error::ERROR_INVALID_PARAMETER as u32;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oom_constructor_sets_correct_code() {
        let err = AppError::oom("test allocation failed");
        assert_eq!(err.code, ReasonCode::RcOutOfMemory);
        assert_eq!(err.message, "test allocation failed");
        assert!(err.reproduction_hints.is_empty());
    }

    #[test]
    fn invalid_param_constructor_sets_correct_code() {
        let err = AppError::invalid_param("hFile", "non-zero handle");
        assert_eq!(err.code, ReasonCode::RcInvalidParameter);
        assert_eq!(err.message, "hFile: expected non-zero handle");
    }

    #[test]
    fn last_error_maps_filesystem_codes() {
        let cases: Vec<(ReasonCode, u32)> = vec![
            (ReasonCode::RcFsNotFound, ERROR_FILE_NOT_FOUND),
            (ReasonCode::RcFsPathInvalid, ERROR_INVALID_NAME),
            (ReasonCode::RcFsAlreadyExists, ERROR_ALREADY_EXISTS),
            (ReasonCode::RcFsReservedName, ERROR_INVALID_NAME),
            (ReasonCode::RcFsPathTooLong, ERROR_INVALID_PARAMETER),
            (ReasonCode::RcFsSharingViolation, ERROR_SHARING_VIOLATION),
            (ReasonCode::RcFsLockViolation, ERROR_LOCK_VIOLATION),
            (ReasonCode::RcFsSandboxEscape, ERROR_ACCESS_DENIED),
            (ReasonCode::RcSandboxPathViolation, ERROR_ACCESS_DENIED),
        ];
        for (code, expected) in &cases {
            assert_eq!(
                AppError::new(*code, "").last_error(),
                *expected,
                "last_error mismatch for {:?}",
                code
            );
        }
    }

    #[test]
    fn last_error_maps_win32_codes() {
        let err = AppError::new(ReasonCode::RcWin32InvalidHandle, "");
        assert_eq!(err.last_error(), ERROR_INVALID_HANDLE);

        let err = AppError::new(ReasonCode::RcHandleStaleOrInvalid, "");
        assert_eq!(err.last_error(), ERROR_INVALID_HANDLE);

        let err = AppError::new(ReasonCode::RcWin32Timeout, "");
        assert_eq!(err.last_error(), ERROR_TIMEOUT);
    }

    #[test]
    fn last_error_maps_pe_jit_codes() {
        let cases: Vec<(ReasonCode, u32)> = vec![
            (ReasonCode::RcPeParseInvalid, ERROR_BAD_FORMAT),
            (ReasonCode::RcImportMissing, ERROR_PROC_NOT_FOUND),
            (ReasonCode::RcUnimplInsn, ERROR_NOT_SUPPORTED),
            (ReasonCode::RcD3dFeatureUnsupported, ERROR_NOT_SUPPORTED),
            (ReasonCode::RcAnticheatDriverDetected, ERROR_ACCESS_DENIED),
            (ReasonCode::RcTlsCertRejected, ERROR_ACCESS_DENIED),
            (ReasonCode::RcTlsValidationFailed, ERROR_ACCESS_DENIED),
            (ReasonCode::RcBufferLimitExceeded, ERROR_INSUFFICIENT_BUFFER),
            (ReasonCode::RcJitCodeAllocFailed, ERROR_NOT_ENOUGH_MEMORY),
            (ReasonCode::RcUnsupportedPlatform, ERROR_NOT_SUPPORTED),
        ];
        for (code, expected) in &cases {
            assert_eq!(
                AppError::new(*code, "").last_error(),
                *expected,
                "last_error mismatch for {:?}",
                code
            );
        }
    }

    #[test]
    fn last_error_maps_graphics_codes() {
        let err = AppError::new(ReasonCode::RcInputUnsupported, "");
        assert_eq!(err.last_error(), ERROR_NOT_SUPPORTED);

        let err = AppError::new(ReasonCode::RcD3d9NotSupported, "");
        assert_eq!(err.last_error(), ERROR_NOT_SUPPORTED);

        let err = AppError::new(ReasonCode::RcVulkanNotSupported, "");
        assert_eq!(err.last_error(), ERROR_NOT_SUPPORTED);

        let err = AppError::new(ReasonCode::RcOpenGlNotSupported, "");
        assert_eq!(err.last_error(), ERROR_NOT_SUPPORTED);

        let err = AppError::new(ReasonCode::RcNotFound, "");
        assert_eq!(err.last_error(), ERROR_FILE_NOT_FOUND);
    }

    #[test]
    fn last_error_maps_audio_codes() {
        let err = AppError::new(ReasonCode::RcAudioUnsupported, "");
        assert_eq!(err.last_error(), ERROR_NOT_SUPPORTED);

        let err = AppError::new(ReasonCode::RcAudioBufferSizeMismatch, "");
        assert_eq!(err.last_error(), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn last_error_maps_network_codes() {
        let err = AppError::new(ReasonCode::RcNetworkUnreachable, "");
        assert_eq!(err.last_error(), ERROR_BAD_NETPATH);

        let err = AppError::new(ReasonCode::RcNetConnectionFailed, "");
        assert_eq!(err.last_error(), ERROR_BAD_NETPATH);

        let err = AppError::new(ReasonCode::RcNetDnsResolutionFailed, "");
        assert_eq!(err.last_error(), 11001); // WSAHOST_NOT_FOUND

        let err = AppError::new(ReasonCode::RcWinsockWouldBlock, "");
        assert_eq!(err.last_error(), 10035); // WSAEWOULDBLOCK

        let err = AppError::new(ReasonCode::RcDnsNotFound, "");
        assert_eq!(err.last_error(), 11001); // WSAHOST_NOT_FOUND

        let err = AppError::new(ReasonCode::RcNetWriteFailed, "");
        assert_eq!(err.last_error(), ERROR_WRITE_FAULT);

        let err = AppError::new(ReasonCode::RcNetReadFailed, "");
        assert_eq!(err.last_error(), ERROR_READ_FAULT);

        let err = AppError::new(ReasonCode::RcNetSocketCreateFailed, "");
        assert_eq!(err.last_error(), ERROR_NETWORK_ACCESS_DENIED);
    }

    #[test]
    fn last_error_maps_drm_codes() {
        let cases: Vec<(ReasonCode, u32)> = vec![
            (ReasonCode::RcDrmInitFailed, ERROR_ACCESS_DENIED),
            (ReasonCode::RcDrmDecryptFailed, ERROR_ACCESS_DENIED),
            (ReasonCode::RcDrmIntegrityFailed, ERROR_ACCESS_DENIED),
            (ReasonCode::RcDrmLicenseInvalid, ERROR_ACCESS_DENIED),
            (ReasonCode::RcDrmPackUnsupported, ERROR_NOT_SUPPORTED),
            (ReasonCode::RcDrmSectionNotFound, ERROR_FILE_NOT_FOUND),
            (ReasonCode::RcDrmRegionNotFound, ERROR_FILE_NOT_FOUND),
        ];
        for (code, expected) in &cases {
            assert_eq!(
                AppError::new(*code, "").last_error(),
                *expected,
                "last_error mismatch for {:?}",
                code
            );
        }
    }

    #[test]
    fn last_error_maps_wmi_codes() {
        let err = AppError::new(ReasonCode::RcWmiClassNotFound, "");
        assert_eq!(err.last_error(), ERROR_FILE_NOT_FOUND);

        let err = AppError::new(ReasonCode::RcWmiObjectNotFound, "");
        assert_eq!(err.last_error(), ERROR_FILE_NOT_FOUND);
    }

    #[test]
    fn last_error_maps_memory_codes() {
        let err = AppError::new(ReasonCode::RcOutOfMemory, "");
        assert_eq!(err.last_error(), ERROR_NOT_ENOUGH_MEMORY);

        let err = AppError::new(ReasonCode::RcOutOfMemoryHint, "");
        assert_eq!(err.last_error(), ERROR_NOT_ENOUGH_MEMORY);

        let err = AppError::new(ReasonCode::RcMemoryAccessViolation, "");
        assert_eq!(err.last_error(), ERROR_NOACCESS);

        let err = AppError::new(ReasonCode::RcGuestPointerOutOfRange, "");
        assert_eq!(err.last_error(), ERROR_NOACCESS);

        let err = AppError::new(ReasonCode::RcExecutableMemoryExhausted, "");
        assert_eq!(err.last_error(), ERROR_NO_SYSTEM_RESOURCES);
    }

    #[test]
    fn last_error_maps_dotnet_steam_media() {
        let err = AppError::new(ReasonCode::RcDotnetUnsupported, "");
        assert_eq!(err.last_error(), ERROR_NOT_SUPPORTED);

        let err = AppError::new(ReasonCode::RcSteamUpdateFailed, "");
        assert_eq!(err.last_error(), ERROR_ACCESS_DENIED);

        let err = AppError::new(ReasonCode::RcMediaInvalid, "");
        assert_eq!(err.last_error(), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn last_error_maps_seh_and_halted() {
        let err = AppError::new(ReasonCode::SehException, "");
        assert_eq!(err.last_error(), ERROR_NOACCESS);

        let err = AppError::new(ReasonCode::Halted, "");
        assert_eq!(err.last_error(), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn last_error_maps_lock_poisoned() {
        let err = AppError::new(ReasonCode::RcLockPoisoned, "");
        assert_eq!(err.last_error(), ERROR_INVALID_PARAMETER);
    }

    /// Verify that every ReasonCode variant has a deterministic last_error().
    /// This test enumerates ALL variants and ensures none panic or return 0
    /// (except Success, which legitimately maps to ERROR_SUCCESS=0).
    #[test]
    fn last_error_every_variant_is_mapped() {
        for value in 0..=3300 {
            if let Some(code) = ReasonCode::from_u32(value) {
                let last_err = AppError::new(code, "").last_error();
                if code == ReasonCode::Success {
                    assert_eq!(last_err, ERROR_SUCCESS, "Success must map to ERROR_SUCCESS");
                } else {
                    assert_ne!(
                        last_err, 0,
                        "last_error for {:?} (value={}) must not be ERROR_SUCCESS (0)",
                        code, value
                    );
                    assert!(
                        last_err < 100000,
                        "last_error for {:?} (value={}) looks suspicious: {}",
                        code,
                        value,
                        last_err
                    );
                }
            }
        }
    }

    // ── hresult() mapping tests ─────────────────────────────────────

    #[test]
    fn hresult_maps_correctly() {
        // Success → S_OK
        let err = AppError::new(ReasonCode::Success, "ok");
        assert_eq!(err.hresult(), 0x0000_0000);

        // Custom code → MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, code)
        let err = AppError::new(ReasonCode::RcOutOfMemory, "oom");
        assert_eq!(err.hresult(), 0x8004_0000 | 3200u32);

        let err = AppError::new(ReasonCode::RcFsNotFound, "not found");
        assert_eq!(err.hresult(), 0x8004_0000 | 1102u32);

        // Verify severity bit is set for errors
        let err = AppError::new(ReasonCode::RcInvalidParameter, "bad");
        assert_eq!(err.hresult() & 0x8000_0000, 0x8000_0000);
    }

    /// Verify every non-Success ReasonCode variant produces a valid HRESULT
    /// in the FACILITY_ITF range with the error severity bit set.
    #[test]
    fn hresult_every_variant_is_mapped() {
        for value in 0..=3300 {
            if let Some(code) = ReasonCode::from_u32(value) {
                let hr = AppError::new(code, "").hresult();
                if code == ReasonCode::Success {
                    assert_eq!(hr, 0x0000_0000, "Success HRESULT must be S_OK");
                } else {
                    // Must have severity bit set
                    assert!(
                        hr & 0x8000_0000 != 0,
                        "HRESULT for {:?} must have severity bit set, got 0x{:08X}",
                        code,
                        hr
                    );
                    // Must use FACILITY_ITF (4), so bits 16-26 should match 0x8004_XXXX
                    assert_eq!(
                        hr & 0x7FFF_0000,
                        0x0004_0000,
                        "HRESULT for {:?} must use FACILITY_ITF, got 0x{:08X}",
                        code,
                        hr
                    );
                    // The low 16 bits should be the ReasonCode value
                    assert_eq!(
                        hr & 0x0000_FFFF,
                        code.as_u32(),
                        "HRESULT for {:?} must embed the reason code in low 16 bits, got 0x{:08X}",
                        code,
                        hr
                    );
                }
            }
        }
    }

    // ── Error context / reproduction-hint tests (Item 59) ───────────

    #[test]
    fn with_hint_appends_to_reproduction_hints() {
        let err = AppError::new(ReasonCode::RcIo, "I/O error")
            .with_hint("function: CreateFileW")
            .with_hint("arg: handle=0x42");
        assert_eq!(err.reproduction_hints.len(), 2);
        assert!(err.reproduction_hints[0].contains("CreateFileW"));
        assert!(err.reproduction_hints[1].contains("handle=0x42"));
    }

    #[test]
    fn from_io_includes_source_info() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = AppError::from_io(ReasonCode::RcFsNotFound, "open_file", &io_err);
        assert!(err.message.contains("open_file"));
        assert!(err.reproduction_hints[0].contains("file not found"));
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use super::*;

    #[test]
    fn ntstatus_success() {
        assert_eq!(ntstatus_to_dos_error(0x0000_0000), ERROR_SUCCESS);
    }

    #[test]
    fn ntstatus_access_violation() {
        assert_eq!(ntstatus_to_dos_error(0xC000_0005), ERROR_NOACCESS);
    }

    #[test]
    fn ntstatus_invalid_handle() {
        assert_eq!(ntstatus_to_dos_error(0xC000_0008), ERROR_INVALID_HANDLE);
    }

    #[test]
    fn ntstatus_invalid_param() {
        assert_eq!(ntstatus_to_dos_error(0xC000_000D), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn ntstatus_no_such_file() {
        assert_eq!(ntstatus_to_dos_error(0xC000_000F), ERROR_FILE_NOT_FOUND);
        assert_eq!(ntstatus_to_dos_error(0xC000_0034), ERROR_FILE_NOT_FOUND);
    }

    #[test]
    fn ntstatus_access_denied() {
        assert_eq!(ntstatus_to_dos_error(0xC000_0022), ERROR_ACCESS_DENIED);
    }

    #[test]
    fn ntstatus_no_memory() {
        assert_eq!(ntstatus_to_dos_error(0xC000_0017), ERROR_NOT_ENOUGH_MEMORY);
    }

    #[test]
    fn ntstatus_sharing_violation() {
        assert_eq!(ntstatus_to_dos_error(0xC000_0043), ERROR_SHARING_VIOLATION);
    }

    #[test]
    fn ntstatus_already_exists() {
        assert_eq!(ntstatus_to_dos_error(0xC000_0035), ERROR_ALREADY_EXISTS);
    }

    #[test]
    fn ntstatus_dll_not_found() {
        // 0xC000_00BB is STATUS_NOT_SUPPORTED, not STATUS_DLL_NOT_FOUND.
        assert_eq!(ntstatus_to_dos_error(0xC000_00BB), ERROR_NOT_SUPPORTED);
        assert_eq!(ntstatus_to_dos_error(0xC000_0135), ERROR_MOD_NOT_FOUND);
    }

    #[test]
    fn ntstatus_ordinal_not_found() {
        assert_eq!(ntstatus_to_dos_error(0xC000_0139), ERROR_PROC_NOT_FOUND);
    }

    #[test]
    fn ntstatus_fallback() {
        // Unknown NTSTATUS should fall back to ERROR_INVALID_PARAMETER
        assert_eq!(ntstatus_to_dos_error(0xFFFF_FFFF), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn hresult_s_ok() {
        assert_eq!(hresult_to_ntstatus(0x0000_0000), 0x0000_0000);
        assert_eq!(hresult_to_dos_error(0x0000_0000), ERROR_SUCCESS);
    }

    #[test]
    fn hresult_e_outofmemory() {
        assert_eq!(hresult_to_ntstatus(0x8000_000E), 0xC000_0017);
        assert_eq!(hresult_to_dos_error(0x8000_000E), ERROR_NOT_ENOUGH_MEMORY);
    }

    #[test]
    fn hresult_e_invalidarg() {
        assert_eq!(hresult_to_ntstatus(0x8000_0057), 0xC000_000D);
        assert_eq!(hresult_to_dos_error(0x8000_0057), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn hresult_class_not_reg() {
        assert_eq!(hresult_to_dos_error(0x8007_000E), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn dos_error_to_errno_mappings() {
        assert_eq!(dos_error_to_errno(0), 0);
        assert_eq!(dos_error_to_errno(2), libc::ENOENT);
        assert_eq!(dos_error_to_errno(4), libc::EMFILE); // ERROR_TOO_MANY_OPEN_FILES
        assert_eq!(dos_error_to_errno(5), libc::EACCES);
        assert_eq!(dos_error_to_errno(6), libc::EBADF);
        assert_eq!(dos_error_to_errno(87), libc::EINVAL);
        assert_eq!(dos_error_to_errno(122), libc::ENOSPC);
        assert_eq!(dos_error_to_errno(1460), libc::ETIMEDOUT);
        assert_eq!(dos_error_to_errno(9999), libc::EINVAL); // fallback
    }

    #[test]
    fn wsa_to_dos_error() {
        assert_eq!(wsa_error_to_dos_error(0), ERROR_SUCCESS);
        assert_eq!(wsa_error_to_dos_error(10038), ERROR_INVALID_HANDLE); // WSAENOTSOCK
        assert_eq!(wsa_error_to_dos_error(10060), ERROR_TIMEOUT); // WSAETIMEDOUT
        assert_eq!(wsa_error_to_dos_error(99999), ERROR_INVALID_PARAMETER); // fallback
    }

    #[test]
    fn last_error_name_known() {
        assert_eq!(last_error_name(0), "ERROR_SUCCESS");
        assert_eq!(last_error_name(2), "ERROR_FILE_NOT_FOUND");
        assert_eq!(last_error_name(87), "ERROR_INVALID_PARAMETER");
        assert_eq!(last_error_name(998), "ERROR_NOACCESS");
    }

    #[test]
    fn last_error_name_fallback() {
        assert_eq!(last_error_name(99999), "ERROR_UNKNOWN");
    }

    #[test]
    fn errno_to_kern_return_success() {
        assert_eq!(errno_to_kern_return(0), 0);
    }

    #[test]
    fn errno_to_kern_return_known() {
        assert_eq!(errno_to_kern_return(libc::EPERM), 1);
        assert_eq!(errno_to_kern_return(libc::ENOMEM), 12);
        assert_eq!(errno_to_kern_return(libc::EINVAL), 22);
        // EAGAIN == EWOULDBLOCK on macOS/Linux; both map to
        // KERN_RESOURCE_SHORTAGE (6).
        assert_eq!(errno_to_kern_return(libc::EAGAIN), 6);
        assert_eq!(errno_to_kern_return(libc::EWOULDBLOCK), 6);
    }

    #[test]
    fn try_vec_and_box_are_fallible() {
        assert!(try_vec::<u8>(0).is_ok());
        assert!(try_vec::<u8>(64).is_ok());
        // Capacity overflow must error, not panic.
        assert!(try_vec::<u8>(usize::MAX).is_err());
        assert!(try_vec::<u64>(usize::MAX / 2).is_err());
        assert!(try_box(42u32).is_ok());
        assert_eq!(*try_box(String::from("hello")).unwrap(), "hello");
    }

    #[test]
    fn roundtrip_ntstatus_to_dos_to_errno() {
        // STATUS_ACCESS_DENIED → ERROR_ACCESS_DENIED → EACCES
        let dos = ntstatus_to_dos_error(0xC000_0022);
        assert_eq!(dos, ERROR_ACCESS_DENIED);
        assert_eq!(dos_error_to_errno(dos), libc::EACCES);
    }

    #[test]
    fn roundtrip_hresult_to_dos_to_errno() {
        // E_OUTOFMEMORY → STATUS_NO_MEMORY → ERROR_NOT_ENOUGH_MEMORY → ENOMEM
        let dos = hresult_to_dos_error(0x8000_000E);
        assert_eq!(dos, ERROR_NOT_ENOUGH_MEMORY);
        assert_eq!(dos_error_to_errno(dos), libc::ENOMEM);
    }
}
