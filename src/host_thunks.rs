//! Centralized host thunk metadata, guest pointer helpers, and subsystem
//! organization for the PE runtime dispatch layer.
//!
//! This module provides:
//! - [`ThunkMetadata`] — centralized metadata for each host thunk (name,
//!   subsystem, argument count, last-error behavior, implementation quality,
//!   Steam-bootstrap criticality).
//! - [`Subsystem`] — enumeration of host thunk subsystems for modular
//!   organization.
//! - [`LastErrorBehavior`] — describes how a thunk affects `GetLastError`.
//! - [`ImplementationLevel`] — classifies how completely a host thunk is
//!   implemented (used by import-coverage diagnostics).
//! - [`THUNK_METADATA`] — the canonical per-DLL thunk metadata table covering
//!   the Steam-bootstrap-critical API surface and the tracked Steam.exe
//!   fixture's imports.
//! - Guest pointer read/write helpers with bounds checking, overflow
//!   protection, and partial-write detection.
//!
//! # Design Goals
//!
//! 1. **Single source of truth** for thunk metadata so argument counts, names,
//!    and last-error behavior stay consistent across dispatch, testing, and
//!    diagnostics.
//! 2. **Safe guest memory access** through validated pointer helpers that
//!    replace ad-hoc `memory.read_u32(...)` calls with bounds-checked
//!    alternatives.
//! 3. **Subsystem-level organization** enabling future modular splitting of
//!    `pe_runtime.rs` by grouping thunks into logical categories.

use crate::cpu::MemoryImage;
use crate::error::AppError;
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Subsystem enumeration
// ---------------------------------------------------------------------------

/// Subsystem categories for host thunks.
///
/// Each thunk belongs to exactly one subsystem, which determines its
/// logical grouping for modular dispatch, testing, and documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subsystem {
    /// Core Win32 kernel APIs (kernel32.dll, kernelbase.dll, ntdll.dll).
    Kernel,
    /// User32 window management and GDI (user32.dll, gdi32.dll).
    User32,
    /// Network APIs (ws2_32.dll, winhttp.dll, wininet.dll).
    Network,
    /// Graphics APIs (d3d11.dll, d3d12.dll, dxgi.dll, d3d9.dll).
    Graphics,
    /// Audio APIs (xaudio2_*.dll, dsound.dll).
    Audio,
    /// COM / OLE automation (ole32.dll, oleaut32.dll).
    Com,
    /// Shell and filesystem (shell32.dll, shlwapi.dll, advapi32.dll).
    Shell,
    /// Steam API (steam_api64.dll, steam_api.dll).
    Steam,
    /// Direct2D / DirectWrite (d2d1.dll, dwrite.dll).
    D2D,
    /// WebView2 (webview2.dll).
    WebView2,
    /// WMI (wbem*.dll).
    Wmi,
    /// Security and cryptography (bcrypt.dll, crypt32.dll).
    Security,
    /// C runtime (msvcrt.dll, ucrtbase.dll, vcruntime*.dll).
    Crt,
    /// Diagnostics and telemetry.
    Diagnostics,
    /// Internal runtime helpers (guest object management, delay-load).
    Runtime,
}

// ---------------------------------------------------------------------------
// Last-error behavior
// ---------------------------------------------------------------------------

/// Describes how a host thunk affects the Win32 last-error value.
///
/// Windows API functions fall into several categories regarding
/// `GetLastError` / `SetLastError`:
///
/// - **SetsOnFailure**: The thunk calls `SetLastError` with a specific code
///   when it fails. On success, last-error may or may not be modified.
/// - **SetsAlways**: The thunk always sets last-error (even on success).
/// - **Preserves**: The thunk never modifies last-error.
/// - **Unknown**: Not yet audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastErrorBehavior {
    /// Sets last-error on failure; may or may not modify on success.
    SetsOnFailure,
    /// Always sets last-error regardless of outcome.
    SetsAlways,
    /// Never modifies last-error.
    Preserves,
    /// Not yet audited — assume it may modify last-error.
    Unknown,
}

// ---------------------------------------------------------------------------
// Implementation quality
// ---------------------------------------------------------------------------

/// Classifies how completely a host thunk is implemented.
///
/// This is the implementation-quality axis of the canonical [`ThunkMetadata`]
/// table.  It is consumed by the import-coverage diagnostics
/// ([`crate::import_coverage::coverage_for_steam_fixture`]) and by the
/// section24 integration model, which reports every Steam.exe import against
/// it and encodes the release requirement that no *runtime-reached*
/// Steam-critical API be `Stub` or `Unsupported`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImplementationLevel {
    /// The thunk is documented as complete: it reads its arguments, performs
    /// the real operation against runtime state, writes guest-visible
    /// results, and reports errors through `last_error`.
    Implemented,
    /// The thunk has a real implementation with known limitations documented
    /// in the dispatch code (e.g. plausible/synthetic values, a restricted
    /// subset of codes or formats, unsupported edge cases that degrade
    /// gracefully).
    Partial,
    /// The thunk is a placeholder/no-op: it returns a canned value (or
    /// ignores its arguments) and performs no meaningful operation.
    Stub,
    /// There is no host thunk for this API — dispatch would fail (the
    /// import maps to `HostThunk::Unsupported` or to nothing at all).
    Unsupported,
}

impl ImplementationLevel {
    /// `true` when the level is `Implemented` or `Partial` — i.e. the API
    /// has at least a working host thunk.
    pub fn has_working_implementation(self) -> bool {
        matches!(
            self,
            ImplementationLevel::Implemented | ImplementationLevel::Partial
        )
    }
}

// ---------------------------------------------------------------------------
// Thunk metadata
// ---------------------------------------------------------------------------

/// Static metadata for a single host thunk.
///
/// This struct centralizes information that was previously scattered across
/// the `HostThunk::x86_arg_bytes()` match arms and dispatch code.
#[derive(Debug, Clone)]
pub struct ThunkMetadata {
    /// Exporting DLL name (lowercase, with extension, e.g. `"kernel32.dll"`).
    pub dll: &'static str,
    /// Human-readable API name (e.g., `"CreateFileW"`).
    pub name: &'static str,
    /// Subsystem this thunk belongs to.
    pub subsystem: Subsystem,
    /// Total size of all arguments in bytes for x86 (32-bit) calling convention.
    /// For x64, arguments are passed in registers (RCX, RDX, R8, R9) and then
    /// stack, so this is primarily used for x86 stack cleanup.
    pub x86_arg_bytes: u32,
    /// How this thunk affects `GetLastError`.
    pub last_error: LastErrorBehavior,
    /// Implementation quality classification (see [`ImplementationLevel`]).
    pub implementation: ImplementationLevel,
    /// Whether this API is Steam-bootstrap-critical: the Steam client cannot
    /// start without a working host thunk for it.  A runtime-reached
    /// Steam-critical API classified `Stub` or `Unsupported` fails the
    /// release requirement encoded in tests/section24.rs.
    pub steam_critical: bool,
}

/// Convenience constructor for [`THUNK_METADATA`] entries.
///
/// `last_error` is conservatively `Unknown` for every table entry: the
/// authoritative last-error behavior lives in the dispatch code, and the
/// table's purpose is implementation quality + Steam criticality.
const fn meta(
    dll: &'static str,
    name: &'static str,
    x86_arg_bytes: u32,
    subsystem: Subsystem,
    implementation: ImplementationLevel,
    steam_critical: bool,
) -> ThunkMetadata {
    ThunkMetadata {
        dll,
        name,
        subsystem,
        x86_arg_bytes,
        last_error: LastErrorBehavior::Unknown,
        implementation,
        steam_critical,
    }
}

/// Canonical host-thunk metadata table.
///
/// Covers every import of the tracked Steam.exe fixture
/// (`ges/steam/drive_c/Steam/Steam.exe`) plus the Steam-bootstrap-critical
/// API surface.  Implementation levels were assigned from the dispatch code
/// in `pe_runtime.rs`:
///
/// - **Implemented** — complete, real behavior (arguments read, guest state
///   updated, results/errors reported).
/// - **Partial** — real behavior with documented limitations (plausible
///   values, restricted code/format subsets, unsupported edges degrade
///   gracefully).
/// - **Stub** — canned/no-op placeholders that return fixed values.
/// - **Unsupported** — no host thunk exists for the API.
///
/// `steam_critical` marks the Steam-bootstrap-critical APIs (kernel32
/// process/thread/IO/handle basics, user32 window/message loop, named pipes,
/// winsock connect/send/recv, WinHTTP/WinINet, registry, COM/OLE init, CRT
/// malloc/free/_beginthreadex/errno, TLS, and the sync-primitive family).
pub static THUNK_METADATA: &[ThunkMetadata] = &[
    // Kernel (kernel32.dll, psapi.dll, version.dll)
    meta(
        "kernel32.dll",
        "AcquireSRWLockExclusive",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "CallNamedPipeW",
        28,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "CloseHandle",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "CompareStringW",
        24,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "ConnectNamedPipe",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "ConvertFiberToThread",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "ConvertThreadToFiber",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "CopyFileW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "CreateDirectoryW",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "CreateEventA",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "CreateEventW",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "CreateFiber",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "CreateFileA",
        28,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "CreateFileMappingW",
        24,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "CreateFileW",
        28,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "CreateIoCompletionPort",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "CreateMutexW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "CreateNamedPipeW",
        32,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "CreateProcessW",
        40,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "CreateSemaphoreW",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "CreateThread",
        24,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "DebugBreak",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "DecodePointer",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "DeleteCriticalSection",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "DeleteFiber",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "DeleteFileW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "DeviceIoControl",
        32,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "DisableThreadLibraryCalls",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "kernel32.dll",
        "DuplicateHandle",
        28,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "EncodePointer",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "EnterCriticalSection",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "ExitProcess",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "ExitThread",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "FileTimeToSystemTime",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "FindClose",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "FindFirstFileExW",
        24,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "FindFirstFileW",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "FindNextFileW",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "FindResourceA",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "FlushFileBuffers",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "FreeEnvironmentStringsW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "FreeLibrary",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetACP",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetCPInfo",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetCommandLineA",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetCommandLineW",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetConsoleCP",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetConsoleMode",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetCurrentDirectoryA",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetCurrentDirectoryW",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetCurrentProcess",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetCurrentProcessId",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetCurrentThread",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetCurrentThreadId",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetDateFormatW",
        24,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetDiskFreeSpaceA",
        20,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetDiskFreeSpaceExW",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetDriveTypeW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetEnvironmentStringsW",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetEnvironmentVariableW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetExitCodeProcess",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetExitCodeThread",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetFileAttributesA",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetFileAttributesExW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetFileAttributesW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetFileInformationByHandle",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetFileInformationByHandleEx",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetFileSizeEx",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetFileTime",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetFileType",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetFullPathNameW",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetLastError",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetModuleFileNameA",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetModuleFileNameW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetModuleHandleA",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetModuleHandleExA",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetModuleHandleExW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetModuleHandleW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetOEMCP",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetOverlappedResult",
        20,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetProcAddress",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetProcessAffinityMask",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetProcessHeap",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetProcessHeaps",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetStartupInfoW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetStdHandle",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetStringTypeW",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetSystemDirectoryW",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetSystemInfo",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetSystemTime",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetSystemTimeAsFileTime",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetTickCount",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetTickCount64",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetTimeFormatW",
        24,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetTimeZoneInformation",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GetVersionExA",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetVersionExW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GetWindowsDirectoryW",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "GlobalAlloc",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GlobalFree",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GlobalLock",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "GlobalMemoryStatusEx",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        true,
    ),
    meta(
        "kernel32.dll",
        "GlobalUnlock",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "HeapAlloc",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "HeapFree",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "HeapLock",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "HeapQueryInformation",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "HeapReAlloc",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "HeapSetInformation",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "HeapSize",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "HeapUnlock",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "HeapValidate",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "HeapWalk",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "InitOnceBeginInitialize",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "InitOnceComplete",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "InitializeCriticalSection",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "InitializeCriticalSectionAndSpinCount",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "InitializeCriticalSectionEx",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "InitializeSListHead",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "InitializeSRWLock",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "InterlockedCompareExchange",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "kernel32.dll",
        "InterlockedDecrement",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "kernel32.dll",
        "InterlockedExchange",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "kernel32.dll",
        "InterlockedExchangeAdd",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "kernel32.dll",
        "InterlockedIncrement",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "kernel32.dll",
        "InterlockedPushEntrySList",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "IsBadWritePtr",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "IsDebuggerPresent",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "IsProcessorFeaturePresent",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "IsValidCodePage",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "LCMapStringW",
        24,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "LeaveCriticalSection",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "LoadLibraryA",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "LoadLibraryExA",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "LoadLibraryExW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "LoadLibraryW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "LoadResource",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "LocalAlloc",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "LocalFree",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "LockResource",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "MapViewOfFile",
        20,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "MoveFileExW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "MulDiv",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "MultiByteToWideChar",
        24,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "OpenEventA",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "OpenEventW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "OpenMutexW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "OpenProcess",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "OpenSemaphoreW",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "OpenThread",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "OutputDebugStringA",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "OutputDebugStringW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "PeekNamedPipe",
        24,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "PostQueuedCompletionStatus",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "ProcessIdToSessionId",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "QueryPerformanceCounter",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "QueryPerformanceFrequency",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "RaiseException",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "ReadConsoleA",
        20,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "ReadConsoleW",
        20,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "ReadFile",
        20,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "ReleaseMutex",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "ReleaseSRWLockExclusive",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "ReleaseSemaphore",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "RemoveDirectoryA",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "RemoveDirectoryW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "ResetEvent",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "ResumeThread",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "RtlUnwind",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetConsoleCtrlHandler",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetConsoleMode",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetCurrentDirectoryW",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "SetEndOfFile",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetEnvironmentVariableW",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "SetErrorMode",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetEvent",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "SetFileAttributesW",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetFilePointer",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetFilePointerEx",
        20,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "SetFileTime",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetHandleInformation",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetLastError",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "SetProcessAffinityMask",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetStdHandle",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetThreadAffinityMask",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetThreadPriority",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "SetUnhandledExceptionFilter",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "SizeofResource",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "Sleep",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "SleepEx",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "SuspendThread",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "kernel32.dll",
        "SwitchToFiber",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "SwitchToThread",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "kernel32.dll",
        "SystemTimeToFileTime",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "SystemTimeToTzSpecificLocalTime",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "TerminateProcess",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "TerminateThread",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "TlsAlloc",
        0,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "TlsFree",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "TlsGetValue",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "TlsSetValue",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "TryAcquireSRWLockExclusive",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "TryEnterCriticalSection",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "UnhandledExceptionFilter",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "UnmapViewOfFile",
        4,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "VerSetConditionMask",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "VerifyVersionInfoW",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "VirtualAlloc",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "VirtualFree",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "VirtualProtect",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "VirtualQuery",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "WaitForMultipleObjects",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "WaitForSingleObject",
        8,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "WaitForSingleObjectEx",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "kernel32.dll",
        "WideCharToMultiByte",
        32,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "WriteConsoleW",
        20,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "kernel32.dll",
        "WriteFile",
        20,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "psapi.dll",
        "GetModuleFileNameExW",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "psapi.dll",
        "GetModuleInformation",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "psapi.dll",
        "GetProcessMemoryInfo",
        12,
        Subsystem::Kernel,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "version.dll",
        "VerQueryValueW",
        16,
        Subsystem::Kernel,
        ImplementationLevel::Implemented,
        false,
    ),
    // User32 / GDI (user32.dll, gdi32.dll, comctl32.dll)
    meta(
        "comctl32.dll",
        "InitCommonControlsEx",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "AddFontMemResourceEx",
        16,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "gdi32.dll",
        "ChoosePixelFormat",
        8,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "gdi32.dll",
        "CreateCompatibleDC",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "CreateDIBSection",
        24,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "CreateFontW",
        56,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "CreateICW",
        16,
        Subsystem::User32,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "gdi32.dll",
        "DeleteDC",
        4,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "gdi32.dll",
        "DeleteObject",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "GetDeviceCaps",
        8,
        Subsystem::User32,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "gdi32.dll",
        "GetStockObject",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "GetTextExtentPoint32W",
        16,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "RemoveFontMemResourceEx",
        4,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "gdi32.dll",
        "SelectObject",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "SetBkColor",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "SetBkMode",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "SetPixelFormat",
        12,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "gdi32.dll",
        "SetTextColor",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "gdi32.dll",
        "SwapBuffers",
        4,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "gdi32.dll",
        "TextOutW",
        20,
        Subsystem::User32,
        ImplementationLevel::Partial,
        true,
    ),
    meta(
        "user32.dll",
        "AllowSetForegroundWindow",
        4,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "user32.dll",
        "BeginPaint",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "CloseClipboard",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "CreateWindowExW",
        48,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "DefWindowProcW",
        0,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "DestroyWindow",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "DialogBoxParamA",
        20,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "DispatchMessageW",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "EmptyClipboard",
        0,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "EndDialog",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "EndPaint",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "EnumChildWindows",
        12,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "user32.dll",
        "EnumWindows",
        8,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "user32.dll",
        "GetClassInfoExW",
        12,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "GetDC",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "GetDesktopWindow",
        0,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "GetDlgItem",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "GetDlgItemInt",
        16,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "GetFocus",
        0,
        Subsystem::User32,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "user32.dll",
        "GetMessageA",
        0,
        Subsystem::User32,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "user32.dll",
        "GetMessageW",
        16,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "GetMonitorInfoW",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "GetProcessWindowStation",
        0,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "user32.dll",
        "GetSystemMetrics",
        4,
        Subsystem::User32,
        ImplementationLevel::Partial,
        true,
    ),
    meta(
        "user32.dll",
        "GetUserObjectInformationW",
        20,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "user32.dll",
        "GetWindowLongW",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "GetWindowRect",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "GetWindowTextA",
        0,
        Subsystem::User32,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "user32.dll",
        "GetWindowTextLengthA",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "GetWindowTextW",
        12,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "GetWindowThreadProcessId",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "InvalidateRect",
        12,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "IsWindowVisible",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "KillTimer",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "LoadCursorW",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "LoadIconW",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "MapWindowPoints",
        16,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "user32.dll",
        "MessageBoxA",
        16,
        Subsystem::User32,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "user32.dll",
        "MessageBoxW",
        16,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "MonitorFromPoint",
        12,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "MonitorFromWindow",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "MoveWindow",
        24,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "MsgWaitForMultipleObjects",
        20,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "OpenClipboard",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "PeekMessageW",
        20,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "PostMessageA",
        0,
        Subsystem::User32,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "user32.dll",
        "PostMessageW",
        0,
        Subsystem::User32,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "user32.dll",
        "PostThreadMessageW",
        16,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "RedrawWindow",
        16,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "RegisterClassExW",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "RegisterClassW",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "ReleaseDC",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "SendMessageW",
        16,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "SetClassLongW",
        12,
        Subsystem::User32,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "user32.dll",
        "SetClipboardData",
        8,
        Subsystem::User32,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "user32.dll",
        "SetDlgItemInt",
        16,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "SetDlgItemTextA",
        12,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "SetFocus",
        0,
        Subsystem::User32,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "user32.dll",
        "SetTimer",
        16,
        Subsystem::User32,
        ImplementationLevel::Partial,
        true,
    ),
    meta(
        "user32.dll",
        "SetWindowLongW",
        12,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "SetWindowPos",
        28,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "SetWindowTextW",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "ShowWindow",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "TranslateMessage",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "UnregisterClassW",
        8,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "user32.dll",
        "UpdateWindow",
        4,
        Subsystem::User32,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "user32.dll",
        "wsprintfA",
        0,
        Subsystem::User32,
        ImplementationLevel::Partial,
        false,
    ),
    // Network (ws2_32.dll, wsock32.dll, winhttp.dll, wininet.dll)
    meta(
        "winhttp.dll",
        "WinHttpConnect",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "winhttp.dll",
        "WinHttpOpen",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "winhttp.dll",
        "WinHttpOpenRequest",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "winhttp.dll",
        "WinHttpReadData",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "winhttp.dll",
        "WinHttpReceiveResponse",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "winhttp.dll",
        "WinHttpSendRequest",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "wininet.dll",
        "HttpOpenRequestW",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "wininet.dll",
        "HttpSendRequestW",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "wininet.dll",
        "InternetConnectW",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "wininet.dll",
        "InternetOpenW",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "wininet.dll",
        "InternetReadFile",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "ws2_32.dll",
        "WSACleanup",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "WSAGetLastError",
        0,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "ws2_32.dll",
        "WSAIoctl",
        36,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "WSARecv",
        28,
        Subsystem::Network,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "ws2_32.dll",
        "WSARecvFrom",
        36,
        Subsystem::Network,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "ws2_32.dll",
        "WSASend",
        28,
        Subsystem::Network,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "ws2_32.dll",
        "WSASendTo",
        36,
        Subsystem::Network,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "ws2_32.dll",
        "WSASetLastError",
        4,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "WSASocketA",
        24,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "WSAStartup",
        8,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "__WSAFDIsSet",
        8,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "bind",
        12,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "closesocket",
        4,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "connect",
        12,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "ws2_32.dll",
        "freeaddrinfo",
        4,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "getaddrinfo",
        16,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "getsockname",
        12,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "htonl",
        4,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "htons",
        4,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "ioctlsocket",
        12,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "ntohl",
        4,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "ntohs",
        4,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "recv",
        16,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "ws2_32.dll",
        "select",
        20,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "send",
        16,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "ws2_32.dll",
        "setsockopt",
        20,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "shutdown",
        8,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "ws2_32.dll",
        "socket",
        12,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "wsock32.dll",
        "WSAStartup",
        8,
        Subsystem::Network,
        ImplementationLevel::Implemented,
        false,
    ),
    // Shell / advapi32 (shell32.dll, advapi32.dll)
    meta(
        "advapi32.dll",
        "DeregisterEventSource",
        4,
        Subsystem::Shell,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "advapi32.dll",
        "InitializeSecurityDescriptor",
        8,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "advapi32.dll",
        "RegCloseKey",
        4,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "advapi32.dll",
        "RegCreateKeyExA",
        36,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "advapi32.dll",
        "RegCreateKeyExW",
        36,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "advapi32.dll",
        "RegOpenKeyA",
        12,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "advapi32.dll",
        "RegOpenKeyExA",
        20,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "advapi32.dll",
        "RegOpenKeyExW",
        20,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "advapi32.dll",
        "RegQueryValueExA",
        24,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "advapi32.dll",
        "RegQueryValueExW",
        24,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "advapi32.dll",
        "RegSetValueExA",
        24,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "advapi32.dll",
        "RegSetValueExW",
        24,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "advapi32.dll",
        "RegisterEventSourceW",
        8,
        Subsystem::Shell,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "advapi32.dll",
        "ReportEventW",
        36,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "advapi32.dll",
        "SetSecurityDescriptorDacl",
        16,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "shell32.dll",
        "CommandLineToArgvW",
        8,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "shell32.dll",
        "IsUserAnAdmin",
        0,
        Subsystem::Shell,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "shell32.dll",
        "SHGetFileInfoW",
        20,
        Subsystem::Shell,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "shell32.dll",
        "SHGetKnownFolderPath",
        16,
        Subsystem::Shell,
        ImplementationLevel::Implemented,
        false,
    ),
    // COM / OLE (ole32.dll, oleaut32.dll)
    meta(
        "ole32.dll",
        "CoCreateInstance",
        20,
        Subsystem::Com,
        ImplementationLevel::Partial,
        true,
    ),
    meta(
        "ole32.dll",
        "CoInitializeEx",
        8,
        Subsystem::Com,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "ole32.dll",
        "CoTaskMemFree",
        4,
        Subsystem::Com,
        ImplementationLevel::Stub,
        false,
    ),
    meta(
        "ole32.dll",
        "CoUninitialize",
        0,
        Subsystem::Com,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "ole32.dll",
        "OleInitialize",
        4,
        Subsystem::Com,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "oleaut32.dll",
        "VariantClear",
        4,
        Subsystem::Com,
        ImplementationLevel::Implemented,
        false,
    ),
    // Security / crypto (crypt32.dll, bcrypt.dll)
    meta(
        "bcrypt.dll",
        "BCryptGenRandom",
        12,
        Subsystem::Security,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "crypt32.dll",
        "CertAddCertificateContextToStore",
        16,
        Subsystem::Security,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "crypt32.dll",
        "CertCloseStore",
        8,
        Subsystem::Security,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "crypt32.dll",
        "CertCreateCertificateContext",
        12,
        Subsystem::Security,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "crypt32.dll",
        "CertFreeCertificateChain",
        4,
        Subsystem::Security,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "crypt32.dll",
        "CertFreeCertificateContext",
        4,
        Subsystem::Security,
        ImplementationLevel::Implemented,
        false,
    ),
    meta(
        "crypt32.dll",
        "CertGetCertificateChain",
        32,
        Subsystem::Security,
        ImplementationLevel::Partial,
        false,
    ),
    meta(
        "crypt32.dll",
        "CertOpenStore",
        20,
        Subsystem::Security,
        ImplementationLevel::Implemented,
        false,
    ),
    // C runtime (msvcrt.dll)
    meta(
        "msvcrt.dll",
        "_beginthreadex",
        0,
        Subsystem::Crt,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "msvcrt.dll",
        "_errno",
        0,
        Subsystem::Crt,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "msvcrt.dll",
        "free",
        0,
        Subsystem::Crt,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "msvcrt.dll",
        "malloc",
        0,
        Subsystem::Crt,
        ImplementationLevel::Implemented,
        true,
    ),
    meta(
        "msvcrt.dll",
        "printf",
        0,
        Subsystem::Crt,
        ImplementationLevel::Unsupported,
        true,
    ),
    meta(
        "msvcrt.dll",
        "sprintf",
        0,
        Subsystem::Crt,
        ImplementationLevel::Unsupported,
        true,
    ),
];

/// Look up the canonical metadata entry for a (DLL, API) pair.
///
/// Matching is case-insensitive and tolerates the `.dll` suffix on either
/// side (`"kernel32"` and `"KERNEL32.DLL"` both match `"kernel32.dll"`).
/// Returns `None` when the API is not covered by [`THUNK_METADATA`] — in
/// coverage terms that means there is no host thunk for it (`Unsupported`).
pub fn lookup_thunk_metadata(dll: &str, api: &str) -> Option<&'static ThunkMetadata> {
    let dll_lower = dll.to_ascii_lowercase();
    let dll_stem = dll_lower.strip_suffix(".dll").unwrap_or(&dll_lower);
    THUNK_METADATA.iter().find(|metadata| {
        metadata
            .dll
            .strip_suffix(".dll")
            .unwrap_or(metadata.dll)
            .eq_ignore_ascii_case(dll_stem)
            && metadata.name.eq_ignore_ascii_case(api)
    })
}

/// Resolve an ordinal-only import to its canonical API name, mirroring the
/// runtime's `HostThunk::from_import` ordinal resolution.
///
/// Covers the ordinals observed in the tracked Steam.exe fixture (ws2_32 /
/// wsock32, shell32 and oleaut32).  Returns `None` for ordinals the runtime
/// does not map — callers report such imports as `ordinal#N`.
pub fn ordinal_import_name(dll: &str, ordinal: u16) -> Option<&'static str> {
    let dll_stem = dll.strip_suffix(".dll").unwrap_or(dll).to_ascii_lowercase();
    match (dll_stem.as_str(), ordinal) {
        ("ws2_32" | "wsock32", 2) => Some("bind"),
        ("ws2_32" | "wsock32", 3) => Some("closesocket"),
        ("ws2_32" | "wsock32", 4) => Some("connect"),
        ("ws2_32" | "wsock32", 6) => Some("getsockname"),
        ("ws2_32" | "wsock32", 8) => Some("htonl"),
        ("ws2_32" | "wsock32", 9) => Some("htons"),
        ("ws2_32" | "wsock32", 10) => Some("ioctlsocket"),
        ("ws2_32" | "wsock32", 14) => Some("ntohl"),
        ("ws2_32" | "wsock32", 15) => Some("ntohs"),
        ("ws2_32" | "wsock32", 16) => Some("recv"),
        ("ws2_32" | "wsock32", 18) => Some("select"),
        ("ws2_32" | "wsock32", 19) => Some("send"),
        ("ws2_32" | "wsock32", 21) => Some("setsockopt"),
        ("ws2_32" | "wsock32", 22) => Some("shutdown"),
        ("ws2_32" | "wsock32", 23) => Some("socket"),
        ("ws2_32" | "wsock32", 111) => Some("WSAGetLastError"),
        ("ws2_32" | "wsock32", 112) => Some("WSASetLastError"),
        ("ws2_32" | "wsock32", 115) => Some("WSAStartup"),
        ("ws2_32" | "wsock32", 116) => Some("WSACleanup"),
        ("ws2_32" | "wsock32", 151) => Some("__WSAFDIsSet"),
        ("wsock32", 1142) => Some("WSAStartup"),
        ("shell32", 680) => Some("IsUserAnAdmin"),
        ("oleaut32", 9) => Some("VariantClear"),
        _ => None,
    }
}

// -----------------------------------------------------------------
// Kernel (kernel32.dll, psapi.dll, version.dll)
// -----------------------------------------------------------------

// ---------------------------------------------------------------------------
// Guest pointer helpers
// ---------------------------------------------------------------------------

/// Validate that a guest pointer range `[address, address+len)` is accessible.
///
/// Checks:
/// - `address` is non-zero (null pointer check)
/// - `address + len` does not overflow `u64`
/// - The range falls within mapped guest memory
///
/// Returns `Ok(())` if the range is valid, or an `AppError` with
/// [`ReasonCode::RcGuestPointerOutOfRange`] otherwise.
pub fn validate_guest_pointer(
    memory: &MemoryImage,
    address: u64,
    len: usize,
) -> Result<(), AppError> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcGuestPointerOutOfRange,
            "guest pointer is null",
        ));
    }
    if len == 0 {
        return Ok(());
    }
    let end = address.checked_add(len as u64).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcGuestPointerOutOfRange,
            format!("guest pointer range overflow: {address:#x}+{len:#x}"),
        )
    })?;
    if !memory.is_range_mapped(address, len) {
        return Err(AppError::new(
            ReasonCode::RcGuestPointerOutOfRange,
            format!("guest pointer range [{address:#x}, {end:#x}) is not mapped"),
        ));
    }
    Ok(())
}

/// Read bytes from guest memory with full pointer validation.
///
/// Performs null-pointer check, overflow check, and range-mapped check before
/// reading. Returns [`ReasonCode::RcGuestPointerOutOfRange`] for invalid addresses.
pub fn read_guest_bytes_checked(
    memory: &MemoryImage,
    address: u64,
    len: usize,
) -> Result<Vec<u8>, AppError> {
    validate_guest_pointer(memory, address, len)?;
    memory.read_bytes(address, len)
}

/// Write a byte slice to guest memory with full pointer validation.
///
/// Performs null-pointer check (if `bytes` is non-empty), overflow check, and
/// range-mapped check before writing. Returns [`ReasonCode::RcGuestPointerOutOfRange`]
/// for invalid addresses.
pub fn write_guest_bytes_checked(
    memory: &mut MemoryImage,
    address: u64,
    bytes: &[u8],
) -> Result<(), AppError> {
    if bytes.is_empty() {
        return Ok(());
    }
    validate_guest_pointer(memory, address, bytes.len())?;
    memory.map_bytes(address, bytes);
    Ok(())
}

/// Read a `u16` from guest memory with pointer validation.
pub fn read_guest_u16_checked(memory: &MemoryImage, address: u64) -> Result<u16, AppError> {
    validate_guest_pointer(memory, address, 2)?;
    memory.read_u16(address)
}

/// Read a `u32` from guest memory with pointer validation.
pub fn read_guest_u32_checked(memory: &MemoryImage, address: u64) -> Result<u32, AppError> {
    validate_guest_pointer(memory, address, 4)?;
    memory.read_u32(address)
}

/// Read a `u64` from guest memory with pointer validation.
pub fn read_guest_u64_checked(memory: &MemoryImage, address: u64) -> Result<u64, AppError> {
    validate_guest_pointer(memory, address, 8)?;
    memory.read_u64(address)
}

/// Write a `u16` to guest memory with pointer validation.
pub fn write_guest_u16_checked(
    memory: &mut MemoryImage,
    address: u64,
    value: u16,
) -> Result<(), AppError> {
    validate_guest_pointer(memory, address, 2)?;
    memory.write_u16(address, value);
    Ok(())
}

/// Write a `u32` to guest memory with pointer validation.
pub fn write_guest_u32_checked(
    memory: &mut MemoryImage,
    address: u64,
    value: u32,
) -> Result<(), AppError> {
    validate_guest_pointer(memory, address, 4)?;
    memory.write_u32(address, value);
    Ok(())
}

/// Write a `u64` to guest memory with pointer validation.
pub fn write_guest_u64_checked(
    memory: &mut MemoryImage,
    address: u64,
    value: u64,
) -> Result<(), AppError> {
    validate_guest_pointer(memory, address, 8)?;
    memory.write_u64(address, value);
    Ok(())
}

/// Read a UTF-16 string from guest memory with full validation.
///
/// Handles:
/// - Null pointer (returns empty string)
/// - Explicit length (reads exactly `length` code units, no null terminator required)
/// - Null-terminated (reads until null when `length < 0`)
/// - Invalid surrogate pairs (replaced with U+FFFD via `String::from_utf16_lossy`)
/// - Truncated strings (if the string crosses a page boundary, unmapped pages
///   result in an error)
///
/// # Arguments
/// * `memory` - Guest memory image
/// * `ptr` - Guest address of the UTF-16 string
/// * `length` - If >= 0, exact number of code units to read. If < 0, read until null.
/// * `max_units` - Safety cap on the number of code units to read (prevents
///   runaway reads on corrupt guest data).
pub fn read_guest_utf16_string_checked(
    memory: &MemoryImage,
    ptr: u64,
    length: i32,
    max_units: usize,
) -> Result<String, AppError> {
    if ptr == 0 {
        return Ok(String::new());
    }
    let mut units = Vec::new();
    if length >= 0 {
        let count = (length as usize).min(max_units);
        // `count * 2` could overflow usize for a huge `max_units`/`length`; a
        // wrapped byte count would validate the wrong (tiny) range and let the
        // read loop walk far beyond mapped memory. Check it explicitly.
        let byte_len = count.checked_mul(2).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcGuestPointerOutOfRange,
                format!("UTF-16 read length overflows: {count} code units"),
            )
        })?;
        // Validate the entire range upfront
        validate_guest_pointer(memory, ptr, byte_len)?;
        for i in 0..count {
            let cu = memory.read_u16(ptr + (i as u64 * 2)).unwrap_or(0);
            units.push(cu);
        }
    } else {
        // Read until null terminator, with safety cap
        loop {
            if units.len() >= max_units {
                break;
            }
            let offset = ptr + (units.len() as u64 * 2);
            // Validate each pair before reading
            if offset.checked_add(2).is_none() {
                break;
            }
            if !memory.is_range_mapped(offset, 2) {
                return Err(AppError::new(
                    ReasonCode::RcGuestPointerOutOfRange,
                    format!(
                        "UTF-16 string read at {offset:#x} exceeds mapped memory (read {} units)",
                        units.len()
                    ),
                ));
            }
            let cu = memory.read_u16(offset).unwrap_or(0);
            if cu == 0 {
                break;
            }
            units.push(cu);
        }
    }
    Ok(String::from_utf16_lossy(&units))
}

/// Read a null-terminated UTF-16 string from guest memory.
///
/// Returns an empty string for null pointers. Replaces invalid surrogate
/// pairs with the replacement character. Reads up to `max_units` code units
/// as a safety cap.
pub fn read_guest_utf16_string_null_terminated(
    memory: &MemoryImage,
    ptr: u64,
    max_units: usize,
) -> Result<String, AppError> {
    read_guest_utf16_string_checked(memory, ptr, -1, max_units)
}

/// Read a sized UTF-16 buffer from guest memory.
///
/// Reads exactly `length` code units (no null terminator required).
/// Replaces invalid surrogate pairs with the replacement character.
pub fn read_guest_utf16_string_sized(
    memory: &MemoryImage,
    ptr: u64,
    length: i32,
    max_units: usize,
) -> Result<String, AppError> {
    read_guest_utf16_string_checked(memory, ptr, length, max_units)
}

/// Write a UTF-16 string to guest memory with null terminator.
///
/// Validates the target range before writing. Returns an error if the
/// target buffer is too small or unmapped.
pub fn write_guest_utf16_string_checked(
    memory: &mut MemoryImage,
    address: u64,
    value: &str,
    capacity_including_null: usize,
) -> Result<(), AppError> {
    let total_bytes = capacity_including_null * 2;
    validate_guest_pointer(memory, address, total_bytes)?;

    let mut bytes = vec![0u8; total_bytes];
    for (index, unit) in value
        .encode_utf16()
        .take(capacity_including_null.saturating_sub(1))
        .enumerate()
    {
        let offset = index * 2;
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    memory.map_bytes(address, &bytes);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::MemoryImage;

    /// Helper: create a MemoryImage with a mapped region at the given address.
    fn make_memory_with_region(base: u64, size: usize) -> MemoryImage {
        let mut mem = MemoryImage::default();
        mem.map_bytes(base, &vec![0xAAu8; size]);
        mem
    }

    // ---- validate_guest_pointer tests ----

    #[test]
    fn test_validate_null_pointer_rejected() {
        let mem = MemoryImage::default();
        let err = validate_guest_pointer(&mem, 0, 4).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
        assert!(err.message.contains("null"));
    }

    #[test]
    fn test_validate_zero_length_null_rejected() {
        let mem = MemoryImage::default();
        // Null pointer is rejected even for zero-length reads (our policy is strict)
        let result = validate_guest_pointer(&mem, 0, 0);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    }

    #[test]
    fn test_validate_unmapped_pointer_rejected() {
        let mem = MemoryImage::default();
        let err = validate_guest_pointer(&mem, 0x1000, 4).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
        assert!(err.message.contains("not mapped"));
    }

    #[test]
    fn test_validate_mapped_pointer_ok() {
        let mem = make_memory_with_region(0x1000, 64);
        validate_guest_pointer(&mem, 0x1000, 4).unwrap();
        validate_guest_pointer(&mem, 0x1000, 64).unwrap();
    }

    #[test]
    fn test_validate_overflow_rejected() {
        let mem = make_memory_with_region(0x1000, 64);
        let err = validate_guest_pointer(&mem, u64::MAX, 4).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
        assert!(err.message.contains("overflow"));
    }

    #[test]
    fn test_validate_partial_unmapped_rejected() {
        let mem = make_memory_with_region(0x1000, 16);
        // Start is mapped but end extends past
        let err = validate_guest_pointer(&mem, 0x1000, 32).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
    }

    // ---- read_guest_u16_checked tests ----

    #[test]
    fn test_read_u16_checked_mapped() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x1000, &0x1234_u16.to_le_bytes());
        let val = read_guest_u16_checked(&mem, 0x1000).unwrap();
        assert_eq!(val, 0x1234);
    }

    #[test]
    fn test_read_u16_checked_null_rejected() {
        let mem = MemoryImage::default();
        let err = read_guest_u16_checked(&mem, 0).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
    }

    #[test]
    fn test_read_u16_checked_unmapped_rejected() {
        let mem = MemoryImage::default();
        let err = read_guest_u16_checked(&mem, 0xDEAD_0000).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
    }

    // ---- read_guest_u32_checked tests ----

    #[test]
    fn test_read_u32_checked_mapped() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x2000, &0xDEADBEEF_u32.to_le_bytes());
        let val = read_guest_u32_checked(&mem, 0x2000).unwrap();
        assert_eq!(val, 0xDEADBEEF);
    }

    #[test]
    fn test_read_u32_checked_null_rejected() {
        let mem = MemoryImage::default();
        assert!(read_guest_u32_checked(&mem, 0).is_err());
    }

    // ---- read_guest_u64_checked tests ----

    #[test]
    fn test_read_u64_checked_mapped() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x3000, &0xCAFEBABE_DEADC0DE_u64.to_le_bytes());
        let val = read_guest_u64_checked(&mem, 0x3000).unwrap();
        assert_eq!(val, 0xCAFEBABE_DEADC0DE);
    }

    #[test]
    fn test_read_u64_checked_null_rejected() {
        let mem = MemoryImage::default();
        assert!(read_guest_u64_checked(&mem, 0).is_err());
    }

    // ---- write_guest_u32_checked tests ----

    #[test]
    fn test_write_u32_checked_roundtrip() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x4000, &[0u8; 8]);
        write_guest_u32_checked(&mut mem, 0x4000, 0x12345678).unwrap();
        let val = read_guest_u32_checked(&mem, 0x4000).unwrap();
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_write_u32_checked_null_rejected() {
        let mut mem = MemoryImage::default();
        assert!(write_guest_u32_checked(&mut mem, 0, 42).is_err());
    }

    // ---- write_guest_u64_checked tests ----

    #[test]
    fn test_write_u64_checked_roundtrip() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x5000, &[0u8; 16]);
        write_guest_u64_checked(&mut mem, 0x5000, 0xAABBCCDDEEFF0011).unwrap();
        let val = read_guest_u64_checked(&mem, 0x5000).unwrap();
        assert_eq!(val, 0xAABBCCDDEEFF0011);
    }

    // ---- read/write bytes checked tests ----

    #[test]
    fn test_read_bytes_checked_null_rejected() {
        let mem = MemoryImage::default();
        assert!(read_guest_bytes_checked(&mem, 0, 4).is_err());
    }

    #[test]
    fn test_read_bytes_checked_mapped() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x1000, &[1, 2, 3, 4]);
        let bytes = read_guest_bytes_checked(&mem, 0x1000, 4).unwrap();
        assert_eq!(bytes, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_write_bytes_checked_roundtrip() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x6000, &[0u8; 8]);
        write_guest_bytes_checked(&mut mem, 0x6000, &[0xAA, 0xBB, 0xCC]).unwrap();
        let bytes = read_guest_bytes_checked(&mem, 0x6000, 3).unwrap();
        assert_eq!(bytes, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_write_bytes_checked_null_rejected() {
        let mut mem = MemoryImage::default();
        assert!(write_guest_bytes_checked(&mut mem, 0, &[1, 2, 3]).is_err());
    }

    #[test]
    fn test_write_bytes_checked_empty_ok() {
        let mut mem = MemoryImage::default();
        write_guest_bytes_checked(&mut mem, 0, &[]).unwrap();
    }

    // ---- UTF-16 string tests ----

    #[test]
    fn test_utf16_null_pointer_returns_empty() {
        let mem = MemoryImage::default();
        let s = read_guest_utf16_string_null_terminated(&mem, 0, 256).unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn test_utf16_read_null_terminated() {
        let mut mem = MemoryImage::default();
        // "Hi\0" in UTF-16LE
        let data: Vec<u8> = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00].to_vec();
        mem.map_bytes(0x1000, &data);
        let s = read_guest_utf16_string_null_terminated(&mem, 0x1000, 256).unwrap();
        assert_eq!(s, "Hi");
    }

    #[test]
    fn test_utf16_read_sized() {
        let mut mem = MemoryImage::default();
        // "ABCD" in UTF-16LE (no null terminator)
        let data: Vec<u8> = [0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00].to_vec();
        mem.map_bytes(0x1000, &data);
        let s = read_guest_utf16_string_sized(&mem, 0x1000, 4, 256).unwrap();
        assert_eq!(s, "ABCD");
    }

    #[test]
    fn test_utf16_truncated_surrogate_pair() {
        let mut mem = MemoryImage::default();
        // High surrogate without low surrogate (U+D800)
        let data: Vec<u8> = [0x00, 0xD8, 0x00, 0x00].to_vec();
        mem.map_bytes(0x1000, &data);
        let s = read_guest_utf16_string_sized(&mem, 0x1000, 2, 256).unwrap();
        // U+D800 is an unpaired surrogate → replacement character
        assert!(
            s.contains('\u{FFFD}'),
            "expected replacement char, got: {s:?}"
        );
    }

    #[test]
    fn test_utf16_invalid_surrogate_pair() {
        let mut mem = MemoryImage::default();
        // High surrogate followed by another high surrogate (invalid)
        let data: Vec<u8> = [0x00, 0xD8, 0x01, 0xD8, 0x00, 0x00].to_vec();
        mem.map_bytes(0x1000, &data);
        let s = read_guest_utf16_string_null_terminated(&mem, 0x1000, 256).unwrap();
        // Both should be replaced
        assert!(
            s.contains('\u{FFFD}'),
            "expected replacement char for invalid surrogate pair, got: {s:?}"
        );
    }

    #[test]
    fn test_utf16_max_units_cap() {
        let mut mem = MemoryImage::default();
        // "ABCDE" in UTF-16LE with no null terminator
        let data: Vec<u8> = [0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00, 0x45, 0x00].to_vec();
        mem.map_bytes(0x1000, &data);
        // Cap at 3 units even though 5 are available
        let s = read_guest_utf16_string_null_terminated(&mem, 0x1000, 3).unwrap();
        assert_eq!(s, "ABC");
    }

    #[test]
    fn test_utf16_unmapped_memory_rejected() {
        let mem = MemoryImage::default();
        let result = read_guest_utf16_string_null_terminated(&mem, 0xFFFF_0000, 256);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    }

    #[test]
    fn test_utf16_write_and_read_roundtrip() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x7000, &[0u8; 32]);
        write_guest_utf16_string_checked(&mut mem, 0x7000, "Hello", 16).unwrap();
        let s = read_guest_utf16_string_null_terminated(&mem, 0x7000, 256).unwrap();
        assert_eq!(s, "Hello");
    }

    #[test]
    fn test_utf16_write_truncates_to_capacity() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x8000, &[0u8; 16]);
        // Write "Hello" into a buffer of capacity 4 (including null) → only "Hel" + null
        write_guest_utf16_string_checked(&mut mem, 0x8000, "Hello", 4).unwrap();
        let s = read_guest_utf16_string_null_terminated(&mem, 0x8000, 256).unwrap();
        assert_eq!(s, "Hel");
    }

    #[test]
    fn test_utf16_write_unmapped_rejected() {
        let mut mem = MemoryImage::default();
        let result = write_guest_utf16_string_checked(&mut mem, 0xDEAD_0000, "test", 8);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    }

    #[test]
    fn test_utf16_non_terminated_string() {
        let mut mem = MemoryImage::default();
        // Write "AB" without null terminator, followed by garbage
        let data: Vec<u8> = [0x41, 0x00, 0x42, 0x00, 0xFF, 0xFF].to_vec();
        mem.map_bytes(0x1000, &data);
        // Read exactly 2 code units (no null terminator expected)
        let s = read_guest_utf16_string_sized(&mem, 0x1000, 2, 256).unwrap();
        assert_eq!(s, "AB");
    }

    // ---- Subsystem and metadata tests ----

    #[test]
    fn test_subsystem_equality() {
        assert_eq!(Subsystem::Kernel, Subsystem::Kernel);
        assert_ne!(Subsystem::Kernel, Subsystem::Network);
    }

    #[test]
    fn test_last_error_behavior_variants() {
        assert_ne!(
            LastErrorBehavior::SetsOnFailure,
            LastErrorBehavior::Preserves
        );
        assert_ne!(LastErrorBehavior::SetsAlways, LastErrorBehavior::Unknown);
    }

    #[test]
    fn test_implementation_level_variants() {
        assert_ne!(
            ImplementationLevel::Implemented,
            ImplementationLevel::Partial
        );
        assert_ne!(ImplementationLevel::Stub, ImplementationLevel::Unsupported);
        assert!(ImplementationLevel::Implemented.has_working_implementation());
        assert!(ImplementationLevel::Partial.has_working_implementation());
        assert!(!ImplementationLevel::Stub.has_working_implementation());
        assert!(!ImplementationLevel::Unsupported.has_working_implementation());
    }

    #[test]
    fn test_implementation_level_serde_roundtrip() {
        let json = serde_json::to_string(&ImplementationLevel::Partial).unwrap();
        assert_eq!(json, "\"Partial\"");
        let back: ImplementationLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ImplementationLevel::Partial);
    }

    #[test]
    fn test_thunk_metadata_fields() {
        let meta = ThunkMetadata {
            dll: "kernel32.dll",
            name: "TestThunk",
            subsystem: Subsystem::Kernel,
            x86_arg_bytes: 12,
            last_error: LastErrorBehavior::SetsOnFailure,
            implementation: ImplementationLevel::Implemented,
            steam_critical: true,
        };
        assert_eq!(meta.dll, "kernel32.dll");
        assert_eq!(meta.name, "TestThunk");
        assert_eq!(meta.subsystem, Subsystem::Kernel);
        assert_eq!(meta.x86_arg_bytes, 12);
        assert_eq!(meta.last_error, LastErrorBehavior::SetsOnFailure);
        assert_eq!(meta.implementation, ImplementationLevel::Implemented);
        assert!(meta.steam_critical);
    }

    // ---- canonical metadata table tests ----

    #[test]
    fn test_metadata_table_lookup_case_insensitive() {
        let entry = lookup_thunk_metadata("KERNEL32.DLL", "createfilew").expect("CreateFileW");
        assert_eq!(entry.name, "CreateFileW");
        assert_eq!(entry.implementation, ImplementationLevel::Implemented);
        assert!(entry.steam_critical);

        let stem = lookup_thunk_metadata("kernel32", "CreateFileW").expect("stem dll");
        assert_eq!(stem.dll, "kernel32.dll");
    }

    #[test]
    fn test_metadata_table_missing_lookup_returns_none() {
        assert!(lookup_thunk_metadata("kernel32.dll", "DoesNotExist").is_none());
        assert!(lookup_thunk_metadata("unknown.dll", "CreateFileW").is_none());
    }

    #[test]
    fn test_metadata_table_covers_steam_critical_surface() {
        // Every entry marked steam_critical must have a classification, and
        // the bootstrap-critical basics must be present.
        for name in [
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "CloseHandle",
            "CreateThread",
            "WaitForSingleObject",
            "GetProcAddress",
            "LoadLibraryW",
            "GetModuleHandleW",
            "HeapAlloc",
            "VirtualAlloc",
            "GetLastError",
            "CreateWindowExW",
            "GetMessageW",
            "connect",
            "WSAGetLastError",
            "WinHttpOpen",
            "CoInitializeEx",
            "RegOpenKeyExW",
            "malloc",
            "TlsAlloc",
        ] {
            let entry = lookup_thunk_metadata("kernel32.dll", name)
                .or_else(|| lookup_thunk_metadata("ws2_32.dll", name))
                .or_else(|| lookup_thunk_metadata("winhttp.dll", name))
                .or_else(|| lookup_thunk_metadata("ole32.dll", name))
                .or_else(|| lookup_thunk_metadata("advapi32.dll", name))
                .or_else(|| lookup_thunk_metadata("msvcrt.dll", name))
                .or_else(|| lookup_thunk_metadata("user32.dll", name))
                .unwrap_or_else(|| panic!("steam-critical API {name} missing from THUNK_METADATA"));
            assert!(entry.steam_critical, "{name} must be marked steam_critical");
        }
        // No duplicate (dll, name) pairs.
        let mut seen = std::collections::HashSet::new();
        for entry in THUNK_METADATA {
            assert!(
                seen.insert((entry.dll, entry.name)),
                "duplicate metadata entry {} / {}",
                entry.dll,
                entry.name
            );
        }
    }

    #[test]
    fn test_metadata_table_steam_critical_quality_stance() {
        // Canonical-surface stance: a steam-critical API that HAS a host
        // thunk must not be a no-op stub — stubs would fail the release gate
        // the moment the guest reaches them.
        for entry in THUNK_METADATA {
            assert!(
                !(entry.steam_critical && entry.implementation == ImplementationLevel::Stub),
                "steam-critical API {} must not be a Stub",
                entry.name
            );
        }
        // Steam-critical Unsupported entries must be exactly the documented
        // no-host-thunk set (they fail the gate only if invoked).
        let mut unsupported_critical: Vec<&str> = THUNK_METADATA
            .iter()
            .filter(|entry| {
                entry.steam_critical && entry.implementation == ImplementationLevel::Unsupported
            })
            .map(|entry| entry.name)
            .collect();
        unsupported_critical.sort_unstable();
        let mut expected: Vec<&str> = vec![
            "GetTickCount64",
            "GetFileInformationByHandleEx",
            "DisableThreadLibraryCalls",
            "InterlockedIncrement",
            "InterlockedDecrement",
            "InterlockedExchange",
            "InterlockedCompareExchange",
            "InterlockedExchangeAdd",
            "PostMessageW",
            "GetFocus",
            "SetFocus",
            "GetMessageA",
            "PostMessageA",
            "GetWindowTextA",
            "GetVersionExA",
            "printf",
            "sprintf",
        ];
        expected.sort_unstable();
        assert_eq!(unsupported_critical, expected);
    }

    #[test]
    fn test_ordinal_import_name_resolution() {
        assert_eq!(ordinal_import_name("ws2_32.dll", 16), Some("recv"));
        assert_eq!(ordinal_import_name("ws2_32.dll", 23), Some("socket"));
        assert_eq!(ordinal_import_name("WS2_32", 111), Some("WSAGetLastError"));
        assert_eq!(ordinal_import_name("wsock32.dll", 1142), Some("WSAStartup"));
        assert_eq!(
            ordinal_import_name("shell32.dll", 680),
            Some("IsUserAnAdmin")
        );
        assert_eq!(ordinal_import_name("oleaut32.dll", 9), Some("VariantClear"));
        assert_eq!(ordinal_import_name("ws2_32.dll", 999), None);
        assert_eq!(ordinal_import_name("kernel32.dll", 1), None);
    }
}
