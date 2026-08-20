//! Real Win32/CRT executors for the reference executable (Windows only).
//!
//! Every category here calls the actual Windows API — GetFullPathNameW,
//! CompareStringOrdinal, GetStringTypeW, CreateFileW, LockFileEx, DeleteFileW,
//! MoveFileExW, LoadLibraryExW, Reg* (HKCU), the synchronization primitives,
//! the UCRT (snprintf/%n/invalid-parameter-handler/strtol/errno) and the TLS
//! functions. Nothing is reimplemented: the reference IS Windows.
//!
//! Protocol-level classification helpers (path `kind`, `has_ads`) are shared
//! with the host model by design — they classify the INPUT shape per the
//! documented Win32 path-form rules, while the authoritative `normalized`
//! string and `last_error` come from GetFullPathNameW itself.

use serde::Deserialize;
use serde_json::{Value, json};
use std::ffi::{CString, c_int, c_void};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ── Win32 types ─────────────────────────────────────────────────────────────

type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type HKEY = *mut c_void;
type DWORD = u32;
type BOOL = i32;
type LPCWSTR = *const u16;
type LPWSTR = *mut u16;
type LPCSTR = *const i8;
type LPVOID = *mut c_void;
type LPBYTE = *mut u8;
type LONG = i32;
type SIZE_T = usize;
type LPDWORD = *mut u32;
type PHKEY = *mut HKEY;

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

const GENERIC_READ: DWORD = 0x8000_0000;
const GENERIC_WRITE: DWORD = 0x4000_0000;
const DELETE_ACCESS: DWORD = 0x0001_0000;
const FILE_SHARE_READ: DWORD = 0x1;
const FILE_SHARE_WRITE: DWORD = 0x2;
const FILE_SHARE_DELETE: DWORD = 0x4;
const CREATE_ALWAYS: DWORD = 2;
const OPEN_EXISTING: DWORD = 3;
const OPEN_ALWAYS: DWORD = 4;
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;
const FILE_ATTRIBUTE_READONLY: DWORD = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: DWORD = 0x20;
const INVALID_FILE_ATTRIBUTES: DWORD = 0xffff_ffff;
const FILE_BEGIN: DWORD = 0;
const FILE_END: DWORD = 2;
const MOVEFILE_REPLACE_EXISTING: DWORD = 0x1;
const LOCKFILE_FAIL_IMMEDIATELY: DWORD = 0x1;
const LOCKFILE_EXCLUSIVE_LOCK: DWORD = 0x2;
const INFINITE: DWORD = 0xffff_ffff;
const WAIT_OBJECT_0: DWORD = 0;
const WAIT_ABANDONED: DWORD = 0x80;
const WAIT_TIMEOUT: DWORD = 0x102;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: DWORD = 0x4;
const LOAD_LIBRARY_SEARCH_SYSTEM32: DWORD = 0x800;
const KEY_ALL_ACCESS: DWORD = 0xf003f;
const HKEY_CURRENT_USER: HKEY = 0x8000_0001usize as HKEY;
const CT_CTYPE1: DWORD = 0x1;
const CSTR_EQUAL: c_int = 2;
const TRUE: BOOL = 1;
const TLS_OUT_OF_INDEXES: DWORD = 0xffff_ffff;
// TLS_MINIMUM_AVAILABLE from the Windows SDK (WinNT.h): the guaranteed
// minimum number of TLS indexes per process.
const TLS_MINIMUM_AVAILABLE: DWORD = 64;

// Virtual-memory constants (WinNT.h / WinBase.h).
const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const MEM_DECOMMIT: DWORD = 0x4000;
const MEM_RELEASE: DWORD = 0x8000;
const MEM_FREE: DWORD = 0x0001_0000;
const MEM_PRIVATE: DWORD = 0x0002_0000;
const PAGE_NOACCESS: DWORD = 0x01;
const PAGE_READONLY: DWORD = 0x02;
const PAGE_READWRITE: DWORD = 0x04;
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const ERROR_INVALID_ADDRESS: DWORD = 487;
const HEAP_ZERO_MEMORY: DWORD = 0x8;
const VER_PLATFORM_WIN32_NT: DWORD = 2;
const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;
const ERROR_NO_MORE_FILES: DWORD = 18;
const ERROR_ENVVAR_NOT_FOUND: DWORD = 203;
const ERROR_PATH_NOT_FOUND: DWORD = 3;
const ERROR_FILE_NOT_FOUND: DWORD = 2;
const ERROR_ACCESS_DENIED: DWORD = 5;
const ERROR_INVALID_HANDLE: DWORD = 6;

/// MEMORY_BASIC_INFORMATION (WinNT.h).  The x64 layout is the 48-byte form;
/// the x86 layout is the 28-byte form (used when a 32-bit runner is added).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base_address: LPVOID,
    allocation_base: LPVOID,
    allocation_protect: DWORD,
    alignment1: DWORD,
    region_size: SIZE_T,
    state: DWORD,
    protect: DWORD,
    ty: DWORD,
    alignment2: DWORD,
}

#[cfg(target_arch = "x86")]
#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base_address: LPVOID,
    allocation_base: LPVOID,
    allocation_protect: DWORD,
    region_size: DWORD,
    state: DWORD,
    protect: DWORD,
    ty: DWORD,
}

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: HANDLE,
}

impl Overlapped {
    fn at(offset: u64) -> Self {
        Overlapped {
            internal: 0,
            internal_high: 0,
            offset: offset as u32,
            offset_high: (offset >> 32) as u32,
            event: null_mut(),
        }
    }
}

/// WIN32_FIND_DATAW (WinBase.h) — the fields the differential consumes.
#[repr(C)]
struct Win32FindDataW {
    attributes: DWORD,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    file_size_high: DWORD,
    file_size_low: DWORD,
    reserved0: DWORD,
    reserved1: DWORD,
    file_name: [u16; 260],
    alternate_file_name: [u16; 14],
}

impl Default for Win32FindDataW {
    fn default() -> Self {
        Win32FindDataW {
            attributes: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            file_size_high: 0,
            file_size_low: 0,
            reserved0: 0,
            reserved1: 0,
            file_name: [0; 260],
            alternate_file_name: [0; 14],
        }
    }
}

/// OSVERSIONINFOEXW (WinNT.h, 156 bytes).
#[repr(C)]
struct OsVersionInfoExW {
    size: DWORD,
    major: DWORD,
    minor: DWORD,
    build: DWORD,
    platform_id: DWORD,
    csd_version: [u16; 128],
    service_pack_major: u16,
    service_pack_minor: u16,
    suite_mask: u16,
    product_type: u8,
    reserved: u8,
}

impl Default for OsVersionInfoExW {
    fn default() -> Self {
        OsVersionInfoExW {
            size: std::mem::size_of::<OsVersionInfoExW>() as DWORD,
            major: 0,
            minor: 0,
            build: 0,
            platform_id: 0,
            csd_version: [0; 128],
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: 0,
            reserved: 0,
        }
    }
}

/// RTL_OSVERSIONINFOW (ntdll).
#[repr(C)]
struct RtlOsVersionInfoW {
    size: DWORD,
    major: DWORD,
    minor: DWORD,
    build: DWORD,
    platform_id: DWORD,
    csd_version: [u16; 128],
}

// ── FFI declarations ────────────────────────────────────────────────────────

#[link(name = "kernel32")]
unsafe extern "C" {
    fn GetLastError() -> DWORD;
    fn SetLastError(error: DWORD) -> ();
    fn GetFullPathNameW(
        file_name: LPCWSTR,
        buffer_length: DWORD,
        buffer: LPWSTR,
        file_part: *mut LPWSTR,
    ) -> DWORD;
    fn GetTickCount64() -> u64;
    fn GetSystemTimeAsFileTime(file_time: *mut u64);
    fn QueryPerformanceCounter(counter: *mut u64) -> BOOL;
    fn QueryPerformanceFrequency(frequency: *mut u64) -> BOOL;
    fn Sleep(milliseconds: DWORD);
    fn GetEnvironmentVariableW(name: LPCWSTR, buffer: LPWSTR, buffer_length: DWORD) -> DWORD;
    fn SetEnvironmentVariableW(name: LPCWSTR, value: LPCWSTR) -> BOOL;
    fn GetEnvironmentStringsW() -> *mut u16;
    fn FreeEnvironmentStringsW(strings: *mut u16) -> BOOL;
    fn CompareStringOrdinal(
        string1: LPCWSTR,
        count1: c_int,
        string2: LPCWSTR,
        count2: c_int,
        ignore_case: BOOL,
    ) -> c_int;
    fn GetStringTypeW(
        info_type: DWORD,
        source: LPCWSTR,
        count: c_int,
        character_type: *mut u16,
    ) -> BOOL;
    fn CreateFileW(
        file_name: LPCWSTR,
        desired_access: DWORD,
        share_mode: DWORD,
        security_attributes: *mut c_void,
        creation_disposition: DWORD,
        flags_and_attributes: DWORD,
        template_file: HANDLE,
    ) -> HANDLE;
    fn CloseHandle(handle: HANDLE) -> BOOL;
    fn DeleteFileW(file_name: LPCWSTR) -> BOOL;
    fn MoveFileExW(existing: LPCWSTR, new_name: LPCWSTR, flags: DWORD) -> BOOL;
    fn GetFileAttributesW(file_name: LPCWSTR) -> DWORD;
    fn SetFileAttributesW(file_name: LPCWSTR, attributes: DWORD) -> BOOL;
    fn GetFileSizeEx(file: HANDLE, size: *mut u64) -> BOOL;
    fn SetFilePointerEx(
        file: HANDLE,
        distance: i64,
        new_position: *mut u64,
        move_method: DWORD,
    ) -> BOOL;
    fn FindFirstFileW(file_name: LPCWSTR, find_data: *mut Win32FindDataW) -> HANDLE;
    fn FindNextFileW(find_file: HANDLE, find_data: *mut Win32FindDataW) -> BOOL;
    fn FindClose(find_file: HANDLE) -> BOOL;
    fn WriteFile(
        file: HANDLE,
        buffer: *const c_void,
        bytes_to_write: DWORD,
        bytes_written: *mut DWORD,
        overlapped: *mut c_void,
    ) -> BOOL;
    fn GetVersionExW(version_information: *mut OsVersionInfoExW) -> BOOL;
    fn lstrlenW(string: LPCWSTR) -> c_int;
    fn lstrcmpW(left: LPCWSTR, right: LPCWSTR) -> c_int;
    fn lstrcpyW(destination: LPWSTR, source: LPCWSTR) -> LPWSTR;
    fn CharUpperW(string: LPWSTR) -> LPWSTR;
    fn CreateFileMappingW(
        file: HANDLE,
        attributes: *mut c_void,
        protect: DWORD,
        maximum_size_high: DWORD,
        maximum_size_low: DWORD,
        name: LPCWSTR,
    ) -> HANDLE;
    fn MapViewOfFile(
        file_mapping_handle: HANDLE,
        desired_access: DWORD,
        offset_high: DWORD,
        offset_low: DWORD,
        number_of_bytes_to_map: SIZE_T,
    ) -> LPVOID;
    fn UnmapViewOfFile(base_address: LPVOID) -> BOOL;
    fn GetProcessHeap() -> HANDLE;
    fn HeapAlloc(heap: HANDLE, flags: DWORD, bytes: SIZE_T) -> LPVOID;
    fn HeapFree(heap: HANDLE, flags: DWORD, memory: LPVOID) -> BOOL;
    fn HeapSize(heap: HANDLE, flags: DWORD, memory: *const c_void) -> SIZE_T;
    fn RtlNtStatusToDosError(status: i32) -> DWORD;
    fn CreateDirectoryW(path: LPCWSTR, security_attributes: *mut c_void) -> BOOL;
    fn SetCurrentDirectoryW(path: LPCWSTR) -> BOOL;
    fn LockFileEx(
        file: HANDLE,
        flags: DWORD,
        reserved: DWORD,
        bytes_low: DWORD,
        bytes_high: DWORD,
        overlapped: *mut Overlapped,
    ) -> BOOL;
    fn UnlockFileEx(
        file: HANDLE,
        reserved: DWORD,
        bytes_low: DWORD,
        bytes_high: DWORD,
        overlapped: *mut Overlapped,
    ) -> BOOL;
    fn LoadLibraryExW(file_name: LPCWSTR, file: HANDLE, flags: DWORD) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: LPCSTR) -> *mut c_void;
    fn GetModuleHandleExW(flags: DWORD, module_name: LPCWSTR, module: *mut HMODULE) -> BOOL;
    fn GetModuleFileNameW(module: HMODULE, file_name: LPWSTR, size: DWORD) -> DWORD;
    fn CreateEventW(
        attributes: *mut c_void,
        manual_reset: BOOL,
        initial_state: BOOL,
        name: LPCWSTR,
    ) -> HANDLE;
    fn CreateMutexW(attributes: *mut c_void, initial_owner: BOOL, name: LPCWSTR) -> HANDLE;
    fn CreateSemaphoreW(
        attributes: *mut c_void,
        initial_count: LONG,
        maximum_count: LONG,
        name: LPCWSTR,
    ) -> HANDLE;
    fn SetEvent(event: HANDLE) -> BOOL;
    fn ResetEvent(event: HANDLE) -> BOOL;
    fn WaitForSingleObject(handle: HANDLE, milliseconds: DWORD) -> DWORD;
    fn ReleaseMutex(mutex: HANDLE) -> BOOL;
    fn ReleaseSemaphore(semaphore: HANDLE, release_count: LONG, previous: *mut LONG) -> BOOL;
    fn CreateThread(
        attributes: *mut c_void,
        stack_size: SIZE_T,
        start_address: ThreadProc,
        parameter: LPVOID,
        creation_flags: DWORD,
        thread_id: LPDWORD,
    ) -> HANDLE;
    fn TlsAlloc() -> DWORD;
    fn TlsFree(index: DWORD) -> BOOL;
    fn TlsSetValue(index: DWORD, value: LPVOID) -> BOOL;
    fn TlsGetValue(index: DWORD) -> LPVOID;
    fn VirtualAlloc(
        address: LPVOID,
        size: SIZE_T,
        allocation_type: DWORD,
        protect: DWORD,
    ) -> LPVOID;
    fn VirtualFree(address: LPVOID, size: SIZE_T, free_type: DWORD) -> BOOL;
    fn VirtualProtect(
        address: LPVOID,
        size: SIZE_T,
        new_protect: DWORD,
        old_protect: *mut DWORD,
    ) -> BOOL;
    fn VirtualQuery(address: LPVOID, info: *mut MemoryBasicInformation, length: SIZE_T) -> SIZE_T;
}

#[link(name = "ntdll")]
unsafe extern "C" {
    fn RtlGetVersion(info: *mut RtlOsVersionInfoW) -> i32;
}

type ThreadProc = unsafe extern "system" fn(LPVOID) -> DWORD;

#[link(name = "advapi32")]
unsafe extern "C" {
    fn RegCreateKeyExW(
        key: HKEY,
        sub_key: LPCWSTR,
        reserved: DWORD,
        class_name: LPWSTR,
        options: DWORD,
        desired_access: DWORD,
        security_attributes: *mut c_void,
        result: PHKEY,
        disposition: *mut DWORD,
    ) -> LONG;
    fn RegSetValueExW(
        key: HKEY,
        value_name: LPCWSTR,
        reserved: DWORD,
        value_type: DWORD,
        data: LPBYTE,
        data_size: DWORD,
    ) -> LONG;
    fn RegQueryValueExW(
        key: HKEY,
        value_name: LPCWSTR,
        reserved: *mut DWORD,
        value_type: *mut DWORD,
        data: LPBYTE,
        data_size: *mut DWORD,
    ) -> LONG;
    fn RegDeleteValueW(key: HKEY, value_name: LPCWSTR) -> LONG;
    fn RegDeleteKeyW(key: HKEY, sub_key: LPCWSTR) -> LONG;
    fn RegCloseKey(key: HKEY) -> LONG;
}

// UCRT functions. The process CRT is the UCRT (ucrtbase.dll), so errno and
// the invalid-parameter handler table are shared with the Rust runtime.
type InvalidParameterHandler = unsafe extern "C" fn(
    expression: *const u16,
    function: *const u16,
    file: *const u16,
    line: u32,
    reserved: usize,
);

#[link(name = "ucrt")]
unsafe extern "C" {
    fn _set_invalid_parameter_handler(
        handler: Option<InvalidParameterHandler>,
    ) -> Option<InvalidParameterHandler>;
    fn _set_printf_count_output(enable: c_int) -> c_int;
    fn _errno() -> *mut c_int;
    fn snprintf(buffer: *mut i8, size: usize, format: *const i8, ...) -> c_int;
    fn strtol(nptr: *const i8, endptr: *mut *mut i8, base: c_int) -> LONG;
}

// ── Input shapes (typed mirrors of the wire JSON) ──────────────────────────

#[derive(Debug, Deserialize)]
struct PathNormalizeInput {
    path: String,
    #[serde(default)]
    cwd: Option<String>,
    // Accepted for schema compatibility; GetFullPathNameW behavior is driven
    // by the process long-path policy, which a per-vector flag cannot change.
    #[serde(default)]
    #[allow(dead_code)]
    long_paths_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct CaseFoldInput {
    left: String,
    right: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct AccessSpec {
    read: bool,
    write: bool,
    delete: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct ShareSpec {
    read: bool,
    write: bool,
    delete: bool,
}

#[derive(Debug, Deserialize)]
struct FileSharingInput {
    path: String,
    first_access: AccessSpec,
    first_share: ShareSpec,
    second_access: AccessSpec,
    // A second open's own share mode never constrains that open on Windows;
    // recorded for protocol completeness only.
    #[allow(dead_code)]
    second_share: ShareSpec,
}

#[derive(Debug, Deserialize)]
struct FileLockInput {
    path: String,
    first_offset: u64,
    first_length: u64,
    second_offset: u64,
    second_length: u64,
    same_handle: bool,
    unlock_after_second: bool,
    retry_after_unlock: bool,
}

#[derive(Debug, Deserialize)]
struct DeleteSemanticsInput {
    path: String,
    op: String,
    first_open: bool,
    first_share: ShareSpec,
}

#[derive(Debug, Deserialize)]
struct ApiSetInput {
    contract: String,
    probe: String,
}

#[derive(Debug, Deserialize)]
struct RegistryInput {
    key: String,
    value_name: String,
    value_type: String,
    data: Value,
    op: String,
}

#[derive(Debug, Deserialize)]
struct SyncInput {
    kind: String,
}

#[derive(Debug, Deserialize)]
struct CrtInput {
    kind: String,
}

#[derive(Debug, Deserialize)]
struct TlsInput {
    kind: String,
}

#[derive(Debug, Deserialize)]
struct CpuFlagsInput {
    /// Arithmetic width in bits: 8 | 16 | 32 | 64.
    width: u32,
    /// "add" | "sub" | "cmp".
    op: String,
    lhs: u64,
    rhs: u64,
}

#[derive(Debug, Deserialize)]
struct VirtualMemoryInput {
    /// "reserve" | "commit" | "decommit" | "release" | "protect" | "query".
    operation: String,
    /// For "reserve": 0 lets the system choose the base.  For every other
    /// operation the address is RELATIVE to the session's first reservation
    /// base (the reference resolves it against the base its own first
    /// reserve returned, so the corpus is host-agnostic).
    #[serde(default)]
    address: u64,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    allocation_type: u32,
    #[serde(default)]
    protection: u32,
    #[serde(default)]
    free_type: u32,
}

#[derive(Debug, Deserialize)]
struct TimeClockInput {
    sleep_ms: u32,
}

#[derive(Debug, Deserialize)]
struct EnvironmentInput {
    name: String,
    #[serde(default)]
    value: String,
    op: String,
}

#[derive(Debug, Deserialize)]
struct FileMetadataInput {
    path: String,
    op: String,
}

#[derive(Debug, Deserialize)]
struct DirectoryEnumerationInput {
    path: String,
    pattern: String,
    op: String,
}

#[derive(Debug, Deserialize)]
struct VersionInput {
    api: String,
}

#[derive(Debug, Deserialize)]
struct ErrorDomainInput {
    op: String,
}

#[derive(Debug, Deserialize)]
struct StringOpsInput {
    op: String,
    #[serde(default)]
    left: String,
    #[serde(default)]
    right: String,
    #[serde(default)]
    character: u32,
}

#[derive(Debug, Deserialize)]
struct SectionMappingInput {
    op: String,
    #[serde(default)]
    size: u32,
}

#[derive(Debug, Deserialize)]
struct HeapInput {
    op: String,
    #[serde(default)]
    size: u32,
}

// ── Shared helpers ──────────────────────────────────────────────────────────

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

fn parse<T: for<'de> Deserialize<'de>>(input: &Value) -> Option<T> {
    serde_json::from_value(input.clone()).ok()
}

/// Protocol-level path-kind classification of the input shape (shared with
/// the host model; see docs/WINDOWS_ORACLE.md).
fn classify_path_kind(input: &str) -> &'static str {
    if input.starts_with("\\\\?\\") {
        "verbatim"
    } else if input.starts_with("\\\\.\\") {
        "device"
    } else if input.starts_with("\\\\") {
        "unc"
    } else if input.len() >= 2
        && input.as_bytes()[0].is_ascii_alphabetic()
        && input.as_bytes()[1] == b':'
    {
        if input.len() == 2 || input.as_bytes()[2] != b'\\' {
            "drive_rel"
        } else {
            "drive_abs"
        }
    } else if input.starts_with('\\') {
        "rooted"
    } else {
        "relative"
    }
}

/// Protocol-level ADS detection (shared with the host model).
fn classify_has_ads(input: &str) -> bool {
    let mut rest = input;
    for prefix in ["\\\\?\\", "\\\\.\\"] {
        if rest.starts_with(prefix) {
            rest = &rest[prefix.len()..];
            break;
        }
    }
    if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
        rest = &rest[2..];
    }
    rest.contains(':')
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn registry_value_bytes(value_type: &str, data: &Value) -> Vec<u8> {
    match value_type {
        "REG_DWORD" => (data.as_u64().unwrap_or(0) as u32).to_le_bytes().to_vec(),
        "REG_SZ" | "REG_EXPAND_SZ" => {
            let mut bytes = Vec::new();
            for unit in data.as_str().unwrap_or_default().encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes
        }
        "REG_BINARY" => data
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| item.as_u64().unwrap_or(0) as u8)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn registry_type_code(value_type: &str) -> u32 {
    match value_type {
        "REG_SZ" => 1,
        "REG_EXPAND_SZ" => 2,
        "REG_BINARY" => 3,
        "REG_DWORD" => 4,
        _ => 0,
    }
}

fn file_exists(path: &str) -> bool {
    let wide = to_wide(path);
    unsafe { GetFileAttributesW(wide.as_ptr()) != INVALID_FILE_ATTRIBUTES }
}

fn close_handle(handle: HANDLE) {
    if !handle.is_null() {
        unsafe {
            CloseHandle(handle);
        }
    }
}

// ── Category executors ──────────────────────────────────────────────────────

pub fn execute(category: &str, input: &Value) -> Value {
    match category {
        "path_normalize" => exec_path_normalize(input),
        "case_fold" => exec_case_fold(input),
        "file_sharing" => exec_file_sharing(input),
        "file_lock" => exec_file_lock(input),
        "delete_semantics" => exec_delete_semantics(input),
        "api_set" => exec_api_set(input),
        "registry" => exec_registry(input),
        "synchronization" => exec_synchronization(input),
        "crt_printf" => exec_crt_printf(input),
        "thread_tls" => exec_thread_tls(input),
        "cpu_arithmetic_flags" => exec_cpu_arithmetic_flags(input),
        "virtual_memory" => exec_virtual_memory(input),
        "d3d12_texture_address_mode" => exec_d3d12_texture_address_mode(input),
        "d3d12_filter_reduction" => exec_d3d12_filter_reduction(input),
        "d3d12_filter_translation" => exec_d3d12_filter_translation(input),
        "time_clock" => exec_time_clock(input),
        "environment" => exec_environment(input),
        "file_metadata" => exec_file_metadata(input),
        "directory_enumeration" => exec_directory_enumeration(input),
        "version" => exec_version(input),
        "error_domain" => exec_error_domain(input),
        "string_ops" => exec_string_ops(input),
        "section_mapping" => exec_section_mapping(input),
        "heap" => exec_heap(input),
        _ => json!({ "error": format!("unknown_category: {category}") }),
    }
}

/// One-time scratch-directory setup shared by file-based categories and the
/// cwd-dependent path vectors.  Mirrors the Casa1 session's
/// `SCRATCH_DIRECTORIES` so the file-based categories operate on the same
/// fixed layout on both sides (a missing parent directory would otherwise
/// turn every CreateFileW into ERROR_PATH_NOT_FOUND).
fn ensure_scratch_dirs() {
    static SETUP: AtomicBool = AtomicBool::new(false);
    if SETUP.swap(true, Ordering::SeqCst) {
        return;
    }
    for directory in [
        "C:\\Windows\\Temp\\casa1-oracle",
        "C:\\Windows\\Temp\\casa1-oracle\\fs",
        "C:\\Windows\\Temp\\casa1-oracle\\lock",
        "C:\\Windows\\Temp\\casa1-oracle\\del",
        "C:\\Windows\\Temp\\casa1-oracle\\meta",
        "C:\\Windows\\Temp\\casa1-oracle\\enum",
        "C:\\Windows\\Temp\\casa1-oracle\\err",
        "C:\\Windows\\Temp\\casa1-oracle-cwd",
    ] {
        let wide = to_wide(directory);
        unsafe {
            CreateDirectoryW(wide.as_ptr(), null_mut());
        }
    }
}

fn exec_path_normalize(input: &Value) -> Value {
    ensure_scratch_dirs();
    let Some(spec) = parse::<PathNormalizeInput>(input) else {
        return json!({ "normalized": "", "kind": "invalid_input", "has_ads": false, "last_error": 87 });
    };
    if let Some(cwd) = &spec.cwd {
        let wide = to_wide(cwd);
        unsafe {
            SetCurrentDirectoryW(wide.as_ptr());
        }
    }
    let wide = to_wide(&spec.path);
    let (normalized, last_error) = unsafe {
        let needed = GetFullPathNameW(wide.as_ptr(), 0, null_mut(), null_mut());
        if needed == 0 {
            (String::new(), GetLastError())
        } else {
            let mut buffer = vec![0u16; needed as usize];
            let written = GetFullPathNameW(
                wide.as_ptr(),
                buffer.len() as DWORD,
                buffer.as_mut_ptr(),
                null_mut(),
            );
            if written == 0 {
                (String::new(), GetLastError())
            } else {
                (from_wide(&buffer[..written as usize]), 0)
            }
        }
    };
    json!({
        "normalized": normalized,
        "kind": classify_path_kind(&spec.path),
        "has_ads": classify_has_ads(&spec.path),
        "last_error": last_error,
    })
}

fn exec_case_fold(input: &Value) -> Value {
    let Some(spec) = parse::<CaseFoldInput>(input) else {
        return json!({ "ordinal_ignore_case_equal": false, "left_c1_type_bits": [], "right_c1_type_bits": [] });
    };
    let left = to_wide(&spec.left);
    let right = to_wide(&spec.right);
    let equal =
        unsafe { CompareStringOrdinal(left.as_ptr(), -1, right.as_ptr(), -1, TRUE) == CSTR_EQUAL };
    json!({
        "ordinal_ignore_case_equal": equal,
        "left_c1_type_bits": c1_type_bits(&spec.left),
        "right_c1_type_bits": c1_type_bits(&spec.right),
    })
}

fn c1_type_bits(value: &str) -> Vec<u32> {
    let wide = to_wide(value);
    let count = (wide.len() - 1) as c_int;
    let mut bits = vec![0u16; count as usize];
    let ok = unsafe { GetStringTypeW(CT_CTYPE1, wide.as_ptr(), count, bits.as_mut_ptr()) };
    if ok == 0 {
        return Vec::new();
    }
    bits.into_iter().map(u32::from).collect()
}

fn access_flags(spec: &AccessSpec) -> DWORD {
    let mut flags = 0;
    if spec.read {
        flags |= GENERIC_READ;
    }
    if spec.write {
        flags |= GENERIC_WRITE;
    }
    if spec.delete {
        flags |= DELETE_ACCESS;
    }
    flags
}

fn share_flags(spec: &ShareSpec) -> DWORD {
    let mut flags = 0;
    if spec.read {
        flags |= FILE_SHARE_READ;
    }
    if spec.write {
        flags |= FILE_SHARE_WRITE;
    }
    if spec.delete {
        flags |= FILE_SHARE_DELETE;
    }
    flags
}

fn open_file(path: &str, access: DWORD, share: DWORD, disposition: DWORD) -> HANDLE {
    let wide = to_wide(path);
    unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            share,
            null_mut(),
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            INVALID_HANDLE_VALUE,
        )
    }
}

fn exec_file_sharing(input: &Value) -> Value {
    ensure_scratch_dirs();
    let Some(spec) = parse::<FileSharingInput>(input) else {
        return json!({ "second_open_succeeds": false, "second_error": 87 });
    };
    let first = open_file(
        &spec.path,
        access_flags(&spec.first_access),
        share_flags(&spec.first_share),
        CREATE_ALWAYS,
    );
    if first == INVALID_HANDLE_VALUE {
        return json!({ "second_open_succeeds": false, "second_error": last_error() });
    }
    let second = open_file(
        &spec.path,
        access_flags(&spec.second_access),
        share_flags(&spec.second_share),
        OPEN_EXISTING,
    );
    let (second_open_succeeds, second_error) = if second == INVALID_HANDLE_VALUE {
        (false, last_error())
    } else {
        close_handle(second);
        (true, 0)
    };
    close_handle(first);
    json!({ "second_open_succeeds": second_open_succeeds, "second_error": second_error })
}

fn lock_range(handle: HANDLE, offset: u64, length: u64) -> (bool, u32) {
    let mut overlapped = Overlapped::at(offset);
    let ok = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK,
            0,
            length as u32,
            0,
            &mut overlapped,
        )
    };
    if ok != 0 {
        (true, 0)
    } else {
        (false, last_error())
    }
}

fn unlock_range(handle: HANDLE, offset: u64, length: u64) -> (bool, u32) {
    let mut overlapped = Overlapped::at(offset);
    let ok = unsafe { UnlockFileEx(handle, 0, length as u32, 0, &mut overlapped) };
    if ok != 0 {
        (true, 0)
    } else {
        (false, last_error())
    }
}

fn lock_op(performed: bool, outcome: (bool, u32)) -> Value {
    if !performed {
        return json!({ "performed": false, "succeeded": false, "error": 0 });
    }
    json!({ "performed": true, "succeeded": outcome.0, "error": outcome.1 })
}

fn exec_file_lock(input: &Value) -> Value {
    ensure_scratch_dirs();
    let Some(spec) = parse::<FileLockInput>(input) else {
        return json!({ "lock1": null, "lock2": null, "unlock1": null, "lock3": null });
    };
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let first = open_file(&spec.path, GENERIC_READ | GENERIC_WRITE, share, OPEN_ALWAYS);
    if first == INVALID_HANDLE_VALUE {
        return json!({ "lock1": null, "lock2": null, "unlock1": null, "lock3": null, "error": last_error() });
    }
    let second = if spec.same_handle {
        first
    } else {
        open_file(&spec.path, GENERIC_READ | GENERIC_WRITE, share, OPEN_ALWAYS)
    };
    let lock1 = lock_range(first, spec.first_offset, spec.first_length);
    let lock2 = lock_range(second, spec.second_offset, spec.second_length);
    let unlock1 = if spec.unlock_after_second {
        unlock_range(first, spec.first_offset, spec.first_length)
    } else {
        (false, 0)
    };
    let lock3 = if spec.retry_after_unlock {
        lock_range(second, spec.second_offset, spec.second_length)
    } else {
        (false, 0)
    };
    if !spec.same_handle {
        close_handle(second);
    }
    close_handle(first);
    json!({
        "lock1": lock_op(true, lock1),
        "lock2": lock_op(true, lock2),
        "unlock1": lock_op(spec.unlock_after_second, unlock1),
        "lock3": lock_op(spec.retry_after_unlock, lock3),
    })
}

fn exec_delete_semantics(input: &Value) -> Value {
    ensure_scratch_dirs();
    let Some(spec) = parse::<DeleteSemanticsInput>(input) else {
        return json!({ "success": false, "error": 87, "file_exists_after": true, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": 87 });
    };
    let wide = to_wide(&spec.path);
    let handle = if spec.first_open {
        open_file(
            &spec.path,
            GENERIC_READ | GENERIC_WRITE,
            share_flags(&spec.first_share),
            CREATE_ALWAYS,
        )
    } else {
        INVALID_HANDLE_VALUE
    };
    let result = match spec.op.as_str() {
        "delete" => {
            let ok = unsafe { DeleteFileW(wide.as_ptr()) };
            let error = if ok != 0 { 0 } else { last_error() };
            let exists_after = file_exists(&spec.path);
            close_handle(handle);
            json!({
                "success": ok != 0,
                "error": error,
                "file_exists_after": exists_after,
                "rename_succeeded": false,
                "second_open_succeeded": false,
                "second_open_error": 0,
            })
        }
        "rename" => {
            let target = format!("{}.ren", spec.path);
            let target_wide = to_wide(&target);
            let ok = unsafe {
                MoveFileExW(
                    wide.as_ptr(),
                    target_wide.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING,
                )
            };
            let error = if ok != 0 { 0 } else { last_error() };
            let exists_after = file_exists(&spec.path);
            close_handle(handle);
            json!({
                "success": ok != 0,
                "error": error,
                "file_exists_after": exists_after,
                "rename_succeeded": ok != 0,
                "second_open_succeeded": false,
                "second_open_error": 0,
            })
        }
        "delete_then_reopen" => {
            let ok = unsafe { DeleteFileW(wide.as_ptr()) };
            let error = if ok != 0 { 0 } else { last_error() };
            let second = open_file(
                &spec.path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                OPEN_EXISTING,
            );
            let (second_open_succeeded, second_open_error) = if second == INVALID_HANDLE_VALUE {
                (false, last_error())
            } else {
                close_handle(second);
                (true, 0)
            };
            let exists_after = file_exists(&spec.path);
            close_handle(handle);
            json!({
                "success": ok != 0,
                "error": error,
                "file_exists_after": exists_after,
                "rename_succeeded": false,
                "second_open_succeeded": second_open_succeeded,
                "second_open_error": second_open_error,
            })
        }
        _ => {
            close_handle(handle);
            json!({ "success": false, "error": 87, "file_exists_after": true, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": 87 })
        }
    };
    // Best-effort cleanup of the rename target.
    if spec.op == "rename" {
        let target = format!("{}.ren", spec.path);
        let target_wide = to_wide(&target);
        unsafe {
            DeleteFileW(target_wide.as_ptr());
        }
    }
    result
}

fn exec_api_set(input: &Value) -> Value {
    let Some(spec) = parse::<ApiSetInput>(input) else {
        return json!({ "loads": false, "resolved_module": "", "export_resolvable": false });
    };
    let contract = to_wide(&spec.contract);
    let module =
        unsafe { LoadLibraryExW(contract.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return json!({ "loads": false, "resolved_module": "", "export_resolvable": false });
    }
    let probe = CString::new(spec.probe.as_bytes()).unwrap_or_default();
    let address = unsafe { GetProcAddress(module, probe.as_ptr()) };
    let mut resolved_module = String::new();
    if !address.is_null() {
        let mut host: HMODULE = null_mut();
        let found = unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                address as LPCWSTR,
                &mut host,
            )
        };
        if found != 0 && !host.is_null() {
            let mut buffer = [0u16; 1024];
            let written =
                unsafe { GetModuleFileNameW(host, buffer.as_mut_ptr(), buffer.len() as DWORD) };
            if written > 0 {
                resolved_module = from_wide(&buffer[..written as usize]);
            }
        }
    }
    json!({
        "loads": true,
        "resolved_module": resolved_module,
        "export_resolvable": !address.is_null(),
    })
}

fn exec_registry(input: &Value) -> Value {
    let Some(spec) = parse::<RegistryInput>(input) else {
        return json!({ "error": 87, "value_bytes": "", "value_type": null });
    };
    let key_wide = to_wide(&spec.key);
    let mut key: HKEY = null_mut();
    let mut disposition: DWORD = 0;
    let open_status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_wide.as_ptr(),
            0,
            null_mut(),
            0,
            KEY_ALL_ACCESS,
            null_mut(),
            &mut key,
            &mut disposition,
        )
    };
    if open_status != 0 {
        return json!({ "error": open_status as u32, "value_bytes": "", "value_type": null });
    }
    let name = to_wide(&spec.value_name);
    let value = match spec.op.as_str() {
        "query_missing" => {
            let mut value_type: DWORD = 0;
            let mut size: DWORD = 0;
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    name.as_ptr(),
                    null_mut(),
                    &mut value_type,
                    null_mut(),
                    &mut size,
                )
            };
            json!({ "error": status as u32, "value_bytes": "", "value_type": null })
        }
        "set_query_delete" => {
            let data = registry_value_bytes(&spec.value_type, &spec.data);
            unsafe {
                RegSetValueExW(
                    key,
                    name.as_ptr(),
                    0,
                    registry_type_code(&spec.value_type),
                    if data.is_empty() {
                        null_mut()
                    } else {
                        data.as_ptr() as LPBYTE
                    },
                    data.len() as DWORD,
                );
                RegDeleteValueW(key, name.as_ptr());
            }
            let mut value_type: DWORD = 0;
            let mut size: DWORD = 0;
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    name.as_ptr(),
                    null_mut(),
                    &mut value_type,
                    null_mut(),
                    &mut size,
                )
            };
            json!({ "error": status as u32, "value_bytes": "", "value_type": null })
        }
        "create_twice" => {
            let mut second_key: HKEY = null_mut();
            let mut second_disposition: DWORD = 0;
            let status = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    key_wide.as_ptr(),
                    0,
                    null_mut(),
                    0,
                    KEY_ALL_ACCESS,
                    null_mut(),
                    &mut second_key,
                    &mut second_disposition,
                )
            };
            if second_key != null_mut() {
                unsafe {
                    RegCloseKey(second_key);
                }
            }
            json!({ "error": status as u32, "value_bytes": "", "value_type": null })
        }
        "set_query" => {
            let data = registry_value_bytes(&spec.value_type, &spec.data);
            let set_status = unsafe {
                RegSetValueExW(
                    key,
                    name.as_ptr(),
                    0,
                    registry_type_code(&spec.value_type),
                    if data.is_empty() {
                        null_mut()
                    } else {
                        data.as_ptr() as LPBYTE
                    },
                    data.len() as DWORD,
                )
            };
            let mut value_type: DWORD = 0;
            let mut size: DWORD = 0;
            let query_status = unsafe {
                RegQueryValueExW(
                    key,
                    name.as_ptr(),
                    null_mut(),
                    &mut value_type,
                    null_mut(),
                    &mut size,
                )
            };
            if query_status != 0 {
                json!({ "error": query_status as u32, "value_bytes": "", "value_type": null })
            } else {
                let mut buffer = vec![0u8; size as usize];
                let mut read_size = size;
                let read_status = unsafe {
                    RegQueryValueExW(
                        key,
                        name.as_ptr(),
                        null_mut(),
                        &mut value_type,
                        buffer.as_mut_ptr() as LPBYTE,
                        &mut read_size,
                    )
                };
                if read_status != 0 {
                    json!({ "error": read_status as u32, "value_bytes": "", "value_type": value_type })
                } else {
                    json!({
                        "error": set_status as u32,
                        "value_bytes": hex_encode(&buffer[..read_size as usize]),
                        "value_type": value_type,
                    })
                }
            }
        }
        _ => json!({ "error": 87, "value_bytes": "", "value_type": null }),
    };
    unsafe {
        RegCloseKey(key);
    }
    value
}

// ── synchronization ─────────────────────────────────────────────────────────

#[repr(C)]
struct SyncThreadContext {
    mutex: HANDLE,
    release_succeeded: AtomicBool,
    release_error: AtomicU32,
    acquired: AtomicBool,
}

unsafe extern "system" fn non_owner_release_proc(parameter: LPVOID) -> DWORD {
    let context = &*(parameter as *const SyncThreadContext);
    let ok = ReleaseMutex(context.mutex);
    context.release_succeeded.store(ok != 0, Ordering::SeqCst);
    if ok == 0 {
        context.release_error.store(last_error(), Ordering::SeqCst);
    }
    0
}

unsafe extern "system" fn abandoned_worker_proc(parameter: LPVOID) -> DWORD {
    let context = &*(parameter as *const SyncThreadContext);
    let wait = WaitForSingleObject(context.mutex, INFINITE);
    context
        .acquired
        .store(wait == WAIT_OBJECT_0, Ordering::SeqCst);
    // Exit WITHOUT releasing: the mutex is left abandoned.
    0
}

fn spawn_thread(start: ThreadProc, parameter: *mut SyncThreadContext) -> HANDLE {
    let mut thread_id: DWORD = 0;
    unsafe { CreateThread(null_mut(), 0, start, parameter as LPVOID, 0, &mut thread_id) }
}

fn release_mutex(mutex: HANDLE) -> Value {
    let ok = unsafe { ReleaseMutex(mutex) };
    if ok != 0 {
        json!({ "succeeded": true, "error": 0 })
    } else {
        json!({ "succeeded": false, "error": last_error() })
    }
}

fn release_semaphore(semaphore: HANDLE, count: i32) -> Value {
    let ok = unsafe { ReleaseSemaphore(semaphore, count, null_mut()) };
    if ok != 0 {
        json!({ "succeeded": true, "error": 0 })
    } else {
        json!({ "succeeded": false, "error": last_error() })
    }
}

fn exec_synchronization(input: &Value) -> Value {
    let Some(spec) = parse::<SyncInput>(input) else {
        return json!({ "waits": [], "releases": [], "abandoned": false });
    };
    match spec.kind.as_str() {
        "event_auto_reset" => {
            let event = unsafe { CreateEventW(null_mut(), 0, 0, null_mut()) };
            unsafe {
                SetEvent(event);
            }
            let wait1 = unsafe { WaitForSingleObject(event, 0) };
            let wait2 = unsafe { WaitForSingleObject(event, 0) };
            close_handle(event);
            json!({ "waits": [wait1, wait2], "releases": [], "abandoned": false })
        }
        "event_manual_reset" => {
            let event = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
            unsafe {
                SetEvent(event);
            }
            let wait1 = unsafe { WaitForSingleObject(event, 0) };
            let wait2 = unsafe { WaitForSingleObject(event, 0) };
            unsafe {
                ResetEvent(event);
            }
            let wait3 = unsafe { WaitForSingleObject(event, 0) };
            close_handle(event);
            json!({ "waits": [wait1, wait2, wait3], "releases": [], "abandoned": false })
        }
        "mutex_recursion" => {
            let mutex = unsafe { CreateMutexW(null_mut(), 0, null_mut()) };
            let wait1 = unsafe { WaitForSingleObject(mutex, INFINITE) };
            let wait2 = unsafe { WaitForSingleObject(mutex, INFINITE) };
            let release1 = release_mutex(mutex);
            let release2 = release_mutex(mutex);
            let wait3 = unsafe { WaitForSingleObject(mutex, 0) };
            let release3 = release_mutex(mutex);
            let release4 = release_mutex(mutex);
            close_handle(mutex);
            json!({
                "waits": [wait1, wait2, wait3],
                "releases": [release1, release2, release3, release4],
                "abandoned": false,
            })
        }
        "mutex_non_owner_release" => {
            let mutex = unsafe { CreateMutexW(null_mut(), 0, null_mut()) };
            let wait1 = unsafe { WaitForSingleObject(mutex, INFINITE) };
            let context = Box::into_raw(Box::new(SyncThreadContext {
                mutex,
                release_succeeded: AtomicBool::new(false),
                release_error: AtomicU32::new(0),
                acquired: AtomicBool::new(false),
            }));
            let thread = spawn_thread(non_owner_release_proc, context);
            unsafe {
                WaitForSingleObject(thread, INFINITE);
                CloseHandle(thread);
            }
            let release = json!({
                "succeeded": unsafe { (*context).release_succeeded.load(Ordering::SeqCst) },
                "error": unsafe { (*context).release_error.load(Ordering::SeqCst) },
            });
            drop(unsafe { Box::from_raw(context) });
            close_handle(mutex);
            json!({ "waits": [wait1], "releases": [release], "abandoned": false })
        }
        "mutex_abandoned" => {
            let mutex = unsafe { CreateMutexW(null_mut(), 0, null_mut()) };
            let wait1 = unsafe { WaitForSingleObject(mutex, INFINITE) };
            let context = Box::into_raw(Box::new(SyncThreadContext {
                mutex,
                release_succeeded: AtomicBool::new(false),
                release_error: AtomicU32::new(0),
                acquired: AtomicBool::new(false),
            }));
            let thread = spawn_thread(abandoned_worker_proc, context);
            unsafe {
                ReleaseMutex(mutex);
            }
            // The worker acquires the mutex and terminates without releasing
            // it; the main thread's wait therefore returns WAIT_ABANDONED.
            let wait2 = unsafe { WaitForSingleObject(mutex, INFINITE) };
            unsafe {
                WaitForSingleObject(thread, INFINITE);
                CloseHandle(thread);
            }
            let release = release_mutex(mutex);
            drop(unsafe { Box::from_raw(context) });
            close_handle(mutex);
            json!({ "waits": [wait1, wait2], "releases": [release], "abandoned": true })
        }
        "semaphore" => {
            let semaphore = unsafe { CreateSemaphoreW(null_mut(), 1, 3, null_mut()) };
            let wait1 = unsafe { WaitForSingleObject(semaphore, 0) };
            let wait2 = unsafe { WaitForSingleObject(semaphore, 0) };
            let release1 = release_semaphore(semaphore, 1);
            let release2 = release_semaphore(semaphore, 2);
            let wait3 = unsafe { WaitForSingleObject(semaphore, 0) };
            let wait4 = unsafe { WaitForSingleObject(semaphore, 0) };
            let wait5 = unsafe { WaitForSingleObject(semaphore, 0) };
            let wait6 = unsafe { WaitForSingleObject(semaphore, 0) };
            close_handle(semaphore);
            json!({
                "waits": [wait1, wait2, wait3, wait4, wait5, wait6],
                "releases": [release1, release2],
                "abandoned": false,
            })
        }
        _ => json!({ "waits": [], "releases": [], "abandoned": false }),
    }
}

// ── crt_printf ──────────────────────────────────────────────────────────────

static INVALID_PARAMETER_INVOCATIONS: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn invalid_parameter_handler(
    _expression: *const u16,
    _function: *const u16,
    _file: *const u16,
    _line: u32,
    _reserved: usize,
) {
    INVALID_PARAMETER_INVOCATIONS.fetch_add(1, Ordering::SeqCst);
}

fn exec_crt_printf(input: &Value) -> Value {
    let Some(spec) = parse::<CrtInput>(input) else {
        return json!({ "handler_invoked": false, "ret": null, "errno": 0, "written": null, "value": null, "end_consumed": null, "buffer": null });
    };
    INVALID_PARAMETER_INVOCATIONS.store(0, Ordering::SeqCst);
    let previous_handler =
        unsafe { _set_invalid_parameter_handler(Some(invalid_parameter_handler)) };
    let result = match spec.kind.as_str() {
        "percent_n_disabled" => {
            // %n is disabled by default in the UCRT: the invalid parameter
            // handler is invoked and the call fails with EINVAL.
            let mut buffer = [0i8; 64];
            let mut written: c_int = 0;
            let format = c"ab%n";
            let ret = unsafe {
                snprintf(
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    format.as_ptr(),
                    &mut written,
                )
            };
            let errno = unsafe { *_errno() };
            json!({
                "handler_invoked": INVALID_PARAMETER_INVOCATIONS.load(Ordering::SeqCst) > 0,
                "ret": ret,
                "errno": errno as u32,
                "written": null,
                "value": null,
                "end_consumed": null,
                "buffer": null,
            })
        }
        "percent_n_enabled" => {
            // _set_printf_count_output(1) re-enables %n.
            unsafe {
                _set_printf_count_output(1);
            }
            let mut buffer = [0i8; 64];
            let mut written: c_int = 0;
            let format = c"%d%n";
            let ret = unsafe {
                snprintf(
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    format.as_ptr(),
                    42,
                    &mut written,
                )
            };
            let errno = unsafe { *_errno() };
            unsafe {
                _set_printf_count_output(0);
            }
            json!({
                "handler_invoked": INVALID_PARAMETER_INVOCATIONS.load(Ordering::SeqCst) > 0,
                "ret": ret,
                "errno": errno as u32,
                "written": written,
                "value": null,
                "end_consumed": null,
                "buffer": null,
            })
        }
        "strtol_overflow" => strtol_vector("999999999999999999999", 10),
        "strtol_underflow" => strtol_vector("-999999999999999999999", 10),
        "strtol_bad_base" => strtol_vector("123", 99),
        "strtol_hex_ok" => strtol_vector("0x7fffffff", 16),
        "snprintf_truncation" => {
            let mut buffer = [0i8; 4];
            let format = c"abcdef";
            let ret = unsafe { snprintf(buffer.as_mut_ptr(), buffer.len(), format.as_ptr()) };
            let errno = unsafe { *_errno() };
            let mut text = Vec::new();
            for byte in buffer.iter().take_while(|byte| **byte != 0) {
                text.push(*byte as u8);
            }
            json!({
                "handler_invoked": INVALID_PARAMETER_INVOCATIONS.load(Ordering::SeqCst) > 0,
                "ret": ret,
                "errno": errno as u32,
                "written": null,
                "value": null,
                "end_consumed": null,
                "buffer": String::from_utf8_lossy(&text).into_owned(),
            })
        }
        "snprintf_size_query" => {
            let format = c"%d";
            let ret = unsafe { snprintf(null_mut(), 0, format.as_ptr(), 7) };
            let errno = unsafe { *_errno() };
            json!({
                "handler_invoked": INVALID_PARAMETER_INVOCATIONS.load(Ordering::SeqCst) > 0,
                "ret": ret,
                "errno": errno as u32,
                "written": null,
                "value": null,
                "end_consumed": null,
                "buffer": null,
            })
        }
        "snprintf_null_format" => {
            let mut buffer = [0i8; 64];
            let ret = unsafe { snprintf(buffer.as_mut_ptr(), buffer.len(), null_mut()) };
            let errno = unsafe { *_errno() };
            json!({
                "handler_invoked": INVALID_PARAMETER_INVOCATIONS.load(Ordering::SeqCst) > 0,
                "ret": ret,
                "errno": errno as u32,
                "written": null,
                "value": null,
                "end_consumed": null,
                "buffer": null,
            })
        }
        _ => {
            json!({ "handler_invoked": false, "ret": null, "errno": 0, "written": null, "value": null, "end_consumed": null, "buffer": null })
        }
    };
    unsafe {
        _set_invalid_parameter_handler(previous_handler);
    }
    result
}

fn strtol_vector(text: &str, base: c_int) -> Value {
    let input = CString::new(text).unwrap_or_default();
    let mut end: *mut i8 = null_mut();
    unsafe {
        *_errno() = 0;
    }
    let value = unsafe { strtol(input.as_ptr(), &mut end, base) };
    let errno = unsafe { *_errno() };
    json!({
        "handler_invoked": INVALID_PARAMETER_INVOCATIONS.load(Ordering::SeqCst) > 0,
        "ret": null,
        "errno": errno as u32,
        "written": null,
        "value": value,
        "end_consumed": end as *const i8 != input.as_ptr(),
        "buffer": null,
    })
}

// ── thread_tls ──────────────────────────────────────────────────────────────

#[repr(C)]
struct TlsThreadContext {
    index: DWORD,
    other_value_is_null: AtomicBool,
}

unsafe extern "system" fn tls_reader_proc(parameter: LPVOID) -> DWORD {
    let context = &*(parameter as *const TlsThreadContext);
    let value = TlsGetValue(context.index);
    context
        .other_value_is_null
        .store(value.is_null(), Ordering::SeqCst);
    0
}

fn exec_thread_tls(input: &Value) -> Value {
    let Some(spec) = parse::<TlsInput>(input) else {
        return json!({ "error": 87 });
    };
    match spec.kind.as_str() {
        "alloc" => {
            let index = unsafe { TlsAlloc() };
            json!({ "index_valid": index != TLS_OUT_OF_INDEXES })
        }
        "roundtrip" => {
            let index = unsafe { TlsAlloc() };
            let marker = 0xABu8;
            let pointer = &marker as *const u8 as LPVOID;
            let set_succeeded = unsafe { TlsSetValue(index, pointer) } != 0;
            let retrieved = unsafe { TlsGetValue(index) };
            json!({ "set_succeeded": set_succeeded, "get_matches": retrieved == pointer })
        }
        "thread_isolation" => {
            let index = unsafe { TlsAlloc() };
            let marker = 0xCDu8;
            let pointer = &marker as *const u8 as LPVOID;
            unsafe {
                TlsSetValue(index, pointer);
            }
            let context = Box::into_raw(Box::new(TlsThreadContext {
                index,
                other_value_is_null: AtomicBool::new(false),
            }));
            let mut thread_id: DWORD = 0;
            let thread = unsafe {
                CreateThread(
                    null_mut(),
                    0,
                    tls_reader_proc,
                    context as LPVOID,
                    0,
                    &mut thread_id,
                )
            };
            unsafe {
                WaitForSingleObject(thread, INFINITE);
                CloseHandle(thread);
            }
            let other_value_is_null =
                unsafe { (*context).other_value_is_null.load(Ordering::SeqCst) };
            drop(unsafe { Box::from_raw(context) });
            let main_value = unsafe { TlsGetValue(index) };
            json!({
                "other_thread_value_is_null": other_value_is_null,
                "main_value_preserved": main_value == pointer,
            })
        }
        "minimum_available" => json!({ "minimum_available": TLS_MINIMUM_AVAILABLE }),
        "free_succeeds" => {
            let index = unsafe { TlsAlloc() };
            let free_succeeded = unsafe { TlsFree(index) } != 0;
            json!({ "free_succeeded": free_succeeded })
        }
        "realloc_valid" => {
            let index = unsafe { TlsAlloc() };
            unsafe {
                TlsFree(index);
            }
            let new_index = unsafe { TlsAlloc() };
            json!({ "new_index_valid": new_index != TLS_OUT_OF_INDEXES })
        }
        "set_invalid_index" => {
            let succeeded = unsafe { TlsSetValue(TLS_OUT_OF_INDEXES, null_mut()) } != 0;
            let error = if succeeded { 0 } else { last_error() };
            json!({ "succeeded": succeeded, "error": error })
        }
        "get_invalid_index" => {
            let value = unsafe { TlsGetValue(TLS_OUT_OF_INDEXES) };
            let error = if value.is_null() { last_error() } else { 0 };
            json!({ "value_is_null": value.is_null(), "error": error })
        }
        _ => json!({ "error": 87 }),
    }
}

// ── d3d12 enum truth ────────────────────────────────────────────────────────
//
// The D3D12 enum values below are hardcoded from d3d12.h — the reference
// executable is the truth emitter, and there is no Casa1-side model to
// consult. Every numeric input the corpus sends (including values outside
// the defined enum range) is answered per the d3d12.h definitions: values
// the enum does not define are validation errors, never guessed defaults.
//
// D3D12_TEXTURE_ADDRESS_MODE (d3d12.h) is 0-based:
//   WRAP=0, MIRROR=1, CLAMP=2, BORDER=3, MIRROR_ONCE=4.
// (The 1-based family is D3D11's legacy SAMPLER_ADDRESS_MODE — D3D12 is
// 0-based, and values outside 0..=4 are undefined.)
const D3D12_TEXTURE_ADDRESS_MODE_WRAP: u32 = 0;
const D3D12_TEXTURE_ADDRESS_MODE_MIRROR: u32 = 1;
const D3D12_TEXTURE_ADDRESS_MODE_CLAMP: u32 = 2;
const D3D12_TEXTURE_ADDRESS_MODE_BORDER: u32 = 3;
const D3D12_TEXTURE_ADDRESS_MODE_MIRROR_ONCE: u32 = 4;

fn d3d12_texture_address_mode_name(mode: u32) -> Option<&'static str> {
    match mode {
        D3D12_TEXTURE_ADDRESS_MODE_WRAP => Some("WRAP"),
        D3D12_TEXTURE_ADDRESS_MODE_MIRROR => Some("MIRROR"),
        D3D12_TEXTURE_ADDRESS_MODE_CLAMP => Some("CLAMP"),
        D3D12_TEXTURE_ADDRESS_MODE_BORDER => Some("BORDER"),
        D3D12_TEXTURE_ADDRESS_MODE_MIRROR_ONCE => Some("MIRROR_ONCE"),
        _ => None, // undefined per d3d12.h — validation error
    }
}

fn exec_d3d12_texture_address_mode(input: &Value) -> Value {
    let mode = input
        .get("mode")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32;
    let name = d3d12_texture_address_mode_name(mode);
    json!({
        "mode": mode,
        "name": name,
        "valid": name.is_some(),
    })
}

// D3D12_FILTER_REDUCTION_TYPE (d3d12.h):
//   STANDARD=0, COMPARISON=1, MINIMUM=2, MAXIMUM=3.
// Values outside 0..=3 are undefined — a validation error.
const D3D12_FILTER_REDUCTION_TYPE_STANDARD: u32 = 0;
const D3D12_FILTER_REDUCTION_TYPE_COMPARISON: u32 = 1;
const D3D12_FILTER_REDUCTION_TYPE_MINIMUM: u32 = 2;
const D3D12_FILTER_REDUCTION_TYPE_MAXIMUM: u32 = 3;

// The D3D12_FILTER bit layout (d3d12.h macros D3D12_FILTER_TYPE_MASK/SHIFT,
// D3D12_FILTER_ANISOTROPIC_SHIFT, D3D12_FILTER_REDUCTION_TYPE_SHIFT):
//   mip filter bits 0-1, mag filter bits 2-3, min filter bits 4-5,
//   anisotropic bit 6, reduction type bits 7-8.
// Ground truth from the named constants:
//   D3D12_FILTER_MIN_MAG_POINT_MIP_LINEAR = 0x1        -> mip at bits 0-1
//   D3D12_FILTER_MIN_POINT_MAG_LINEAR_MIP_POINT = 0x4  -> mag at bits 2-3
//   D3D12_FILTER_MIN_LINEAR_MAG_MIP_POINT = 0x10       -> min at bits 4-5
//   D3D12_FILTER_ANISOTROPIC = 0x55                    -> bit 6
//   COMPARISON=0x80 / MINIMUM=0x100 / MAXIMUM=0x180    -> reduction bits 7-8
fn d3d12_filter_reduction_name(reduction: u32) -> Option<&'static str> {
    match reduction {
        D3D12_FILTER_REDUCTION_TYPE_STANDARD => Some("STANDARD"),
        D3D12_FILTER_REDUCTION_TYPE_COMPARISON => Some("COMPARISON"),
        D3D12_FILTER_REDUCTION_TYPE_MINIMUM => Some("MINIMUM"),
        D3D12_FILTER_REDUCTION_TYPE_MAXIMUM => Some("MAXIMUM"),
        _ => None,
    }
}

fn exec_d3d12_filter_reduction(input: &Value) -> Value {
    let value = input
        .get("value")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32;
    let name = d3d12_filter_reduction_name(value);
    json!({
        "value": value,
        "name": name,
        "valid": name.is_some(),
        "bit_layout": {
            "mip_filter_bits": [0, 1],
            "mag_filter_bits": [2, 3],
            "min_filter_bits": [4, 5],
            "anisotropic_bit": 6,
            "reduction_bits": [7, 8],
        },
    })
}

// Every named D3D12_FILTER value with its d3d12.h name. The D3D12_FILTER
// enum has exactly these 36 members (4 families × 8 filter combos + the
// four ANISOTROPIC variants). Values not in this table are undefined — a
// validation error on Windows.
const D3D12_FILTER_NAMES: &[(u32, &str)] = &[
    (0x0000_0000, "D3D12_FILTER_MIN_MAG_MIP_POINT"),
    (0x0000_0001, "D3D12_FILTER_MIN_MAG_POINT_MIP_LINEAR"),
    (0x0000_0004, "D3D12_FILTER_MIN_POINT_MAG_LINEAR_MIP_POINT"),
    (0x0000_0005, "D3D12_FILTER_MIN_POINT_MAG_LINEAR_MIP_LINEAR"),
    (0x0000_0010, "D3D12_FILTER_MIN_LINEAR_MAG_MIP_POINT"),
    (0x0000_0011, "D3D12_FILTER_MIN_LINEAR_MAG_POINT_MIP_LINEAR"),
    (0x0000_0014, "D3D12_FILTER_MIN_LINEAR_MAG_LINEAR_MIP_POINT"),
    (0x0000_0015, "D3D12_FILTER_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR"),
    (0x0000_0055, "D3D12_FILTER_ANISOTROPIC"),
    (0x0000_0080, "D3D12_FILTER_COMPARISON_MIN_MAG_MIP_POINT"),
    (
        0x0000_0081,
        "D3D12_FILTER_COMPARISON_MIN_MAG_POINT_MIP_LINEAR",
    ),
    (
        0x0000_0084,
        "D3D12_FILTER_COMPARISON_MIN_POINT_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0085,
        "D3D12_FILTER_COMPARISON_MIN_POINT_MAG_LINEAR_MIP_LINEAR",
    ),
    (
        0x0000_0090,
        "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_MIP_POINT",
    ),
    (
        0x0000_0091,
        "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_POINT_MIP_LINEAR",
    ),
    (
        0x0000_0094,
        "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0095,
        "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_00d5, "D3D12_FILTER_COMPARISON_ANISOTROPIC"),
    (0x0000_0100, "D3D12_FILTER_MINIMUM_MIN_MAG_MIP_POINT"),
    (0x0000_0101, "D3D12_FILTER_MINIMUM_MIN_MAG_POINT_MIP_LINEAR"),
    (
        0x0000_0104,
        "D3D12_FILTER_MINIMUM_MIN_POINT_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0105,
        "D3D12_FILTER_MINIMUM_MIN_POINT_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_0110, "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_MIP_POINT"),
    (
        0x0000_0111,
        "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_POINT_MIP_LINEAR",
    ),
    (
        0x0000_0114,
        "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0115,
        "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_0155, "D3D12_FILTER_MINIMUM_ANISOTROPIC"),
    (0x0000_0180, "D3D12_FILTER_MAXIMUM_MIN_MAG_MIP_POINT"),
    (0x0000_0181, "D3D12_FILTER_MAXIMUM_MIN_MAG_POINT_MIP_LINEAR"),
    (
        0x0000_0184,
        "D3D12_FILTER_MAXIMUM_MIN_POINT_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0185,
        "D3D12_FILTER_MAXIMUM_MIN_POINT_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_0190, "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_MIP_POINT"),
    (
        0x0000_0191,
        "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_POINT_MIP_LINEAR",
    ),
    (
        0x0000_0194,
        "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0195,
        "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_01d5, "D3D12_FILTER_MAXIMUM_ANISOTROPIC"),
];

/// Decompose a D3D12_FILTER value per the d3d12.h bit layout. The min/mag/
/// mip fields are 0=POINT, 1=LINEAR (the only values any named filter
/// uses); the reduction field is the 2-bit D3D12_FILTER_REDUCTION_TYPE.
fn d3d12_filter_decomposition(filter: u32) -> (u32, u32, u32, bool, u32) {
    let min = (filter >> 4) & 0x3;
    let mag = (filter >> 2) & 0x3;
    let mip = filter & 0x3;
    let anisotropic = (filter >> 6) & 0x1 != 0;
    let reduction = (filter >> 7) & 0x3;
    (min, mag, mip, anisotropic, reduction)
}

fn exec_d3d12_filter_translation(input: &Value) -> Value {
    let filter = input
        .get("filter")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32;
    let name = D3D12_FILTER_NAMES
        .iter()
        .find(|(value, _)| *value == filter)
        .map(|(_, name)| *name);
    let (min, mag, mip, anisotropic, reduction) = d3d12_filter_decomposition(filter);
    let field = |value: u32| if value == 1 { "LINEAR" } else { "POINT" };
    json!({
        "filter": filter,
        "name": name,
        "min_filter": field(min),
        "mag_filter": field(mag),
        "mip_filter": field(mip),
        "anisotropic": anisotropic,
        "reduction": reduction,
        "reduction_name": d3d12_filter_reduction_name(reduction),
        "valid": name.is_some(),
    })
}

// ── cpu_arithmetic_flags ────────────────────────────────────────────────────
//
// REAL x86 flag truth via stable inline assembly (core::arch::asm!, stable
// since Rust 1.59).  The reference executable runs natively on Windows
// x86/x64, so it executes the ACTUAL instruction (add/sub/cmp at the vector
// width) and captures the FLAGS register — never a reimplementation.  The
// flags are the contract: for add/sub the result is discarded, for cmp the
// instruction itself is the operation.
//
// Flags are captured with `lahf` (AH = SF:ZF:0:AF:0:PF:1:CF, i.e. RFLAGS
// bits 0/2/4/6/7) plus `seto al` (OF, RFLAGS bit 11), which avoids touching
// the stack.  On x86_64-pc-windows-msvc the asm blocks use the x86_64
// register forms; on i686-pc-windows-msvc the x86 forms (64-bit arithmetic
// does not exist in 32-bit mode and is reported as an explicit error).  The
// crate is compiled for the target Windows runner — x64 first; x86 is
// documented as a follow-up when a 32-bit runner is added.

#[derive(Debug, Clone, Copy)]
enum FlagsOp {
    Add,
    Sub,
    Cmp,
}

fn flags_op(name: &str) -> Option<FlagsOp> {
    match name {
        "add" => Some(FlagsOp::Add),
        "sub" => Some(FlagsOp::Sub),
        "cmp" => Some(FlagsOp::Cmp),
        _ => None,
    }
}

/// Capture RFLAGS after the width-masked instruction as a packed u64:
/// bit 0 = CF, bit 2 = PF, bit 4 = AF, bit 6 = ZF, bit 7 = SF,
/// bit 8 = OF (the lahf/seto layout).
#[cfg(target_arch = "x86_64")]
macro_rules! flags_after_arithmetic {
    ($insn:expr, $lhs:expr, $rhs:expr, $dst:tt, $src:tt) => {{
        let mut flags: u64 = 0;
        unsafe {
            core::arch::asm!(
                "mov rcx, {lhs}",
                "mov rdx, {rhs}",
                concat!($insn, " ", $dst, ", ", $src),
                "lahf",
                "seto al",
                "movzx eax, ax",
                "mov {flags}, rax",
                lhs = in(reg) $lhs,
                rhs = in(reg) $rhs,
                flags = inout(reg) flags,
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                options(nostack),
            );
        }
        flags
    }};
}

#[cfg(target_arch = "x86")]
macro_rules! flags_after_arithmetic {
    ($insn:expr, $lhs:expr, $rhs:expr, $dst:tt, $src:tt) => {{
        // 32-bit mode has no u64 register class; the operands and the
        // captured flags are 32-bit (64-bit arithmetic is unsupported on
        // x86 anyway — the executor reports it explicitly).
        let mut flags: u32 = 0;
        unsafe {
            core::arch::asm!(
                "mov ecx, {lhs}",
                "mov edx, {rhs}",
                concat!($insn, " ", $dst, ", ", $src),
                "lahf",
                "seto al",
                "movzx eax, ax",
                "mov {flags}, eax",
                lhs = in(reg) $lhs,
                rhs = in(reg) $rhs,
                flags = inout(reg) flags,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
                options(nostack),
            );
        }
        u64::from(flags)
    }};
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn real_cpu_flags(op: FlagsOp, width: u32, lhs: u64, rhs: u64) -> u64 {
    let insn = match op {
        FlagsOp::Add => "add",
        FlagsOp::Sub => "sub",
        FlagsOp::Cmp => "cmp",
    };
    #[cfg(target_arch = "x86_64")]
    {
        match (insn, width) {
            ("add", 8) => flags_after_arithmetic!("add", lhs, rhs, "cl", "dl"),
            ("add", 16) => flags_after_arithmetic!("add", lhs, rhs, "cx", "dx"),
            ("add", 32) => flags_after_arithmetic!("add", lhs, rhs, "ecx", "edx"),
            ("add", 64) => flags_after_arithmetic!("add", lhs, rhs, "rcx", "rdx"),
            ("sub", 8) => flags_after_arithmetic!("sub", lhs, rhs, "cl", "dl"),
            ("sub", 16) => flags_after_arithmetic!("sub", lhs, rhs, "cx", "dx"),
            ("sub", 32) => flags_after_arithmetic!("sub", lhs, rhs, "ecx", "edx"),
            ("sub", 64) => flags_after_arithmetic!("sub", lhs, rhs, "rcx", "rdx"),
            ("cmp", 8) => flags_after_arithmetic!("cmp", lhs, rhs, "cl", "dl"),
            ("cmp", 16) => flags_after_arithmetic!("cmp", lhs, rhs, "cx", "dx"),
            ("cmp", 32) => flags_after_arithmetic!("cmp", lhs, rhs, "ecx", "edx"),
            ("cmp", 64) => flags_after_arithmetic!("cmp", lhs, rhs, "rcx", "rdx"),
            _ => 0,
        }
    }
    #[cfg(target_arch = "x86")]
    {
        // The operands are 32-bit (the low 8/16/32 bits of the vector's
        // operands); 64-bit arithmetic does not exist in 32-bit mode.
        let (lhs, rhs) = (lhs as u32, rhs as u32);
        match (insn, width) {
            ("add", 8) => flags_after_arithmetic!("add", lhs, rhs, "cl", "dl"),
            ("add", 16) => flags_after_arithmetic!("add", lhs, rhs, "cx", "dx"),
            ("add", 32) => flags_after_arithmetic!("add", lhs, rhs, "ecx", "edx"),
            ("sub", 8) => flags_after_arithmetic!("sub", lhs, rhs, "cl", "dl"),
            ("sub", 16) => flags_after_arithmetic!("sub", lhs, rhs, "cx", "dx"),
            ("sub", 32) => flags_after_arithmetic!("sub", lhs, rhs, "ecx", "edx"),
            ("cmp", 8) => flags_after_arithmetic!("cmp", lhs, rhs, "cl", "dl"),
            ("cmp", 16) => flags_after_arithmetic!("cmp", lhs, rhs, "cx", "dx"),
            ("cmp", 32) => flags_after_arithmetic!("cmp", lhs, rhs, "ecx", "edx"),
            // 64-bit arithmetic is reported by the executor, never here.
            _ => 0,
        }
    }
}

fn flags_output(raw: u64) -> Value {
    json!({
        "zf": raw & (1 << 6) != 0,
        "sf": raw & (1 << 7) != 0,
        "pf": raw & (1 << 2) != 0,
        "cf": raw & (1 << 0) != 0,
        "of": raw & (1 << 8) != 0,
        "af": raw & (1 << 4) != 0,
    })
}

fn exec_cpu_arithmetic_flags(input: &Value) -> Value {
    let Some(spec) = parse::<CpuFlagsInput>(input) else {
        return json!({ "error": "invalid_input" });
    };
    let Some(op) = flags_op(&spec.op) else {
        return json!({ "error": "invalid_input" });
    };
    if !matches!(spec.width, 8 | 16 | 32 | 64) {
        return json!({ "error": "invalid_input" });
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        #[cfg(target_arch = "x86")]
        if spec.width == 64 {
            // A 32-bit reference build cannot execute 64-bit arithmetic; an
            // x86 capture therefore reports the vector explicitly instead of
            // fabricating flags.  The CI runner is x64.
            return json!({ "error": "no_64bit_arithmetic_on_x86" });
        }
        return flags_output(real_cpu_flags(op, spec.width, spec.lhs, spec.rhs));
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = (op, spec.width, spec.lhs, spec.rhs);
        json!({ "error": "unsupported_arch" })
    }
}

// ── virtual_memory ──────────────────────────────────────────────────────────
//
// REAL VirtualAlloc / VirtualFree / VirtualProtect / VirtualQuery sequences.
// The reference process's address space IS the session: state carries across
// vectors in file order exactly like the runtime session carries across
// vectors in the compare run.  The base of the session's first reservation
// is recorded (the corpus's first vector is the reserve), and every
// `base_address` in the output is reported RELATIVE to that base — the
// absolute base is ASLR-environmental, while the relative layout is the
// semantic contract.  For MEM_FREE regions the query reports NULL base + 0
// size (the documented VirtualQuery contract for unmapped addresses).

static VM_SESSION_BASE: AtomicU64 = AtomicU64::new(0);

fn exec_virtual_memory(input: &Value) -> Value {
    let Some(spec) = parse::<VirtualMemoryInput>(input) else {
        return json!({ "error": 87, "state": MEM_FREE, "protection": PAGE_NOACCESS, "region_size": 0, "base_address": 0, "committed_set_summary": false });
    };
    let session_base = VM_SESSION_BASE.load(Ordering::SeqCst);
    let absolute = if spec.operation == "reserve" {
        spec.address
    } else {
        session_base.wrapping_add(spec.address)
    };
    let (error, query_address, old_protection) = match spec.operation.as_str() {
        "reserve" => {
            let base = unsafe {
                VirtualAlloc(
                    absolute as LPVOID,
                    spec.size as SIZE_T,
                    spec.allocation_type,
                    spec.protection,
                )
            };
            if base.is_null() {
                (last_error(), if absolute == 0 { 0 } else { absolute }, None)
            } else {
                if VM_SESSION_BASE.load(Ordering::SeqCst) == 0 {
                    VM_SESSION_BASE.store(base as u64, Ordering::SeqCst);
                }
                (0, base as u64, None)
            }
        }
        "commit" => {
            let base = unsafe {
                VirtualAlloc(
                    absolute as LPVOID,
                    spec.size as SIZE_T,
                    MEM_COMMIT,
                    spec.protection,
                )
            };
            (
                if base.is_null() { last_error() } else { 0 },
                absolute,
                None,
            )
        }
        "decommit" => {
            let ok = unsafe { VirtualFree(absolute as LPVOID, spec.size as SIZE_T, MEM_DECOMMIT) };
            (if ok == 0 { last_error() } else { 0 }, absolute, None)
        }
        "release" => {
            let ok = unsafe { VirtualFree(absolute as LPVOID, spec.size as SIZE_T, MEM_RELEASE) };
            (if ok == 0 { last_error() } else { 0 }, absolute, None)
        }
        "protect" => {
            let mut old: DWORD = 0;
            let ok = unsafe {
                VirtualProtect(
                    absolute as LPVOID,
                    spec.size as SIZE_T,
                    spec.protection,
                    &mut old,
                )
            };
            (if ok == 0 { last_error() } else { 0 }, absolute, Some(old))
        }
        "query" => (0, absolute, None),
        _ => (87, absolute, None),
    };
    // VirtualQuery at the target address — the post-operation memory state.
    let mut mbi = MemoryBasicInformation::default();
    let written = unsafe {
        VirtualQuery(
            query_address as LPVOID,
            &mut mbi,
            std::mem::size_of::<MemoryBasicInformation>() as SIZE_T,
        )
    };
    let (state, protection, region_size, base_address) = if written == 0 {
        (MEM_FREE, PAGE_NOACCESS, 0_u64, 0_u64)
    } else {
        let session_base = VM_SESSION_BASE.load(Ordering::SeqCst);
        let base = mbi.base_address as u64;
        let relative = if mbi.state == MEM_FREE {
            0
        } else {
            base.wrapping_sub(session_base)
        };
        (mbi.state, mbi.protect, mbi.region_size as u64, relative)
    };
    let mut output = json!({
        "error": error,
        "state": state,
        "protection": protection,
        "region_size": region_size,
        "base_address": base_address,
        "committed_set_summary": state == MEM_COMMIT,
    });
    if let Some(old) = old_protection {
        output["old_protection"] = json!(old);
    }
    output
}

// ── time_clock ──────────────────────────────────────────────────────────────
//
// REAL GetTickCount64 / GetSystemTimeAsFileTime / QueryPerformanceCounter
// deltas across a real Sleep.  The output carries only RELATIVE deltas plus
// the frequency-normalized QPC seconds (qpc_seconds_100ns =
// qpc_delta × 10_000_000 / frequency) — the compare contract validates the
// semantics structurally (monotonicity, the 100-ns FILETIME domain, the QPC
// units-vs-frequency relation), so the corpus is portable across machines.

fn exec_time_clock(input: &Value) -> Value {
    let Some(spec) = parse::<TimeClockInput>(input) else {
        return json!({
            "sleep_ms": 0, "ticks_delta": 0, "filetime_delta": 0,
            "qpc_delta": 0, "qpc_seconds_100ns": 0,
        });
    };
    let ticks_before = unsafe { GetTickCount64() };
    let mut filetime_before: u64 = 0;
    unsafe {
        GetSystemTimeAsFileTime(&mut filetime_before);
    }
    let mut qpc_before: u64 = 0;
    let mut frequency: u64 = 0;
    unsafe {
        QueryPerformanceCounter(&mut qpc_before);
        QueryPerformanceFrequency(&mut frequency);
    }
    unsafe {
        Sleep(spec.sleep_ms);
    }
    let ticks_after = unsafe { GetTickCount64() };
    let mut filetime_after: u64 = 0;
    unsafe {
        GetSystemTimeAsFileTime(&mut filetime_after);
    }
    let mut qpc_after: u64 = 0;
    unsafe {
        QueryPerformanceCounter(&mut qpc_after);
    }
    let ticks_delta = ticks_after - ticks_before;
    let filetime_delta = filetime_after - filetime_before;
    let qpc_delta = qpc_after - qpc_before;
    let qpc_seconds_100ns = if frequency == 0 {
        0
    } else {
        qpc_delta.saturating_mul(10_000_000) / frequency
    };
    json!({
        "sleep_ms": spec.sleep_ms,
        "ticks_delta": ticks_delta,
        "filetime_delta": filetime_delta,
        "qpc_delta": qpc_delta,
        "qpc_seconds_100ns": qpc_seconds_100ns,
    })
}

// ── environment ─────────────────────────────────────────────────────────────
//
// REAL GetEnvironmentVariableW / SetEnvironmentVariableW /
// GetEnvironmentStringsW semantics: present/missing, the required-size
// return (units including the trailing NUL), the too-small-buffer case
// (ERROR_INSUFFICIENT_BUFFER while still returning the required size),
// case-insensitive name lookup, and the sorted NAME=VALUE block entries
// (normalized to sorted entries so the block order — process-dependent on
// Windows — is never part of the differential).

fn exec_environment(input: &Value) -> Value {
    let Some(spec) = parse::<EnvironmentInput>(input) else {
        return json!({ "found": false, "error": 87 });
    };
    match spec.op.as_str() {
        "roundtrip" => {
            let name = to_wide(&spec.name);
            let value = to_wide(&spec.value);
            let set_succeeded = unsafe { SetEnvironmentVariableW(name.as_ptr(), value.as_ptr()) };
            let mangled = to_wide(&spec.name.to_lowercase());
            let query = |name: &[u16]| unsafe {
                let required = GetEnvironmentVariableW(name.as_ptr(), null_mut(), 0);
                if required == 0 {
                    return json!({ "found": false, "error": last_error() });
                }
                let mut buffer = vec![0u16; required as usize];
                let copied = GetEnvironmentVariableW(
                    name.as_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len() as DWORD,
                );
                let retrieved = from_wide(&buffer[..copied as usize]);
                // Too-small buffer: report the required size and the
                // ERROR_INSUFFICIENT_BUFFER error.
                let mut small = vec![0u16; 4];
                let small_copied = GetEnvironmentVariableW(
                    name.as_ptr(),
                    small.as_mut_ptr(),
                    small.len() as DWORD,
                );
                let small_error = if small_copied == 0 { last_error() } else { 0 };
                json!({
                    "found": true,
                    "retrieved": retrieved,
                    "retrieved_units": copied,
                    "required_size": required,
                    "small_buffer_error": small_error,
                    "small_buffer_required": small_copied,
                    "trailing_null": buffer.get(copied as usize).copied() == Some(0),
                    "error": 0,
                })
            };
            let result = query(&name);
            let mut output = result;
            if output["found"] == json!(true) {
                output["case_insensitive_found"] = json!(query(&mangled)["found"] == json!(true));
            } else {
                output["case_insensitive_found"] = json!(false);
            }
            output["set_succeeded"] = json!(set_succeeded != 0);
            output
        }
        "missing" => {
            let name = to_wide(&spec.name);
            let required = unsafe { GetEnvironmentVariableW(name.as_ptr(), null_mut(), 0) };
            let error = if required == 0 { last_error() } else { 0 };
            json!({
                "found": required != 0,
                "error": error,
                "required_size": required,
            })
        }
        "block" => {
            let name = to_wide(&spec.name);
            let value = to_wide(&spec.value);
            unsafe {
                SetEnvironmentVariableW(name.as_ptr(), value.as_ptr());
            }
            let block = unsafe { GetEnvironmentStringsW() };
            let mut entries = Vec::new();
            if !block.is_null() {
                let mut cursor = block;
                loop {
                    let mut units = Vec::new();
                    let mut unit = unsafe { *cursor };
                    while unit != 0 {
                        units.push(unit);
                        cursor = unsafe { cursor.add(1) };
                        unit = unsafe { *cursor };
                    }
                    if units.is_empty() {
                        break;
                    }
                    entries.push(from_wide(&units));
                    cursor = unsafe { cursor.add(1) };
                }
                unsafe {
                    FreeEnvironmentStringsW(block);
                }
            }
            let prefix = "CASA1_ORACLE_BLOCK_";
            let mut filtered = entries
                .into_iter()
                .filter(|entry| entry.starts_with(prefix))
                .collect::<Vec<_>>();
            filtered.sort();
            json!({ "entries": filtered, "error": 0 })
        }
        _ => json!({ "found": false, "error": 87 }),
    }
}

// ── file_metadata ───────────────────────────────────────────────────────────
//
// REAL GetFileAttributesW / GetFileSizeEx / SetFilePointerEx semantics.
// Attributes are reported as the differential-stable projections (exists /
// is_directory / is_readonly — the raw FILE_ATTRIBUTE_* bit masks are not
// stable across file systems); sizes and pointer positions are exact byte
// values; errors are the ERROR_* codes (2 / 3 / 6).

fn file_attr_projection(path: &str) -> (bool, bool, bool, DWORD) {
    let wide = to_wide(path);
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        (false, false, false, last_error())
    } else {
        (
            true,
            attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            attributes & FILE_ATTRIBUTE_READONLY != 0,
            0,
        )
    }
}

fn exec_file_metadata(input: &Value) -> Value {
    ensure_scratch_dirs();
    let Some(spec) = parse::<FileMetadataInput>(input) else {
        return json!({ "error": 87, "exists": false });
    };
    let read_write = GENERIC_READ | GENERIC_WRITE;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let (exists, is_directory, is_readonly, attr_error) = file_attr_projection(&spec.path);
    let mut output = json!({
        "op": spec.op,
        "exists": exists,
        "is_directory": is_directory,
        "is_readonly": is_readonly,
        "error": 0,
        "size": null,
        "sizes": null,
        "pointer_begin": null,
        "pointer_end": null,
        "set_succeeded": null,
        "clear_succeeded": null,
        "is_readonly_after_clear": null,
    });
    match spec.op.as_str() {
        "create" => {
            let handle = open_file(&spec.path, read_write, share, CREATE_ALWAYS);
            if handle == INVALID_HANDLE_VALUE {
                output["error"] = json!(last_error());
                output["exists"] = json!(false);
                return output;
            }
            let mut size: u64 = 0;
            let size_ok = unsafe { GetFileSizeEx(handle, &mut size) };
            output["size"] = json!(if size_ok != 0 { size } else { 0 });
            output["error"] = json!(if size_ok != 0 { 0 } else { last_error() });
            close_handle(handle);
            output["exists"] = json!(file_attr_projection(&spec.path).0);
            output
        }
        "size_after_writes" => {
            let handle = open_file(&spec.path, read_write, share, CREATE_ALWAYS);
            if handle == INVALID_HANDLE_VALUE {
                output["error"] = json!(last_error());
                return output;
            }
            let mut written: DWORD = 0;
            let first_ok = unsafe {
                WriteFile(
                    handle,
                    b"hello".as_ptr() as *const c_void,
                    5,
                    &mut written,
                    null_mut(),
                )
            };
            let mut first_size: u64 = 0;
            let first = if first_ok != 0 {
                unsafe { GetFileSizeEx(handle, &mut first_size) };
                json!(first_size)
            } else {
                json!(null)
            };
            let mut second_size: u64 = 0;
            let second = if first_ok != 0 {
                let second_ok = unsafe {
                    WriteFile(
                        handle,
                        b"abc".as_ptr() as *const c_void,
                        3,
                        &mut written,
                        null_mut(),
                    )
                };
                if second_ok != 0 {
                    unsafe { GetFileSizeEx(handle, &mut second_size) };
                    json!(second_size)
                } else {
                    json!(null)
                }
            } else {
                json!(null)
            };
            close_handle(handle);
            output["sizes"] = json!([first, second]);
            output["error"] = json!(if first == json!(null) || second == json!(null) {
                last_error()
            } else {
                0
            });
            output
        }
        "seek" => {
            let handle = open_file(&spec.path, read_write, share, CREATE_ALWAYS);
            if handle == INVALID_HANDLE_VALUE {
                output["error"] = json!(last_error());
                return output;
            }
            let mut written: DWORD = 0;
            unsafe {
                WriteFile(
                    handle,
                    b"01234567".as_ptr() as *const c_void,
                    8,
                    &mut written,
                    null_mut(),
                );
            }
            let mut begin: u64 = 0;
            let begin_ok = unsafe { SetFilePointerEx(handle, 3, &mut begin, FILE_BEGIN) };
            let mut end: u64 = 0;
            let end_ok = unsafe { SetFilePointerEx(handle, -2, &mut end, FILE_END) };
            close_handle(handle);
            output["pointer_begin"] = json!(if begin_ok != 0 { begin } else { 0 });
            output["pointer_end"] = json!(if end_ok != 0 { end } else { 0 });
            output["error"] = json!(if begin_ok != 0 && end_ok != 0 { 0 } else { last_error() });
            output
        }
        "directory" => {
            let wide = to_wide(&spec.path);
            let created = unsafe { CreateDirectoryW(wide.as_ptr(), null_mut()) };
            output["error"] = json!(if created != 0 { 0 } else { last_error() });
            let (exists, is_directory, is_readonly, _) = file_attr_projection(&spec.path);
            output["exists"] = json!(exists);
            output["is_directory"] = json!(is_directory);
            output["is_readonly"] = json!(is_readonly);
            output
        }
        "missing" => {
            output["error"] = json!(if exists { 0 } else { attr_error });
            output
        }
        "missing_parent" => {
            output["error"] = json!(if exists { 0 } else { attr_error });
            output
        }
        "invalid_handle" => {
            let mut size: u64 = 0;
            let ok = unsafe { GetFileSizeEx(INVALID_HANDLE_VALUE, &mut size) };
            output["error"] = json!(if ok != 0 { 0 } else { last_error() });
            output
        }
        "readonly_roundtrip" => {
            let handle = open_file(&spec.path, read_write, share, CREATE_ALWAYS);
            if handle != INVALID_HANDLE_VALUE {
                close_handle(handle);
            }
            let wide = to_wide(&spec.path);
            let set_succeeded = unsafe {
                SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE)
            };
            output["set_succeeded"] = json!(set_succeeded != 0);
            output["is_readonly"] = json!(file_attr_projection(&spec.path).2);
            let clear_succeeded =
                unsafe { SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_ARCHIVE) };
            output["clear_succeeded"] = json!(clear_succeeded != 0);
            output["is_readonly_after_clear"] = json!(file_attr_projection(&spec.path).2);
            output["error"] = json!(0);
            output
        }
        _ => json!({ "error": 87, "exists": false }),
    }
}

// ── directory_enumeration ───────────────────────────────────────────────────
//
// REAL FindFirstFileW / FindNextFileW / FindClose over the fixed fixture
// layout the executor provisions itself (alpha/: dir_a + dir_c directories,
// file_a.txt + file_b.bin files).  Entry names, per-entry directory flags
// and the sorted order are the differential; the no-match /
// missing-directory / exhaustion cases report the ERROR_* codes.

fn provision_enum_fixture() {
    let base = "C:\\Windows\\Temp\\casa1-oracle\\enum\\alpha";
    let dirs = [base, "C:\\Windows\\Temp\\casa1-oracle\\enum"];
    for directory in dirs {
        let wide = to_wide(directory);
        unsafe {
            CreateDirectoryW(wide.as_ptr(), null_mut());
        }
    }
    for name in ["dir_a", "dir_c"] {
        let wide = to_wide(&format!("{base}\\{name}"));
        unsafe {
            CreateDirectoryW(wide.as_ptr(), null_mut());
        }
    }
    for name in ["file_a.txt", "file_b.bin"] {
        let handle = open_file(
            &format!("{base}\\{name}"),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            CREATE_ALWAYS,
        );
        if handle != INVALID_HANDLE_VALUE {
            close_handle(handle);
        }
    }
}

fn exec_directory_enumeration(input: &Value) -> Value {
    ensure_scratch_dirs();
    provision_enum_fixture();
    let Some(spec) = parse::<DirectoryEnumerationInput>(input) else {
        return json!({ "find_succeeded": false, "error": 87, "entries": [] });
    };
    let path = to_wide(&spec.path);
    let mut find_data = Win32FindDataW::default();
    let handle = unsafe { FindFirstFileW(path.as_ptr(), &mut find_data) };
    if handle == INVALID_HANDLE_VALUE {
        return json!({
            "find_succeeded": false,
            "invalid_handle": true,
            "error": last_error(),
            "entries": [],
            "exhausted": false,
            "next_error": 0,
            "close_succeeded": false,
        });
    }
    let mut entries = vec![json!({
        "name": from_wide(&find_data.file_name),
        "is_directory": find_data.attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
    })];
    let mut exhausted = false;
    let mut next_error = 0;
    loop {
        let mut next = Win32FindDataW::default();
        let ok = unsafe { FindNextFileW(handle, &mut next) };
        if ok == 0 {
            next_error = last_error();
            exhausted = true;
            break;
        }
        entries.push(json!({
            "name": from_wide(&next.file_name),
            "is_directory": next.attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        }));
    }
    let close_succeeded = unsafe { FindClose(handle) } != 0;
    json!({
        "find_succeeded": true,
        "invalid_handle": false,
        "error": 0,
        "entries": entries,
        "exhausted": exhausted,
        "next_error": next_error,
        "close_succeeded": close_succeeded,
    })
}

// ── version ─────────────────────────────────────────────────────────────────
//
// REAL GetVersionExW and RtlGetVersion.  The output reports both APIs'
// fields plus the structural contract booleans; the compare accepts the
// SHAPE (the raw version numbers differ between the reference machine and
// the Casa1 configured profile — the CONTRACT is cross-API consistency
// within each side plus the Windows-10-family shape).

fn exec_version(input: &Value) -> Value {
    let Some(spec) = parse::<VersionInput>(input) else {
        return json!({ "error": 87 });
    };
    if spec.api != "both" {
        return json!({ "error": 87 });
    }
    let fields = |major: u32,
                  minor: u32,
                  build: u32,
                  platform_id: u32,
                  service_pack_major: u16,
                  service_pack_minor: u16|
     -> Value {
        json!({
            "major": major,
            "minor": minor,
            "build": build,
            "platform_id": platform_id,
            "service_pack_major": service_pack_major,
            "service_pack_minor": service_pack_minor,
        })
    };
    let mut version_ex = OsVersionInfoExW::default();
    let version_ex_ok = unsafe { GetVersionExW(&mut version_ex) };
    let mut rtl = RtlOsVersionInfoW {
        size: std::mem::size_of::<RtlOsVersionInfoW>() as DWORD,
        major: 0,
        minor: 0,
        build: 0,
        platform_id: 0,
        csd_version: [0; 128],
    };
    let rtl_ok = unsafe { RtlGetVersion(&mut rtl) };
    let version_ex_fields = if version_ex_ok != 0 {
        fields(
            version_ex.major,
            version_ex.minor,
            version_ex.build,
            version_ex.platform_id,
            version_ex.service_pack_major,
            version_ex.service_pack_minor,
        )
    } else {
        json!({ "major": 0, "minor": 0, "build": 0, "platform_id": 0, "service_pack_major": 0, "service_pack_minor": 0 })
    };
    let rtl_fields = if rtl_ok == 0 {
        fields(
            rtl.major,
            rtl.minor,
            rtl.build,
            rtl.platform_id,
            0,
            0,
        )
    } else {
        json!({ "major": 0, "minor": 0, "build": 0, "platform_id": 0, "service_pack_major": 0, "service_pack_minor": 0 })
    };
    let cross_consistent = version_ex_ok != 0
        && rtl_ok == 0
        && version_ex_fields["major"] == rtl_fields["major"]
        && version_ex_fields["minor"] == rtl_fields["minor"]
        && version_ex_fields["build"] == rtl_fields["build"]
        && version_ex_fields["platform_id"] == rtl_fields["platform_id"];
    let shape_ok = version_ex_ok != 0
        && rtl_ok == 0
        && version_ex.major == 10
        && version_ex.build > 0
        && version_ex.platform_id == VER_PLATFORM_WIN32_NT;
    json!({
        "version_ex": version_ex_fields,
        "rtl": rtl_fields,
        "cross_consistent": cross_consistent,
        "build_positive": shape_ok && version_ex.build > 0,
        "major_win10_family": shape_ok && version_ex.major == 10,
        "platform_nt": shape_ok && version_ex.platform_id == VER_PLATFORM_WIN32_NT,
    })
}

// ── error_domain ────────────────────────────────────────────────────────────
//
// REAL SetLastError / GetLastError semantics plus the ERROR_* ↔ NTSTATUS
// mapping (RtlNtStatusToDosError): for each fixed failure class the
// executor performs a REAL failing API call and reports the resulting
// GetLastError value; the ERROR_* values are identical across Windows and
// Casa1 (2 / 6 / 5 / 203).

fn exec_error_domain(input: &Value) -> Value {
    ensure_scratch_dirs();
    let Some(spec) = parse::<ErrorDomainInput>(input) else {
        return json!({ "get_last_error": 87, "status_mapped": 87, "matches": true });
    };
    let (get_last_error, status) = match spec.op.as_str() {
        "missing_file" => {
            let path = format!("{}\\err\\missing-000.bin", "C:\\Windows\\Temp\\casa1-oracle");
            let handle = open_file(&path, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING);
            let error = if handle == INVALID_HANDLE_VALUE {
                last_error()
            } else {
                close_handle(handle);
                0
            };
            (error, 0xC000_0034_u32) // STATUS_OBJECT_NAME_NOT_FOUND
        }
        "invalid_handle" => {
            let mut size: u64 = 0;
            let ok = unsafe { GetFileSizeEx(INVALID_HANDLE_VALUE, &mut size) };
            (if ok != 0 { 0 } else { last_error() }, 0xC000_0008_u32) // STATUS_INVALID_HANDLE
        }
        "readonly_delete" => {
            let base = "C:\\Windows\\Temp\\casa1-oracle\\err";
            let path = format!("{base}\\readonly-001.bin");
            let handle = open_file(
                &path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                CREATE_ALWAYS,
            );
            if handle != INVALID_HANDLE_VALUE {
                close_handle(handle);
            }
            let wide = to_wide(&path);
            unsafe {
                SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_READONLY);
            }
            let ok = unsafe { DeleteFileW(wide.as_ptr()) };
            let error = if ok != 0 { 0 } else { last_error() };
            unsafe {
                SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            }
            (error, 0xC000_0022_u32) // STATUS_ACCESS_DENIED
        }
        "set_roundtrip" => {
            unsafe {
                SetLastError(ERROR_ENVVAR_NOT_FOUND);
            }
            (unsafe { GetLastError() }, 0)
        }
        _ => return json!({ "get_last_error": 87, "status_mapped": 87, "matches": true }),
    };
    let status_mapped = if spec.op == "set_roundtrip" {
        get_last_error
    } else {
        unsafe { RtlNtStatusToDosError(status as i32) }
    };
    json!({
        "op": spec.op,
        "get_last_error": get_last_error,
        "status_mapped": status_mapped,
        "matches": get_last_error == status_mapped,
    })
}

// ── string_ops ──────────────────────────────────────────────────────────────
//
// REAL lstrlenW / lstrcpyW / lstrcmpW / CharUpperW semantics.

fn exec_string_ops(input: &Value) -> Value {
    let Some(spec) = parse::<StringOpsInput>(input) else {
        return json!({ "error": 87 });
    };
    match spec.op.as_str() {
        "len" => {
            let wide = to_wide(&spec.left);
            let length = unsafe { lstrlenW(wide.as_ptr()) };
            json!({ "op": "len", "length": length, "error": 0 })
        }
        "copy" => {
            let source = to_wide(&spec.left);
            let mut destination = vec![0u16; source.len()];
            unsafe {
                lstrcpyW(destination.as_mut_ptr(), source.as_ptr());
            }
            let dest_length = unsafe { lstrlenW(destination.as_ptr()) };
            let terminated = destination.get(source.len() - 1).copied() == Some(0);
            json!({
                "op": "copy",
                "copied_length": dest_length,
                "dest_length": dest_length,
                "terminated": terminated,
                "error": 0,
            })
        }
        "cmp" => {
            let left = to_wide(&spec.left);
            let right = to_wide(&spec.right);
            let sign = unsafe { lstrcmpW(left.as_ptr(), right.as_ptr()) };
            json!({ "op": "cmp", "sign": sign, "error": 0 })
        }
        "upper_char" => {
            let mut value = [0u16; 2];
            value[0] = (spec.character & 0xFFFF) as u16;
            // Single-character form: the high word is zero, CharUpperW
            // converts the low word and RETURNS the converted character.
            let upper = if spec.character <= u16::MAX as u32 {
                unsafe { CharUpperW(value.as_mut_ptr()) as usize as u32 }
            } else {
                spec.character
            };
            json!({
                "op": "upper_char",
                "character": spec.character,
                "upper": upper,
                "error": 0,
            })
        }
        "upper_string" => {
            let mut wide = to_wide(&spec.left);
            unsafe {
                CharUpperW(wide.as_mut_ptr());
            }
            json!({
                "op": "upper_string",
                "upper": from_wide(&wide),
                "error": 0,
            })
        }
        _ => json!({ "error": 87 }),
    }
}

// ── section_mapping ─────────────────────────────────────────────────────────
//
// REAL CreateFileMappingW / MapViewOfFile / UnmapViewOfFile over ANONYMOUS
// (non-file-backed) sections — the Casa1 runtime models named/anonymous
// shared sections, not file-backed ones.  The differential is the mapping
// SIZE and the content visibility after writes (never base addresses).

fn exec_section_mapping(input: &Value) -> Value {
    let Some(spec) = parse::<SectionMappingInput>(input) else {
        return json!({ "error": 87 });
    };
    let create = |size: u32| unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            null_mut(),
            PAGE_READWRITE,
            0,
            size,
            null_mut(),
        )
    };
    match spec.op.as_str() {
        "anon" => {
            let section = create(spec.size);
            if section.is_null() {
                return json!({
                    "op": "anon", "mapping_size": 0, "view_size": 0,
                    "map_succeeded": false, "unmap_succeeded": false,
                    "error": last_error(), "content_matches": null, "persisted": null,
                });
            }
            let view = unsafe { MapViewOfFile(section, 0xF001F, 0, 0, 0) };
            if view.is_null() {
                let error = last_error();
                unsafe {
                    CloseHandle(section);
                }
                return json!({
                    "op": "anon", "mapping_size": spec.size, "view_size": 0,
                    "map_succeeded": false, "unmap_succeeded": false,
                    "error": error, "content_matches": null, "persisted": null,
                });
            }
            let view_size = view_size_of(section, view, spec.size);
            let unmapped = unsafe { UnmapViewOfFile(view) } != 0;
            unsafe {
                CloseHandle(section);
            }
            json!({
                "op": "anon",
                "mapping_size": spec.size,
                "view_size": view_size,
                "map_succeeded": true,
                "unmap_succeeded": unmapped,
                "error": 0,
                "content_matches": null,
                "persisted": null,
            })
        }
        "write_visible" => {
            let section = create(spec.size);
            if section.is_null() {
                return json!({
                    "op": "write_visible", "mapping_size": 0, "view_size": 0,
                    "map_succeeded": false, "unmap_succeeded": false,
                    "error": last_error(), "content_matches": null, "persisted": null,
                });
            }
            let view = unsafe { MapViewOfFile(section, 0xF001F, 0, 0, 0) };
            if view.is_null() {
                let error = last_error();
                unsafe {
                    CloseHandle(section);
                }
                return json!({
                    "op": "write_visible", "mapping_size": spec.size, "view_size": 0,
                    "map_succeeded": false, "unmap_succeeded": false,
                    "error": error, "content_matches": null, "persisted": null,
                });
            }
            let payload: &[u8] = b"section-payload-0123456789";
            unsafe {
                std::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    (view as *mut u8).add(0x10),
                    payload.len(),
                );
            }
            let mut read_back = vec![0u8; payload.len()];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (view as *const u8).add(0x10),
                    read_back.as_mut_ptr(),
                    payload.len(),
                );
            }
            let matches = read_back == payload;
            let unmapped = unsafe { UnmapViewOfFile(view) } != 0;
            unsafe {
                CloseHandle(section);
            }
            json!({
                "op": "write_visible",
                "mapping_size": spec.size,
                "view_size": spec.size,
                "map_succeeded": true,
                "unmap_succeeded": unmapped,
                "error": 0,
                "content_matches": matches,
                "persisted": null,
            })
        }
        "unmap_remap" => {
            let section = create(spec.size);
            if section.is_null() {
                return json!({
                    "op": "unmap_remap", "mapping_size": 0, "view_size": 0,
                    "map_succeeded": false, "unmap_succeeded": false,
                    "error": last_error(), "content_matches": null, "persisted": null,
                });
            }
            let first = unsafe { MapViewOfFile(section, 0xF001F, 0, 0, 0) };
            if first.is_null() {
                let error = last_error();
                unsafe {
                    CloseHandle(section);
                }
                return json!({
                    "op": "unmap_remap", "mapping_size": spec.size, "view_size": 0,
                    "map_succeeded": false, "unmap_succeeded": false,
                    "error": error, "content_matches": null, "persisted": null,
                });
            }
            let payload: &[u8] = b"persist-me";
            unsafe {
                std::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    (first as *mut u8).add(0x10),
                    payload.len(),
                );
                UnmapViewOfFile(first);
            }
            let second = unsafe { MapViewOfFile(section, 0xF001F, 0, 0, 0) };
            let persisted = if second.is_null() {
                false
            } else {
                let mut read_back = vec![0u8; payload.len()];
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        (second as *const u8).add(0x10),
                        read_back.as_mut_ptr(),
                        payload.len(),
                    );
                    UnmapViewOfFile(second);
                }
                read_back == payload
            };
            unsafe {
                CloseHandle(section);
            }
            json!({
                "op": "unmap_remap",
                "mapping_size": spec.size,
                "view_size": spec.size,
                "map_succeeded": true,
                "unmap_succeeded": true,
                "error": 0,
                "content_matches": null,
                "persisted": persisted,
            })
        }
        "invalid_handle" => {
            let view = unsafe { MapViewOfFile(INVALID_HANDLE_VALUE, 0xF001F, 0, 0, 0) };
            let error = if view.is_null() { last_error() } else { 0 };
            if !view.is_null() {
                unsafe {
                    UnmapViewOfFile(view);
                }
            }
            json!({
                "op": "invalid_handle",
                "mapping_size": 0,
                "view_size": 0,
                "map_succeeded": !view.is_null(),
                "unmap_succeeded": false,
                "error": error,
                "content_matches": null,
                "persisted": null,
            })
        }
        _ => json!({ "error": 87 }),
    }
}

/// The mapped view size: when MapViewOfFile maps the whole section (0), the
/// view covers the full section; report the section's real size via
/// VirtualQuery on the view base (the view is rounded up to page
/// granularity, but the section size is the semantic contract).
fn view_size_of(_section: HANDLE, view: LPVOID, requested: u32) -> u64 {
    let mut mbi = MemoryBasicInformation::default();
    let written = unsafe {
        VirtualQuery(
            view,
            &mut mbi,
            std::mem::size_of::<MemoryBasicInformation>() as SIZE_T,
        )
    };
    if written != 0 {
        return mbi.region_size as u64;
    }
    // The caller requested an explicit view size; report it.
    u64::from(requested)
}

// ── heap ────────────────────────────────────────────────────────────────────
//
// REAL HeapAlloc / HeapFree / HeapSize on the process heap: allocation
// success, size ≥ requested, 16-byte alignment (the alignment IS
// differential), HEAP_ZERO_MEMORY zeroing, and HeapFree invalidating the
// size query.

fn exec_heap(input: &Value) -> Value {
    let Some(spec) = parse::<HeapInput>(input) else {
        return json!({ "error": 87 });
    };
    let heap = unsafe { GetProcessHeap() };
    if heap.is_null() {
        return json!({ "error": 87 });
    }
    match spec.op.as_str() {
        "alloc_zero" => {
            let pointer =
                unsafe { HeapAlloc(heap, HEAP_ZERO_MEMORY, spec.size as SIZE_T) };
            if pointer.is_null() {
                return json!({
                    "op": "alloc_zero",
                    "alloc_succeeded": false,
                    "aligned_16": false,
                    "zeroed": false,
                    "size_ge_requested": false,
                    "error": last_error(),
                });
            }
            let size = unsafe { HeapSize(heap, 0, pointer) };
            let aligned_16 = (pointer as usize) % 16 == 0;
            let bytes = unsafe {
                std::slice::from_raw_parts(pointer as *const u8, spec.size as usize).to_vec()
            };
            let zeroed = bytes.iter().all(|byte| *byte == 0);
            unsafe {
                HeapFree(heap, 0, pointer);
            }
            json!({
                "op": "alloc_zero",
                "alloc_succeeded": true,
                "aligned_16": aligned_16,
                "zeroed": zeroed,
                "size_ge_requested": size >= spec.size as SIZE_T,
                "error": 0,
            })
        }
        "free_size" => {
            let pointer = unsafe { HeapAlloc(heap, 0, spec.size as SIZE_T) };
            if pointer.is_null() {
                return json!({
                    "op": "free_size",
                    "alloc_succeeded": false,
                    "freed": false,
                    "size_ge_requested": false,
                    "size_after_free_fails": false,
                    "error": last_error(),
                });
            }
            let size = unsafe { HeapSize(heap, 0, pointer) };
            let freed = unsafe { HeapFree(heap, 0, pointer) } != 0;
            let size_after = unsafe { HeapSize(heap, 0, pointer) };
            let size_after_free_fails = freed && size_after == SIZE_T::MAX;
            json!({
                "op": "free_size",
                "alloc_succeeded": true,
                "freed": freed,
                "size_ge_requested": size >= spec.size as SIZE_T,
                "size_after_free_fails": size_after_free_fails,
                "error": if freed { 0 } else { last_error() },
            })
        }
        _ => json!({ "error": 87 }),
    }
}
