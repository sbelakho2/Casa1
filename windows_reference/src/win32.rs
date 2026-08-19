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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

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
const INVALID_FILE_ATTRIBUTES: DWORD = 0xffff_ffff;
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
        "d3d12_texture_address_mode" => exec_d3d12_texture_address_mode(input),
        "d3d12_filter_reduction" => exec_d3d12_filter_reduction(input),
        "d3d12_filter_translation" => exec_d3d12_filter_translation(input),
        _ => json!({ "error": format!("unknown_category: {category}") }),
    }
}

/// One-time scratch-directory setup shared by file-based categories and the
/// cwd-dependent path vectors.
fn ensure_scratch_dirs() {
    static SETUP: AtomicBool = AtomicBool::new(false);
    if SETUP.swap(true, Ordering::SeqCst) {
        return;
    }
    for directory in [
        "C:\\Windows\\Temp\\casa1-oracle",
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
                "succeeded": (*context).release_succeeded.load(Ordering::SeqCst),
                "error": (*context).release_error.load(Ordering::SeqCst),
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
        "end_consumed": end != input.as_ptr(),
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
    (0x0000_0081, "D3D12_FILTER_COMPARISON_MIN_MAG_POINT_MIP_LINEAR"),
    (0x0000_0084, "D3D12_FILTER_COMPARISON_MIN_POINT_MAG_LINEAR_MIP_POINT"),
    (0x0000_0085, "D3D12_FILTER_COMPARISON_MIN_POINT_MAG_LINEAR_MIP_LINEAR"),
    (0x0000_0090, "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_MIP_POINT"),
    (0x0000_0091, "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_POINT_MIP_LINEAR"),
    (0x0000_0094, "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_LINEAR_MIP_POINT"),
    (0x0000_0095, "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR"),
    (0x0000_00d5, "D3D12_FILTER_COMPARISON_ANISOTROPIC"),
    (0x0000_0100, "D3D12_FILTER_MINIMUM_MIN_MAG_MIP_POINT"),
    (0x0000_0101, "D3D12_FILTER_MINIMUM_MIN_MAG_POINT_MIP_LINEAR"),
    (0x0000_0104, "D3D12_FILTER_MINIMUM_MIN_POINT_MAG_LINEAR_MIP_POINT"),
    (0x0000_0105, "D3D12_FILTER_MINIMUM_MIN_POINT_MAG_LINEAR_MIP_LINEAR"),
    (0x0000_0110, "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_MIP_POINT"),
    (0x0000_0111, "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_POINT_MIP_LINEAR"),
    (0x0000_0114, "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_POINT"),
    (0x0000_0115, "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR"),
    (0x0000_0155, "D3D12_FILTER_MINIMUM_ANISOTROPIC"),
    (0x0000_0180, "D3D12_FILTER_MAXIMUM_MIN_MAG_MIP_POINT"),
    (0x0000_0181, "D3D12_FILTER_MAXIMUM_MIN_MAG_POINT_MIP_LINEAR"),
    (0x0000_0184, "D3D12_FILTER_MAXIMUM_MIN_POINT_MAG_LINEAR_MIP_POINT"),
    (0x0000_0185, "D3D12_FILTER_MAXIMUM_MIN_POINT_MAG_LINEAR_MIP_LINEAR"),
    (0x0000_0190, "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_MIP_POINT"),
    (0x0000_0191, "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_POINT_MIP_LINEAR"),
    (0x0000_0194, "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_LINEAR_MIP_POINT"),
    (0x0000_0195, "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR"),
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
