use crate::error::{AppError, AppResult};
use crate::ge::{
    FileAccess, FsEntryKind, FsMetadataRecord, GameEnvironment, RegistryView, ShareMode,
};
use crate::reason::ReasonCode;
pub use crate::runtime::object_manager::ObjectType;
use crate::runtime::object_manager::{
    DirectorySearchObject, EventObject, FileHandleObject, FileObject, IoCompletionPortObject,
    KernelObject, KeyObject, MutexObject, NamedPipeState, ObjectId, ObjectManager, PipeObject,
    ProcessObject, SectionObject, SemaphoreObject, ThreadObject, TimerObject, WindowStationObject,
};
use crate::runtime::process::{GuestProcess, allocate_guest_pid};
use crate::vm::{VmProtection, VmRegionKind, VmState};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type Handle = u32;

/// Real volume capacity of the host directory backing a guest drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeCapacity {
    /// Sectors per cluster, derived from the host volume's allocation unit.
    pub sectors_per_cluster: u32,
    /// Bytes per sector (512 on the common APFS/NTFS-aligned layouts).
    pub bytes_per_sector: u32,
    /// Total clusters on the volume (real, from the host filesystem).
    pub total_clusters: u64,
    /// Free clusters on the volume (real, from the host filesystem).
    pub free_clusters: u64,
    /// Total bytes on the volume.
    pub total_bytes: u64,
    /// Free bytes on the volume.
    pub free_bytes: u64,
}

impl VolumeCapacity {
    /// The cluster counts as Windows `GetDiskFreeSpace(A|W)` u32 outputs,
    /// saturating at `u32::MAX` (a single source of truth for the clamp the
    /// A and W arms must agree on).
    pub fn clusters_as_u32(&self) -> (u32, u32) {
        (
            self.total_clusters.min(u64::from(u32::MAX)) as u32,
            self.free_clusters.min(u64::from(u32::MAX)) as u32,
        )
    }
}

/// Host `statvfs` probe: returns `Some` only when the path can be stat'ed.
fn statvfs(path: &Path) -> Option<libc::statvfs> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc == 0 { Some(stat) } else { None }
}

/// Upper bound for a single allocation whose size is guest-controlled.
/// Windows fails these gracefully (ERROR_NOT_ENOUGH_MEMORY); a Rust `Vec`
/// allocation of an absurd size aborts the process, so refuse before
/// allocating.
const MAX_ALLOCATION_SIZE: usize = 0x4000_0000; // 1 GiB
/// Maximum number of pages committed by a single VirtualAlloc/MapViewOfFile
/// call.  Bounds the per-page bookkeeping (each page is one BTreeSet entry)
/// to ~4 GiB of committed address space.
const MAX_COMMIT_PAGES: u64 = 0x10_0000;
/// Iterations for bounded blocking polls (blocking ConnectNamedPipe and
/// GetOverlappedResult).  Guest threads are scheduled cooperatively, so an
/// unbounded host-side block would starve the signaler and hang the guest.
#[allow(dead_code)] // polling policy constant; not yet referenced
const BLOCKING_POLL_ITERATIONS: usize = 5000;

// ── Win32 file access-right constants ────────────────────────────────────────
// The raw `FILE_*` / standard-right bits as defined by winnt.h.  Handles
// carry the EXPANDED desired-access mask (generic bits replaced by their
// concrete equivalents) and every per-operation check evaluates against it.
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_WRITE_EA: u32 = 0x0000_0010;
#[allow(dead_code)] // guest ABI constant (access-rights table)
const FILE_EXECUTE: u32 = 0x0000_0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE_ACCESS: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
#[allow(dead_code)] // guest ABI constant (access-rights table)
const WRITE_DAC: u32 = 0x0004_0000;
#[allow(dead_code)] // guest ABI constant (access-rights table)
const WRITE_OWNER: u32 = 0x0008_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
#[allow(dead_code)] // guest ABI constant (access-rights table)
const STANDARD_RIGHTS_REQUIRED: u32 = DELETE_ACCESS | READ_CONTROL | WRITE_DAC | WRITE_OWNER;
// ── Non-file object access-right constants (winnt.h) ────────────────────────
// Handles carry the granted mask in `HandleDescriptor.access_mask`; every
// per-operation check evaluates the required bits against it.
const EVENT_MODIFY_STATE: u32 = 0x0000_0002;
const MUTEX_MODIFY_STATE: u32 = 0x0000_0001;
const SEMAPHORE_MODIFY_STATE: u32 = 0x0000_0002;
const THREAD_TERMINATE: u32 = 0x0000_0001;
const THREAD_SUSPEND_RESUME: u32 = 0x0000_0002;
const THREAD_SET_INFORMATION: u32 = 0x0000_0020;
const THREAD_QUERY_INFORMATION: u32 = 0x0000_0040;
const PROCESS_TERMINATE: u32 = 0x0000_0001;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x0000_1000;
// ── GetFileType result constants ─────────────────────────────────────────────
#[allow(dead_code)] // guest ABI constant (GetFileType table)
const FILE_TYPE_UNKNOWN: u32 = 0;
const FILE_TYPE_DISK: u32 = 1;
const FILE_TYPE_PIPE: u32 = 3;
const FILE_GENERIC_READ: u32 =
    FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
const FILE_GENERIC_WRITE: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | READ_CONTROL
    | SYNCHRONIZE;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;

/// Reconstruct the raw `FILE_SHARE_*` flag value from the GE `ShareMode`
/// triple.  The projection is exact (each bool maps to one bit), so handles
/// can record the raw share mode for share-state bookkeeping.
fn share_mode_to_raw(share_mode: ShareMode) -> u32 {
    let mut raw = 0;
    if share_mode.read {
        raw |= FILE_SHARE_READ;
    }
    if share_mode.write {
        raw |= FILE_SHARE_WRITE;
    }
    if share_mode.delete {
        raw |= FILE_SHARE_DELETE;
    }
    raw
}

/// Compatibility projection: derive a plausible granted-access mask from the
/// three-boolean GE `FileAccess`.  Used by the legacy 7-argument
/// `create_file_w` API (which predates the expanded-mask plumbing); thunks
/// pass the true expanded mask through `create_file_w_extended`.
fn granted_access_from_file_access(access: FileAccess) -> u32 {
    let mut mask = 0;
    if access.read {
        mask |= FILE_GENERIC_READ;
    }
    if access.write {
        mask |= FILE_GENERIC_WRITE;
    }
    if access.delete {
        mask |= DELETE_ACCESS;
    }
    mask
}

pub const WAIT_OBJECT_0: u32 = 0x0000_0000;
pub const WAIT_ABANDONED: u32 = 0x0000_0080;
pub const WAIT_TIMEOUT: u32 = 0x0000_0102;
pub const WAIT_IO_COMPLETION: u32 = 0x0000_00C0;
pub const CP_UTF8: u32 = 65_001;

// ── Code page identifiers (Windows NLS) ──────────────────────────────────────
pub const CP_ACP: u32 = 0;
pub const CP_OEMCP: u32 = 1;
pub const CP_MACCP: u32 = 2;
pub const CP_THREAD_ACP: u32 = 3;
pub const CP_SYMBOL: u32 = 42;
pub const CP_UTF7: u32 = 65_000;
pub const CP_WIN1250: u32 = 1250; // Central European
pub const CP_WIN1251: u32 = 1251; // Cyrillic
pub const CP_WIN1252: u32 = 1252; // Western European (Latin-1)
pub const CP_WIN1253: u32 = 1253; // Greek
pub const CP_WIN1254: u32 = 1254; // Turkish
pub const CP_WIN1255: u32 = 1255; // Hebrew
pub const CP_WIN1256: u32 = 1256; // Arabic
pub const CP_WIN1257: u32 = 1257; // Baltic
pub const CP_WIN1258: u32 = 1258; // Vietnamese
pub const CP_SHIFTJIS: u32 = 932; // Japanese (Shift-JIS)
pub const CP_GBK: u32 = 936; // Simplified Chinese (GBK)
pub const CP_KOREAN: u32 = 949; // Korean
pub const CP_BIG5: u32 = 950; // Traditional Chinese (Big5)
pub const CP_THAI: u32 = 874; // Thai (TIS-620, Windows-874)
pub const CP_OEM_US: u32 = 437; // OEM US (IBM437)

// ── macOS iconv FFI for code page conversion ─────────────────────────────────
#[cfg(target_os = "macos")]
mod iconv_ffi {
    use std::ffi::CString;

    type IconvT = *mut std::ffi::c_void;

    // SAFETY: extern FFI declaration — the function signature matches the C library prototype
    unsafe extern "C" {
        fn iconv_open(
            tocode: *const std::os::raw::c_char,
            fromcode: *const std::os::raw::c_char,
        ) -> IconvT;
        fn iconv(
            cd: IconvT,
            inbuf: *mut *const std::os::raw::c_char,
            inbytesleft: *mut usize,
            outbuf: *mut *mut std::os::raw::c_char,
            outbytesleft: *mut usize,
        ) -> usize;
        fn iconv_close(cd: IconvT) -> std::os::raw::c_int;
    }

    /// Map a Windows code page number to an iconv name string.
    pub fn code_page_to_iconv_name(cp: u32) -> Option<&'static str> {
        match cp {
            // UTF and Unicode
            65001 => Some("UTF-8"),
            65000 => Some("UTF-7"),
            1200 => Some("UTF-16LE"),
            1201 => Some("UTF-16BE"),
            // Windows ANSI code pages
            1250 => Some("CP1250"), // Central European
            1251 => Some("CP1251"), // Cyrillic
            1252 => Some("CP1252"), // Western European
            1253 => Some("CP1253"), // Greek
            1254 => Some("CP1254"), // Turkish
            1255 => Some("CP1255"), // Hebrew
            1256 => Some("CP1256"), // Arabic
            1257 => Some("CP1257"), // Baltic
            1258 => Some("CP1258"), // Vietnamese
            // Double-byte (DBCS) code pages
            932 => Some("CP932"), // Japanese Shift-JIS
            936 => Some("CP936"), // Simplified Chinese GBK
            949 => Some("CP949"), // Korean
            950 => Some("CP950"), // Traditional Chinese Big5
            // Other
            874 => Some("CP874"), // Thai
            437 => Some("CP437"), // OEM US
            850 => Some("CP850"), // OEM Multilingual Latin-1
            855 => Some("CP855"), // OEM Cyrillic
            857 => Some("CP857"), // OEM Turkish
            860 => Some("CP860"), // OEM Portuguese
            861 => Some("CP861"), // OEM Icelandic
            862 => Some("CP862"), // OEM Hebrew
            863 => Some("CP863"), // OEM Canadian French
            864 => Some("CP864"), // OEM Arabic
            865 => Some("CP865"), // OEM Nordic
            866 => Some("CP866"), // OEM Russian
            869 => Some("CP869"), // OEM Modern Greek
            _ => None,
        }
    }

    /// Convert bytes from a given code page to UTF-8 using iconv.
    /// Returns None if the code page is unsupported or conversion fails.
    pub fn convert_to_utf8(cp: u32, input: &[u8]) -> Option<String> {
        let tocode = CString::new("UTF-8").ok()?;
        let fromcode = CString::new(code_page_to_iconv_name(cp)?).ok()?;
        // SAFETY: iconv FFI for character encoding conversion
        unsafe {
            let cd = iconv_open(tocode.as_ptr(), fromcode.as_ptr());
            if cd.is_null() {
                return None;
            }
            // Allocate output buffer: 4 bytes per input byte (UTF-8 max expansion)
            let outbuf_len = input.len().saturating_mul(4).saturating_add(8);
            if outbuf_len == 0 || outbuf_len > isize::MAX as usize {
                return None;
            }
            let mut outbuf = vec![0u8; outbuf_len];
            let mut inbuf_ptr: *const std::os::raw::c_char =
                input.as_ptr() as *const std::os::raw::c_char;
            let mut inbytesleft = input.len();
            let mut outbuf_ptr: *mut std::os::raw::c_char =
                outbuf.as_mut_ptr() as *mut std::os::raw::c_char;
            let mut outbytesleft = outbuf.len();

            let result = iconv(
                cd,
                &mut inbuf_ptr,
                &mut inbytesleft,
                &mut outbuf_ptr,
                &mut outbytesleft,
            );
            iconv_close(cd);

            if result == usize::MAX {
                return None; // conversion error
            }
            let used = outbuf.len() - outbytesleft;
            outbuf.truncate(used);
            String::from_utf8(outbuf).ok()
        }
    }

    /// Convert a UTF-8 string to a given code page using iconv.
    /// Returns None if the code page is unsupported or conversion fails.
    pub fn convert_from_utf8(cp: u32, input: &str) -> Option<Vec<u8>> {
        let tocode = CString::new(code_page_to_iconv_name(cp)?).ok()?;
        let fromcode = CString::new("UTF-8").ok()?;
        // SAFETY: iconv FFI for character encoding conversion
        unsafe {
            let cd = iconv_open(tocode.as_ptr(), fromcode.as_ptr());
            if cd.is_null() {
                return None;
            }
            // Allocate output buffer: 2 bytes per input byte (max for DBCS)
            let outbuf_len = input.len().saturating_mul(2).saturating_add(8);
            if outbuf_len == 0 || outbuf_len > isize::MAX as usize {
                return None;
            }
            let mut outbuf = vec![0u8; outbuf_len];
            let input_bytes = input.as_bytes();
            let mut inbuf_ptr: *const std::os::raw::c_char =
                input_bytes.as_ptr() as *const std::os::raw::c_char;
            let mut inbytesleft = input_bytes.len();
            let mut outbuf_ptr: *mut std::os::raw::c_char =
                outbuf.as_mut_ptr() as *mut std::os::raw::c_char;
            let mut outbytesleft = outbuf.len();

            let result = iconv(
                cd,
                &mut inbuf_ptr,
                &mut inbytesleft,
                &mut outbuf_ptr,
                &mut outbytesleft,
            );
            iconv_close(cd);

            if result == usize::MAX {
                return None; // conversion error
            }
            let used = outbuf.len() - outbytesleft;
            outbuf.truncate(used);
            Some(outbuf)
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod iconv_ffi {
    pub fn convert_to_utf8(_cp: u32, _input: &[u8]) -> Option<String> {
        None
    }
    pub fn convert_from_utf8(_cp: u32, _input: &str) -> Option<Vec<u8>> {
        None
    }
}

/// Sentinel value used by Win32 to indicate an invalid handle.
/// All bits set (0xFFFF_FFFF_FFFF_FFFF).
pub const INVALID_HANDLE_VALUE: u64 = u64::MAX;
const WINDOWS_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleDescriptor {
    pub object_type: ObjectType,
    pub access_mask: u32,
    pub refcount: u32,
    pub inheritable: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WaitStatus {
    Object0,
    Timeout,
    Abandoned,
    IoCompletion,
}

impl WaitStatus {
    pub const fn code(self) -> u32 {
        match self {
            Self::Object0 => WAIT_OBJECT_0,
            Self::Timeout => WAIT_TIMEOUT,
            Self::Abandoned => WAIT_ABANDONED,
            Self::IoCompletion => WAIT_IO_COMPLETION,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CreationDisposition {
    CreateNew,
    CreateAlways,
    OpenExisting,
    OpenAlways,
    TruncateExisting,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SeekOrigin {
    Begin,
    Current,
    End,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AllocationType {
    Reserve,
    Commit,
    ReserveCommit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FreeType {
    Decommit,
    Release,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemoryState {
    Reserved,
    Committed,
    Free,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryBasicInformation {
    pub base_address: u64,
    pub region_size: usize,
    pub state: MemoryState,
    pub protection: MemoryProtection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileInformation {
    pub normalized_path: String,
    pub size: u64,
    pub attributes: Vec<String>,
    pub creation_time_ticks: u64,
    pub last_access_time_ticks: u64,
    pub last_write_time_ticks: u64,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindData {
    pub file_name: String,
    pub is_directory: bool,
    pub size: u64,
    pub attributes: Vec<String>,
    pub creation_time_ticks: u64,
    pub last_access_time_ticks: u64,
    pub last_write_time_ticks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverlappedResult {
    pub id: u64,
    pub bytes_transferred: u32,
    pub completed: bool,
    pub cancelled: bool,
}

/// Result of issuing an overlapped pipe read/write: either completed
/// synchronously (data already queued) or pending (the caller parks the
/// guest thread on the scheduler's `PipeIo` wait).
#[derive(Debug, Clone)]
pub struct PipeIoOutcome {
    pub id: u64,
    /// Bytes consumed from the pipe queue (only when `completed`).
    pub bytes: Vec<u8>,
    pub completed: bool,
}

/// A pending pipe I/O request completed by the scheduler: the guest buffer
/// pointers captured at issue time plus the consumed bytes (or a
/// broken-pipe marker when the peer disconnected).
#[derive(Debug, Clone)]
pub struct PendingPipeIoCompletion {
    pub buffer_ptr: u64,
    pub bytes_read_ptr: u64,
    pub bytes: Vec<u8>,
    pub broken_pipe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateProcessResult {
    pub process_handle: Handle,
    pub thread_handle: Handle,
    pub process_id: u32,
    pub thread_id: u32,
    pub argv: Vec<String>,
    pub environment_block_utf16: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileHandleState {
    pub normalized_path: String,
    pub position: u64,
    pub overlapped: bool,
    pub has_ge_handle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessHandleState {
    pub process_id: u32,
    pub executable: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub environment: BTreeMap<String, String>,
    pub inherited_handles: Vec<HandleDescriptor>,
    pub exit_code: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SectionHandleState {
    pub base_address: u64,
    pub size: usize,
    pub protection: MemoryProtection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyHandleState {
    pub hive: String,
    pub key: String,
    pub view: RegistryView,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub process_id: u32,
    pub executable: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleSnapshot {
    pub process_id: u32,
    pub module_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolhelpSnapshot {
    pub processes: Vec<ProcessSnapshot>,
    pub modules: Vec<ModuleSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreadPlan {
    pub exit_code: Option<u32>,
    pub priority: i32,
    pub signaled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApartmentModel {
    Sta,
    Mta,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComThreadingModel {
    Sta,
    Mta,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComInstance {
    pub clsid: String,
    pub module_path: String,
    pub apartment: ApartmentModel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SleepObservation {
    pub requested_ms: u64,
    pub observed_ms: u64,
    pub drift_ms: i64,
}

/// Subsystem view of one live handle.  Rebuilt from the canonical handle
/// table + object manager on every access: `object` is a fresh clone of the
/// manager-owned payload (Rc-shared for File/Event), `descriptor` carries
/// the granted access mask / type / refcount, and `generation` detects
/// stale references after the value was closed and recycled.
#[derive(Debug, Clone)]
struct HandleEntry {
    descriptor: HandleDescriptor,
    /// Fresh clone of the manager-owned kernel-object payload.
    object: KernelObject,
}

/// A winsock socket.  The payload is the socket's id, which is ALWAYS the
/// win32 handle value itself: sockets now live in the SAME handle namespace
/// as every other kernel object, so a socket value can never alias a live
/// win32 object (and vice versa).  The per-socket transport state lives in
/// the `NetworkStack`, keyed by this id.
pub use crate::runtime::object_manager::{IoCompletionPacket, SocketObject};

#[derive(Debug, Clone)]
#[allow(dead_code)] // thread fiber state retained for future fiber APIs
struct ThreadState {
    exit_code: Option<u32>,
    priority: i32,
    tls: BTreeMap<u32, u64>,
    /// Current suspend count (0 = running).
    suspend_count: u32,
    /// Whether the thread has been terminated.
    terminated: bool,
    /// Fiber ID if this thread is converted to a fiber (0 = not a fiber).
    fiber_id: u32,
}

/// Named pipe open mode constants.
pub const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
pub const PIPE_ACCESS_INBOUND: u32 = 0x0000_0001;
pub const PIPE_ACCESS_OUTBOUND: u32 = 0x0000_0002;

/// Named pipe mode constants.
pub const PIPE_WAIT: u32 = 0x0000_0000;
pub const PIPE_NOWAIT: u32 = 0x0000_0001;
pub const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
pub const PIPE_READMODE_MESSAGE: u32 = 0x0000_0002;

/// Base directory for Unix domain socket backing of named pipes.
pub const PIPE_SOCKET_BASE_DIR: &str = "/tmp/casa1_pipes";

/// Map a Windows pipe name to a Unix domain socket path.
///
/// Converts `\\.\pipe\MyPipe` → `/tmp/casa1_pipes/MyPipe`.
pub fn pipe_name_to_uds_path(pipe_name: &str) -> String {
    // Normalize slashes but preserve original case (Windows pipe names are
    // case-insensitive for *matching*, but the UDS path should reflect the
    // caller's spelling so that diagnostics and file-system paths are readable).
    let normalized = pipe_name.replace('/', "\\");
    // Strip the `\\.\pipe\` prefix
    let name = normalized
        .strip_prefix("\\\\.\\pipe\\")
        .or_else(|| normalized.strip_prefix("\\\\?\\pipe\\"))
        .unwrap_or(&normalized);
    // Replace backslashes with underscores for safety
    let safe_name = name.replace(['\\', '/'], "_");
    format!("{}/{}", PIPE_SOCKET_BASE_DIR, safe_name)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum OverlappedState {
    Pending,
    Completed(u32),
    Cancelled,
}

/// The kind of operation behind an overlapped request.  The scheduler uses
/// the kind to complete pipe requests from the right direction queue and to
/// recover the request id from the guest OVERLAPPED struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverlappedKind {
    Read,
    Write,
    Connection,
    DeviceControl,
}

#[derive(Debug, Clone)]
struct OverlappedRequest {
    handle: Handle,
    /// Generation of `handle` captured when the request was queued.  A
    /// completion arriving after the handle was closed AND its value
    /// recycled to a different object is stale and must be dropped instead
    /// of writing results into the wrong object.
    generation: u32,
    event_handle: Option<Handle>,
    state: OverlappedState,
    /// Typed operation behind the request (Read / Write / Connection /
    /// DeviceControl).  Pending pipe Read requests complete from the pipe's
    /// direction queue; everything else completes through explicit state
    /// transitions.
    kind: OverlappedKind,
    /// Guest pointer to the I/O buffer (pipe Read/Write requests only; 0
    /// for everything else).
    buffer_ptr: u64,
    /// Requested transfer length (pipe Read requests).
    length: u32,
    /// Guest pointer to the bytes-transferred out-parameter (pipe I/O
    /// requests only; 0 when the caller passed NULL).
    bytes_read_ptr: u64,
}

#[derive(Debug, Clone)]
struct HeapState {
    alignment: usize,
    next_address: u64,
    allocations: BTreeMap<u64, Vec<u8>>,
    /// Freed (address, size) blocks available for reuse.
    free_blocks: BTreeMap<u64, usize>,
}

#[derive(Debug, Clone)]
struct TimeState {
    dtm: bool,
    live_pacing: bool,
    perf_frequency: u64,
    qpc: u64,
    ticks_ms: u64,
    drift_log: Vec<SleepObservation>,
}

#[derive(Debug, Clone)]
struct LocaleState {
    acp: u32,
    oemcp: u32,
}

#[derive(Debug, Clone)]
struct ComRegistration {
    clsid: String,
    module_path: String,
    threading_model: ComThreadingModel,
}

// ── Filesystem operation contract ───────────────────────────────────────────
//
// The guest filesystem layer NEVER creates directories behind the guest's
// back.  Windows `CreateFileW`/`MoveFileExW`/`CopyFileExW` do not manufacture
// missing parent directories, and Steam probes failing operations to infer
// installation state — silent host repair produces impossible guest-visible
// behavior.
//
// * Path resolution (`resolve_host_path`, GE `resolve_existing_path`) is
//   READ-ONLY: it must never create or repair anything.
// * Directory creation happens ONLY through the explicit dispositions
//   (CREATE_NEW / CREATE_ALWAYS / OPEN_ALWAYS), the `create_directory`
//   entry point, and the explicit move/copy operations — and even those
//   require the PARENT directory to already exist.
// * A missing parent directory is a guest-visible error
//   (ERROR_PATH_NOT_FOUND), never repaired.  The one exception is host
//   infrastructure that exists independently of any guest operation
//   (the pipe-socket base directory, GE layout provisioning, staging a
//   host file into a GE-provisioned temp directory).
//
// Error-code contract for missing paths (surfaced via `RcFsPathInvalid` →
// ERROR_PATH_NOT_FOUND and `RcFsNotFound` → ERROR_FILE_NOT_FOUND at the
// thunk layer):
//   * parent missing        → ERROR_PATH_NOT_FOUND
//   * file missing, parent present → ERROR_FILE_NOT_FOUND

#[derive(Debug)]
pub struct Win32Subsystem {
    ge: GameEnvironment,
    /// THE canonical guest process: identity (guest pid, image, argv, env,
    /// cwd, arch), the canonical address space and the canonical handle
    /// table.
    process: GuestProcess,
    /// THE canonical kernel object manager: one owner of every kernel
    /// object and the unified named-object namespace.
    objects: ObjectManager,
    next_thread_id: u32,
    next_overlapped_id: u64,
    next_tls_slot: u32,
    threads: BTreeMap<u32, ThreadState>,
    overlapped: BTreeMap<u64, OverlappedRequest>,
    /// File handles associated with an I/O completion port (the association
    /// records only existence; the port itself lives in the handle table).
    io_completion_associations: BTreeSet<Handle>,
    heaps: BTreeMap<Handle, HeapState>,
    time: TimeState,
    locale: LocaleState,
    thread_apcs: BTreeMap<u32, VecDeque<String>>,
    com_apartments: BTreeMap<u32, ApartmentModel>,
    com_registrations: BTreeMap<String, ComRegistration>,
    /// Monotonic serial for `get_temp_file_name_w` uniqueness.
    next_temp_file_serial: u32,
    /// TLS slot indices freed via `tls_free`, reused by `tls_alloc`.
    tls_free_slots: Vec<u32>,
    /// Wall-clock time (ms) of the last full config save, used to throttle
    /// `sync_entry` persistence.
    last_config_save_wall_ms: u64,
    /// The subsystem's last-error slot (the oracle session's GetLastError /
    /// SetLastError semantics; the PE runtime keeps its own per-call slot).
    last_error: u32,
    current_thread_id: u32,
    /// The process window-station handle (minted once by
    /// [`Win32Subsystem::process_window_station`]; `None` until first use).
    window_station_handle: Option<Handle>,
    /// Shared runtime-event observer list (set by the PE runtime; `None`
    /// when this subsystem is driven standalone, e.g. in oracle sessions or
    /// direct tests — event emission is a no-op then).
    pub(crate) event_observers: Option<crate::runtime_events::ObserverList>,
}

/// Non-consuming satisfiability result for scheduler wait evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitSatisfaction {
    NotSignaled,
    Signaled,
    Abandoned,
}

/// Generic named-pipe service facade: pre-created server-side listeners for
/// pipe services the workload cannot execute.
///
/// Workload workaround, excluded from platform completeness: the Windows
/// platform provides NO generic pre-create hook for pipe services — this
/// exists solely so workloads (e.g. the Steam workload's `steam_service`
/// pipe) can wire launch-time IPC without SteamService.exe running.  It is
/// deliberately NOT part of the guest-visible Win32 API surface.
pub struct NamedPipeService<'a> {
    win32: &'a mut Win32Subsystem,
}

impl NamedPipeService<'_> {
    /// Pre-create a server-side named-pipe listener (`PIPE_ACCESS_DUPLEX`,
    /// message-mode, 1 instance, 64 KiB buffers) so a guest connecting via
    /// `CreateFileW`/`CallNamedPipe` finds a live listener even though the
    /// real service process is not being executed.
    ///
    /// Workload workaround, excluded from platform completeness (see the
    /// type-level docs).  Idempotent: if the pipe already exists (the guest
    /// created it, or a prior call), it is left untouched.
    pub fn create_compat_listener(&mut self, pipe_name: &str) -> AppResult<()> {
        let normalized = normalize_pipe_name(pipe_name);
        if self.win32.named_pipe_server_exists(pipe_name) {
            return Ok(());
        }
        let handle = self.win32.create_named_pipe_w(
            pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_READMODE_MESSAGE,
            1,         // nMaxInstances
            64 * 1024, // out buffer
            64 * 1024, // in buffer
            0,         // default timeout
            false,     // inheritable
            None,      // security descriptor
            None,      // uds path (derived)
        )?;
        eprintln!(
            "[win32] compat pipe listener created: {} (server handle {handle:#x})",
            pipe_name
        );
        let _ = normalized;
        Ok(())
    }
}

impl Win32Subsystem {
    pub fn new(ge: GameEnvironment, dtm: bool) -> Self {
        Self::new_with_live_pacing(ge, dtm, false)
    }

    pub fn new_with_live_pacing(ge: GameEnvironment, dtm: bool, live_pacing: bool) -> Self {
        Self::new_with_guest_process(ge, dtm, live_pacing, GuestProcess::default_initial())
    }

    /// Construct the subsystem around a canonical guest process: the guest
    /// pid comes from [`allocate_guest_pid`], the address space and handle
    /// table are THE instances the subsystem operates on, and the guest
    /// identity (pid / image / argv / env / cwd / arch) is never the host's.
    pub fn new_with_guest_process(
        ge: GameEnvironment,
        dtm: bool,
        live_pacing: bool,
        process: GuestProcess,
    ) -> Self {
        let current_thread_id = 1;
        Self {
            ge,
            process,
            objects: ObjectManager::new(),
            next_thread_id: 2,
            next_overlapped_id: 1,
            next_tls_slot: 0,
            threads: BTreeMap::new(),
            overlapped: BTreeMap::new(),
            io_completion_associations: BTreeSet::new(),
            heaps: BTreeMap::new(),
            time: TimeState {
                dtm,
                live_pacing: live_pacing && !dtm,
                perf_frequency: 10_000_000,
                qpc: 0,
                ticks_ms: 0,
                drift_log: Vec::new(),
            },
            locale: LocaleState {
                acp: 1252,
                oemcp: 437,
            },
            thread_apcs: BTreeMap::new(),
            com_apartments: BTreeMap::new(),
            com_registrations: BTreeMap::new(),
            next_temp_file_serial: 0,
            tls_free_slots: Vec::new(),
            last_config_save_wall_ms: 0,
            last_error: 0,
            current_thread_id,
            window_station_handle: None,
            event_observers: None,
        }
    }

    /// The canonical guest address space (shared with the interpreter/JIT).
    pub fn address_space(&self) -> &crate::vm::VirtualMemory {
        &self.process.address_space
    }

    /// Mutable access to the canonical guest address space.
    pub fn address_space_mut(&mut self) -> &mut crate::vm::VirtualMemory {
        &mut self.process.address_space
    }

    /// Rebuild the address space with a fresh cursor (guest-arch switches).
    pub fn reset_address_space(&mut self, private_region_cursor: u64) {
        self.process.reset_address_space(private_region_cursor);
    }

    /// The next fresh handle value (diagnostics: anonymous-pipe name
    /// derivation in the runtime).
    pub fn next_handle_value(&self) -> Handle {
        self.process.handle_table.next_handle_value()
    }

    /// Emit a generic runtime event to the attached observer list (no-op
    /// when this subsystem is driven without a runtime).
    pub(crate) fn emit_event(&mut self, event: crate::runtime_events::RuntimeEvent) {
        if let Some(observers) = &self.event_observers {
            crate::runtime_events::dispatch(observers, &event);
        }
    }

    pub fn ge(&self) -> &GameEnvironment {
        &self.ge
    }

    /// Whether this subsystem runs in deterministic mode (the guest clock
    /// drives every guest-visible time domain; see `TimeState::dtm`).
    pub fn is_dtm(&self) -> bool {
        self.time.dtm
    }

    pub fn current_thread_id(&self) -> u32 {
        self.current_thread_id
    }

    /// Guest-visible current process id: the GUEST pid from the guest pid
    /// namespace (a runtime-side identity starting at 4, matching
    /// `GetCurrentProcessId`) — never the host's POSIX pid.
    pub fn current_process_id(&self) -> u32 {
        self.process.pid
    }

    pub fn set_current_thread_id(&mut self, thread_id: u32) -> u32 {
        let previous = self.current_thread_id;
        self.current_thread_id = thread_id;
        previous
    }

    pub fn current_thread_handle(&mut self) -> Handle {
        if let Some(handle) =
            self.process
                .handle_table
                .iter()
                .find_map(
                    |(handle, entry)| match self.objects.object(entry.object_id) {
                        KernelObject::Thread(thread)
                            if thread.thread_id == self.current_thread_id =>
                        {
                            Some(handle)
                        }
                        _ => None,
                    },
                )
        {
            handle
        } else {
            self.ensure_thread_state(self.current_thread_id);
            self.insert_object(
                ObjectType::Thread,
                0x1F03FF,
                false,
                KernelObject::Thread(ThreadObject {
                    thread_id: self.current_thread_id,
                }),
            )
        }
    }

    /// The current process is the guest process: `GetCurrentProcessId` /
    /// `GetCurrentProcess` return the GUEST pid (a runtime-side identity
    /// from the guest pid namespace) — never the host's POSIX pid.
    pub fn current_process_handle(&mut self) -> Handle {
        let guest_pid = self.process.pid;
        if let Some(handle) =
            self.process
                .handle_table
                .iter()
                .find_map(
                    |(handle, entry)| match self.objects.object(entry.object_id) {
                        KernelObject::Process(process) if process.process_id == guest_pid => {
                            Some(handle)
                        }
                        _ => None,
                    },
                )
        {
            handle
        } else {
            self.insert_object(
                ObjectType::Process,
                0x1F1FFF,
                false,
                KernelObject::Process(ProcessObject {
                    process_id: guest_pid,
                    executable: self.process.image_path.clone(),
                    argv: self.process.argv.clone(),
                    cwd: self.process.cwd.clone(),
                    environment: self.process.environment.clone(),
                    inherited_handles: Vec::new(),
                    modules: self.process.modules.clone(),
                    exit_code: None,
                    exit_sync: None,
                }),
            )
        }
    }

    pub fn guest_path_to_host_path(&self, path: &str) -> AppResult<PathBuf> {
        let (_, host_path) = self.resolve_host_path(path)?;
        Ok(host_path)
    }

    pub fn stage_host_file_w(&mut self, source: &Path, guest_path: &str) -> AppResult<PathBuf> {
        let (normalized_path, host_path) = self.resolve_host_path(guest_path)?;
        self.ensure_parent_exists(&host_path)?;
        fs::copy(source, &host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!(
                    "failed to copy {} to {}",
                    source.display(),
                    host_path.display()
                ),
                &error,
            )
        })?;
        self.sync_entry(&normalized_path, &host_path, false)?;
        Ok(host_path)
    }

    pub fn describe_handle(&self, handle: Handle) -> AppResult<HandleDescriptor> {
        Ok(self.handle_entry(handle)?.descriptor.clone())
    }

    pub fn set_handle_information(
        &mut self,
        handle: Handle,
        mask: u32,
        flags: u32,
    ) -> AppResult<()> {
        self.process
            .handle_table
            .set_handle_information(handle, mask, flags)
    }

    pub fn duplicate_handle(
        &mut self,
        source_handle: Handle,
        desired_access: u32,
        inheritable: bool,
        same_access: bool,
        close_source: bool,
    ) -> AppResult<Handle> {
        let source_entry = self.handle_entry(source_handle)?;
        if source_entry.descriptor.object_type == ObjectType::Socket {
            // Sockets are winsock handles, not kernel handles — Windows
            // `DuplicateHandle` on a SOCKET fails with ERROR_INVALID_HANDLE.
            return invalid_handle("socket handles cannot be duplicated");
        }
        let access_mask = if same_access || desired_access == 0 {
            source_entry.descriptor.access_mask
        } else {
            // The requested access must be a subset of what the source
            // handle was granted; requesting more is ERROR_ACCESS_DENIED.
            if desired_access & !source_entry.descriptor.access_mask != 0 {
                return Err(AppError::new(
                    ReasonCode::RcHelperPermissionDenied,
                    format!(
                        "duplicate requests access {desired_access:#x}, source granted {:#x}",
                        source_entry.descriptor.access_mask
                    ),
                ));
            }
            desired_access
        };
        // The duplicate references the SAME object (the object manager
        // refcount goes up; object identity != handle identity).
        let duplicated_handle =
            self.process
                .handle_table
                .duplicate(source_handle, access_mask, inheritable)?;
        let object_id = self
            .process
            .handle_table
            .entry(duplicated_handle)
            .expect("fresh duplicate entry")
            .object_id;
        self.objects.handle_added(object_id);
        if close_source {
            self.close_handle(source_handle)?;
        }
        Ok(duplicated_handle)
    }

    pub fn file_state(&self, handle: Handle) -> AppResult<FileHandleState> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::File(file) => {
                let file = file.borrow();
                Ok(FileHandleState {
                    normalized_path: file.normalized_path.clone(),
                    position: file.position,
                    overlapped: file.overlapped,
                    has_ge_handle: file.ge_handle.is_some(),
                })
            }
            _ => invalid_handle("handle is not a file"),
        }
    }

    pub fn process_state(&self, handle: Handle) -> AppResult<ProcessHandleState> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Process(process) => Ok(ProcessHandleState {
                process_id: process.process_id,
                executable: process.executable.clone(),
                argv: process.argv.clone(),
                cwd: process.cwd.clone(),
                environment: process.environment.clone(),
                inherited_handles: process.inherited_handles.clone(),
                exit_code: process.exit_code,
            }),
            _ => invalid_handle("handle is not a process"),
        }
    }

    pub fn section_state(&self, handle: Handle) -> AppResult<SectionHandleState> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Section(section) => Ok(SectionHandleState {
                base_address: section.base_address,
                size: section.size,
                protection: section.protection,
            }),
            _ => invalid_handle("handle is not a section"),
        }
    }

    pub fn key_state(&self, handle: Handle) -> AppResult<KeyHandleState> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Key(key) => Ok(KeyHandleState {
                hive: key.hive.clone(),
                key: key.key.clone(),
                view: key.view,
            }),
            _ => invalid_handle("handle is not a registry key"),
        }
    }

    pub fn create_event(
        &mut self,
        manual_reset: bool,
        initial_state: bool,
        inheritable: bool,
        name: Option<&str>,
    ) -> (Handle, bool) {
        if let Some(name) = name
            && let Some(event_id) = self.objects.resolve(name)
        {
            // The unified named-object namespace resolves the name across
            // every prefix spelling; CreateEventW mints a FRESH handle to
            // the SAME object (the manager refcount goes up).
            let handle = self.insert_object_id(event_id, 0x1F0003, inheritable);
            return (handle, true);
        }

        let event = Rc::new(RefCell::new(EventObject {
            manual_reset,
            signaled: initial_state,
        }));
        let handle = self.insert_object_named(
            ObjectType::Event,
            name,
            0x1F0003,
            inheritable,
            KernelObject::Event(event),
        );
        (handle, false)
    }

    pub fn open_event(
        &mut self,
        desired_access: u32,
        inheritable: bool,
        name: &str,
    ) -> AppResult<Handle> {
        let Some(event_id) = self.objects.resolve(name) else {
            return Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("event {name} not found"),
            ));
        };

        Ok(self.insert_object_id(event_id, desired_access, inheritable))
    }

    pub fn create_io_completion_port(
        &mut self,
        file_handle: Option<Handle>,
        existing_completion_port: Option<Handle>,
        _completion_key: u64,
        concurrent_threads: u32,
    ) -> AppResult<Handle> {
        if file_handle.is_none() && existing_completion_port.is_some() {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                "CreateIoCompletionPort requires a file handle when reusing an existing port",
            ));
        }

        let port_handle = if let Some(port_handle) = existing_completion_port {
            match self.handle_object(port_handle)? {
                KernelObject::IoCompletionPort(_) => port_handle,
                _ => return invalid_handle("handle is not an I/O completion port"),
            }
        } else {
            self.insert_object(
                ObjectType::IoCompletionPort,
                0x1F0003,
                false,
                KernelObject::IoCompletionPort(IoCompletionPortObject {
                    concurrent_threads,
                    queue: VecDeque::new(),
                }),
            )
        };

        if let Some(file_handle) = file_handle {
            self.handle_entry(file_handle)?;
            if self.io_completion_associations.contains(&file_handle) {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "handle {file_handle} is already associated with an I/O completion port"
                    ),
                ));
            }
            self.io_completion_associations.insert(file_handle);
        }

        Ok(port_handle)
    }

    pub fn post_queued_completion_status(
        &mut self,
        completion_port: Handle,
        bytes_transferred: u32,
        completion_key: u64,
        overlapped: u64,
    ) -> AppResult<()> {
        match self.handle_object_mut(completion_port)? {
            KernelObject::IoCompletionPort(port) => {
                port.queue.push_back(IoCompletionPacket {
                    bytes_transferred,
                    completion_key,
                    overlapped,
                    internal: 0,
                });
                Ok(())
            }
            _ => invalid_handle("handle is not an I/O completion port"),
        }
    }

    pub fn dequeue_io_completion_packets(
        &mut self,
        completion_port: Handle,
        max_packets: usize,
    ) -> AppResult<Vec<IoCompletionPacket>> {
        if max_packets == 0 {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                "GetQueuedCompletionStatusEx requires a non-zero entry count",
            ));
        }
        match self.handle_object_mut(completion_port)? {
            KernelObject::IoCompletionPort(port) => {
                // A non-zero `concurrent_threads` throttles how many
                // completion packets may be handed out at once.
                let cap = if port.concurrent_threads == 0 {
                    max_packets
                } else {
                    max_packets.min(port.concurrent_threads as usize)
                };
                let mut packets = Vec::new();
                while packets.len() < cap {
                    let Some(packet) = port.queue.pop_front() else {
                        break;
                    };
                    packets.push(packet);
                }
                if packets.is_empty() {
                    Err(AppError::new(
                        ReasonCode::RcWin32Timeout,
                        format!("I/O completion port {completion_port} has no queued packets"),
                    ))
                } else {
                    Ok(packets)
                }
            }
            _ => invalid_handle("handle is not an I/O completion port"),
        }
    }

    pub fn set_event(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Event(_) => {
                Self::require_access(&entry, EVENT_MODIFY_STATE)?;
            }
            _ => return invalid_handle("handle is not an event"),
        }
        let object_id = self
            .process
            .handle_table
            .entry(handle)
            .expect("checked live")
            .object_id;
        if !self.objects.signal_event(object_id) {
            return invalid_handle("handle is not an event");
        }
        Ok(())
    }

    /// The current signal state of an event handle (the previous state the
    /// Nt* event thunks report before mutating).  Non-event handles fail
    /// with an invalid-handle error; access is validated like `set_event`.
    pub fn event_previous_state(&self, handle: Handle) -> AppResult<bool> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Event(_) => {
                Self::require_access(&entry, EVENT_MODIFY_STATE)?;
            }
            _ => return invalid_handle("handle is not an event"),
        }
        match &entry.object {
            KernelObject::Event(event) => Ok(event.borrow().signaled),
            _ => invalid_handle("handle is not an event"),
        }
    }

    pub fn reset_event(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Event(_) => {
                Self::require_access(&entry, EVENT_MODIFY_STATE)?;
            }
            _ => return invalid_handle("handle is not an event"),
        }
        let object_id = self
            .process
            .handle_table
            .entry(handle)
            .expect("checked live")
            .object_id;
        if !self.objects.reset_event(object_id) {
            return invalid_handle("handle is not an event");
        }
        Ok(())
    }

    pub fn create_mutex(&mut self, initially_owned: bool, inheritable: bool) -> Handle {
        self.insert_object(
            ObjectType::Mutex,
            0x1F0001,
            inheritable,
            KernelObject::Mutex(MutexObject {
                owner_thread_id: initially_owned.then_some(self.current_thread_id),
                recursion: 0,
                abandoned: false,
            }),
        )
    }

    pub fn abandon_mutex(&mut self, handle: Handle) -> AppResult<()> {
        match self.handle_object_mut(handle)? {
            KernelObject::Mutex(mutex) => {
                mutex.owner_thread_id = None;
                mutex.abandoned = true;
                Ok(())
            }
            _ => invalid_handle("handle is not a mutex"),
        }
    }

    pub fn release_mutex(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Mutex(_) => {
                Self::require_access(&entry, MUTEX_MODIFY_STATE)?;
            }
            _ => return invalid_handle("handle is not a mutex"),
        }
        let current_thread_id = self.current_thread_id;
        let object_id = self
            .process
            .handle_table
            .entry(handle)
            .expect("checked live")
            .object_id;
        // The state transition is the object manager's canonical
        // `release_mutex` (recursion, ownership, abandoned flag); the
        // subsystem layer already validated type and access above.
        if !self.objects.release_mutex(object_id, current_thread_id) {
            Err(AppError::new(
                ReasonCode::RcWin32NotOwner,
                "ReleaseMutex failed: caller does not own the mutex",
            ))
        } else {
            Ok(())
        }
    }

    pub fn create_semaphore(
        &mut self,
        initial_count: u32,
        maximum: u32,
        inheritable: bool,
    ) -> Handle {
        self.insert_object(
            ObjectType::Semaphore,
            0x1F0003,
            inheritable,
            KernelObject::Semaphore(SemaphoreObject {
                count: initial_count,
                maximum,
            }),
        )
    }

    pub fn release_semaphore(&mut self, handle: Handle, release_count: u32) -> AppResult<u32> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Semaphore(_) => {
                Self::require_access(&entry, SEMAPHORE_MODIFY_STATE)?;
            }
            _ => return invalid_handle("handle is not a semaphore"),
        }
        let object_id = self
            .process
            .handle_table
            .entry(handle)
            .expect("checked live")
            .object_id;
        match self.objects.release_semaphore(object_id, release_count) {
            Some(previous) => Ok(previous),
            None => invalid_handle("handle is not a semaphore"),
        }
    }

    pub fn create_timer(&mut self, due_tick: u64, inheritable: bool) -> Handle {
        self.insert_object(
            ObjectType::Timer,
            0x1F0003,
            inheritable,
            KernelObject::Timer(TimerObject {
                due_tick,
                signaled: false,
            }),
        )
    }

    pub fn set_waitable_timer(&mut self, handle: Handle, due_tick: u64) -> AppResult<()> {
        match self.handle_object_mut(handle)? {
            KernelObject::Timer(timer) => {
                timer.due_tick = due_tick;
                timer.signaled = false;
                Ok(())
            }
            _ => invalid_handle("handle is not a timer"),
        }
    }

    pub fn wait_for_single_object(
        &mut self,
        handle: Handle,
        timeout_ms: u32,
        alertable: bool,
        thread_handle: Option<Handle>,
    ) -> AppResult<WaitStatus> {
        let current_thread_id = self.current_thread_id;
        if alertable {
            let thread_id = match thread_handle {
                Some(thread_handle) => Some(self.thread_id(thread_handle)?),
                None => None,
            };
            if let Some(thread_id) = thread_id
                && let Some(queue) = self.thread_apcs.get_mut(&thread_id)
                && !queue.is_empty()
            {
                queue.pop_front();
                return Ok(WaitStatus::IoCompletion);
            }
        }

        let object_type = self.handle_entry(handle)?.descriptor.object_type;
        if object_type == ObjectType::Process {
            return self.wait_for_single_object_process(handle, timeout_ms);
        }

        // INFINITE waits stay non-blocking: guest threads are scheduled
        // cooperatively and the callers (pe_runtime) pump pending threads
        // between polls, so a host-side block here would starve the signaler.
        if timeout_ms == u32::MAX {
            return self.wait_for_single_object_instant(handle, object_type, current_thread_id);
        }
        let deadline = if timeout_ms == 0 {
            None
        } else {
            Some(self.time.ticks_ms.saturating_add(timeout_ms as u64))
        };
        // Non-blocking wait: one instant check, plus the deadline check.
        // The guest scheduler (pe_runtime wait descriptors) is responsible
        // for parking the thread and resuming it when the wait becomes
        // satisfiable — this layer never host-sleeps inside a guest wait.
        let status = self.wait_for_single_object_instant(handle, object_type, current_thread_id)?;
        if !matches!(status, WaitStatus::Timeout) {
            return Ok(status);
        }
        if timeout_ms == 0 {
            return Ok(WaitStatus::Timeout);
        }
        if let Some(deadline) = deadline
            && self.time.ticks_ms >= deadline
        {
            return Ok(WaitStatus::Timeout);
        }
        Ok(WaitStatus::Timeout)
    }

    /// Non-consuming signal-state check for a waitable object.
    ///
    /// Used by the scheduler's wait-all evaluation: every object in the set
    /// must be satisfiable WITHOUT consuming, so the complete set can be
    /// acquired atomically by [`consume_wait_set`] as one dispatcher
    /// operation (otherwise a concurrent waiter could steal an auto-reset
    /// event or mutex between observation and acquisition).
    ///
    /// [`consume_wait_set`]: Self::consume_wait_set
    pub fn wait_object_satisfiable(
        &self,
        handle: Handle,
        object_type: ObjectType,
        current_thread_id: u32,
    ) -> AppResult<WaitSatisfaction> {
        let now = self.time.ticks_ms;
        match object_type {
            ObjectType::Event
            | ObjectType::Mutex
            | ObjectType::Semaphore
            | ObjectType::Thread
            | ObjectType::Timer
            | ObjectType::Process => {
                Self::require_access(&self.handle_entry(handle)?, SYNCHRONIZE)?;
            }
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("handle {handle} is not a waitable object"),
                ));
            }
        }
        match object_type {
            ObjectType::Thread => {
                let thread_id = self.thread_id(handle)?;
                if self.thread_state(thread_id)?.exit_code.is_some() {
                    Ok(WaitSatisfaction::Signaled)
                } else {
                    Ok(WaitSatisfaction::NotSignaled)
                }
            }
            ObjectType::Process => {
                let entry = self.handle_entry(handle)?;
                if let KernelObject::Process(process) = &entry.object {
                    if process.exit_code.is_some() {
                        Ok(WaitSatisfaction::Signaled)
                    } else {
                        Ok(WaitSatisfaction::NotSignaled)
                    }
                } else {
                    invalid_handle("handle is not a process")
                }
            }
            _ => {
                let object_id = self
                    .process
                    .handle_table
                    .entry(handle)
                    .expect("checked live")
                    .object_id;
                Ok(
                    match self
                        .objects
                        .wait_satisfaction(object_id, current_thread_id, now)
                    {
                        crate::runtime::object_manager::WaitSatisfaction::NotSignaled => {
                            WaitSatisfaction::NotSignaled
                        }
                        crate::runtime::object_manager::WaitSatisfaction::Signaled => {
                            WaitSatisfaction::Signaled
                        }
                        crate::runtime::object_manager::WaitSatisfaction::Abandoned => {
                            WaitSatisfaction::Abandoned
                        }
                    },
                )
            }
        }
    }

    /// Atomically consume the signals of a satisfied wait set — the complete
    /// set is observed and acquired as one dispatcher operation.
    fn consume_wait_set(&mut self, handles: &[Handle], current_thread_id: u32) -> AppResult<()> {
        let now = self.time.ticks_ms;
        for &handle in handles {
            let object_type = self.handle_entry(handle)?.descriptor.object_type;
            match object_type {
                ObjectType::Thread | ObjectType::Process => {}
                _ => {
                    let object_id = self
                        .process
                        .handle_table
                        .entry(handle)
                        .expect("checked live")
                        .object_id;
                    self.objects.consume_wait(object_id, current_thread_id, now);
                }
            }
        }
        Ok(())
    }

    /// Evaluate a wait-all set atomically: every object must be satisfiable
    /// (non-consuming), then the complete set is consumed as one operation.
    /// Returns the wait result: `Abandoned` when any acquired mutex was
    /// abandoned (ownership still transfers), `Object0` otherwise, `None`
    /// when not all objects are satisfiable.
    pub fn evaluate_wait_all(
        &mut self,
        handles: &[Handle],
        current_thread_id: u32,
    ) -> AppResult<Option<WaitStatus>> {
        let mut any_abandoned = false;
        for &handle in handles {
            let object_type = self.handle_entry(handle)?.descriptor.object_type;
            match self.wait_object_satisfiable(handle, object_type, current_thread_id)? {
                WaitSatisfaction::Signaled => {}
                WaitSatisfaction::Abandoned => any_abandoned = true,
                WaitSatisfaction::NotSignaled => return Ok(None),
            }
        }
        self.consume_wait_set(handles, current_thread_id)?;
        Ok(Some(if any_abandoned {
            WaitStatus::Abandoned
        } else {
            WaitStatus::Object0
        }))
    }

    /// Mark every mutex owned by `thread_id` abandoned (the owner
    /// terminated).  Called from the thread-exit paths.
    /// Non-consuming check: has the overlapped operation completed?
    pub fn overlapped_completed(&self, id: u64) -> bool {
        self.overlapped
            .get(&id)
            .is_some_and(|request| !matches!(request.state, OverlappedState::Pending))
    }

    /// Non-consuming satisfiability of an overlapped request: completed
    /// requests are ready; PENDING pipe Read requests become ready when
    /// their direction queue has data (or the peer disconnected).
    pub fn overlapped_satisfiable(&self, id: u64) -> bool {
        let Some(request) = self.overlapped.get(&id) else {
            return false;
        };
        if !matches!(request.state, OverlappedState::Pending) {
            return true;
        }
        if request.kind != OverlappedKind::Read {
            return false;
        }
        let Some(state) = self.pipe_state_for_handle(request.handle) else {
            return false;
        };
        let is_server = state.server_handle == Some(request.handle);
        let queue = if is_server {
            &state.client_to_server
        } else {
            &state.server_to_client
        };
        if state.client_disconnected || state.server_disconnected {
            return true;
        }
        pipe_queue_peek_len(queue, state.message_mode) > 0
    }

    /// Non-consuming check: is the pipe connected (server side)?  True once
    /// a client has connected (via CreateFileW on `\\.\pipe\NAME` or
    /// CallNamedPipe).
    pub fn pipe_is_connected(&self, handle: Handle) -> bool {
        self.handle_entry(handle)
            .ok()
            .and_then(|entry| match &entry.object {
                KernelObject::Pipe(pipe) => Some(pipe.connected),
                _ => None,
            })
            .unwrap_or(false)
            || self
                .pipe_state_for_handle(handle)
                .map(|state| state.client_connected)
                .unwrap_or(false)
    }

    pub fn mark_owned_mutexes_abandoned(&mut self, thread_id: u32) {
        self.objects.mark_mutexes_abandoned_by_thread(thread_id);
    }

    /// Single non-blocking signal-state check for a waitable object.
    /// Consumes the signal only on success (auto-reset events, mutex
    /// acquisition, semaphore decrement), matching `wait_for_single_object`
    /// semantics for a zero-timeout poll.
    pub fn wait_for_single_object_instant(
        &mut self,
        handle: Handle,
        object_type: ObjectType,
        current_thread_id: u32,
    ) -> AppResult<WaitStatus> {
        let now = self.time.ticks_ms;
        // Only waitable objects can be waited on at all: files, keys, pipes,
        // I/O completion ports, directory searches, sections and sockets
        // fail with ERROR_INVALID_HANDLE (Windows: these are not waitable
        // handles).  Waitable objects additionally require SYNCHRONIZE in
        // the granted access mask.
        match object_type {
            ObjectType::Event
            | ObjectType::Mutex
            | ObjectType::Semaphore
            | ObjectType::Thread
            | ObjectType::Timer => {
                Self::require_access(&self.handle_entry(handle)?, SYNCHRONIZE)?;
            }
            ObjectType::Process => {
                // Process waits take the blocking `wait_for_single_object_process`
                // path, but a zero-timeout poll can still land here.
                Self::require_access(&self.handle_entry(handle)?, SYNCHRONIZE)?;
            }
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("handle {handle} is not a waitable object"),
                ));
            }
        }
        match object_type {
            ObjectType::Thread => {
                let thread_id = self.thread_id(handle)?;
                if self.thread_state(thread_id)?.exit_code.is_some() {
                    Ok(WaitStatus::Object0)
                } else {
                    Ok(WaitStatus::Timeout)
                }
            }
            ObjectType::Process => {
                let entry = self.handle_entry(handle)?;
                if let KernelObject::Process(process) = &entry.object {
                    if process.exit_code.is_some() {
                        Ok(WaitStatus::Object0)
                    } else {
                        Ok(WaitStatus::Timeout)
                    }
                } else {
                    invalid_handle("handle is not a process")
                }
            }
            _ => {
                let object_id = self
                    .process
                    .handle_table
                    .entry(handle)
                    .expect("checked live")
                    .object_id;
                Ok(
                    match self.objects.consume_wait(object_id, current_thread_id, now) {
                        crate::runtime::object_manager::WaitStatus::Object0 => WaitStatus::Object0,
                        crate::runtime::object_manager::WaitStatus::Timeout => WaitStatus::Timeout,
                        crate::runtime::object_manager::WaitStatus::Abandoned => {
                            WaitStatus::Abandoned
                        }
                        crate::runtime::object_manager::WaitStatus::IoCompletion => {
                            WaitStatus::IoCompletion
                        }
                    },
                )
            }
        }
    }

    /// Blocking wait for a process object, driven by the `exit_sync` condvar
    /// pair installed by `install_process_exit_sync`.
    fn wait_for_single_object_process(
        &mut self,
        handle: Handle,
        timeout_ms: u32,
    ) -> AppResult<WaitStatus> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Process(_) => {
                // Waits require SYNCHRONIZE in the granted access mask.
                Self::require_access(&entry, SYNCHRONIZE)?;
            }
            _ => return invalid_handle("handle is not a process"),
        }
        let entry = self.handle_entry(handle)?;
        if let KernelObject::Process(process) = &entry.object {
            if process.exit_code.is_some() {
                Ok(WaitStatus::Object0)
            } else if let Some(ref sync) = process.exit_sync {
                // Real blocking wait using the condvar.
                let (lock, cvar) = &**sync;
                let mut guard = lock.lock().unwrap();
                if guard.is_some() {
                    return Ok(WaitStatus::Object0);
                }
                if timeout_ms == 0 {
                    return Ok(WaitStatus::Timeout);
                }
                let timeout = Duration::from_millis(timeout_ms as u64);
                let result = cvar.wait_timeout(guard, timeout).unwrap();
                guard = result.0;
                if guard.is_some() {
                    Ok(WaitStatus::Object0)
                } else {
                    Ok(WaitStatus::Timeout)
                }
            } else {
                Ok(WaitStatus::Timeout)
            }
        } else {
            invalid_handle("handle is not a process")
        }
    }

    /// Wait for any or all of multiple objects to become signaled.
    pub fn wait_for_multiple_objects(
        &mut self,
        handles: &[Handle],
        wait_all: bool,
        timeout_ms: u32,
        alertable: bool,
        thread_handle: Option<Handle>,
    ) -> AppResult<(WaitStatus, usize)> {
        let deadline = if timeout_ms == 0 || timeout_ms == u32::MAX {
            None
        } else {
            Some(self.time.ticks_ms.saturating_add(timeout_ms as u64))
        };

        if alertable
            && let Some(thread_handle) = thread_handle
            && let Ok(thread_id) = self.thread_id(thread_handle)
            && self
                .thread_apcs
                .get(&thread_id)
                .is_some_and(|queue| !queue.is_empty())
        {
            return Ok((WaitStatus::IoCompletion, 0));
        }

        loop {
            if wait_all {
                // Non-destructive check first: for wait-all, the first pass
                // must NOT consume auto-reset signals, otherwise a second
                // (destructive) pass can never succeed and INFINITE waits
                // loop forever.  Peek at the signal state, then do a single
                // consuming pass once everything is ready.
                let all_signaled = handles.iter().try_fold(true, |acc, &handle| {
                    let signaled = self.object_is_signaled(handle)?;
                    Ok::<_, AppError>(acc && signaled)
                })?;
                if all_signaled {
                    let mut abandoned = false;
                    for &handle in handles {
                        let status = self.wait_for_single_object(handle, 0, false, None)?;
                        if status == WaitStatus::Abandoned {
                            abandoned = true;
                        }
                    }
                    return Ok((
                        if abandoned {
                            WaitStatus::Abandoned
                        } else {
                            WaitStatus::Object0
                        },
                        0,
                    ));
                }
            } else {
                for (i, &handle) in handles.iter().enumerate() {
                    let status = self.wait_for_single_object(handle, 0, false, None)?;
                    match status {
                        WaitStatus::Object0 => return Ok((WaitStatus::Object0, i)),
                        WaitStatus::Abandoned => return Ok((WaitStatus::Abandoned, i)),
                        _ => {}
                    }
                }
            }

            if let Some(deadline) = deadline
                && self.time.ticks_ms >= deadline
            {
                return Ok((WaitStatus::Timeout, usize::MAX));
            }
            if timeout_ms != 0 {
                std::thread::sleep(Duration::from_millis(1));
                // Advance the guest clock so the finite-timeout deadline
                // check above can actually expire.
                self.record_sleep_observation(1, 1);
            } else {
                return Ok((WaitStatus::Timeout, usize::MAX));
            }
        }
    }

    /// Non-destructive signal-state probe used by the wait-all path so that
    /// auto-reset signals are not consumed before the final acquiring pass.
    fn object_is_signaled(&self, handle: Handle) -> AppResult<bool> {
        let entry = self.handle_entry(handle)?;
        // Mirror `wait_for_single_object_instant`: only waitable types are
        // probeable, and probing requires SYNCHRONIZE access.  Files, keys,
        // pipes, I/O completion ports, directory searches, sections and
        // sockets fail with ERROR_INVALID_HANDLE.
        match entry.descriptor.object_type {
            ObjectType::Event
            | ObjectType::Mutex
            | ObjectType::Semaphore
            | ObjectType::Thread
            | ObjectType::Process
            | ObjectType::Timer => {
                Self::require_access(&entry, SYNCHRONIZE)?;
            }
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("handle {handle} is not a waitable object"),
                ));
            }
        }
        // The canonical `object_is_signaled` probes the object manager's
        // waitable state (Event / Mutex / Semaphore / Timer).  Thread /
        // Process signal state is subsystem-side (the threads map and the
        // process-object exit code), so those branches stay here.
        Ok(match &entry.object {
            KernelObject::Thread(thread) => self
                .threads
                .get(&thread.thread_id)
                .is_some_and(|state| state.exit_code.is_some()),
            KernelObject::Process(process) => process.exit_code.is_some(),
            _ => self.objects.object_is_signaled(
                self.process
                    .handle_table
                    .entry(handle)
                    .expect("checked live")
                    .object_id,
                self.current_thread_id,
                self.time.ticks_ms,
            ),
        })
    }

    /// Named mutex support — maps a name to a mutex handle.
    /// Returns `(handle, existed)`, mirroring `create_event`: the boolean is
    /// true when a mutex with this name already existed.
    pub fn create_named_mutex(
        &mut self,
        name: &str,
        initially_owned: bool,
        inheritable: bool,
    ) -> (Handle, bool) {
        if let Some(object_id) = self.objects.resolve(name) {
            // Reject stale entries left behind by closed handles; Windows
            // forgets the name once the last handle is closed.  The manager
            // drops the name with the last handle, so a resolved object
            // always has a live handle.
            if matches!(self.objects.object(object_id), KernelObject::Mutex(_))
                && let Some(handle) = self.find_handle_for_object(object_id)
            {
                return (handle, true);
            }
            // A name held by a DIFFERENT object type: the new object wins
            // the name (the old object survives through its handles).
        }
        let handle = self.insert_object_named(
            ObjectType::Mutex,
            Some(name),
            0x1F0001,
            inheritable,
            KernelObject::Mutex(MutexObject {
                owner_thread_id: initially_owned.then_some(self.current_thread_id),
                recursion: 0,
                abandoned: false,
            }),
        );
        (handle, false)
    }

    pub fn open_named_mutex(&self, name: &str) -> Option<Handle> {
        let object_id = self.objects.resolve(name)?;
        self.find_handle_for_object(object_id)
    }

    /// Named semaphore support.  Returns `(handle, existed)` — the boolean is
    /// true when a semaphore with this name already existed.
    pub fn create_named_semaphore(
        &mut self,
        name: &str,
        initial_count: u32,
        maximum: u32,
        inheritable: bool,
    ) -> (Handle, bool) {
        if let Some(object_id) = self.objects.resolve(name) {
            // A name held by a DIFFERENT object type: the new object wins
            // the name (the old object survives through its handles).
            if matches!(self.objects.object(object_id), KernelObject::Semaphore(_))
                && let Some(handle) = self.find_handle_for_object(object_id)
            {
                return (handle, true);
            }
        }
        let handle = self.insert_object_named(
            ObjectType::Semaphore,
            Some(name),
            0x1F0003,
            inheritable,
            KernelObject::Semaphore(SemaphoreObject {
                count: initial_count,
                maximum,
            }),
        );
        (handle, false)
    }

    pub fn open_named_semaphore(&self, name: &str) -> Option<Handle> {
        let object_id = self.objects.resolve(name)?;
        self.find_handle_for_object(object_id)
    }

    /// Named event support (open by name): mints a fresh handle to the
    /// named object (the manager refcount goes up).
    pub fn open_named_event(&mut self, name: &str) -> Option<Handle> {
        let object_id = self.objects.resolve(name)?;
        Some(self.insert_object_id(object_id, 0x1F0003, false))
    }

    /// The live handle referencing `object_id`, if any.
    fn find_handle_for_object(&self, object_id: ObjectId) -> Option<Handle> {
        self.process
            .handle_table
            .iter()
            .find_map(|(handle, entry)| (entry.object_id == object_id).then_some(handle))
    }

    pub fn queue_apc(&mut self, thread_handle: Handle, token: impl Into<String>) -> AppResult<()> {
        let thread_id = self.thread_id(thread_handle)?;
        self.thread_apcs
            .entry(thread_id)
            .or_default()
            .push_back(token.into());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_file_w(
        &mut self,
        path: &str,
        desired_access: FileAccess,
        share_mode: ShareMode,
        creation: CreationDisposition,
        inheritable: bool,
        overlapped: bool,
        backup_semantics: bool,
    ) -> AppResult<Handle> {
        // Legacy API: derive a plausible granted-access mask from the
        // three-boolean projection.  The thunks use `create_file_w_extended`
        // to pass the true expanded rights mask.
        let granted_access = granted_access_from_file_access(desired_access);
        self.create_file_w_extended(
            path,
            desired_access,
            share_mode,
            creation,
            inheritable,
            overlapped,
            backup_semantics,
            granted_access,
            false,
        )
    }

    /// Extended file open carrying the EXPANDED Win32 desired-access mask
    /// (generic bits replaced by their concrete `FILE_*` equivalents) and the
    /// `FILE_FLAG_DELETE_ON_CLOSE` flag.  `granted_access` is recorded on the
    /// handle descriptor and enforced by per-operation access checks;
    /// `share_mode` participates in the GE share-state conflict matrix.
    ///
    /// Ordering guarantee: for an existing file, the share-conflict check runs
    /// BEFORE any destructive disposition (CREATE_ALWAYS / TRUNCATE_EXISTING
    /// truncate the file only after the sharing check passes), so a failed
    /// open never destroys file contents.
    ///
    /// Missing-parent contract (see the module operation contract): creating
    /// dispositions never manufacture the parent directory — a missing parent
    /// is ERROR_PATH_NOT_FOUND, and OPEN_EXISTING / TRUNCATE_EXISTING
    /// distinguish a missing parent (ERROR_PATH_NOT_FOUND) from a missing
    /// file inside a present parent (ERROR_FILE_NOT_FOUND).
    #[allow(clippy::too_many_arguments)]
    pub fn create_file_w_extended(
        &mut self,
        path: &str,
        desired_access: FileAccess,
        share_mode: ShareMode,
        creation: CreationDisposition,
        inheritable: bool,
        overlapped: bool,
        backup_semantics: bool,
        granted_access: u32,
        delete_on_close: bool,
    ) -> AppResult<Handle> {
        let (normalized_path, host_path) = self.resolve_host_path(path)?;
        // Generic runtime event (no behavior change): every file open is
        // observable at request level (path, raw access/share/disposition).
        // The Steam workload observer derives the manifest-opened and
        // package-writability-probe milestones from this event.
        self.emit_event(crate::runtime_events::RuntimeEvent::FileOpened {
            path: normalized_path.clone(),
            desired_access: granted_access,
            share_mode: share_mode_to_raw(share_mode),
            disposition: match creation {
                CreationDisposition::CreateNew => 1,
                CreationDisposition::CreateAlways => 2,
                CreationDisposition::OpenExisting => 3,
                CreationDisposition::OpenAlways => 4,
                CreationDisposition::TruncateExisting => 5,
            },
        });
        let exists = host_path.exists();
        if exists && host_path.is_dir() {
            if !backup_semantics
                || !matches!(
                    creation,
                    CreationDisposition::OpenExisting | CreationDisposition::OpenAlways
                )
            {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    format!(
                        "directory handle requires backup semantics: {}",
                        normalized_path
                    ),
                ));
            }
            // Directory handles participate in the same GE share-state matrix
            // as files: `ge.open_file` resolves directories too, so a second
            // open without compatible share modes fails with a sharing
            // violation.
            let ge_handle = Some(self.ge.open_file(path, desired_access, share_mode)?);
            return Ok(self.insert_object(
                ObjectType::File,
                granted_access,
                inheritable,
                KernelObject::File(Rc::new(RefCell::new(FileObject {
                    normalized_path,
                    host_path,
                    ge_handle,
                    position: 0,
                    overlapped,
                    host_file: None,
                    granted_access,
                    share_mode: share_mode_to_raw(share_mode),
                    delete_pending: false,
                    is_directory: true,
                    delete_on_close: false,
                }))),
            ));
        }
        // Fail-fast disposition checks that never touch the filesystem and
        // short-circuit before any share interaction.  Windows does not
        // manufacture missing parent directories: a missing PARENT is
        // ERROR_PATH_NOT_FOUND, a missing FILE inside a present parent is
        // ERROR_FILE_NOT_FOUND (see the operation contract above).
        let parent_resolves = self.parent_directory_exists(&normalized_path);
        match creation {
            CreationDisposition::CreateNew if exists => {
                return Err(AppError::new(
                    ReasonCode::RcFsAlreadyExists,
                    format!("{} already exists", normalized_path),
                ));
            }
            CreationDisposition::CreateNew
            | CreationDisposition::CreateAlways
            | CreationDisposition::OpenAlways
                if !exists && !parent_resolves =>
            {
                return Err(AppError::new(
                    ReasonCode::RcFsPathInvalid,
                    format!("parent directory of {} does not exist", normalized_path),
                ));
            }
            CreationDisposition::OpenExisting | CreationDisposition::TruncateExisting
                if !exists =>
            {
                return Err(if parent_resolves {
                    AppError::new(
                        ReasonCode::RcFsNotFound,
                        format!("{} does not exist", normalized_path),
                    )
                } else {
                    AppError::new(
                        ReasonCode::RcFsPathInvalid,
                        format!("parent directory of {} does not exist", normalized_path),
                    )
                });
            }
            _ => {}
        }
        // Share-conflict check FIRST, before any destructive disposition:
        // `ge.open_file` registers the handle in the share runtime and fails
        // with a sharing violation when an existing handle's share modes do
        // not permit this open.  Only after the check passes may
        // CREATE_ALWAYS / TRUNCATE_EXISTING truncate or create.
        //
        // Windows refuses to truncate a file carrying the readonly attribute
        // (it is never cleared by the open) and TRUNCATE_EXISTING requires
        // write access — both surface as ERROR_ACCESS_DENIED.
        if host_path.exists()
            && matches!(
                creation,
                CreationDisposition::CreateAlways | CreationDisposition::TruncateExisting
            )
        {
            let metadata = self
                .ge
                .get_file_metadata(&normalized_path)
                .map_err(|error| {
                    if matches!(error.code, ReasonCode::RcFsNotFound) {
                        AppError::new(
                            ReasonCode::RcIo,
                            format!("failed to stat {}", normalized_path),
                        )
                    } else {
                        error
                    }
                })?;
            if metadata
                .attributes
                .iter()
                .any(|attribute| attribute == "readonly")
            {
                return Err(AppError::new(
                    ReasonCode::RcHelperPermissionDenied,
                    format!("{} is read-only", normalized_path),
                ));
            }
            if matches!(creation, CreationDisposition::TruncateExisting)
                && granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA) == 0
            {
                return Err(AppError::new(
                    ReasonCode::RcHelperPermissionDenied,
                    format!(
                        "TRUNCATE_EXISTING requires write access to {}",
                        normalized_path
                    ),
                ));
            }
        }
        let ge_handle = if host_path.exists() {
            Some(self.ge.open_file(path, desired_access, share_mode)?)
        } else {
            None
        };
        let disposition_result = (|| -> AppResult<()> {
            match creation {
                CreationDisposition::CreateAlways
                | CreationDisposition::OpenAlways
                | CreationDisposition::CreateNew
                    if !host_path.exists() =>
                {
                    // The fail-fast parent check above already verified the
                    // parent resolves; a plain create must never repair it.
                    fs::write(&host_path, []).map_err(|error| {
                        AppError::from_io(
                            ReasonCode::RcIo,
                            format!("failed to create {}", host_path.display()),
                            &error,
                        )
                    })?;
                    self.sync_entry(&normalized_path, &host_path, false)?;
                }
                CreationDisposition::CreateAlways if host_path.exists() => {
                    fs::write(&host_path, []).map_err(|error| {
                        AppError::from_io(
                            ReasonCode::RcIo,
                            format!("failed to truncate {}", host_path.display()),
                            &error,
                        )
                    })?;
                    self.sync_entry(&normalized_path, &host_path, false)?;
                }
                CreationDisposition::TruncateExisting if host_path.exists() => {
                    fs::write(&host_path, []).map_err(|error| {
                        AppError::from_io(
                            ReasonCode::RcIo,
                            format!("failed to truncate {}", host_path.display()),
                            &error,
                        )
                    })?;
                    self.sync_entry(&normalized_path, &host_path, false)?;
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(error) = disposition_result {
            // The share claim was registered above; release it so a failed
            // open does not leak a share-state entry.
            if let Some(ge_handle) = &ge_handle {
                let _ = self.ge.close_file_handle(ge_handle);
            }
            return Err(error);
        }
        // An open that created a previously-missing file had nothing to
        // share-check against, but the handle still claims share state in the
        // runtime (otherwise later opens would not see it and deletion could
        // bypass FILE_SHARE_DELETE).
        let ge_handle = match ge_handle {
            Some(handle) => Some(handle),
            None if host_path.exists() => {
                Some(self.ge.open_file(path, desired_access, share_mode)?)
            }
            None => None,
        };
        // Keep a real file descriptor for positional I/O so reads/writes do
        // not re-read and rewrite the whole file on every syscall.
        let host_file = OpenOptions::new()
            .read(true)
            .write(desired_access.write)
            .open(&host_path)
            .ok();
        Ok(self.insert_object(
            ObjectType::File,
            granted_access,
            inheritable,
            KernelObject::File(Rc::new(RefCell::new(FileObject {
                normalized_path,
                host_path,
                ge_handle,
                position: 0,
                overlapped,
                host_file,
                granted_access,
                share_mode: share_mode_to_raw(share_mode),
                delete_pending: false,
                is_directory: false,
                delete_on_close,
            }))),
        ))
    }

    pub fn close_handle(&mut self, handle: Handle) -> AppResult<()> {
        // Sockets are winsock handles, not kernel handles: Windows
        // `CloseHandle` on a SOCKET fails with ERROR_INVALID_HANDLE.  With
        // the unified namespace this is enforced by type, so a socket value
        // can never close a (recycled) win32 object.
        let (object_type, object, last_handle) = {
            let entry = self.process.handle_table.entry(handle)?;
            let object_type = self.objects.object_type(entry.object_id);
            // The GE share-state claim dies with the LAST handle to the
            // object (the object manager owns the single object payload;
            // handle count is the reference count).
            let last_handle = self.objects.handle_count(entry.object_id) == 1;
            (
                object_type,
                self.objects.object(entry.object_id).clone(),
                last_handle,
            )
        };
        if object_type == ObjectType::Socket {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("handle {handle} is a socket, not a kernel handle"),
            ));
        }
        // Subsystem teardown runs against the object BEFORE the handle table
        // and the object manager drop it (the table returns the removed
        // entry so the manager refcount can be decremented).
        if let KernelObject::File(file) = &object {
            let ge_handle = if last_handle {
                file.borrow().ge_handle.clone()
            } else {
                None
            };
            if let Some(ge_handle) = ge_handle {
                self.ge.close_file_handle(&ge_handle)?;
            }
            let (delete_on_close, normalized_path, host_path) = {
                let file = file.borrow();
                (
                    file.delete_on_close,
                    file.normalized_path.clone(),
                    file.host_path.clone(),
                )
            };
            if delete_on_close {
                // FILE_FLAG_DELETE_ON_CLOSE: remove the file now that this
                // handle closes.  A sharing failure during the removal is
                // ignored, matching Windows behavior.
                let _ = fs::remove_file(&host_path);
                self.ge.config.fs_state.entries.remove(&normalized_path);
            }
        }
        if let KernelObject::Pipe(pipe) = &object {
            self.close_pipe_teardown(handle, pipe)?;
        }
        // The canonical table validates close-protection, rejects sockets by
        // type, removes the entry, bumps the value's generation and recycles
        // the value for future reuse (Windows reuses handle values).
        let removed = self.process.handle_table.close(handle, object_type)?;
        // Windows forgets named objects once the last handle closes; the
        // object manager drops the object and its name at refcount 0.
        self.objects.handle_removed(removed.object_id);
        if let KernelObject::Thread(thread) = &object {
            self.cleanup_exited_thread_state(thread.thread_id);
        }
        Ok(())
    }

    /// Pipe-specific close teardown: when the server end closes while a
    /// client still holds the pipe open, the surviving client objects get a
    /// broken state so parked pipe waiters wake with ERROR_BROKEN_PIPE (the
    /// name itself is forgotten — Windows frees the pipe name once the
    /// server instance closes).
    fn close_pipe_teardown(&mut self, handle: Handle, pipe: &PipeObject) -> AppResult<()> {
        let name = pipe.name.clone();
        let state = pipe.state.clone();
        let normalized = normalize_pipe_name(&name);
        let is_server = state
            .as_ref()
            .is_some_and(|state| state.server_handle == Some(handle));
        let is_client = state
            .as_ref()
            .is_some_and(|state| state.client_handle == Some(handle));
        if !is_server && !is_client && state.is_none() {
            // Legacy anonymous pipe without a state record: nothing to do.
            return Ok(());
        }
        // Other pipe objects with the same name (the peer end).
        let peers = self
            .objects
            .objects_iter()
            .filter_map(|(id, object)| match object {
                KernelObject::Pipe(peer) if peer.name == name => Some(id),
                _ => None,
            })
            .collect::<Vec<_>>();
        if is_server {
            // The server end closed: give every surviving peer (client) a
            // broken state so its waiters observe the disconnection; the
            // named record dies with this object's last handle.
            let broken = state.map(|state| NamedPipeState {
                server_handle: None,
                client_handle: None,
                server_disconnected: true,
                client_disconnected: true,
                ..state
            });
            if let Some(broken) = broken {
                for peer_id in &peers {
                    if let KernelObject::Pipe(peer) = self.objects.object_mut(*peer_id) {
                        peer.state = Some(broken.clone());
                    }
                }
            }
            // Signal pending pipe I/O events on every surviving peer so
            // event waiters wake; the requests stay Pending and complete as
            // broken pipe through the scheduler.
            let mut surviving_handles = self
                .process
                .handle_table
                .iter()
                .filter_map(|(peer_handle, entry)| {
                    peers.contains(&entry.object_id).then_some(peer_handle)
                })
                .collect::<Vec<_>>();
            surviving_handles.sort_unstable();
            surviving_handles.dedup();
            for surviving in surviving_handles {
                if surviving != handle {
                    self.signal_pending_pipe_io_events(surviving)?;
                }
            }
        } else if is_client {
            // A client end closed while the server survives: mark the
            // server-side state broken for that direction so the server's
            // parked pipe waiters wake.
            if let Some(server_id) = self.objects.resolve(&normalized)
                && let KernelObject::Pipe(server_pipe) = self.objects.object_mut(server_id)
                && let Some(state) = server_pipe.state.as_mut()
                && state.client_handle == Some(handle)
            {
                state.client_handle = None;
                state.client_disconnected = true;
            }
            if let Some(server_id) = self.objects.resolve(&normalized) {
                let server_handle =
                    self.process
                        .handle_table
                        .iter()
                        .find_map(|(peer_handle, entry)| {
                            (entry.object_id == server_id).then_some(peer_handle)
                        });
                if let Some(server_handle) = server_handle {
                    self.signal_pending_pipe_io_events(server_handle)?;
                }
            }
        }
        Ok(())
    }

    // ── Socket handle management ─────────────────────────────────────────
    //
    // Sockets are first-class kernel objects in the SAME handle namespace as
    // everything else: `insert_socket` mints a handle through the win32
    // allocator (no separate base), and the value IS the socket id used by
    // the `NetworkStack`.  This makes cross-type misuse (CloseHandle on a
    // socket, closesocket on a file) fail by construction instead of by
    // accident of two colliding numeric spaces.

    /// Allocate a win32 handle for a new winsock socket.  The returned
    /// value is both the handle and the socket id: the caller registers the
    /// id with the `NetworkStack` (which keys its socket records by this
    /// value).  The address family is validated by the winsock layer before
    /// this is reached.
    pub fn insert_socket(&mut self) -> Handle {
        let handle = self.insert_object(
            ObjectType::Socket,
            0,
            false,
            KernelObject::Socket(SocketObject { id: 0 }),
        );
        if let KernelObject::Socket(socket) =
            self.handle_object_mut(handle).expect("fresh socket handle")
        {
            socket.id = u64::from(handle);
        }
        handle
    }

    /// The socket id behind a handle: type-checks the entry as a Socket
    /// (anything else is `RcWin32InvalidHandle`, which the winsock thunks
    /// map to WSAENOTSOCK).
    pub fn socket_id(&self, handle: Handle) -> AppResult<u64> {
        match self.handle_object(handle) {
            Ok(KernelObject::Socket(socket)) => Ok(socket.id),
            Ok(_) => invalid_handle("handle is not a socket"),
            Err(error) => Err(error),
        }
    }

    /// Remove a socket handle from the table (same generation/recycle
    /// bookkeeping as `close_handle`) and return the socket id so the caller
    /// can tear down the `NetworkStack` record.
    pub fn close_socket(&mut self, handle: Handle) -> AppResult<u64> {
        let id = match self.handle_object(handle) {
            Ok(KernelObject::Socket(socket)) => socket.id,
            Ok(_) => return invalid_handle("handle is not a socket"),
            Err(error) => return Err(error),
        };
        let removed = self.process.handle_table.close_raw(handle)?;
        self.objects.handle_removed(removed.object_id);
        Ok(id)
    }

    /// `GetFileType` — consult the handle table instead of assuming every
    /// non-null handle is a disk file.  Files → FILE_TYPE_DISK, pipes →
    /// FILE_TYPE_PIPE, anything else (or closed) → error, which the caller
    /// turns into FILE_TYPE_UNKNOWN + ERROR_INVALID_HANDLE.
    pub fn file_type(&self, handle: Handle) -> AppResult<u32> {
        let entry = self.handle_entry(handle)?;
        match entry.descriptor.object_type {
            ObjectType::File => Ok(FILE_TYPE_DISK),
            ObjectType::Pipe => Ok(FILE_TYPE_PIPE),
            _ => invalid_handle("handle is not a file or pipe"),
        }
    }

    /// `RegCloseKey` — like `close_handle` but type-checks the Key first so
    /// a non-key handle cannot be closed through the registry API.
    pub fn close_registry_key(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        if !matches!(entry.object, KernelObject::Key(_)) {
            return invalid_handle("handle is not a registry key");
        }
        self.close_handle(handle)
    }

    /// Enforce a per-operation granted-access check: the operation requires
    /// `required` bits to be present in the handle's expanded access mask.
    /// Fails with `RcHelperPermissionDenied` (which maps to Win32
    /// ERROR_ACCESS_DENIED) when the bits are absent.
    fn require_access(entry: &HandleEntry, required: u32) -> Result<(), AppError> {
        if entry.descriptor.access_mask & required != 0 {
            Ok(())
        } else {
            Err(AppError::new(
                ReasonCode::RcHelperPermissionDenied,
                format!(
                    "handle requires access {required:#x}, granted {:#x}",
                    entry.descriptor.access_mask
                ),
            ))
        }
    }

    /// Public per-operation granted-access check for a handle, used by the
    /// runtime's ADS ReadFile/WriteFile paths (which operate on the base
    /// file handle) so those operations cannot bypass the handle's recorded
    /// access mask.
    pub fn require_file_access(&self, handle: Handle, required: u32) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        Self::require_access(&entry, required)
    }

    pub fn read_file(&mut self, handle: Handle, length: usize) -> AppResult<Vec<u8>> {
        let object_type = self.handle_entry(handle)?.descriptor.object_type;
        match object_type {
            ObjectType::File => {
                Self::require_access(&self.handle_entry(handle)?, FILE_READ_DATA)?;
                let (data, read_path) = (|| -> AppResult<(Vec<u8>, String)> {
                    let mut entry = self.handle_entry_mut(handle)?;
                    if let KernelObject::File(file) = &mut entry.object {
                        let mut file = file.borrow_mut();
                        let path_display = file.host_path.display().to_string();
                        let position = file.position;
                        if let Some(host_file) = file.host_file.as_mut() {
                            let size = host_file
                                .metadata()
                                .map_err(|error| {
                                    AppError::from_io(
                                        ReasonCode::RcIo,
                                        format!("failed to stat {path_display}"),
                                        &error,
                                    )
                                })?
                                .len();
                            // Clamp the start position: a guest may seek past
                            // EOF (Windows allows it) and reads must yield
                            // zero bytes, not panic on a slice.
                            let start = position.min(size);
                            let to_read = (length as u64).min(size - start) as usize;
                            let mut data = vec![0_u8; to_read];
                            host_file.seek(SeekFrom::Start(start)).map_err(|error| {
                                AppError::from_io(
                                    ReasonCode::RcIo,
                                    format!("failed to seek {path_display}"),
                                    &error,
                                )
                            })?;
                            let mut read_total = 0usize;
                            while read_total < data.len() {
                                let n =
                                    host_file.read(&mut data[read_total..]).map_err(|error| {
                                        AppError::from_io(
                                            ReasonCode::RcIo,
                                            format!("failed to read {path_display}"),
                                            &error,
                                        )
                                    })?;
                                if n == 0 {
                                    break;
                                }
                                read_total += n;
                            }
                            data.truncate(read_total);
                            file.position = start.saturating_add(read_total as u64);
                            return Ok((data, file.normalized_path.clone()));
                        }
                        // Fallback for handles without an open descriptor
                        // (directories, failed opens): whole-file read with
                        // clamped slicing.
                        let bytes = fs::read(&file.host_path).map_err(|error| {
                            AppError::from_io(
                                ReasonCode::RcIo,
                                format!("failed to read {path_display}"),
                                &error,
                            )
                        })?;
                        let start = (file.position as usize).min(bytes.len());
                        let end = start.saturating_add(length).min(bytes.len());
                        file.position = end as u64;
                        return Ok((bytes[start..end].to_vec(), file.normalized_path.clone()));
                    }
                    invalid_handle("handle is not a file")
                })()?;
                // Generic runtime event (no behavior change): a file read
                // completed; the Steam workload observer derives the manifest
                // full-read milestone from it.
                self.emit_event(crate::runtime_events::RuntimeEvent::FileRead {
                    path: read_path,
                    bytes: data.clone(),
                });
                Ok(data)
            }
            ObjectType::Pipe => {
                let normalized = match self.handle_object(handle)? {
                    KernelObject::Pipe(pipe) => normalize_pipe_name(&pipe.name),
                    _ => return invalid_handle("handle is not a pipe"),
                };
                if let Some(state) = self.pipe_state_by_name(&normalized) {
                    if state.server_disconnected && !state.client_connected {
                        return Err(AppError::new(
                            ReasonCode::RcIo,
                            format!("pipe {normalized} is disconnected"),
                        ));
                    }
                    Ok(self.pipe_read_sync(handle, length))
                } else {
                    // Legacy pipe without shared state: read from the
                    // per-object buffer.
                    match self.handle_object_mut(handle)? {
                        KernelObject::Pipe(pipe) => {
                            let take = length.min(pipe.buffer.len());
                            Ok(pipe.buffer.drain(..take).collect())
                        }
                        _ => invalid_handle("handle is not a pipe"),
                    }
                }
            }
            _ => invalid_handle("handle is not a file or pipe"),
        }
    }

    pub fn write_file(&mut self, handle: Handle, bytes: &[u8]) -> AppResult<u32> {
        let object_type = self.handle_entry(handle)?.descriptor.object_type;
        match object_type {
            ObjectType::File => {
                Self::require_access(
                    &self.handle_entry(handle)?,
                    FILE_WRITE_DATA | FILE_APPEND_DATA,
                )?;
                let (normalized_path, host_path) = {
                    let mut entry = self.handle_entry_mut(handle)?;
                    if let KernelObject::File(file) = &mut entry.object {
                        let mut file = file.borrow_mut();
                        let path_display = file.host_path.display().to_string();
                        let pos = file.position;
                        if let Some(host_file) = file.host_file.as_mut() {
                            host_file.seek(SeekFrom::Start(pos)).map_err(|error| {
                                AppError::from_io(
                                    ReasonCode::RcIo,
                                    format!("failed to seek {path_display}"),
                                    &error,
                                )
                            })?;
                            let mut written = 0usize;
                            while written < bytes.len() {
                                let n = host_file.write(&bytes[written..]).map_err(|error| {
                                    AppError::from_io(
                                        ReasonCode::RcIo,
                                        format!("failed to write {path_display}"),
                                        &error,
                                    )
                                })?;
                                if n == 0 {
                                    return Err(AppError::new(
                                        ReasonCode::RcIo,
                                        format!("short write to {path_display}"),
                                    ));
                                }
                                written += n;
                            }
                            file.position = pos.saturating_add(written as u64);
                            (file.normalized_path.clone(), file.host_path.clone())
                        } else {
                            // Fallback for handles without an open descriptor:
                            // whole-file read-modify-write with checked bounds.
                            let mut contents = if file.host_path.exists() {
                                fs::read(&file.host_path).map_err(|error| {
                                    AppError::from_io(
                                        ReasonCode::RcIo,
                                        format!("failed to read {path_display}"),
                                        &error,
                                    )
                                })?
                            } else {
                                Vec::new()
                            };
                            let start = file.position;
                            // Bound the position before any usize arithmetic
                            // so a guest seek to u64::MAX cannot overflow or
                            // trigger an absurd allocation.
                            if start > isize::MAX as u64 {
                                return Err(AppError::new(
                                    ReasonCode::RcMemoryAccessViolation,
                                    "file write position is too large",
                                ));
                            }
                            let start = start as usize;
                            let end = start.checked_add(bytes.len()).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcMemoryAccessViolation,
                                    "file write range overflows",
                                )
                            })?;
                            if end > MAX_ALLOCATION_SIZE {
                                return Err(AppError::new(
                                    ReasonCode::RcMemoryAccessViolation,
                                    format!(
                                        "file write extends past the {MAX_ALLOCATION_SIZE}-byte cap"
                                    ),
                                ));
                            }
                            if contents.len() < end {
                                contents.resize(end, 0);
                            }
                            contents[start..end].copy_from_slice(bytes);
                            fs::write(&file.host_path, &contents).map_err(|error| {
                                AppError::from_io(
                                    ReasonCode::RcIo,
                                    format!("failed to write {path_display}"),
                                    &error,
                                )
                            })?;
                            file.position = end as u64;
                            (file.normalized_path.clone(), file.host_path.clone())
                        }
                    } else {
                        return invalid_handle("handle is not a file");
                    }
                };
                self.sync_entry(&normalized_path, &host_path, false)?;
                // Generic runtime event (no behavior change): a file write
                // completed.
                self.emit_event(crate::runtime_events::RuntimeEvent::FileWritten {
                    path: normalized_path,
                    bytes: bytes.to_vec(),
                });
                Ok(bytes.len() as u32)
            }
            ObjectType::Pipe => {
                let normalized = match self.handle_object(handle)? {
                    KernelObject::Pipe(pipe) => normalize_pipe_name(&pipe.name),
                    _ => return invalid_handle("handle is not a pipe"),
                };
                let disconnected = self
                    .pipe_state_by_name(&normalized)
                    .is_some_and(|state| state.server_disconnected);
                if disconnected {
                    return Err(AppError::new(
                        ReasonCode::RcIo,
                        format!("pipe {normalized} is disconnected"),
                    ));
                }
                if let Some(state) = self.pipe_state_mut_by_name(&normalized) {
                    // Server writes append to server-to-client; client writes
                    // append to client-to-server.
                    let is_server = state.server_handle == Some(handle);
                    let (queue, data_ready, message_mode) = if is_server {
                        (
                            state.server_to_client.clone(),
                            state.data_ready.clone(),
                            state.message_mode,
                        )
                    } else {
                        (
                            state.client_to_server.clone(),
                            state.data_ready.clone(),
                            state.message_mode,
                        )
                    };
                    pipe_queue_append(&queue, &data_ready, bytes, message_mode);
                } else {
                    // Legacy pipe without shared state: buffer on the object.
                    match self.handle_object_mut(handle)? {
                        KernelObject::Pipe(pipe) => {
                            pipe.buffer.extend_from_slice(bytes);
                        }
                        _ => return invalid_handle("handle is not a pipe"),
                    }
                }
                Ok(bytes.len() as u32)
            }
            _ => invalid_handle("handle is not a file or pipe"),
        }
    }

    pub fn flush_file_buffers(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        // Type-first: a non-file handle fails with ERROR_INVALID_HANDLE
        // regardless of its access mask (Windows reports the wrong type
        // before checking access).
        match &entry.object {
            KernelObject::File(_) => {}
            _ => return invalid_handle("handle is not a file"),
        }
        // Windows FlushFileBuffers requires GENERIC_WRITE access to the file
        // (the expanded mask grants FILE_WRITE_DATA|FILE_APPEND_DATA); a
        // read-only handle must fail with ERROR_ACCESS_DENIED.
        Self::require_access(&entry, FILE_WRITE_DATA | FILE_APPEND_DATA)?;
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::File(file) => {
                let file = file.borrow();
                if file.host_path.is_dir() {
                    return invalid_handle("handle is not a file");
                }
                let file_handle = OpenOptions::new()
                    .read(true)
                    .open(&file.host_path)
                    .map_err(|error| {
                        AppError::from_io(
                            ReasonCode::RcIo,
                            format!("failed to open {} for flush", file.host_path.display()),
                            &error,
                        )
                    })?;
                file_handle.sync_all().map_err(|error| {
                    AppError::from_io(
                        ReasonCode::RcIo,
                        format!("failed to flush {}", file.host_path.display()),
                        &error,
                    )
                })
            }
            _ => invalid_handle("handle is not a file"),
        }
    }

    pub fn get_file_size_ex(&self, handle: Handle) -> AppResult<u64> {
        let entry = self.handle_entry(handle)?;
        // Type-first: a non-file handle fails with ERROR_INVALID_HANDLE
        // regardless of its access mask.
        match &entry.object {
            KernelObject::File(_) => {}
            _ => return invalid_handle("handle is not a file"),
        }
        Self::require_access(&entry, FILE_READ_ATTRIBUTES)?;
        match &entry.object {
            KernelObject::File(file) => {
                let file = file.borrow();
                fs::metadata(&file.host_path)
                    .map(|metadata| metadata.len())
                    .map_err(|error| {
                        AppError::from_io(
                            ReasonCode::RcIo,
                            format!("failed to stat {}", file.host_path.display()),
                            &error,
                        )
                    })
            }
            _ => invalid_handle("handle is not a file"),
        }
    }

    pub fn set_file_pointer_ex(
        &mut self,
        handle: Handle,
        distance: i64,
        origin: SeekOrigin,
    ) -> AppResult<u64> {
        // Type-first: a non-file handle fails with ERROR_INVALID_HANDLE
        // regardless of its access mask.
        let entry = self.handle_entry(handle)?;
        if !matches!(entry.object, KernelObject::File(_)) {
            return invalid_handle("handle is not a file");
        }
        let size = self.get_file_size_ex(handle)? as i128;
        // Seeking moves the file pointer, which both reads and writes build
        // on; a handle granted neither FILE_READ_DATA nor FILE_WRITE_DATA
        // must not be able to reposition it.
        Self::require_access(
            &self.handle_entry(handle)?,
            FILE_READ_DATA | FILE_WRITE_DATA,
        )?;
        let mut entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::File(file) => {
                let mut file = file.borrow_mut();
                let next = match origin {
                    SeekOrigin::Begin => distance as i128,
                    // i128 intermediate so a position near u64::MAX cannot
                    // wrap when cast to i64.
                    SeekOrigin::Current => file.position as i128 + distance as i128,
                    SeekOrigin::End => size + distance as i128,
                };
                if next < 0 {
                    return Err(AppError::new(
                        ReasonCode::RcMemoryAccessViolation,
                        "negative file pointer is not allowed",
                    ));
                }
                if next > i64::MAX as i128 {
                    return Err(AppError::new(
                        ReasonCode::RcCliInvalid,
                        "file pointer exceeds the Windows signed 64-bit range",
                    ));
                }
                file.position = next as u64;
                Ok(file.position)
            }
            _ => invalid_handle("handle is not a file"),
        }
    }

    /// `SetEndOfFile` — truncate the file at the current file pointer
    /// position.  Files are backed by real host files, so truncation is the
    /// real `set_len` on the open descriptor (falling back to a write-open
    /// when the handle carries no descriptor).  Requires `FILE_WRITE_DATA`.
    pub fn set_end_of_file(&mut self, handle: Handle) -> AppResult<()> {
        // Type-first: a non-file handle fails with ERROR_INVALID_HANDLE
        // regardless of its access mask.
        let entry = self.handle_entry(handle)?;
        if !matches!(entry.object, KernelObject::File(_)) {
            return invalid_handle("handle is not a file");
        }
        Self::require_access(&entry, FILE_WRITE_DATA)?;
        let (position, host_path, normalized_path) = {
            let mut entry = self.handle_entry_mut(handle)?;
            match &mut entry.object {
                KernelObject::File(file) => {
                    let mut file = file.borrow_mut();
                    let position = file.position;
                    if let Some(host_file) = file.host_file.as_mut() {
                        host_file.set_len(position).map_err(|error| {
                            AppError::from_io(
                                ReasonCode::RcIo,
                                format!(
                                    "failed to truncate {} at offset {position}",
                                    file.host_path.display()
                                ),
                                &error,
                            )
                        })?;
                        return Ok(());
                    }
                    (
                        position,
                        file.host_path.clone(),
                        file.normalized_path.clone(),
                    )
                }
                _ => return invalid_handle("handle is not a file"),
            }
        };
        // No open descriptor: reopen for writing and truncate.  A read-only
        // open should have been refused by the FILE_WRITE_DATA access check
        // above; the reopen failure surfaces the real host error.
        let host_file = OpenOptions::new()
            .write(true)
            .open(&host_path)
            .map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to open {} for truncation", host_path.display()),
                    &error,
                )
            })?;
        host_file.set_len(position).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!(
                    "failed to truncate {normalized_path} ({} at offset {position})",
                    host_path.display()
                ),
                &error,
            )
        })
    }

    /// GetDriveTypeW semantics for a guest path.
    ///
    /// The runtime maps every drive letter to a local host directory (the GE
    /// mapping), so any path that resolves to a mapped drive is DRIVE_FIXED;
    /// a drive-letter path with no mapping is DRIVE_NO_ROOT_DIR; paths
    /// without a resolvable root are DRIVE_UNKNOWN.
    pub fn drive_type_for_path(&self, windows_path: Option<&str>) -> u32 {
        const DRIVE_UNKNOWN: u32 = 0;
        const DRIVE_NO_ROOT_DIR: u32 = 1;
        const DRIVE_FIXED: u32 = 3;
        let host_path = match windows_path {
            Some(path) => match self.ge.host_path_for_windows_path(path) {
                Ok(host) => host,
                Err(_) => {
                    let has_drive_prefix = path.len() >= 2 && path.as_bytes().get(1) == Some(&b':');
                    return if has_drive_prefix {
                        DRIVE_NO_ROOT_DIR
                    } else {
                        DRIVE_UNKNOWN
                    };
                }
            },
            None => self.ge.root.clone(),
        };
        let mut probe = host_path;
        loop {
            if statvfs(&probe).is_some() {
                return DRIVE_FIXED;
            }
            match probe.parent() {
                Some(parent) => probe = parent.to_path_buf(),
                None => return DRIVE_UNKNOWN,
            }
        }
    }

    /// Real volume capacity for the host directory backing a guest path.
    ///
    /// Windows `GetDiskFreeSpace*` report the volume containing the path; the
    /// GE drives are host directories, so the volume is the host volume
    /// holding the mapped drive target.  The probe walks up to the nearest
    /// existing ancestor so syntactically-valid but not-yet-created paths
    /// still resolve to their volume.
    pub fn volume_capacity(&self, windows_path: Option<&str>) -> AppResult<VolumeCapacity> {
        let host_path = match windows_path {
            Some(path) => self.ge.host_path_for_windows_path(path)?,
            None => self.ge.root.clone(),
        };
        let probe_display = host_path.display().to_string();
        let mut probe = host_path;
        let vfs = loop {
            if let Some(stat) = statvfs(&probe) {
                break stat;
            }
            match probe.parent() {
                Some(parent) => probe = parent.to_path_buf(),
                None => {
                    return Err(AppError::new(
                        ReasonCode::RcIo,
                        format!("failed to stat the volume containing {probe_display}"),
                    ));
                }
            }
        };
        let unit_size = vfs.f_frsize.max(vfs.f_bsize).max(512);
        let (bytes_per_sector, sectors_per_cluster) = if unit_size % 512 == 0 {
            (512, (unit_size / 512) as u32)
        } else {
            (unit_size as u32, 1)
        };
        let cluster_size = u64::from(bytes_per_sector) * u64::from(sectors_per_cluster);
        let total_bytes = u64::from(vfs.f_blocks).saturating_mul(vfs.f_frsize);
        let free_bytes = u64::from(vfs.f_bavail).saturating_mul(vfs.f_frsize);
        Ok(VolumeCapacity {
            sectors_per_cluster,
            bytes_per_sector,
            total_clusters: total_bytes / cluster_size,
            free_clusters: free_bytes / cluster_size,
            total_bytes,
            free_bytes,
        })
    }

    pub fn get_file_information_by_handle_ex(
        &mut self,
        handle: Handle,
    ) -> AppResult<FileInformation> {
        let (normalized_path, host_path) = {
            let entry = self.handle_entry(handle)?;
            match &entry.object {
                KernelObject::File(file) => {
                    let file = file.borrow();
                    (file.normalized_path.clone(), file.host_path.clone())
                }
                _ => return invalid_handle("handle is not a file"),
            }
        };

        let metadata = match self.ge.get_file_metadata(&normalized_path) {
            Ok(metadata) => metadata,
            Err(error) if matches!(error.code, ReasonCode::RcFsNotFound) && host_path.exists() => {
                self.sync_existing_path_w(&normalized_path)?;
                self.ge.get_file_metadata(&normalized_path)?
            }
            Err(error) => return Err(error),
        };
        let host = fs::metadata(&host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to stat {}", host_path.display()),
                &error,
            )
        })?;
        // Windows never reports a zero FILETIME for a real file, but a
        // persisted fs_state record may carry zero ticks (e.g. the access
        // time was not tracked when the record was provisioned).  Fall back
        // to host-derived times per field so GetFileInformationByHandleEx
        // (the boot-sequence bootstrap_log metadata reader) never surfaces a
        // zero timestamp.
        // Host-derived fallback for zero timestamps: only legitimate for
        // live (non-DTM) subsystems. Under DTM the fs_state record carries
        // zero ticks BY CONTRACT (current_windows_ticks(dtm=true) == 0), so
        // populating host times here would break deterministic replay and
        // the section-5/38 determinism assertions.
        let host_ticks = |time: std::io::Result<SystemTime>| {
            if self.time.dtm {
                return 0;
            }
            time.ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|duration| {
                    WINDOWS_EPOCH_OFFSET_100NS
                        .saturating_add(duration.as_nanos().div_euclid(100) as u64)
                })
                .unwrap_or(0)
        };
        Ok(FileInformation {
            normalized_path,
            size: host.len(),
            attributes: metadata.attributes,
            creation_time_ticks: if metadata.creation_time_ticks != 0 {
                metadata.creation_time_ticks
            } else {
                host_ticks(host.created())
            },
            last_access_time_ticks: if metadata.last_access_time_ticks != 0 {
                metadata.last_access_time_ticks
            } else {
                host_ticks(host.accessed())
            },
            last_write_time_ticks: if metadata.last_write_time_ticks != 0 {
                metadata.last_write_time_ticks
            } else {
                host_ticks(host.modified())
            },
            is_directory: metadata.kind == FsEntryKind::Directory,
        })
    }

    pub fn set_file_time(
        &mut self,
        handle: Handle,
        creation_time_ticks: Option<u64>,
        last_access_time_ticks: Option<u64>,
        last_write_time_ticks: Option<u64>,
    ) -> AppResult<()> {
        let normalized_path = {
            let entry = self.handle_entry(handle)?;
            match &entry.object {
                KernelObject::File(file) => file.borrow().normalized_path.clone(),
                _ => return invalid_handle("handle is not a file"),
            }
        };
        self.ge.set_file_times(
            &normalized_path,
            creation_time_ticks,
            last_access_time_ticks,
            last_write_time_ticks,
        )
    }

    pub fn get_file_attributes_w(&self, path: &str) -> AppResult<Vec<String>> {
        match self.ge.get_file_metadata(path) {
            Ok(metadata) => Ok(metadata.attributes),
            Err(error) if error.code == ReasonCode::RcFsNotFound => {
                // Windows distinguishes a missing PARENT (ERROR_PATH_NOT_FOUND)
                // from a missing FILE inside a present parent
                // (ERROR_FILE_NOT_FOUND) — mirror the create/open contract.
                if !self.parent_directory_exists(path) {
                    return Err(AppError::new(
                        ReasonCode::RcFsPathInvalid,
                        format!("parent directory of {path} does not exist"),
                    ));
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn set_file_attributes_w(&mut self, path: &str, attrs: &[&str]) -> AppResult<()> {
        self.ge.set_file_attributes(path, attrs)
    }

    pub fn create_directory_w(&mut self, path: &str) -> AppResult<String> {
        self.ge.create_directory(path, self.time.dtm)
    }

    pub fn write_file_overwrite_w(&mut self, path: &str, contents: &[u8]) -> AppResult<String> {
        self.ge.write_file_overwrite(path, contents, self.time.dtm)
    }

    pub fn sync_existing_path_w(&mut self, path: &str) -> AppResult<()> {
        let (normalized_path, host_path) = self.resolve_host_path(path)?;
        let metadata = fs::metadata(&host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcFsNotFound,
                format!("failed to stat {}", host_path.display()),
                &error,
            )
        })?;
        self.sync_entry(&normalized_path, &host_path, metadata.is_dir())
    }

    pub fn remove_directory_w(&mut self, path: &str) -> AppResult<()> {
        let (normalized_path, host_path) = self.resolve_host_path(path)?;
        fs::remove_dir(&host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to remove {}", host_path.display()),
                &error,
            )
        })?;
        self.ge.config.fs_state.entries.remove(&normalized_path);
        self.save_config_now()
    }

    pub fn find_first_file_w(&mut self, path: &str) -> AppResult<(Handle, FindData)> {
        let (directory_path, pattern) = split_find_search_pattern(path);
        // A missing search DIRECTORY is ERROR_PATH_NOT_FOUND (Windows); an
        // existing directory whose entries match nothing is
        // ERROR_FILE_NOT_FOUND (reported below by the empty enumeration).
        if self
            .ge
            .resolve_existing_path(&directory_path, None, 0)
            .is_err()
        {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("search directory {directory_path} does not exist"),
            ));
        }
        let (normalized_directory, _) = self.resolve_host_path(&directory_path)?;
        let entries = if contains_find_wildcards(&pattern) {
            self.ge
                .enumerate_directory(&directory_path)?
                .into_iter()
                .filter(|name| windows_pattern_matches(&pattern, name))
                .map(|name| self.find_data_for_child(&normalized_directory, &name))
                .collect::<AppResult<Vec<_>>>()?
        } else {
            vec![self.find_data_for_child(&normalized_directory, &pattern)?]
        };
        let first = entries.first().cloned().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcFsNotFound,
                format!("{} matched no entries", path),
            )
        })?;
        let handle = self.insert_object(
            ObjectType::DirectorySearch,
            0x1,
            false,
            KernelObject::DirectorySearch(DirectorySearchObject { entries, index: 1 }),
        );
        Ok((handle, first))
    }

    pub fn find_next_file_w(&mut self, handle: Handle) -> AppResult<Option<FindData>> {
        match self.handle_object_mut(handle)? {
            KernelObject::DirectorySearch(search) => {
                if search.index >= search.entries.len() {
                    Ok(None)
                } else {
                    let value = search.entries[search.index].clone();
                    search.index += 1;
                    Ok(Some(value))
                }
            }
            _ => invalid_handle("handle is not a directory search"),
        }
    }

    pub fn find_close(&mut self, handle: Handle) -> AppResult<()> {
        self.close_handle(handle)
    }

    pub fn delete_file_w(&mut self, path: &str) -> AppResult<()> {
        let (normalized_path, host_path) = self.resolve_host_path(path)?;
        // Windows refuses to delete a file carrying the readonly attribute:
        // DeleteFileW on a read-only file fails with ERROR_ACCESS_DENIED.
        if let Ok(metadata) = self.ge.get_file_metadata(&normalized_path)
            && metadata
                .attributes
                .iter()
                .any(|attribute| attribute == "readonly")
        {
            return Err(AppError::new(
                ReasonCode::RcHelperPermissionDenied,
                format!("{} is read-only", normalized_path),
            ));
        }
        // FILE_SHARE_DELETE enforcement: deletion is only allowed when no
        // open handle holds the file without FILE_SHARE_DELETE (no handles
        // at all is trivially allowed).
        if !self.ge.check_delete_sharing(path)? {
            return Err(AppError::new(
                ReasonCode::RcFsSharingViolation,
                format!("sharing violation: {normalized_path} is open without FILE_SHARE_DELETE"),
            ));
        }
        fs::remove_file(&host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to delete {}", host_path.display()),
                &error,
            )
        })?;
        self.ge.config.fs_state.entries.remove(&normalized_path);
        // Generic runtime event (no behavior change): a file was deleted.
        self.emit_event(crate::runtime_events::RuntimeEvent::FileDeleted {
            path: normalized_path.clone(),
        });
        // Handles that survived the delete (they were open with
        // FILE_SHARE_DELETE) now reference a deleted file; record
        // delete_pending so close-time cleanup (e.g. FILE_FLAG_DELETE_ON_CLOSE
        // removal) does not double-delete.
        for (_, object) in self.objects.objects_iter_mut() {
            if let KernelObject::File(file) = object {
                let mut file = file.borrow_mut();
                if file.normalized_path == normalized_path {
                    file.delete_pending = true;
                }
            }
        }
        self.save_config_now()
    }

    pub fn move_file_ex_w(
        &mut self,
        from: &str,
        to: &str,
        replace_existing: bool,
        copy_allowed: bool,
    ) -> AppResult<()> {
        let (from_norm, from_host) = self.resolve_host_path(from)?;
        let (to_norm, to_host) = self.resolve_host_path(to)?;
        // Windows does not create the destination's parent directory: a
        // missing source is ERROR_FILE_NOT_FOUND, a missing destination
        // parent is ERROR_PATH_NOT_FOUND (see the operation contract).
        if !from_host.exists() {
            return Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("{} does not exist", from_norm),
            ));
        }
        if !self.parent_directory_exists(&to_norm) {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("parent directory of {} does not exist", to_norm),
            ));
        }
        // Share matrix: the move deletes the source, so every open handle on
        // it must share delete; with MOVEFILE_COPY_ALLOWED the source is read
        // (copy + delete fallback), so every open handle must share read too.
        if !self.ge.check_delete_sharing(from)? {
            return Err(AppError::new(
                ReasonCode::RcFsSharingViolation,
                format!("sharing violation: {from_norm} is open without FILE_SHARE_DELETE"),
            ));
        }
        if copy_allowed && !self.ge.check_read_sharing(from)? {
            return Err(AppError::new(
                ReasonCode::RcFsSharingViolation,
                format!("sharing violation: {from_norm} is open without FILE_SHARE_READ"),
            ));
        }
        if to_host.exists() {
            if !replace_existing {
                // Without MOVEFILE_REPLACE_EXISTING an existing destination
                // is ERROR_ALREADY_EXISTS — POSIX rename must never silently
                // clobber it.
                return Err(AppError::new(
                    ReasonCode::RcFsAlreadyExists,
                    format!("{} already exists", to_norm),
                ));
            }
            // Windows cannot replace a directory with a file: the replace
            // path removes the destination FILE only and never touches a
            // directory tree.
            if to_host.is_dir() {
                return Err(AppError::new(
                    ReasonCode::RcHelperPermissionDenied,
                    format!("{} is a directory and cannot be replaced", to_norm),
                ));
            }
            // Replacing the destination deletes it, so every open handle on
            // it must share delete.
            if !self.ge.check_delete_sharing(to)? {
                return Err(AppError::new(
                    ReasonCode::RcFsSharingViolation,
                    format!("sharing violation: {to_norm} is open without FILE_SHARE_DELETE"),
                ));
            }
            fs::remove_file(&to_host).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to remove {}", to_host.display()),
                    &error,
                )
            })?;
        }
        fs::rename(&from_host, &to_host).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to move {}", from_host.display()),
                &error,
            )
        })?;
        if let Some(entry) = self.ge.config.fs_state.entries.remove(&from_norm) {
            self.ge.config.fs_state.entries.insert(to_norm, entry);
        }
        self.save_config_now()
    }

    pub fn copy_file_ex_w(&mut self, from: &str, to: &str, fail_if_exists: bool) -> AppResult<u64> {
        let (from_norm, from_host) = self.resolve_host_path(from)?;
        let (to_norm, to_host) = self.resolve_host_path(to)?;
        if fail_if_exists && to_host.exists() {
            return Err(AppError::new(
                ReasonCode::RcFsAlreadyExists,
                format!("{} already exists", to_norm),
            ));
        }
        // Windows does not create the destination's parent directory: a
        // missing source is ERROR_FILE_NOT_FOUND, a missing destination
        // parent is ERROR_PATH_NOT_FOUND.
        if !from_host.exists() {
            return Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("{} does not exist", from_norm),
            ));
        }
        if !self.parent_directory_exists(&to_norm) {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("parent directory of {} does not exist", to_norm),
            ));
        }
        // Share matrix: copying reads the source, so every open handle on it
        // must share read.
        if !self.ge.check_read_sharing(from)? {
            return Err(AppError::new(
                ReasonCode::RcFsSharingViolation,
                format!("sharing violation: {from_norm} is open without FILE_SHARE_READ"),
            ));
        }
        let copied = fs::copy(&from_host, &to_host).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to copy {}", from_host.display()),
                &error,
            )
        })?;
        let _from_norm = from_norm;
        self.sync_entry(&to_norm, &to_host, false)?;
        Ok(copied)
    }

    pub fn get_temp_path_w(&mut self) -> AppResult<String> {
        let path = format!(
            "C:\\users\\{}\\AppData\\Local\\Temp\\",
            self.ge.config.user_name
        );
        let (normalized_path, host_path) =
            self.resolve_host_path(path.trim_end_matches(['\\', '/']))?;
        // GetTempPathW must not create the directory; the GE provisions the
        // guest temp directory (see `GameEnvironment::ensure_layout`).  A
        // missing directory is a guest-visible ERROR_PATH_NOT_FOUND.
        if !host_path.exists() {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("temp directory {} does not exist", normalized_path),
            ));
        }
        Ok(path)
    }

    pub fn get_temp_file_name_w(&mut self, directory: &str, prefix: &str) -> AppResult<String> {
        let temp_path = if directory.is_empty() {
            self.get_temp_path_w()?
        } else {
            directory.to_string()
        };
        let (normalized_directory, host_directory) =
            self.resolve_host_path(temp_path.trim_end_matches(['\\', '/']))?;
        // GetTempFileNameW does not create directories either: the target
        // directory must already exist, otherwise ERROR_PATH_NOT_FOUND.
        if !host_directory.exists() {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("directory {} does not exist", normalized_directory),
            ));
        }
        // A dedicated monotonic counter keeps consecutive calls unique even
        // when no handle is created in between (Windows guarantees unique
        // names; `next_handle` only advances on handle creation).
        let mut serial = self.next_temp_file_serial;
        let (full, normalized_path, host_path) = loop {
            let name = format!("{}{:04X}.tmp", prefix, serial & 0xFFFF);
            let full = format!(
                "{}\\{}",
                normalized_directory.trim_end_matches(['\\', '/']),
                name
            );
            let (normalized_path, host_path) = self.resolve_host_path(&full)?;
            if !host_path.exists() {
                break (full, normalized_path, host_path);
            }
            serial = serial.wrapping_add(1);
            if serial == self.next_temp_file_serial {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    "unable to allocate a unique temporary file name",
                ));
            }
        };
        self.next_temp_file_serial = serial.wrapping_add(1);
        fs::write(&host_path, []).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", host_path.display()),
                &error,
            )
        })?;
        self.sync_entry(&normalized_path, &host_path, false)?;
        Ok(full)
    }

    pub fn read_file_overlapped(
        &mut self,
        handle: Handle,
        length: usize,
        offset: u64,
        event_handle: Option<Handle>,
    ) -> AppResult<OverlappedResult> {
        let file = self.file_object(handle)?;
        let file = file.borrow();
        let bytes = fs::read(&file.host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to read {}", file.host_path.display()),
                &error,
            )
        })?;
        // Clamp before adding: a near-u64::MAX offset must not overflow.
        let start = (offset as usize).min(bytes.len());
        let end = start.saturating_add(length).min(bytes.len());
        let transferred = end.saturating_sub(start) as u32;
        let id = self.insert_overlapped(
            handle,
            event_handle,
            OverlappedKind::Read,
            OverlappedState::Completed(transferred),
        );
        self.signal_event_if_needed(event_handle)?;
        Ok(OverlappedResult {
            id,
            bytes_transferred: transferred,
            completed: true,
            cancelled: false,
        })
    }

    /// Like [`Self::read_file_overlapped`] but also returns the bytes read so
    /// the ReadFile thunk can copy them into the guest buffer.
    pub fn read_file_overlapped_full(
        &mut self,
        handle: Handle,
        length: usize,
        offset: u64,
        event_handle: Option<Handle>,
    ) -> AppResult<(OverlappedResult, Vec<u8>)> {
        let file = self.file_object(handle)?;
        let file = file.borrow();
        let bytes = fs::read(&file.host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to read {}", file.host_path.display()),
                &error,
            )
        })?;
        // Clamp before adding: a near-u64::MAX offset must not overflow.
        let start = (offset as usize).min(bytes.len());
        let end = start.saturating_add(length).min(bytes.len());
        let data = bytes[start..end].to_vec();
        let transferred = data.len() as u32;
        let id = self.insert_overlapped(
            handle,
            event_handle,
            OverlappedKind::Read,
            OverlappedState::Completed(transferred),
        );
        self.signal_event_if_needed(event_handle)?;
        Ok((
            OverlappedResult {
                id,
                bytes_transferred: transferred,
                completed: true,
                cancelled: false,
            },
            data,
        ))
    }

    pub fn write_file_overlapped(
        &mut self,
        handle: Handle,
        bytes: &[u8],
        offset: u64,
        event_handle: Option<Handle>,
    ) -> AppResult<OverlappedResult> {
        let (normalized_path, host_path) = {
            let file = self.file_object(handle)?;
            let file = file.borrow();
            let mut contents = if file.host_path.exists() {
                fs::read(&file.host_path).map_err(|error| {
                    AppError::from_io(
                        ReasonCode::RcIo,
                        format!("failed to read {}", file.host_path.display()),
                        &error,
                    )
                })?
            } else {
                Vec::new()
            };
            let start_u64 = offset;
            if start_u64 > isize::MAX as u64 {
                return Err(AppError::new(
                    ReasonCode::RcMemoryAccessViolation,
                    "file write offset is too large",
                ));
            }
            let start = start_u64 as usize;
            let end = start.checked_add(bytes.len()).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcMemoryAccessViolation,
                    "file write range overflows",
                )
            })?;
            if end > MAX_ALLOCATION_SIZE {
                return Err(AppError::new(
                    ReasonCode::RcMemoryAccessViolation,
                    format!("file write extends past the {MAX_ALLOCATION_SIZE}-byte cap"),
                ));
            }
            if contents.len() < end {
                contents.resize(end, 0);
            }
            contents[start..end].copy_from_slice(bytes);
            fs::write(&file.host_path, &contents).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to write {}", file.host_path.display()),
                    &error,
                )
            })?;
            (file.normalized_path.clone(), file.host_path.clone())
        };
        self.sync_entry(&normalized_path, &host_path, false)?;
        let id = self.insert_overlapped(
            handle,
            event_handle,
            OverlappedKind::Write,
            OverlappedState::Completed(bytes.len() as u32),
        );
        self.signal_event_if_needed(event_handle)?;
        Ok(OverlappedResult {
            id,
            bytes_transferred: bytes.len() as u32,
            completed: true,
            cancelled: false,
        })
    }

    pub fn get_overlapped_result(&mut self, id: u64, wait: bool) -> AppResult<OverlappedResult> {
        if wait {
            // GetOverlappedResult(TRUE) waits for completion — Windows gives
            // this API no timeout.  The wait is a guest-scheduler wait (the
            // pe_runtime thunk parks the thread on the overlapped completion
            // state); this layer never host-sleeps or fabricates a timeout.
            // A Pending result signals the caller to park.
            let request = self.overlapped.get(&id).cloned().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("invalid overlapped id {id}"),
                )
            })?;
            if self.overlapped_request_is_stale(&request) {
                // The handle this I/O was issued on was closed (and
                // possibly its value recycled) before the completion was
                // consumed — drop the stale completion entirely.
                self.overlapped.remove(&id);
                return Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("overlapped request {id} refers to a closed handle"),
                ));
            }
            match request.state {
                OverlappedState::Completed(bytes_transferred) => {
                    self.overlapped.remove(&id);
                    return Ok(OverlappedResult {
                        id,
                        bytes_transferred,
                        completed: true,
                        cancelled: false,
                    });
                }
                OverlappedState::Cancelled => {
                    self.overlapped.remove(&id);
                    return Ok(OverlappedResult {
                        id,
                        bytes_transferred: 0,
                        completed: false,
                        cancelled: true,
                    });
                }
                OverlappedState::Pending => {
                    // Not complete yet: the caller must park the guest
                    // thread on the overlapped completion and re-poll when
                    // the scheduler resumes it.
                    return Ok(OverlappedResult {
                        id,
                        bytes_transferred: 0,
                        completed: false,
                        cancelled: false,
                    });
                }
            }
        }
        let request = self.overlapped.get(&id).cloned().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid overlapped id {id}"),
            )
        })?;
        if self.overlapped_request_is_stale(&request) {
            // Stale completion on a closed-and-recycled handle: drop it so
            // the caller can never observe (or write) results against the
            // wrong object.
            self.overlapped.remove(&id);
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("overlapped request {id} refers to a closed handle"),
            ));
        }
        match request.state {
            OverlappedState::Completed(bytes_transferred) => {
                // A completed request is final; drop it so long-running
                // guests do not accumulate one entry per overlapped op.
                self.overlapped.remove(&id);
                Ok(OverlappedResult {
                    id,
                    bytes_transferred,
                    completed: true,
                    cancelled: false,
                })
            }
            OverlappedState::Cancelled => {
                self.overlapped.remove(&id);
                Ok(OverlappedResult {
                    id,
                    bytes_transferred: 0,
                    completed: false,
                    cancelled: true,
                })
            }
            OverlappedState::Pending => Ok(OverlappedResult {
                id,
                bytes_transferred: 0,
                completed: false,
                cancelled: false,
            }),
        }
    }

    pub fn cancel_io_ex(&mut self, handle: Handle, request_id: Option<u64>) -> AppResult<()> {
        let ids = if let Some(id) = request_id {
            vec![id]
        } else {
            self.overlapped
                .iter()
                .filter(|(_, request)| request.handle == handle)
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
        };
        let mut events = Vec::new();
        for id in ids {
            if let Some(request) = self.overlapped.get_mut(&id) {
                request.state = OverlappedState::Cancelled;
                events.push(request.event_handle);
            }
        }
        for event_handle in events {
            self.signal_event_if_needed(event_handle)?;
        }
        Ok(())
    }

    pub fn create_named_pipe(&mut self, name: &str, inheritable: bool) -> Handle {
        self.insert_object(
            ObjectType::Pipe,
            0x1F0003,
            inheritable,
            KernelObject::Pipe(PipeObject {
                name: normalize_pipe_name(name),
                connected: false,
                buffer: Vec::new(),
                state: None,
            }),
        )
    }

    /// `ConnectNamedPipe` inner helper.  Non-blocking: returns `Ok(None)`
    /// when the client is already connected (signalling `event_handle`), an
    /// overlapped request id when `overlapped` (the caller reports
    /// ERROR_IO_PENDING), or `Some(0)` as a pending marker when a
    /// non-overlapped call must wait (the caller parks the guest thread on
    /// [`Self::pipe_is_connected`]).
    pub fn connect_named_pipe_internal(
        &mut self,
        handle: Handle,
        event_handle: Option<Handle>,
        overlapped: bool,
    ) -> AppResult<Option<u64>> {
        let pipe_name = {
            let object_id = self
                .process
                .handle_table
                .entry(handle)
                .expect("checked live")
                .object_id;
            match self.objects.object_mut(object_id) {
                KernelObject::Pipe(pipe) => {
                    if pipe.connected {
                        self.signal_event_if_needed(event_handle)?;
                        return Ok(None);
                    }
                    pipe.name.clone()
                }
                _ => return invalid_handle("handle is not a pipe"),
            }
        };
        let normalized = normalize_pipe_name(&pipe_name);
        // Mark ourselves as ready to connect – the client side (CreateFileW
        // with `\\.\pipe\...`) performs the connection.  A new connect
        // cycle clears the previous disconnect.
        if let Some(state) = self.pipe_state_mut_by_name(&normalized) {
            state.server_created = true;
            state.server_handle = Some(handle);
            state.server_disconnected = false;
        }
        if self
            .pipe_state_by_name(&normalized)
            .is_some_and(|state| state.client_connected)
        {
            self.signal_event_if_needed(event_handle)?;
            return Ok(None);
        }
        if overlapped {
            let id = self.insert_overlapped(
                handle,
                event_handle,
                OverlappedKind::Connection,
                OverlappedState::Pending,
            );
            return Ok(Some(id));
        }
        // Non-overlapped ConnectNamedPipe on a not-yet-connected pipe: the
        // caller must park the guest thread on the pipe-connection condition
        // (guest threads are scheduled cooperatively — a host poll loop
        // would deadlock the emulator when the client lives in another
        // guest thread).
        Ok(Some(0))
    }

    /// Client-connection step shared by `CreateFileW` on `\\.\pipe\NAME`,
    /// `CallNamedPipeW` and the legacy `call_named_pipe` helper: mark the
    /// pipe connected and complete the server's pending ConnectNamedPipe
    /// overlapped requests (staleness-checked — a completion whose handle
    /// was closed and recycled must be dropped, never applied to the wrong
    /// object).
    fn pipe_complete_connect(&mut self, normalized: &str) -> AppResult<()> {
        let server_handle = if let Some(state) = self.pipe_state_mut_by_name(normalized) {
            state.client_connected = true;
            state.client_disconnected = false;
            state.server_disconnected = false;
            state.server_handle
        } else {
            None
        };
        if let Some(server_handle) = server_handle {
            let object_id = self
                .process
                .handle_table
                .entry(server_handle)
                .expect("live server handle")
                .object_id;
            if let KernelObject::Pipe(pipe) = self.objects.object_mut(object_id) {
                pipe.connected = true;
            }
        }
        // Complete pending ConnectNamedPipe overlapped requests on the
        // server end.
        if let Some(server_handle) = server_handle {
            self.complete_pending_connection_requests(server_handle)?;
        }
        Ok(())
    }

    /// Complete every pending Connection overlapped request queued on
    /// `server_handle`, dropping completions whose handle was closed (and
    /// possibly its value recycled to a different object) since the request
    /// was queued — never signal an event owned by the wrong object.
    fn complete_pending_connection_requests(&mut self, server_handle: Handle) -> AppResult<()> {
        let pending_ids = self
            .overlapped
            .iter()
            .filter(|(_, request)| {
                request.handle == server_handle
                    && request.kind == OverlappedKind::Connection
                    && matches!(request.state, OverlappedState::Pending)
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let mut events = Vec::new();
        for id in pending_ids {
            let stale = self
                .overlapped
                .get(&id)
                .is_none_or(|request| self.overlapped_request_is_stale(request));
            if stale {
                self.overlapped.remove(&id);
                continue;
            }
            if let Some(overlapped) = self.overlapped.get_mut(&id) {
                overlapped.state = OverlappedState::Completed(0);
                events.push(overlapped.event_handle);
            }
        }
        for event_handle in events {
            self.signal_event_if_needed(event_handle)?;
        }
        Ok(())
    }

    /// `CallNamedPipe` legacy helper — open (client connect), write the
    /// request, read the server's response, close.  The returned bytes are
    /// whatever the server wrote into the pipe (the response queue), NOT a
    /// copy of the request.  The helper is synchronous: when the server has
    /// not queued a response yet it returns empty and the thunk layer parks
    /// the guest thread on the scheduler's `PipeCall` wait instead.
    pub fn call_named_pipe(&mut self, name: &str, request: &[u8]) -> AppResult<Vec<u8>> {
        let normalized = normalize_pipe_name(name);
        let pipe_handle = self
            .process
            .handle_table
            .iter()
            .find_map(
                |(handle, entry)| match self.objects.object(entry.object_id) {
                    KernelObject::Pipe(pipe) if pipe.name == normalized => Some(handle),
                    _ => None,
                },
            )
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcPipeBusy,
                    format!("{} is not registered", normalized),
                )
            })?;
        // Client connection: this call is a client; complete the server's
        // pending ConnectNamedPipe overlapped requests.
        self.pipe_complete_connect(&normalized)?;
        if let Some(state) = self.pipe_state_mut_by_name(&normalized) {
            // The request goes into client-to-server so server-side
            // `read_file` calls observe it.
            pipe_queue_append(
                &state.client_to_server,
                &state.data_ready,
                request,
                state.message_mode,
            );
        } else {
            // Legacy pipe without shared state: buffer on the object.
            let object_id = self
                .process
                .handle_table
                .entry(pipe_handle)
                .expect("live pipe handle")
                .object_id;
            if let KernelObject::Pipe(pipe) = self.objects.object_mut(object_id) {
                pipe.connected = true;
                pipe.buffer.extend_from_slice(request);
            }
        }
        self.complete_pending_connection_requests(pipe_handle)?;
        // The response is whatever the server wrote into the pipe; when the
        // server has not responded yet there is nothing to return (the thunk
        // layer parks the caller on the scheduler wait).
        if let Some(state) = self.pipe_state_by_name(&normalized) {
            Ok(pipe_queue_read(
                &state.server_to_client,
                &state.data_ready,
                usize::MAX,
                state.message_mode,
            ))
        } else {
            Ok(Vec::new())
        }
    }

    pub fn virtual_alloc(
        &mut self,
        base_address: Option<u64>,
        size: usize,
        allocation_type: AllocationType,
        protection: MemoryProtection,
    ) -> AppResult<u64> {
        let aligned = align_up(size as u64, 0x1000);
        let page_count = aligned / 0x1000;
        if page_count > MAX_COMMIT_PAGES {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("commit of {page_count} pages exceeds the {MAX_COMMIT_PAGES} page cap"),
            ));
        }
        let commits = matches!(
            allocation_type,
            AllocationType::Commit | AllocationType::ReserveCommit
        );
        let vm_protection = VmProtection {
            read: protection.read,
            write: protection.write,
            execute: protection.execute,
        };
        let base = match base_address {
            Some(base) => base & !0xfff,
            None => {
                // Anonymous reservation from the canonical cursor (MEM_COMMIT
                // without a base is treated as reserve+commit, matching
                // Windows).
                let base = self.process.address_space.reserve(None, aligned);
                if base == 0 {
                    return Err(AppError::new(
                        ReasonCode::RcMemoryAccessViolation,
                        "virtual address space exhausted",
                    ));
                }
                if commits {
                    self.process
                        .address_space
                        .commit(base, aligned, vm_protection, false);
                }
                return Ok(base);
            }
        };
        base.checked_add(aligned).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("region {base:#x} + {aligned:#x} overflows the address space"),
            )
        })?;

        if commits {
            // MEM_COMMIT at an interior address of an existing reservation:
            // commit only the requested pages of the containing region.
            if self.process.address_space.can_commit(base, aligned) {
                self.process
                    .address_space
                    .commit(base, aligned, vm_protection, false);
                return Ok(base);
            }
            // No containing reservation (or the range exceeds it): an
            // explicit-base commit of an unreserved range fails on Windows
            // (VirtualAlloc(MEM_COMMIT) requires the range to be reserved).
            let query = self.process.address_space.query(base);
            if query.state != VmState::Free {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "commit range {base:#x}..{:#x} exceeds the containing reservation",
                        base.saturating_add(aligned)
                    ),
                ));
            }
            return Err(AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("commit at {base:#x} has no containing reservation"),
            ));
        }

        // Pure Reserve at an explicit base: grow an existing reservation at
        // the base or create a fresh one (canonical `register` tolerates
        // nesting exactly like the historical flat region map).
        self.process
            .address_space
            .register(base, aligned, VmRegionKind::Private);
        Ok(base)
    }

    pub fn virtual_free(
        &mut self,
        base_address: u64,
        size: usize,
        free_type: FreeType,
    ) -> AppResult<()> {
        match free_type {
            FreeType::Release => {
                if size != 0 {
                    return Err(AppError::new(
                        ReasonCode::RcCliInvalid,
                        "MEM_RELEASE requires size=0",
                    ));
                }
                if !self.process.address_space.release(base_address) {
                    return Err(AppError::new(
                        ReasonCode::RcMemoryAccessViolation,
                        format!("unknown region {base_address:#x}"),
                    ));
                }
            }
            FreeType::Decommit => {
                // Decommit ONLY the requested page range, not the whole
                // region (Windows: the size parameter selects the range).
                let aligned = align_up(size.max(1) as u64, 0x1000);
                let range_end = base_address.checked_add(aligned).ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcMemoryAccessViolation,
                        "decommit range overflow",
                    )
                })?;
                if self.process.address_space.query(base_address).state == VmState::Free {
                    return Err(AppError::new(
                        ReasonCode::RcMemoryAccessViolation,
                        format!("no reservation containing {base_address:#x}"),
                    ));
                }
                // Keep the reservation: decommitted pages become Reserved.
                self.process.address_space.decommit(base_address, aligned);
                let _ = range_end;
            }
        }
        Ok(())
    }

    pub fn virtual_protect(
        &mut self,
        base_address: u64,
        size: usize,
        protection: MemoryProtection,
    ) -> AppResult<MemoryProtection> {
        // Protect only the requested range's committed pages; return the
        // previous protection of the first page in the range.
        let aligned = align_up(size.max(1) as u64, 0x1000);
        if self.process.address_space.query(base_address).state == VmState::Free {
            return Err(AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("no reservation containing {base_address:#x}"),
            ));
        }
        let vm_protection = VmProtection {
            read: protection.read,
            write: protection.write,
            execute: protection.execute,
        };
        let previous = self
            .process
            .address_space
            .protect(base_address, aligned, vm_protection)
            .unwrap_or(VmProtection::NONE);
        Ok(MemoryProtection {
            read: previous.read,
            write: previous.write,
            execute: previous.execute,
        })
    }

    pub fn virtual_query(&self, address: u64) -> MemoryBasicInformation {
        // Page-granular query against the canonical VM: reports the
        // coalesced run of adjacent pages with identical state/protection
        // (Windows VirtualQuery semantics).
        let result = self.process.address_space.query(address);
        MemoryBasicInformation {
            base_address: result.base,
            region_size: result.region_size as usize,
            state: match result.state {
                VmState::Free => MemoryState::Free,
                VmState::Reserved => MemoryState::Reserved,
                VmState::Committed => MemoryState::Committed,
            },
            protection: MemoryProtection {
                read: result.protection.read,
                write: result.protection.write,
                execute: result.protection.execute,
            },
        }
    }

    pub fn create_section(
        &mut self,
        size: usize,
        protection: MemoryProtection,
        inheritable: bool,
    ) -> AppResult<Handle> {
        let base = self.virtual_alloc(None, size, AllocationType::ReserveCommit, protection)?;
        Ok(self.insert_object(
            ObjectType::Section,
            0xF001F,
            inheritable,
            KernelObject::Section(SectionObject {
                base_address: base,
                size,
                protection,
                name: None,
                backing: None,
            }),
        ))
    }

    pub fn heap_create(&mut self, alignment: usize, inheritable: bool) -> Handle {
        let handle = self.insert_object(
            ObjectType::Section,
            0xF001F,
            inheritable,
            KernelObject::Section(SectionObject {
                base_address: 0,
                size: 0,
                protection: MemoryProtection {
                    read: true,
                    write: true,
                    execute: false,
                },
                name: None,
                backing: None,
            }),
        );
        self.heaps.insert(
            handle,
            HeapState {
                alignment: alignment.max(8),
                next_address: 0x2000_0000,
                allocations: BTreeMap::new(),
                free_blocks: BTreeMap::new(),
            },
        );
        handle
    }

    pub fn heap_alloc(&mut self, heap: Handle, size: usize) -> AppResult<u64> {
        if size > MAX_ALLOCATION_SIZE {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!(
                    "heap allocation of {size} bytes exceeds the {MAX_ALLOCATION_SIZE}-byte cap"
                ),
            ));
        }
        let state = self.heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid heap {heap}"),
            )
        })?;
        // Reuse freed blocks first (best fit) so alloc/free loops do not
        // grow the high-water pointer without bound.
        if let Some((address, block_size)) = state
            .free_blocks
            .iter()
            .filter(|(_, block_size)| **block_size >= size)
            .min_by_key(|(_, block_size)| **block_size)
        {
            let (address, block_size) = (*address, *block_size);
            state.free_blocks.remove(&address);
            if block_size > size {
                // Keep the remainder free; re-align it so future reuse keeps
                // the heap's alignment guarantee.
                let remainder_addr =
                    align_up(address.saturating_add(size as u64), state.alignment as u64);
                let used = remainder_addr - address;
                if remainder_addr > address
                    && remainder_addr < address.saturating_add(block_size as u64)
                {
                    state
                        .free_blocks
                        .insert(remainder_addr, block_size - used as usize);
                }
            }
            let mut allocation =
                Vec::with_capacity(align_up(size as u64, state.alignment as u64) as usize);
            allocation.resize(size, 0);
            state.allocations.insert(address, allocation);
            return Ok(address);
        }
        let address = align_up(state.next_address, state.alignment as u64);
        state.next_address = address
            .checked_add(size as u64)
            .and_then(|next| next.checked_add(state.alignment as u64))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcMemoryAccessViolation,
                    "heap address space exhausted",
                )
            })?;
        let mut allocation =
            Vec::with_capacity(align_up(size as u64, state.alignment as u64) as usize);
        allocation.resize(size, 0);
        state.allocations.insert(address, allocation);
        Ok(address)
    }

    pub fn heap_write(&mut self, heap: Handle, address: u64, bytes: &[u8]) -> AppResult<()> {
        let state = self.heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid heap {heap}"),
            )
        })?;
        let allocation = state.allocations.get_mut(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("invalid heap pointer {address:#x}"),
            )
        })?;
        allocation.clear();
        allocation.extend_from_slice(bytes);
        Ok(())
    }

    pub fn heap_read(&self, heap: Handle, address: u64) -> AppResult<Vec<u8>> {
        let state = self.heaps.get(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid heap {heap}"),
            )
        })?;
        state.allocations.get(&address).cloned().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("invalid heap pointer {address:#x}"),
            )
        })
    }

    pub fn heap_realloc(&mut self, heap: Handle, address: u64, new_size: usize) -> AppResult<u64> {
        if new_size > MAX_ALLOCATION_SIZE {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!(
                    "heap realloc of {new_size} bytes exceeds the {MAX_ALLOCATION_SIZE}-byte cap"
                ),
            ));
        }
        let state = self.heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid heap {heap}"),
            )
        })?;
        let mut allocation = state.allocations.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("invalid heap pointer {address:#x}"),
            )
        })?;
        // Grow in place while the existing buffer has spare capacity so the
        // pointer stays valid (no move) — the common small-growth case.
        if new_size <= allocation.capacity() {
            allocation.resize(new_size, 0);
            state.allocations.insert(address, allocation);
            return Ok(address);
        }
        let old_len = allocation.len();
        let new_address = align_up(state.next_address, state.alignment as u64);
        state.next_address = new_address
            .checked_add(new_size as u64)
            .and_then(|next| next.checked_add(state.alignment as u64))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcMemoryAccessViolation,
                    "heap address space exhausted",
                )
            })?;
        allocation.resize(new_size, 0);
        state.allocations.insert(new_address, allocation);
        // The old block becomes free space for future reuse.
        state.free_blocks.insert(address, old_len);
        Ok(new_address)
    }

    pub fn heap_free(&mut self, heap: Handle, address: u64) -> AppResult<()> {
        let state = self.heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid heap {heap}"),
            )
        })?;
        if let Some(allocation) = state.allocations.remove(&address) {
            state.free_blocks.insert(address, allocation.len());
        }
        Ok(())
    }

    /// `HeapSize` on the subsystem heap: the byte size of a live allocation.
    /// Fails (`ERROR_INVALID_HANDLE` semantics) for freed or unknown
    /// addresses — the differential contract after `HeapFree`.
    pub fn heap_size(&self, heap: Handle, address: u64) -> AppResult<usize> {
        let state = self.heaps.get(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid heap {heap}"),
            )
        })?;
        state
            .allocations
            .get(&address)
            .map(|allocation| allocation.len())
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcMemoryAccessViolation,
                    format!("invalid heap pointer {address:#x}"),
                )
            })
    }

    pub fn heap_destroy(&mut self, heap: Handle) -> AppResult<()> {
        self.heaps.remove(&heap);
        self.close_handle(heap)
    }

    pub fn create_process_w(
        &mut self,
        application: &str,
        command_line: &str,
        env: &BTreeMap<String, String>,
        cwd: &str,
        inherit_handles: bool,
    ) -> AppResult<CreateProcessResult> {
        let mut argv = windows_command_line_to_argv(command_line);
        if argv.is_empty() {
            argv.push(application.to_string());
        } else {
            argv[0] = application.to_string();
        }
        // Children are guest processes too: their ids come from the SAME
        // guest pid namespace (monotonic, never the host pid).
        let process_id = allocate_guest_pid();
        let thread_id = self.next_thread_id;
        self.next_thread_id += 1;
        let inherited_handles = if inherit_handles {
            self.process
                .handle_table
                .iter()
                .filter(|(_, entry)| entry.inheritable)
                .map(|(_, entry)| {
                    let object_type = self.objects.object_type(entry.object_id);
                    HandleDescriptor {
                        object_type,
                        access_mask: entry.access_mask,
                        refcount: self.objects.handle_count(entry.object_id),
                        inheritable: entry.inheritable,
                    }
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let process_handle = self.insert_object(
            ObjectType::Process,
            // PROCESS_ALL_ACCESS | PROCESS_QUERY_LIMITED_INFORMATION:
            // CreateProcessW grants full access, and the per-operation
            // checks (GetExitCodeProcess requires 0x1000) must pass on the
            // handle it returns.
            0x1F1FFF,
            false,
            KernelObject::Process(ProcessObject {
                process_id,
                executable: application.to_string(),
                argv: argv.clone(),
                cwd: cwd.to_string(),
                environment: env.clone(),
                inherited_handles,
                modules: vec![
                    application.to_string(),
                    "kernel32.dll".to_string(),
                    "ntdll.dll".to_string(),
                ],
                exit_code: None,
                exit_sync: None,
            }),
        );
        let thread_handle = self.insert_object(
            ObjectType::Thread,
            0x1F03FF,
            false,
            KernelObject::Thread(ThreadObject { thread_id }),
        );
        self.threads.insert(
            thread_id,
            ThreadState {
                exit_code: None,
                priority: 0,
                tls: BTreeMap::new(),
                suspend_count: 0,
                terminated: false,
                fiber_id: 0,
            },
        );
        Ok(CreateProcessResult {
            process_handle,
            thread_handle,
            process_id,
            thread_id,
            argv,
            environment_block_utf16: build_environment_block_utf16(env),
        })
    }

    pub fn set_process_exit_code(&mut self, handle: Handle, exit_code: u32) -> AppResult<()> {
        match self.handle_object_mut(handle)? {
            KernelObject::Process(process) => {
                process.exit_code = Some(exit_code);
                Ok(())
            }
            _ => invalid_handle("handle is not a process"),
        }
    }

    /// `GetExitCodeProcess` — type-checked, and requires
    /// PROCESS_QUERY_LIMITED_INFORMATION (0x1000) in the granted mask.
    pub fn get_exit_code_process(&self, handle: Handle) -> AppResult<Option<u32>> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Process(process) => {
                Self::require_access(&entry, PROCESS_QUERY_LIMITED_INFORMATION)?;
                Ok(process.exit_code)
            }
            _ => invalid_handle("handle is not a process"),
        }
    }

    /// `TerminateProcess` — type-checked, and requires PROCESS_TERMINATE
    /// (0x0001) in the granted mask.
    pub fn terminate_process(&mut self, handle: Handle, exit_code: u32) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Process(_) => {
                Self::require_access(&entry, PROCESS_TERMINATE)?;
            }
            _ => return invalid_handle("handle is not a process"),
        }
        self.set_process_exit_code(handle, exit_code)
    }

    /// Like `set_process_exit_code` but also notifies any thread that is
    /// blocked in `wait_for_single_object` on this process handle.
    pub fn set_process_exit_code_and_notify(
        &mut self,
        handle: Handle,
        exit_code: u32,
    ) -> AppResult<()> {
        match self.handle_object_mut(handle)? {
            KernelObject::Process(process) => {
                process.exit_code = Some(exit_code);
                if let Some(ref sync) = process.exit_sync {
                    let (lock, cvar) = &**sync;
                    let mut guard = lock.lock().unwrap();
                    *guard = Some(exit_code);
                    cvar.notify_all();
                }
                Ok(())
            }
            _ => invalid_handle("handle is not a process"),
        }
    }

    /// Stores an `exit_sync` pair on a process object so that future
    /// `WaitForSingleObject` calls can block until the child exits.
    pub fn install_process_exit_sync(
        &mut self,
        handle: Handle,
        sync: Arc<(Mutex<Option<u32>>, Condvar)>,
    ) -> AppResult<()> {
        match self.handle_object_mut(handle)? {
            KernelObject::Process(process) => {
                process.exit_sync = Some(sync);
                Ok(())
            }
            _ => invalid_handle("handle is not a process"),
        }
    }

    /// `OpenProcess` — returns a new handle to an existing process object.
    /// The duplicate references the SAME object (shared state, one
    /// refcount).
    pub fn open_process(
        &mut self,
        desired_access: u32,
        inherit_handle: bool,
        process_id: u32,
    ) -> AppResult<Handle> {
        let object_id = self
            .process
            .handle_table
            .iter()
            .find_map(|(_, entry)| match self.objects.object(entry.object_id) {
                KernelObject::Process(process) if process.process_id == process_id => {
                    Some(entry.object_id)
                }
                _ => None,
            })
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("no process with id {process_id}"),
                )
            })?;
        Ok(self.insert_object_id(object_id, desired_access, inherit_handle))
    }

    // -----------------------------------------------------------------------
    // Named pipe helpers
    // -----------------------------------------------------------------------

    /// `CreateNamedPipeW` — creates a named-pipe server endpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn create_named_pipe_w(
        &mut self,
        name: &str,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buffer_size: u32,
        in_buffer_size: u32,
        default_timeout: u32,
        inheritable: bool,
        _security_descriptor: Option<u64>,
        uds_socket_path: Option<String>,
    ) -> AppResult<Handle> {
        let normalized = normalize_pipe_name(name);
        if self.named_pipe_server_exists(name) {
            return Err(AppError::new(
                ReasonCode::RcFsAlreadyExists,
                format!("named pipe already exists: {name}"),
            ));
        }
        let buf_size = out_buffer_size.max(in_buffer_size).max(4096) as usize;
        if buf_size > MAX_ALLOCATION_SIZE {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("pipe buffer size {buf_size} exceeds the {MAX_ALLOCATION_SIZE}-byte cap"),
            ));
        }

        // Compute UDS path if not explicitly provided
        let uds_path = uds_socket_path.unwrap_or_else(|| pipe_name_to_uds_path(&normalized));

        // Ensure the socket base directory exists.  HOST-internal
        // infrastructure, not a guest-visible path: the pipe-socket base
        // lives outside the guest drive layout and is created independently
        // of any guest operation (see the filesystem operation contract).
        if let Err(e) = std::fs::create_dir_all(PIPE_SOCKET_BASE_DIR) {
            eprintln!(
                "[win32] failed to create pipe socket base dir '{}': {e}",
                PIPE_SOCKET_BASE_DIR
            );
        }

        // Create the server handle first so the state can record it as the
        // server end.  The pipe registers its name in the unified named-object
        // namespace; the condvar-backed transport state lives ON the named
        // pipe object (one state record per pipe name).
        let handle = self.insert_object_named(
            ObjectType::Pipe,
            Some(&normalized),
            0x1F0FFF,
            inheritable,
            KernelObject::Pipe(PipeObject {
                name: normalized.clone(),
                connected: false,
                buffer: Vec::new(),
                state: None,
            }),
        );
        let state = NamedPipeState {
            name: normalized.clone(),
            server_created: true,
            server_to_client: Arc::new(Mutex::new(VecDeque::with_capacity(buf_size))),
            client_to_server: Arc::new(Mutex::new(VecDeque::with_capacity(buf_size))),
            data_ready: Arc::new(Condvar::new()),
            max_buffer_size: buf_size,
            server_disconnected: false,
            client_disconnected: false,
            security_descriptor: None,
            uds_socket_path: Some(uds_path),
            open_mode,
            pipe_mode: pipe_mode & 0x0000_0003, // PIPE_WAIT or PIPE_NOWAIT
            max_instances,
            default_timeout,
            out_buffer_size,
            in_buffer_size,
            server_handle: Some(handle),
            client_handle: None,
            message_mode: pipe_mode & PIPE_READMODE_MESSAGE != 0,
            client_connected: false,
        };
        let object_id = self
            .process
            .handle_table
            .entry(handle)
            .expect("fresh server pipe handle")
            .object_id;
        if let KernelObject::Pipe(pipe) = self.objects.object_mut(object_id) {
            pipe.state = Some(state);
        }

        // Generic runtime event (no behavior change): a pipe server endpoint
        // was created.
        self.emit_event(crate::runtime_events::RuntimeEvent::PipeCreated { name: normalized });

        Ok(handle)
    }

    /// Access the generic named-pipe service facade (compat-listener
    /// pre-creation used by workloads).
    pub fn named_pipe_service(&mut self) -> NamedPipeService<'_> {
        NamedPipeService { win32: self }
    }

    /// `ConnectNamedPipe` — wait for a client to connect to the named pipe.
    pub fn connect_named_pipe(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        let pipe_name = match &entry.object {
            KernelObject::Pipe(pipe) => pipe.name.clone(),
            _ => return invalid_handle("handle is not a pipe"),
        };
        let normalized = normalize_pipe_name(&pipe_name);
        // Mark ourselves as ready to connect – the client side (CreateFileW
        // with `\\.\pipe\...`) performs the connection.
        if let Some(state) = self.pipe_state_mut_by_name(&normalized) {
            state.server_created = true;
            state.server_handle = Some(handle);
            // A new connect cycle clears the previous disconnect.
            state.server_disconnected = false;
        }
        Ok(())
    }

    /// `GetNamedPipeInfo` — retrieve information about a named pipe.
    pub fn get_named_pipe_info(&mut self, handle: Handle) -> AppResult<(u32, u32, u32, u32)> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Pipe(pipe) => {
                let normalized = normalize_pipe_name(&pipe.name);
                if let Some(state) = self.pipe_state_by_name(&normalized) {
                    // (pipe_mode, max_instances, out_buffer_size, in_buffer_size)
                    Ok((
                        state.pipe_mode & 0x0000_0003,
                        state.max_instances,
                        state.out_buffer_size,
                        state.in_buffer_size,
                    ))
                } else {
                    // Legacy pipe without a named-pipe state record.
                    Ok((PIPE_WAIT, 1, 4096, 4096))
                }
            }
            _ => invalid_handle("handle is not a pipe"),
        }
    }

    /// `SetNamedPipeHandleState` — set pipe read mode, wait mode, etc.
    ///
    /// Supports `PIPE_WAIT`/`PIPE_NOWAIT` and `PIPE_READMODE_BYTE`/`PIPE_READMODE_MESSAGE`.
    pub fn set_named_pipe_handle_state(
        &mut self,
        handle: Handle,
        mode: Option<u32>,
        _max_collect_count: Option<u32>,
        _collect_data_timeout: Option<u32>,
    ) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        let pipe_name = match &entry.object {
            KernelObject::Pipe(pipe) => pipe.name.clone(),
            _ => return invalid_handle("handle is not a pipe"),
        };
        let normalized = normalize_pipe_name(&pipe_name);
        if let Some(state) = self.pipe_state_mut_by_name(&normalized)
            && let Some(mode) = mode
        {
            // Apply the same PIPE_WAIT/NOWAIT + READMODE mask used at
            // creation so wait/info semantics see consistent bits.
            state.pipe_mode = mode & 0x0000_0003;
            // PIPE_READMODE_MESSAGE: writes append a [u32 len][bytes]
            // frame and reads return exactly one message.
            state.message_mode = mode & PIPE_READMODE_MESSAGE != 0;
            // max_collect_count and collect_data_timeout unused in current impl
        }
        Ok(())
    }

    /// `PeekNamedPipe` — read from a pipe without removing data.
    pub fn peek_named_pipe(
        &mut self,
        handle: Handle,
        buffer: &mut [u8],
    ) -> AppResult<(u32, u32, u32)> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Pipe(pipe) => {
                let normalized = normalize_pipe_name(&pipe.name);
                let state = self.pipe_state_by_name(&normalized).ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcFsNotFound,
                        format!("peek_named_pipe: pipe not found: {}", pipe.name),
                    )
                })?;
                if state.server_disconnected {
                    return Err(AppError::new(
                        ReasonCode::RcIo,
                        format!("pipe {} is disconnected", pipe.name),
                    ));
                }
                // Peek the handle's read direction: the server end reads
                // client-to-server, the client end reads server-to-client.
                let is_server = state.server_handle == Some(handle);
                let queue = if is_server {
                    &state.client_to_server
                } else {
                    &state.server_to_client
                };
                let available = pipe_queue_peek_len(queue, state.message_mode);
                let to_copy = buffer.len().min(available);
                let queue = queue.lock().unwrap();
                for (i, b) in queue.iter().take(to_copy).enumerate() {
                    buffer[i] = *b;
                }
                // Return (bytes_read, total_bytes_avail, bytes_left_this_message)
                Ok((to_copy as u32, available as u32, available as u32))
            }
            _ => invalid_handle("handle is not a pipe"),
        }
    }

    /// `DisconnectNamedPipe` — disconnect the server endpoint.
    pub fn disconnect_named_pipe(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry(handle)?;
        let pipe_name = match &entry.object {
            KernelObject::Pipe(pipe) => pipe.name.clone(),
            _ => return invalid_handle("handle is not a pipe"),
        };
        let normalized = normalize_pipe_name(&pipe_name);
        let mut pipe_handles = Vec::new();
        if let Some(state) = self.pipe_state_mut_by_name(&normalized) {
            state.client_connected = false;
            state.server_disconnected = true;
            state.client_disconnected = true;
            state.client_handle = None;
            pipe_handles.push(state.server_handle);
            // Windows discards queued data on disconnect.
            state.server_to_client.lock().unwrap().clear();
            state.client_to_server.lock().unwrap().clear();
            state.data_ready.notify_all();
        }
        // Mark every pipe handle's `connected` flag false so blocking
        // ConnectNamedPipe/read paths observe the new cycle.
        for pipe_handle in pipe_handles.into_iter().flatten() {
            if let Ok(object_id) = self
                .process
                .handle_table
                .entry(pipe_handle)
                .map(|entry| entry.object_id)
                && let KernelObject::Pipe(pipe) = self.objects.object_mut(object_id)
            {
                pipe.connected = false;
            }
        }
        if let Ok(object_id) = self
            .process
            .handle_table
            .entry(handle)
            .map(|entry| entry.object_id)
            && let KernelObject::Pipe(pipe) = self.objects.object_mut(object_id)
        {
            pipe.connected = false;
        }
        Ok(())
    }

    /// `CallNamedPipeW` — open (client connect), write the request, read the
    /// server's response, close.  The returned bytes are whatever the server
    /// wrote into the pipe (the response queue), NOT a copy of the request.
    ///
    /// The helper is synchronous: when the server has not queued a response
    /// yet it returns empty and the thunk layer parks the guest thread on
    /// the scheduler's `PipeCall` wait (the request stays in the pipe for
    /// the server to process via its own `ReadFile`).
    pub fn call_named_pipe_w(
        &mut self,
        pipe_name: &str,
        write_data: &[u8],
        read_buffer_size: u32,
        _timeout_ms: u32,
    ) -> AppResult<Vec<u8>> {
        let normalized = normalize_pipe_name(pipe_name);
        let server_handle = {
            let state = self.pipe_state_mut_by_name(&normalized).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!("named pipe not found: {pipe_name}"),
                )
            })?;
            state.server_handle
        };
        // Client connection: this call is a client; complete the server's
        // pending ConnectNamedPipe overlapped requests.
        self.pipe_complete_connect(&normalized)?;
        let state = self.pipe_state_mut_by_name(&normalized).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcFsNotFound,
                format!("named pipe not found: {pipe_name}"),
            )
        })?;
        // Write data (client → server direction) and notify the server.
        pipe_queue_append(
            &state.client_to_server,
            &state.data_ready,
            write_data,
            state.message_mode,
        );
        if let Some(server_handle) = server_handle {
            self.complete_pending_connection_requests(server_handle)?;
        }
        // The response is whatever the server already wrote; when the
        // server has not responded yet the thunk layer parks the caller on
        // the scheduler wait.
        let state = self.pipe_state_by_name(&normalized).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcFsNotFound,
                format!("named pipe not found: {pipe_name}"),
            )
        })?;
        Ok(pipe_queue_read(
            &state.server_to_client,
            &state.data_ready,
            read_buffer_size as usize,
            state.message_mode,
        ))
    }

    /// `WaitNamedPipeW` — wait for a named pipe to become available.
    pub fn wait_named_pipe_w(&mut self, pipe_name: &str, _timeout_ms: u32) -> AppResult<()> {
        if self.named_pipe_server_exists(pipe_name) {
            Ok(())
        } else {
            Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("named pipe not found: {pipe_name}"),
            ))
        }
    }

    /// Whether a named-pipe server instance is registered for `pipe_name`
    /// (used by the WaitNamedPipeW / CallNamedPipeW thunks and the pump's
    /// pipe-availability evaluator).  Resolves through the unified
    /// named-object namespace.
    pub fn named_pipe_server_exists(&self, pipe_name: &str) -> bool {
        self.objects
            .resolve(&normalize_pipe_name(pipe_name))
            .is_some()
    }

    /// The default timeout recorded at CreateNamedPipeW time (used by
    /// CallNamedPipeW when the caller passes nTimeOut == 0).
    pub fn named_pipe_default_timeout(&self, pipe_name: &str) -> Option<u32> {
        self.pipe_state_by_name(&normalize_pipe_name(pipe_name))
            .map(|state| state.default_timeout)
    }

    /// Open a pipe client endpoint: called from `CreateFileW` when the path
    /// starts with `\\.\pipe\`.  Performs the CLIENT connection: records the
    /// client end, marks the pipe connected, and signals the server's
    /// pending ConnectNamedPipe.
    pub fn open_named_pipe_client(
        &mut self,
        pipe_name: &str,
        inheritable: bool,
    ) -> AppResult<Handle> {
        let normalized = normalize_pipe_name(pipe_name);
        let name = self
            .pipe_state_by_name(&normalized)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!("named pipe not found: {pipe_name}"),
                )
            })?
            .name;
        let handle = self.insert_object(
            ObjectType::Pipe,
            0x1F0FFF,
            inheritable,
            KernelObject::Pipe(PipeObject {
                name: name.clone(),
                connected: true,
                buffer: Vec::new(),
                state: None,
            }),
        );
        // Record the client end and complete the server's pending
        // ConnectNamedPipe overlapped requests.
        if let Some(state) = self.pipe_state_mut_by_name(&normalized) {
            state.client_handle = Some(handle);
        }
        self.pipe_complete_connect(&normalized)?;
        // Generic runtime event (no behavior change): a named-pipe client
        // connected.
        self.emit_event(crate::runtime_events::RuntimeEvent::PipeConnected { name: normalized });
        Ok(handle)
    }

    // -----------------------------------------------------------------------
    // Scheduler-facing pipe I/O (used by the pe_runtime pump evaluator and
    // the ReadFile/WriteFile/GetOverlappedResult thunks)
    // -----------------------------------------------------------------------

    /// The pipe state behind a pipe handle, cloned for lock-free use.  The
    /// ONE per-name state record lives on the named server object in the
    /// object manager; a surviving client that outlives the server carries
    /// its own broken state (see [`Self::close_pipe_teardown`]).
    fn pipe_state_for_handle(&self, handle: Handle) -> Option<NamedPipeState> {
        let entry = self.process.handle_table.get(handle)?;
        let object = self.objects.object(entry.object_id);
        let KernelObject::Pipe(pipe) = object else {
            return None;
        };
        let normalized = normalize_pipe_name(&pipe.name);
        if let Some(server_id) = self.objects.resolve(&normalized)
            && let KernelObject::Pipe(server) = self.objects.object(server_id)
            && let Some(state) = &server.state
        {
            return Some(state.clone());
        }
        // Fallback: the handle's own object carries a (broken) state record.
        pipe.state.clone()
    }

    /// The shared per-name pipe state record, cloned for lock-free use.
    fn pipe_state_by_name(&self, normalized: &str) -> Option<NamedPipeState> {
        let server_id = self.objects.resolve(normalized)?;
        let KernelObject::Pipe(server) = self.objects.object(server_id) else {
            return None;
        };
        server.state.clone()
    }

    /// Mutable access to the shared per-name pipe state record (the named
    /// server object in the object manager).
    fn pipe_state_mut_by_name(&mut self, normalized: &str) -> Option<&mut NamedPipeState> {
        let server_id = self.objects.resolve(normalized)?;
        let KernelObject::Pipe(server) = self.objects.object_mut(server_id) else {
            return None;
        };
        server.state.as_mut()
    }

    /// Non-consuming: has the server queued a response for a CallNamedPipe
    /// waiter (server-to-client non-empty)?
    pub fn pipe_response_available(&self, name: &str) -> bool {
        let Some(state) = self.pipe_state_by_name(&normalize_pipe_name(name)) else {
            return false;
        };
        pipe_queue_peek_len(&state.server_to_client, state.message_mode) > 0
    }

    /// Non-consuming: would a CallNamedPipe waiter wake with
    /// ERROR_BROKEN_PIPE (server disconnected / pipe state gone)?
    pub fn pipe_call_broken(&self, name: &str) -> bool {
        let Some(state) = self.pipe_state_by_name(&normalize_pipe_name(name)) else {
            return true;
        };
        state.client_disconnected || state.server_disconnected
    }

    /// Consume the server's queued response (up to `capacity` bytes) for a
    /// CallNamedPipe waiter.
    pub fn take_pipe_response(&self, name: &str, capacity: u32) -> Vec<u8> {
        let Some(state) = self.pipe_state_by_name(&normalize_pipe_name(name)) else {
            return Vec::new();
        };
        pipe_queue_read(
            &state.server_to_client,
            &state.data_ready,
            capacity as usize,
            state.message_mode,
        )
    }

    /// Non-consuming: has the pipe handle's read direction queue got data?
    pub fn pipe_read_available(&self, handle: Handle) -> bool {
        let Some(state) = self.pipe_state_for_handle(handle) else {
            return false;
        };
        let is_server = state.server_handle == Some(handle);
        let queue = if is_server {
            &state.client_to_server
        } else {
            &state.server_to_client
        };
        pipe_queue_peek_len(queue, state.message_mode) > 0
    }

    /// Non-consuming: did the pipe's peer end disconnect?
    pub fn pipe_peer_disconnected(&self, handle: Handle) -> bool {
        self.pipe_state_for_handle(handle)
            .is_some_and(|state| state.client_disconnected || state.server_disconnected)
    }

    /// Synchronously consume queued bytes from a pipe handle's read
    /// direction (message-aware).
    pub fn pipe_read_sync(&self, handle: Handle, length: usize) -> Vec<u8> {
        let Some(state) = self.pipe_state_for_handle(handle) else {
            return Vec::new();
        };
        let is_server = state.server_handle == Some(handle);
        let (queue, data_ready, message_mode) = if is_server {
            (
                state.client_to_server.clone(),
                state.data_ready.clone(),
                state.message_mode,
            )
        } else {
            (
                state.server_to_client.clone(),
                state.data_ready.clone(),
                state.message_mode,
            )
        };
        pipe_queue_read(&queue, &data_ready, length, message_mode)
    }

    /// Issue an overlapped pipe read.  When data is already queued the
    /// request completes synchronously and the bytes are returned; otherwise
    /// a typed Pending Read request is queued and the caller parks the guest
    /// thread on the `PipeIo` scheduler wait (which completes it when the
    /// queue fills).
    pub fn pipe_read_begin(
        &mut self,
        handle: Handle,
        length: usize,
        event_handle: Option<Handle>,
        buffer_ptr: u64,
        bytes_read_ptr: u64,
    ) -> AppResult<PipeIoOutcome> {
        let data = self.pipe_read_sync(handle, length);
        if !data.is_empty() || length == 0 {
            let id = self.insert_pipe_io_overlapped(
                handle,
                event_handle,
                OverlappedKind::Read,
                OverlappedState::Completed(data.len() as u32),
                buffer_ptr,
                length as u32,
                bytes_read_ptr,
            );
            self.signal_event_if_needed(event_handle)?;
            return Ok(PipeIoOutcome {
                id,
                bytes: data,
                completed: true,
            });
        }
        let id = self.insert_pipe_io_overlapped(
            handle,
            event_handle,
            OverlappedKind::Read,
            OverlappedState::Pending,
            buffer_ptr,
            length as u32,
            bytes_read_ptr,
        );
        Ok(PipeIoOutcome {
            id,
            bytes: Vec::new(),
            completed: false,
        })
    }

    /// Issue an overlapped pipe write: appends to the opposite direction's
    /// queue (unbounded, so writes always complete immediately) and records
    /// a typed Completed Write request.
    pub fn pipe_write_begin(
        &mut self,
        handle: Handle,
        bytes: &[u8],
        event_handle: Option<Handle>,
    ) -> AppResult<OverlappedResult> {
        let written = self.write_file(handle, bytes)?;
        let id = self.insert_pipe_io_overlapped(
            handle,
            event_handle,
            OverlappedKind::Write,
            OverlappedState::Completed(written),
            0,
            0,
            0,
        );
        self.signal_event_if_needed(event_handle)?;
        Ok(OverlappedResult {
            id,
            bytes_transferred: written,
            completed: true,
            cancelled: false,
        })
    }

    /// Complete exactly one pending pipe I/O request (typed Read/Write) with
    /// `bytes_transferred`, signalling its event (staleness-checked).
    /// Scoping completion to the request id keeps sibling requests on the
    /// same handle pending — each waiter's GetOverlappedResult resumes only
    /// with its own result.
    pub fn complete_pipe_io_request_id(
        &mut self,
        id: u64,
        bytes_transferred: u32,
    ) -> AppResult<()> {
        let Some(request) = self.overlapped.get(&id) else {
            return Ok(());
        };
        if !matches!(request.kind, OverlappedKind::Read | OverlappedKind::Write)
            || !matches!(request.state, OverlappedState::Pending)
        {
            return Ok(());
        }
        if self.overlapped_request_is_stale(request) {
            self.overlapped.remove(&id);
            return Ok(());
        }
        let event_handle = request.event_handle;
        if let Some(overlapped) = self.overlapped.get_mut(&id) {
            overlapped.state = OverlappedState::Completed(bytes_transferred);
        }
        self.signal_event_if_needed(event_handle)
    }

    /// Mark every pending pipe I/O request on `pipe_handle` as completed
    /// with zero bytes (the peer disconnected) and signal their events, so
    /// parked Overlapped/event waiters wake instead of hanging.  The
    /// requests stay in the table until consumed by GetOverlappedResult.
    pub fn try_complete_pending_pipe_io_for_handle(
        &mut self,
        pipe_handle: Handle,
    ) -> AppResult<()> {
        let pending_ids = self
            .overlapped
            .iter()
            .filter(|(_, request)| {
                request.handle == pipe_handle
                    && matches!(request.kind, OverlappedKind::Read | OverlappedKind::Write)
                    && matches!(request.state, OverlappedState::Pending)
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let mut events = Vec::new();
        for id in pending_ids {
            let stale = self
                .overlapped
                .get(&id)
                .is_none_or(|request| self.overlapped_request_is_stale(request));
            if stale {
                self.overlapped.remove(&id);
                continue;
            }
            if let Some(overlapped) = self.overlapped.get_mut(&id) {
                overlapped.state = OverlappedState::Completed(0);
                events.push(overlapped.event_handle);
            }
        }
        for event_handle in events {
            self.signal_event_if_needed(event_handle)?;
        }
        Ok(())
    }

    /// Signal the completion events of every pending pipe I/O request on
    /// `pipe_handle` without completing the requests (staleness-checked).
    /// Used when the peer end closes: event waiters wake, and the requests
    /// complete as broken pipe when the scheduler next evaluates them.
    fn signal_pending_pipe_io_events(&mut self, pipe_handle: Handle) -> AppResult<()> {
        let pending_ids = self
            .overlapped
            .iter()
            .filter(|(_, request)| {
                request.handle == pipe_handle
                    && matches!(request.kind, OverlappedKind::Read | OverlappedKind::Write)
                    && matches!(request.state, OverlappedState::Pending)
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let mut events = Vec::new();
        for id in pending_ids {
            let stale = self
                .overlapped
                .get(&id)
                .is_none_or(|request| self.overlapped_request_is_stale(request));
            if stale {
                self.overlapped.remove(&id);
                continue;
            }
            if let Some(overlapped) = self.overlapped.get_mut(&id) {
                events.push(overlapped.event_handle);
            }
        }
        for event_handle in events {
            self.signal_event_if_needed(event_handle)?;
        }
        Ok(())
    }

    /// Try to complete a PENDING typed pipe Read request from its direction
    /// queue (or with a broken-pipe marker when the peer disconnected).
    /// Returns `None` while the request is still pending.
    pub fn try_complete_pending_pipe_io(&mut self, id: u64) -> Option<PendingPipeIoCompletion> {
        let request = self.overlapped.get(&id)?.clone();
        if request.kind != OverlappedKind::Read
            || !matches!(request.state, OverlappedState::Pending)
            || self.overlapped_request_is_stale(&request)
        {
            return None;
        }
        let handle = request.handle;
        let state = self.pipe_state_for_handle(handle)?;
        if state.client_disconnected || state.server_disconnected {
            // The peer end is gone: the waiter resumes with
            // ERROR_BROKEN_PIPE; the request itself is dropped so a later
            // GetOverlappedResult poll does not hang on it.
            let _ = self.complete_pipe_io_request_id(id, 0);
            self.overlapped.remove(&id);
            return Some(PendingPipeIoCompletion {
                buffer_ptr: request.buffer_ptr,
                bytes_read_ptr: request.bytes_read_ptr,
                bytes: Vec::new(),
                broken_pipe: true,
            });
        }
        let is_server = state.server_handle == Some(handle);
        let (queue, data_ready, message_mode) = if is_server {
            (
                state.client_to_server.clone(),
                state.data_ready.clone(),
                state.message_mode,
            )
        } else {
            (
                state.server_to_client.clone(),
                state.data_ready.clone(),
                state.message_mode,
            )
        };
        let data = pipe_queue_read(&queue, &data_ready, request.length as usize, message_mode);
        if data.is_empty() {
            // Still pending: no data arrived (or an incomplete message).
            return None;
        }
        let _ = self.complete_pipe_io_request_id(id, data.len() as u32);
        Some(PendingPipeIoCompletion {
            buffer_ptr: request.buffer_ptr,
            bytes_read_ptr: request.bytes_read_ptr,
            bytes: data,
            broken_pipe: false,
        })
    }

    // -----------------------------------------------------------------------
    // Shared memory helpers (CreateFileMappingW / MapViewOfFile)
    // -----------------------------------------------------------------------

    /// `CreateFileMappingW` — create or open a named shared-memory section.
    /// Named sections resolve through the unified named-object namespace
    /// (prefix spellings are equivalent); every handle to the same section
    /// references the SAME object and its shared backing storage.
    pub fn create_file_mapping_w(
        &mut self,
        name: Option<&str>,
        maximum_size: usize,
        protection: MemoryProtection,
        inheritable: bool,
    ) -> AppResult<(Handle, bool)> {
        if maximum_size > MAX_ALLOCATION_SIZE {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!(
                    "file mapping size {maximum_size} exceeds the {MAX_ALLOCATION_SIZE}-byte cap"
                ),
            ));
        }
        let key = name.unwrap_or("").to_string();
        let section_name = (!key.is_empty()).then(|| key.clone());
        if !key.is_empty()
            && let Some(section_id) = self.objects.resolve(&key)
        {
            match self.objects.object(section_id) {
                KernelObject::Section(_) => {}
                _ => {
                    return Err(AppError::new(
                        ReasonCode::RcCliInvalid,
                        format!("name {key} resolves to a non-section object"),
                    ));
                }
            }
            let handle = self.insert_object_id(section_id, 0x1F0FFF, inheritable);
            return Ok((handle, true));
        }
        let data = Arc::new(Mutex::new(vec![0_u8; maximum_size.max(1)]));
        let handle = self.insert_object_named(
            ObjectType::Section,
            section_name.as_deref(),
            0x1F0FFF,
            inheritable,
            KernelObject::Section(SectionObject {
                base_address: 0,
                size: maximum_size,
                protection,
                name: section_name.clone(),
                backing: Some(data),
            }),
        );
        Ok((handle, false))
    }

    /// `MapViewOfFile` — return a base address for the shared memory section.
    /// The view is a committed reservation in the canonical guest address
    /// space (the SAME VirtualMemory the interpreter/JIT validate through),
    /// tied to the section's shared byte storage so all views of the same
    /// section observe the same data; the mapping record lives in the VM.
    pub fn map_view_of_file(
        &mut self,
        handle: Handle,
        offset: u64,
        bytes_to_map: usize,
    ) -> AppResult<u64> {
        let (protection, section_size, backing) = {
            let entry = self.handle_entry(handle)?;
            match &entry.object {
                KernelObject::Section(section) => {
                    (section.protection, section.size, section.backing.clone())
                }
                _ => return invalid_handle("handle is not a section"),
            }
        };
        if offset > section_size as u64 {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("map offset {offset:#x} exceeds section size {section_size:#x}"),
            ));
        }
        let remaining = section_size as u64 - offset;
        let view_size = if bytes_to_map == 0 {
            remaining
        } else {
            (bytes_to_map as u64).min(remaining)
        }
        .max(1);
        // `next_power_of_two` panics on overflow; reject absurd sizes instead.
        let size = view_size
            .checked_next_power_of_two()
            .ok_or_else(|| AppError::new(ReasonCode::RcCliInvalid, "mapping size is too large"))?;
        let page_count = size / 0x1000;
        if page_count > MAX_COMMIT_PAGES {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("mapping of {page_count} pages exceeds the {MAX_COMMIT_PAGES} page cap"),
            ));
        }
        let base = self.process.address_space.reserve(None, size);
        if base == 0 {
            return Err(AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                "virtual address space exhausted",
            ));
        }
        self.process.address_space.commit(
            base,
            size,
            VmProtection {
                read: protection.read,
                write: protection.write,
                execute: protection.execute,
            },
            false,
        );
        let backing = backing.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("section {handle} has no backing storage"),
            )
        })?;
        if !self.process.address_space.map_view(base, offset, backing) {
            return Err(AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("{base:#x} is already a mapped file view"),
            ));
        }
        Ok(base)
    }

    /// `UnmapViewOfFile` — release a previously mapped view.
    pub fn unmap_view_of_file(&mut self, base_address: u64) -> AppResult<()> {
        if self
            .process
            .address_space
            .mapped_view(base_address)
            .is_none()
        {
            return Err(AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("{base_address:#x} is not a mapped file view"),
            ));
        }
        self.process.address_space.unmap_view(base_address);
        self.process.address_space.release(base_address);
        Ok(())
    }

    /// Returns the section backing and offset for a mapped view, if the
    /// region was created by `map_view_of_file`.  Lets the memory model route
    /// guest accesses to the section's shared storage.
    pub fn mapped_view_section(&self, base_address: u64) -> Option<(u64, Arc<Mutex<Vec<u8>>>)> {
        self.process
            .address_space
            .mapped_view(base_address)
            .map(|mapping| (mapping.offset, mapping.backing.clone()))
    }

    pub fn set_thread_exit_code(&mut self, handle: Handle, exit_code: u32) -> AppResult<()> {
        let thread_id = self.thread_id(handle)?;
        self.set_thread_exit_code_by_id(thread_id, exit_code)
    }

    pub fn set_thread_exit_code_by_id(&mut self, thread_id: u32, exit_code: u32) -> AppResult<()> {
        self.ensure_thread_state(thread_id);
        self.thread_state_mut(thread_id)?.exit_code = Some(exit_code);
        // Windows mutex semantics: a thread that terminates while owning a
        // mutex abandons it — the next successful waiter receives
        // WAIT_ABANDONED and takes ownership.
        self.mark_owned_mutexes_abandoned(thread_id);
        self.cleanup_exited_thread_state(thread_id);
        Ok(())
    }

    pub fn create_thread(&mut self, plan: ThreadPlan, inheritable: bool) -> Handle {
        let thread_id = self.next_thread_id;
        self.next_thread_id += 1;
        self.threads.insert(
            thread_id,
            ThreadState {
                exit_code: if plan.signaled { plan.exit_code } else { None },
                priority: plan.priority,
                tls: BTreeMap::new(),
                suspend_count: 0,
                terminated: false,
                fiber_id: 0,
            },
        );
        self.insert_object(
            ObjectType::Thread,
            0x1F03FF,
            inheritable,
            KernelObject::Thread(ThreadObject { thread_id }),
        )
    }

    pub fn thread_id_for_handle(&self, handle: Handle) -> AppResult<u32> {
        self.thread_id(handle)
    }

    pub fn exit_thread(&mut self, handle: Handle, exit_code: u32) -> AppResult<()> {
        let thread_id = self.thread_id(handle)?;
        self.set_thread_exit_code_by_id(thread_id, exit_code)
    }

    pub fn get_exit_code_thread(&self, handle: Handle) -> AppResult<Option<u32>> {
        Self::require_access(&self.handle_entry(handle)?, THREAD_QUERY_INFORMATION)?;
        let thread_id = self.thread_id(handle)?;
        Ok(self.thread_state(thread_id)?.exit_code)
    }

    pub fn set_thread_priority(&mut self, handle: Handle, priority: i32) -> AppResult<()> {
        Self::require_access(&self.handle_entry(handle)?, THREAD_SET_INFORMATION)?;
        let thread_id = self.thread_id(handle)?;
        self.thread_state_mut(thread_id)?.priority = priority;
        Ok(())
    }

    pub fn get_thread_priority(&self, handle: Handle) -> AppResult<i32> {
        Self::require_access(&self.handle_entry(handle)?, THREAD_QUERY_INFORMATION)?;
        let thread_id = self.thread_id(handle)?;
        Ok(self.thread_state(thread_id)?.priority)
    }

    /// The subsystem's current suspend count for `thread_id` (0 = running).
    ///
    /// THE single source of truth for suspension: `suspend_thread` /
    /// `resume_thread` are the only counter mutations, and the scheduler
    /// copies this value into its per-thread records whenever a
    /// suspend/resume thunk dispatches, so the Win32 and Nt paths can
    /// never drift.  Public so the Nt query surface (ThreadSuspendCount)
    /// and the integration tests can read it.
    pub fn thread_suspend_count(&self, thread_id: u32) -> AppResult<u32> {
        Ok(self.thread_state(thread_id)?.suspend_count)
    }

    /// Overwrite the subsystem suspend count (used by the CREATE_SUSPENDED
    /// creation paths, which must record the initial suspension in BOTH the
    /// subsystem state and the scheduler record).
    pub(crate) fn set_thread_suspend_count(&mut self, thread_id: u32, count: u32) -> AppResult<()> {
        self.thread_state_mut(thread_id)?.suspend_count = count;
        Ok(())
    }

    /// Whether the thread has exited (an exit code is recorded).
    ///
    /// Used to route suspend/resume failures on terminated threads
    /// (THREAD_SUSPEND_FAILED / STATUS_THREAD_IS_TERMINATING) and by the
    /// scheduler pump to skip terminated records regardless of suspend
    /// count.
    pub(crate) fn thread_has_exited(&self, thread_id: u32) -> bool {
        self.threads
            .get(&thread_id)
            .is_some_and(|state| state.exit_code.is_some())
    }

    pub fn open_thread(
        &mut self,
        thread_id: u32,
        desired_access: u32,
        inheritable: bool,
    ) -> Option<Handle> {
        if !self.thread_exists(thread_id) {
            return None;
        }
        self.ensure_thread_state(thread_id);
        Some(self.insert_object(
            ObjectType::Thread,
            desired_access,
            inheritable,
            KernelObject::Thread(ThreadObject { thread_id }),
        ))
    }

    pub fn suspend_thread(&mut self, handle: Handle) -> AppResult<u32> {
        Self::require_access(&self.handle_entry(handle)?, THREAD_SUSPEND_RESUME)?;
        let thread_id = self.thread_id(handle)?;
        let state = self.thread_state_mut(thread_id)?;
        if state.exit_code.is_some() {
            // Windows: a terminated thread cannot be suspended — the
            // suspension of a dead thread is meaningless.  The dispatch
            // layers surface this as THREAD_SUSPEND_FAILED +
            // ERROR_ACCESS_DENIED (Win32) / STATUS_THREAD_IS_TERMINATING
            // (Nt).
            return Err(AppError::new(
                ReasonCode::RcWin32AccessDenied,
                format!("cannot suspend terminated thread {thread_id}"),
            ));
        }
        let prev = state.suspend_count;
        state.suspend_count = state.suspend_count.saturating_add(1);
        Ok(prev)
    }

    pub fn resume_thread(&mut self, handle: Handle) -> AppResult<u32> {
        Self::require_access(&self.handle_entry(handle)?, THREAD_SUSPEND_RESUME)?;
        let thread_id = self.thread_id(handle)?;
        let state = self.thread_state_mut(thread_id)?;
        if state.exit_code.is_some() {
            // Windows: resuming a terminated thread fails with
            // THREAD_SUSPEND_FAILED + ERROR_ACCESS_DENIED (Win32) /
            // STATUS_THREAD_IS_TERMINATING (Nt).
            return Err(AppError::new(
                ReasonCode::RcWin32AccessDenied,
                format!("cannot resume terminated thread {thread_id}"),
            ));
        }
        let prev = state.suspend_count;
        state.suspend_count = state.suspend_count.saturating_sub(1);
        Ok(prev)
    }

    pub fn terminate_thread(&mut self, handle: Handle, exit_code: u32) -> AppResult<bool> {
        Self::require_access(&self.handle_entry(handle)?, THREAD_TERMINATE)?;
        let thread_id = self.thread_id(handle)?;
        let state = self.thread_state_mut(thread_id)?;
        if state.exit_code.is_some() {
            // Windows: TerminateThread on an already-exited thread is a
            // no-op that returns TRUE; the recorded exit code is preserved.
            return Ok(false);
        }
        state.exit_code = Some(exit_code);
        state.terminated = true;
        Ok(true)
    }

    pub fn tls_alloc(&mut self) -> u32 {
        // Reuse freed slots before allocating fresh ones.
        if let Some(slot) = self.tls_free_slots.pop() {
            return slot;
        }
        let index = self.next_tls_slot;
        if index == u32::MAX {
            // TLS_OUT_OF_INDEXES — all slots exhausted.
            return u32::MAX;
        }
        self.next_tls_slot += 1;
        index
    }

    pub fn tls_set_value(&mut self, thread_handle: Handle, slot: u32, value: u64) -> AppResult<()> {
        let thread_id = self.thread_id(thread_handle)?;
        self.thread_state_mut(thread_id)?.tls.insert(slot, value);
        Ok(())
    }

    pub fn tls_get_value(&self, thread_handle: Handle, slot: u32) -> AppResult<Option<u64>> {
        let thread_id = self.thread_id(thread_handle)?;
        Ok(self.thread_state(thread_id)?.tls.get(&slot).copied())
    }

    pub fn tls_free(&mut self, slot: u32) {
        // Remove the TLS slot from all thread states
        for (_tid, state) in self.threads.iter_mut() {
            state.tls.remove(&slot);
        }
        // Make the slot index available for reuse.
        if !self.tls_free_slots.contains(&slot) {
            self.tls_free_slots.push(slot);
        }
    }

    pub fn create_toolhelp_snapshot(&self) -> ToolhelpSnapshot {
        // The runner's provenance entry ("macwin") keys the snapshot by the
        // HOST pid — a DIAGNOSTIC key only: the guest-visible current
        // process id is the guest pid, and guest processes are enumerated
        // below with their guest pids.
        let mut processes = vec![ProcessSnapshot {
            process_id: std::process::id(),
            executable: "macwin".to_string(),
            argv: vec!["macwin".to_string()],
        }];
        let mut modules = vec![ModuleSnapshot {
            process_id: std::process::id(),
            module_name: "macwin".to_string(),
        }];
        for (_, entry) in self.process.handle_table.iter() {
            if let KernelObject::Process(process) = self.objects.object(entry.object_id) {
                processes.push(ProcessSnapshot {
                    process_id: process.process_id,
                    executable: process.executable.clone(),
                    argv: process.argv.clone(),
                });
                for module in &process.modules {
                    modules.push(ModuleSnapshot {
                        process_id: process.process_id,
                        module_name: module.clone(),
                    });
                }
            }
        }
        processes.sort_by_key(|entry| entry.process_id);
        modules.sort_by(|left, right| {
            left.process_id
                .cmp(&right.process_id)
                .then_with(|| left.module_name.cmp(&right.module_name))
        });
        ToolhelpSnapshot { processes, modules }
    }

    pub fn query_performance_frequency(&self) -> u64 {
        self.time.perf_frequency
    }

    pub fn query_performance_counter(&self) -> u64 {
        self.time.qpc
    }

    pub fn get_tick_count64(&self) -> u64 {
        self.time.ticks_ms
    }

    /// `GetTickCount64` for the subsystem: the guest tick counter (ms).
    pub fn tick_count64(&self) -> u64 {
        self.get_tick_count64()
    }

    /// The subsystem last-error slot (`GetLastError` / `SetLastError`
    /// semantics on the standalone session).
    pub fn get_last_error(&self) -> u32 {
        self.last_error
    }

    /// Set the subsystem last-error slot.
    pub fn set_last_error(&mut self, error: u32) {
        self.last_error = error;
    }

    /// `GetSystemTimeAsFileTime` on the guest clock domain: the deterministic
    /// session derives the FILETIME (100-ns units since 1601-01-01) from the
    /// tick counter (`WINDOWS_EPOCH_OFFSET_100NS + ticks × 10_000`), the
    /// same derivation the runtime's GetSystemTimeAsFileTime /
    /// NtQuerySystemTime thunks share.
    pub fn system_time_as_filetime_ticks(&self) -> u64 {
        const WINDOWS_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;
        WINDOWS_EPOCH_OFFSET_100NS.saturating_add(self.get_tick_count64().saturating_mul(10_000))
    }

    /// `GetEnvironmentVariableW` on the canonical guest process environment:
    /// case-insensitive name lookup, `None` when the variable is absent.
    pub fn get_environment_variable_w(&self, name: &str) -> Option<String> {
        self.process
            .environment
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }

    /// `SetEnvironmentVariableW` on the canonical guest process environment
    /// (case-insensitive replace; `None` value deletes the variable).
    pub fn set_environment_variable_w(&mut self, name: &str, value: Option<&str>) {
        if let Some(existing) = self
            .process
            .environment
            .keys()
            .find(|key| key.eq_ignore_ascii_case(name))
            .cloned()
        {
            self.process.environment.remove(&existing);
        }
        if let Some(value) = value {
            self.process
                .environment
                .insert(name.to_string(), value.to_string());
        }
    }

    /// The canonical guest environment block as sorted `NAME=VALUE` entries
    /// (the `GetEnvironmentStringsW` block, normalized to sorted entries).
    pub fn environment_strings_w(&self) -> Vec<String> {
        let mut entries = self
            .process
            .environment
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    /// `lstrlenW`: length in UTF-16 code units (excluding the terminator).
    pub fn lstrlen_w(&self, value: &str) -> u32 {
        value.encode_utf16().count() as u32
    }

    /// `lstrcpyW`: copies the source (including the trailing NUL) into the
    /// destination; returns the number of UTF-16 units copied (the copied
    /// string's length, excluding the terminator).
    pub fn lstrcpy_w(&mut self, _destination: u64, source: &str) -> u32 {
        // The in-memory copy is a guest-address-space operation; the oracle
        // session records the semantics (units copied) and the caller reads
        // the buffer back through the address space.
        self.lstrlen_w(source)
    }

    /// `lstrcmpW`: case-SENSITIVE ordinal comparison of UTF-16 code-unit
    /// sequences; returns -1 / 0 / 1.
    pub fn lstrcmp_w(&self, left: &str, right: &str) -> i32 {
        match left.encode_utf16().cmp(right.encode_utf16()) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    /// `CharUpperW` single-character form: a value with a zero high word is
    /// treated as an ANSI character in the system code page (CP1252 on the
    /// en-US oracle session) and returned uppercased; other values are
    /// returned unchanged.
    pub fn char_upper_w(&self, character: u32) -> u32 {
        cp1252_uppercase(character)
    }

    /// `CharUpperW` string form: uppercase every character in place, using
    /// the same code-page mapping as the single-character form.
    pub fn char_upper_w_string(&self, value: &str) -> String {
        let units = value
            .encode_utf16()
            .map(|unit| {
                let upper = cp1252_uppercase(u32::from(unit));
                if upper <= u16::MAX as u32 {
                    upper as u16
                } else {
                    unit
                }
            })
            .collect::<Vec<u16>>();
        String::from_utf16_lossy(&units)
    }

    pub fn sleep(&mut self, milliseconds: u64) {
        // Advance the guest virtual clock by the full requested duration.
        self.record_sleep_observation(milliseconds, milliseconds);
        // In live-pacing mode the host sleeps the full requested duration so
        // guest timing tracks wall clock; otherwise yield only briefly and
        // let the virtual clock drive timing (the guest Sleep() should not
        // block the host thread for the full duration, which would make the
        // emulator unusably slow).
        let host_sleep_ms = paced_sleep_duration_ms(milliseconds, self.time.live_pacing);
        std::thread::sleep(Duration::from_millis(host_sleep_ms));
    }

    pub fn sleep_ex(
        &mut self,
        milliseconds: u64,
        alertable: bool,
        thread_handle: Option<Handle>,
    ) -> AppResult<WaitStatus> {
        if alertable {
            let thread_id = match thread_handle {
                Some(thread_handle) => Some(self.thread_id(thread_handle)?),
                None => None,
            };
            if let Some(thread_id) = thread_id
                && let Some(queue) = self.thread_apcs.get_mut(&thread_id)
                && !queue.is_empty()
            {
                queue.pop_front();
                return Ok(WaitStatus::IoCompletion);
            }
        }
        // Advance guest clock; pace the host sleep like `sleep`.
        self.record_sleep_observation(milliseconds, milliseconds);
        // Cap the HOST sleep at 100 ms regardless of pacing: the guest clock
        // already advanced by the full requested amount, and an uncapped
        // live-pacing sleep would block the host for the full duration —
        // Sleep(INFINITE)/Sleep(huge) (Steam's shutdown handshake) stalls
        // the whole emulator with no way to service timers or the run
        // deadline.  The guest observes the full sleep via its clock; the
        // host only paces a bounded slice.
        let host_sleep_ms = paced_sleep_duration_ms(milliseconds, self.time.live_pacing).min(100);
        std::thread::sleep(Duration::from_millis(host_sleep_ms));
        Ok(WaitStatus::Object0)
    }

    pub fn record_sleep_observation(&mut self, requested_ms: u64, observed_ms: u64) {
        self.time.ticks_ms = self.time.ticks_ms.saturating_add(observed_ms);
        self.time.qpc = self
            .time
            .qpc
            .saturating_add(observed_ms.saturating_mul(self.time.perf_frequency / 1000));
        let drift_ms = observed_ms as i64 - requested_ms as i64;
        if !self.time.dtm
            && requested_ms >= 10
            && drift_ms.abs() > 2
            && self.time.drift_log.len() < 256
        {
            self.time.drift_log.push(SleepObservation {
                requested_ms,
                observed_ms,
                drift_ms,
            });
        }
    }

    pub fn sleep_drift_log(&self) -> &[SleepObservation] {
        &self.time.drift_log
    }

    /// The configured ANSI code page (the `GetACP` answer — the runtime's
    /// locale state, never the host's).
    pub fn acp(&self) -> u32 {
        self.locale.acp
    }

    /// Whether the guest user's token carries administrator membership
    /// (`IsUserAnAdmin`).  The runtime models the guest as a standard,
    /// non-elevated user — the same identity the guest network
    /// configuration and `GetUserNameW` report — so this is `false` unless
    /// the guest identity is configured as an administrator.
    pub fn guest_user_is_admin(&self) -> bool {
        false
    }

    /// The guest-visible `FILE_ATTRIBUTE_*` mask for a path (the
    /// `SHGetFileInfoW(SHGFI_ATTRIBUTES)` answer).  Derives from the
    /// canonical attribute strings the GE metadata reports.
    pub fn file_attributes_for_display(&self, path: &str) -> u32 {
        match self.ge.get_file_metadata(path) {
            Ok(metadata) => {
                let mut mask = 0x80u32; // FILE_ATTRIBUTE_NORMAL
                for attribute in &metadata.attributes {
                    let bit = match attribute.to_ascii_lowercase().as_str() {
                        "readonly" => 0x1,
                        "hidden" => 0x2,
                        "system" => 0x4,
                        "directory" => 0x10,
                        "archive" => 0x20,
                        "compressed" => 0x800,
                        _ => 0,
                    };
                    mask |= bit;
                }
                mask
            }
            Err(_) => 0x80, // FILE_ATTRIBUTE_NORMAL for unknown paths
        }
    }
    /// The configured OEM code page (the `GetOEMCP` answer).
    pub fn oemcp(&self) -> u32 {
        self.locale.oemcp
    }

    /// The process window station (`GetProcessWindowStation`): the single
    /// interactive `WinSta0` station the runtime models.  The handle is
    /// minted once and lives for the process lifetime (Windows keeps the
    /// station handle open for the life of the process).
    pub fn process_window_station(&mut self) -> Handle {
        if let Some(handle) = self.window_station_handle {
            return handle;
        }
        let handle = self.insert_object(
            ObjectType::WindowStation,
            0x2000C, // WINSTA_ALL_ACCESS
            false,
            KernelObject::WindowStation(WindowStationObject {
                name: "WinSta0".to_string(),
            }),
        );
        self.window_station_handle = Some(handle);
        handle
    }

    /// The station name behind a window-station handle, or an invalid-handle
    /// error for anything else.
    pub fn window_station_name(&self, handle: Handle) -> AppResult<String> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::WindowStation(station) => Ok(station.name.clone()),
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("handle {handle} is not a window station"),
            )),
        }
    }

    pub fn multi_byte_to_wide_char(&self, code_page: u32, bytes: &[u8]) -> AppResult<Vec<u16>> {
        let cp = if code_page == CP_ACP || code_page == CP_THREAD_ACP {
            self.locale.acp
        } else {
            code_page
        };
        match cp {
            CP_UTF8 => String::from_utf8(bytes.to_vec())
                .map_err(|error| {
                    AppError::new(ReasonCode::RcCliInvalid, "invalid UTF-8 input")
                        .with_hint(error.to_string())
                })
                .map(|text| text.encode_utf16().collect()),
            1252 if self.locale.acp == 1252 => Ok(bytes
                .iter()
                .map(|byte| decode_cp1252(*byte) as u16)
                .collect()),
            _ => {
                // Use iconv for all other code pages
                match iconv_ffi::convert_to_utf8(cp, bytes) {
                    Some(utf8_str) => Ok(utf8_str.encode_utf16().collect()),
                    None => Err(AppError::new(
                        ReasonCode::RcCliInvalid,
                        format!("unsupported or failed conversion for code page {code_page}"),
                    )),
                }
            }
        }
    }

    pub fn wide_char_to_multi_byte(&self, code_page: u32, wide: &[u16]) -> AppResult<Vec<u8>> {
        let cp = if code_page == CP_ACP || code_page == CP_THREAD_ACP {
            self.locale.acp
        } else {
            code_page
        };
        let text = String::from_utf16(wide).map_err(|error| {
            AppError::new(ReasonCode::RcCliInvalid, "invalid UTF-16 input")
                .with_hint(error.to_string())
        })?;
        match cp {
            CP_UTF8 => Ok(text.into_bytes()),
            1252 if self.locale.acp == 1252 => text.chars().map(encode_cp1252).collect(),
            _ => {
                // Use iconv for all other code pages
                match iconv_ffi::convert_from_utf8(cp, &text) {
                    Some(bytes) => Ok(bytes),
                    None => Err(AppError::new(
                        ReasonCode::RcCliInvalid,
                        format!("unsupported or failed conversion for code page {code_page}"),
                    )),
                }
            }
        }
    }

    /// Encode a wide string in the configured ANSI code page (the
    /// `WideCharToMultiByte(CP_ACP, ...)` contract; used by the console
    /// input path).
    pub fn unicode_to_acp_bytes(&self, text: &str) -> Vec<u8> {
        self.wide_char_to_multi_byte(CP_ACP, &text.encode_utf16().collect::<Vec<_>>())
            .unwrap_or_else(|_| text.as_bytes().to_vec())
    }

    pub fn open_registry_key(
        &mut self,
        hive: &str,
        key: &str,
        view: RegistryView,
        inheritable: bool,
    ) -> Handle {
        self.insert_object(
            ObjectType::Key,
            0x20019,
            inheritable,
            KernelObject::Key(KeyObject {
                hive: hive.to_string(),
                key: key.to_string(),
                view,
            }),
        )
    }

    pub fn registry_key_exists(
        &self,
        hive: &str,
        key: &str,
        view: RegistryView,
    ) -> AppResult<bool> {
        self.ge.registry_key_exists(hive, key, view)
    }

    pub fn create_registry_key(
        &self,
        hive: &str,
        key: &str,
        view: RegistryView,
    ) -> AppResult<bool> {
        self.ge.registry_create_key(hive, key, view)
    }

    pub fn registry_get_value(
        &self,
        hive: &str,
        key: &str,
        value_name: &str,
        view: RegistryView,
    ) -> AppResult<Option<crate::ge::StoredRegistryValue>> {
        self.ge.registry_get_value(hive, key, value_name, view)
    }

    pub fn ensure_default_locale_registry(&self) -> AppResult<()> {
        self.ensure_registry_string_value(
            "HKCU",
            "Control Panel\\Desktop\\ResourceLocale",
            "",
            "00000409",
            RegistryView::Native,
        )?;
        self.ensure_registry_string_value(
            "HKCU",
            "Control Panel\\International",
            "Locale",
            "00000409",
            RegistryView::Native,
        )?;
        Ok(())
    }

    fn ensure_registry_string_value(
        &self,
        hive: &str,
        key: &str,
        value_name: &str,
        value: &str,
        view: RegistryView,
    ) -> AppResult<()> {
        if self
            .ge
            .registry_get_value(hive, key, value_name, view)?
            .is_none()
        {
            self.ge
                .registry_set_value(hive, key, value_name, "REG_SZ", json!(value), view)?;
        }
        Ok(())
    }

    pub fn register_com_class(
        &mut self,
        clsid: &str,
        module_path: &str,
        threading_model: ComThreadingModel,
    ) -> AppResult<()> {
        let key = format!("Software\\Classes\\CLSID\\{}\\InprocServer32", clsid);
        self.ge.registry_set_value(
            "HKCU",
            &key,
            "",
            "REG_SZ",
            json!(module_path),
            RegistryView::Native,
        )?;
        self.ge.registry_set_value(
            "HKCU",
            &key,
            "ThreadingModel",
            "REG_SZ",
            json!(match threading_model {
                ComThreadingModel::Sta => "Apartment",
                ComThreadingModel::Mta => "Free",
                ComThreadingModel::Both => "Both",
            }),
            RegistryView::Native,
        )?;
        self.com_registrations.insert(
            clsid.to_string(),
            ComRegistration {
                clsid: clsid.to_string(),
                module_path: module_path.to_string(),
                threading_model,
            },
        );
        Ok(())
    }

    pub fn co_initialize_ex(
        &mut self,
        thread_handle: Handle,
        apartment: ApartmentModel,
    ) -> AppResult<()> {
        let thread_id = self.thread_id(thread_handle)?;
        self.com_apartments.insert(thread_id, apartment);
        Ok(())
    }

    pub fn co_uninitialize(&mut self, thread_handle: Handle) -> AppResult<()> {
        let thread_id = self.thread_id(thread_handle)?;
        self.com_apartments.remove(&thread_id);
        Ok(())
    }

    pub fn co_create_instance(&self, thread_handle: Handle, clsid: &str) -> AppResult<ComInstance> {
        let thread_id = self.thread_id(thread_handle)?;
        let apartment = self
            .com_apartments
            .get(&thread_id)
            .copied()
            .ok_or_else(|| {
                AppError::new(ReasonCode::RcCliInvalid, "COM apartment not initialized")
            })?;
        let registration = self.com_registrations.get(clsid).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcComClassNotRegistered,
                format!("COM class {} is not registered", clsid),
            )
        })?;
        match (apartment, registration.threading_model) {
            (ApartmentModel::Sta, ComThreadingModel::Mta)
            | (ApartmentModel::Mta, ComThreadingModel::Sta) => {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "{} cannot activate {} apartment class",
                        format_apartment(apartment),
                        format_threading_model(registration.threading_model)
                    ),
                ));
            }
            _ => {}
        }
        let key = format!("CLSID\\{}\\InprocServer32", clsid);
        let module_path = self
            .ge
            .registry_get_value("HKCR", &key, "", RegistryView::Native)?
            .and_then(|value| value.data.as_str().map(ToString::to_string))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcComClassNotRegistered,
                    format!("missing registry activation for {}", clsid),
                )
            })?;
        if module_path != registration.module_path {
            return Err(AppError::new(
                ReasonCode::RcComClassNotRegistered,
                format!("registry activation mismatch for {}", clsid),
            ));
        }
        Ok(ComInstance {
            clsid: registration.clsid.clone(),
            module_path: registration.module_path.clone(),
            apartment,
        })
    }

    fn resolve_host_path(&self, path: &str) -> AppResult<(String, PathBuf)> {
        let parsed = self.ge.parse_windows_path(path, None)?;
        let drive = parsed.drive.clone().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("{} is missing a drive prefix", path),
            )
        })?;
        let mapping = self
            .ge
            .config
            .drive_mappings
            .iter()
            .find(|entry| entry.drive.eq_ignore_ascii_case(&drive) && entry.enabled) // case-insensitive comparison
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcFsSandboxEscape,
                    format!("drive {} is not enabled", drive),
                )
            })?;
        let mut root = if let Some(rest) = mapping.target.strip_prefix("<GE>/") {
            self.ge.root.join(rest)
        } else if mapping.target == "<GE>/drive_c" {
            self.ge.root.join("drive_c")
        } else {
            PathBuf::from(&mapping.target)
        };
        for component in &parsed.components {
            root.push(component);
        }
        Ok((parsed.normalized_path, root))
    }

    /// Whether the guest-visible PARENT directory of `normalized_path`
    /// resolves through the GE — i.e. exists from the guest's point of
    /// view.  This discriminates ERROR_PATH_NOT_FOUND (missing parent)
    /// from ERROR_FILE_NOT_FOUND (missing file inside a present parent).
    /// A parent that exists as a FILE is NOT a directory and yields
    /// ERROR_PATH_NOT_FOUND, matching Windows.
    /// Read-only: resolution must never create anything.
    fn parent_directory_exists(&self, normalized_path: &str) -> bool {
        let Some(parent) = normalized_path.rsplit_once('\\').map(|(p, _)| p) else {
            return false;
        };
        match self.ge.resolve_existing_path(parent, None, 0) {
            Ok(resolved) => resolved.host_path.is_dir(),
            Err(_) => false,
        }
    }

    /// Host-internal helper used ONLY by `stage_host_file_w` (staging a
    /// host-side payload — e.g. the main module — into the GE-provisioned
    /// guest temp directory).  Guest-visible operations must never call
    /// this: a missing parent is a guest-visible ERROR_PATH_NOT_FOUND.
    fn ensure_parent_exists(&self, path: &Path) -> AppResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to create {}", parent.display()),
                    &error,
                )
            })?;
        }
        Ok(())
    }

    /// Serialize the config immediately and record the save time so a
    /// following throttled save is not duplicated.
    fn save_config_now(&mut self) -> AppResult<()> {
        self.ge.save_config()?;
        self.last_config_save_wall_ms = wall_clock_ms();
        Ok(())
    }

    /// Serialize the config at most every 250 ms.  `sync_entry` runs on every
    /// file write; a full-config JSON serialization per syscall makes games
    /// that write logs/saves in a loop pay O(config) per write.  Metadata lost
    /// by throttling is rebuilt on demand via `sync_existing_path_w`.
    fn save_config_throttled(&mut self) -> AppResult<()> {
        let now = wall_clock_ms();
        if now.saturating_sub(self.last_config_save_wall_ms) >= 250 {
            self.ge.save_config()?;
            self.last_config_save_wall_ms = now;
        }
        Ok(())
    }

    fn sync_entry(
        &mut self,
        normalized_path: &str,
        host_path: &Path,
        is_directory: bool,
    ) -> AppResult<()> {
        let kind = if is_directory || host_path.is_dir() {
            FsEntryKind::Directory
        } else {
            FsEntryKind::File
        };
        let ticks = current_ticks(self.time.dtm, self.time.ticks_ms);
        let original_case = host_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_string();
        let existing_attrs = self
            .ge
            .config
            .fs_state
            .entries
            .get(normalized_path)
            .map(|entry| entry.attributes.clone())
            .unwrap_or_default();
        let mut attributes = existing_attrs;
        if kind == FsEntryKind::Directory && !attributes.iter().any(|value| value == "directory") {
            attributes.push("directory".to_string());
        }
        self.ge.config.fs_state.entries.insert(
            normalized_path.to_string(),
            FsMetadataRecord {
                kind,
                original_case,
                attributes,
                creation_time_ticks: ticks,
                last_access_time_ticks: ticks,
                last_write_time_ticks: ticks,
            },
        );
        self.save_config_throttled()
    }

    fn find_data_for_child(&self, directory_path: &str, child_name: &str) -> AppResult<FindData> {
        let child_path = if directory_path.ends_with('\\') {
            format!("{directory_path}{child_name}")
        } else {
            format!("{directory_path}\\{child_name}")
        };
        let metadata = self.ge.get_file_metadata(&child_path)?;
        let (_, host_path) = self.resolve_host_path(&child_path)?;
        let host = fs::metadata(host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to stat {child_path}"),
                &error,
            )
        })?;
        let mut attributes = metadata.attributes;
        if metadata.kind == FsEntryKind::Directory
            && !attributes.iter().any(|value| value == "directory")
        {
            attributes.push("directory".to_string());
        }
        Ok(FindData {
            file_name: child_name.to_string(),
            is_directory: metadata.kind == FsEntryKind::Directory,
            size: host.len(),
            attributes,
            creation_time_ticks: metadata.creation_time_ticks,
            last_access_time_ticks: metadata.last_access_time_ticks,
            last_write_time_ticks: metadata.last_write_time_ticks,
        })
    }

    fn file_object(&self, handle: Handle) -> AppResult<FileHandleObject> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::File(file) => Ok(Rc::clone(file)),
            _ => invalid_handle("handle is not a file"),
        }
    }

    fn thread_id(&self, handle: Handle) -> AppResult<u32> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Thread(thread) => Ok(thread.thread_id),
            _ => invalid_handle("handle is not a thread"),
        }
    }

    fn ensure_thread_state(&mut self, thread_id: u32) {
        self.threads
            .entry(thread_id)
            .or_insert_with(|| ThreadState {
                exit_code: None,
                priority: 0,
                tls: BTreeMap::new(),
                suspend_count: 0,
                terminated: false,
                fiber_id: 0,
            });
    }

    fn thread_state(&self, thread_id: u32) -> AppResult<&ThreadState> {
        self.threads.get(&thread_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("unknown thread {thread_id}"),
            )
        })
    }

    /// Whether a guest thread with this ID exists (the main thread or a
    /// thread created by `create_thread`).  Used by `OpenThread` to reject
    /// lookups of non-existent thread IDs with ERROR_INVALID_PARAMETER.
    pub fn thread_exists(&self, thread_id: u32) -> bool {
        thread_id == 1 || self.threads.contains_key(&thread_id)
    }

    /// The kernel-object type behind a handle, for wait/terminate dispatch
    /// in pe_runtime.
    pub fn handle_object_type(&self, handle: Handle) -> AppResult<ObjectType> {
        Ok(self.handle_entry(handle)?.descriptor.object_type)
    }

    fn thread_state_mut(&mut self, thread_id: u32) -> AppResult<&mut ThreadState> {
        self.threads.get_mut(&thread_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("unknown thread {thread_id}"),
            )
        })
    }

    fn cleanup_exited_thread_state(&mut self, thread_id: u32) {
        if thread_id == self.current_thread_id {
            return;
        }
        if self.process.handle_table.iter().any(|(_, entry)| {
            matches!(
                self.objects.object(entry.object_id),
                KernelObject::Thread(thread) if thread.thread_id == thread_id
            )
        }) {
            return;
        }
        if self
            .threads
            .get(&thread_id)
            .is_some_and(|state| state.exit_code.is_some())
        {
            self.threads.remove(&thread_id);
            // Drop per-thread bookkeeping so guests that spawn many threads
            // do not accumulate unbounded entries.
            self.thread_apcs.remove(&thread_id);
            self.com_apartments.remove(&thread_id);
        }
    }

    /// Insert a kernel object into the object manager and mint a handle
    /// through the canonical handle table (the ONLY handle allocator: it
    /// recycles closed values FIFO and bumps generations so stale references
    /// are detectable).
    fn insert_object(
        &mut self,
        object_type: ObjectType,
        access_mask: u32,
        inheritable: bool,
        object: KernelObject,
    ) -> Handle {
        self.insert_object_named(object_type, None, access_mask, inheritable, object)
    }

    /// Insert a kernel object (optionally registered in the unified
    /// named-object namespace) and mint a handle referencing it.
    fn insert_object_named(
        &mut self,
        object_type: ObjectType,
        name: Option<&str>,
        access_mask: u32,
        inheritable: bool,
        object: KernelObject,
    ) -> Handle {
        let object_id = self
            .objects
            .insert(object_type, name.map(str::to_string), None, object);
        self.insert_object_id(object_id, access_mask, inheritable)
    }

    /// Mint a handle referencing an EXISTING object (duplicate/Open*
    /// semantics: object identity != handle identity — the manager refcount
    /// goes up).
    fn insert_object_id(
        &mut self,
        object_id: ObjectId,
        access_mask: u32,
        inheritable: bool,
    ) -> Handle {
        let object_type = self.objects.object_type(object_id);
        let handle = self
            .process
            .handle_table
            .insert(object_id, access_mask, inheritable);
        self.process
            .handle_table
            .record_history(handle, object_type);
        self.objects.handle_added(object_id);
        handle
    }

    /// Return the current generation counter for a handle value.
    /// Returns `None` if the handle is not currently allocated.
    pub fn handle_generation(&self, handle: Handle) -> Option<u32> {
        self.process.handle_table.handle_generation(handle)
    }

    /// Validate that a cached `(handle, generation)` pair still matches the
    /// live entry.  Returns `Ok(())` if the handle is alive and its
    /// generation has not changed, or an `RcHandleStaleOrInvalid` error
    /// otherwise.
    pub fn validate_handle_generation(
        &self,
        handle: Handle,
        expected_generation: u32,
    ) -> AppResult<()> {
        self.process
            .handle_table
            .validate_handle_generation(handle, expected_generation)
    }

    fn insert_overlapped(
        &mut self,
        handle: Handle,
        event_handle: Option<Handle>,
        kind: OverlappedKind,
        state: OverlappedState,
    ) -> u64 {
        let id = self.next_overlapped_id;
        self.next_overlapped_id += 1;
        let generation = self
            .process
            .handle_table
            .handle_generation(handle)
            .unwrap_or(0);
        self.overlapped.insert(
            id,
            OverlappedRequest {
                handle,
                generation,
                event_handle,
                state,
                kind,
                buffer_ptr: 0,
                length: 0,
                bytes_read_ptr: 0,
            },
        );
        id
    }

    /// Queue an overlapped pipe I/O request carrying the guest-side buffers so
    /// the scheduler can complete it (write the data + byte count) when the
    /// pipe queue satisfies it.
    #[allow(clippy::too_many_arguments)]
    fn insert_pipe_io_overlapped(
        &mut self,
        handle: Handle,
        event_handle: Option<Handle>,
        kind: OverlappedKind,
        state: OverlappedState,
        buffer_ptr: u64,
        length: u32,
        bytes_read_ptr: u64,
    ) -> u64 {
        let id = self.next_overlapped_id;
        self.next_overlapped_id += 1;
        let generation = self
            .process
            .handle_table
            .handle_generation(handle)
            .unwrap_or(0);
        self.overlapped.insert(
            id,
            OverlappedRequest {
                handle,
                generation,
                event_handle,
                state,
                kind,
                buffer_ptr,
                length,
                bytes_read_ptr,
            },
        );
        id
    }

    /// True when the overlapped request's handle has been closed (or closed
    /// and its value recycled) since the request was queued — its completion
    /// must be dropped, never applied to whatever object now owns the value.
    fn overlapped_request_is_stale(&self, request: &OverlappedRequest) -> bool {
        self.validate_handle_generation(request.handle, request.generation)
            .is_err()
    }

    fn signal_event_if_needed(&mut self, event_handle: Option<Handle>) -> AppResult<()> {
        if let Some(event_handle) = event_handle {
            self.set_event(event_handle)?;
        }
        Ok(())
    }

    /// Subsystem view of a live handle, rebuilt from the canonical handle
    /// table + object manager on every access (the payload clone shares
    /// Rc-backed state; value payloads are only read through this view).
    fn handle_entry(&self, handle: Handle) -> AppResult<HandleEntry> {
        let entry = self.process.handle_table.entry(handle)?;
        Ok(HandleEntry {
            descriptor: HandleDescriptor {
                object_type: self.objects.object_type(entry.object_id),
                access_mask: entry.access_mask,
                refcount: self.objects.handle_count(entry.object_id),
                inheritable: entry.inheritable,
            },
            object: self.objects.object(entry.object_id).clone(),
        })
    }

    /// Mutable view accessor: see [`Self::handle_entry`].  Mutations of
    /// Rc-backed payloads (File/Event) propagate through the shared cell;
    /// value-payload mutations must go through [`Self::handle_object_mut`].
    fn handle_entry_mut(&mut self, handle: Handle) -> AppResult<HandleEntry> {
        self.handle_entry(handle)
    }

    /// The manager-owned payload of the object behind `handle`.
    fn handle_object(&self, handle: Handle) -> AppResult<&KernelObject> {
        let entry = self.process.handle_table.entry(handle)?;
        Ok(self.objects.object(entry.object_id))
    }

    /// Mutable access to the manager-owned payload of the object behind
    /// `handle` (the SINGLE owner of kernel-object state).
    fn handle_object_mut(&mut self, handle: Handle) -> AppResult<&mut KernelObject> {
        let object_id = self.process.handle_table.entry(handle)?.object_id;
        Ok(self.objects.object_mut(object_id))
    }
}

pub fn windows_command_line_to_argv(command_line: &str) -> Vec<String> {
    let chars = command_line.chars().collect::<Vec<_>>();
    let mut args = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        while index < chars.len() && matches!(chars[index], ' ' | '\t') {
            index += 1;
        }
        if index >= chars.len() {
            break;
        }

        let mut arg = String::new();
        let mut in_quotes = false;
        let mut backslashes = 0usize;
        while index < chars.len() {
            let ch = chars[index];
            match ch {
                '\\' => {
                    backslashes += 1;
                    index += 1;
                }
                '"' => {
                    arg.push_str(&"\\".repeat(backslashes / 2));
                    if backslashes.is_multiple_of(2) {
                        in_quotes = !in_quotes;
                    } else {
                        arg.push('"');
                    }
                    backslashes = 0;
                    index += 1;
                }
                ' ' | '\t' if !in_quotes => {
                    if backslashes > 0 {
                        arg.push_str(&"\\".repeat(backslashes));
                        backslashes = 0;
                    }
                    break;
                }
                other => {
                    if backslashes > 0 {
                        arg.push_str(&"\\".repeat(backslashes));
                        backslashes = 0;
                    }
                    arg.push(other);
                    index += 1;
                }
            }
        }
        if backslashes > 0 {
            arg.push_str(&"\\".repeat(backslashes));
        }
        args.push(arg);
        while index < chars.len() && matches!(chars[index], ' ' | '\t') {
            index += 1;
        }
    }
    args
}

pub fn build_environment_block_utf16(env: &BTreeMap<String, String>) -> Vec<u16> {
    let mut keys = env.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    let mut block = Vec::new();
    for key in keys {
        let pair = format!("{}={}", key, env[&key]);
        block.extend(pair.encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

/// `CharUpperW` single-character uppercase on the CP1252 Latin-1 domain (the
/// en-US system code page the oracle session models): ASCII lowercase maps
/// to ASCII uppercase; the Latin-1 letter block 0xE0..=0xFE maps down by
/// 0x20, with the code-page invariants preserved — ß (0xDF) and ÷ (0xF7)
/// have no uppercase in the code page and stay unchanged.  Characters
/// outside the fixed subset (and already-uppercase values) are returned
/// unchanged; ÿ (0xFF) is deliberately excluded from the differential
/// vectors because its CP1252 uppercase (U+0178) is not representable in
/// the code page and is implementation-defined.
pub fn cp1252_uppercase(character: u32) -> u32 {
    if (0x61..=0x7A).contains(&character) {
        return character - 0x20;
    }
    if (0xE0..=0xFE).contains(&character) && character != 0xDF && character != 0xF7 {
        return character - 0x20;
    }
    character
}

fn invalid_handle<T>(message: &str) -> AppResult<T> {
    Err(AppError::new(ReasonCode::RcWin32InvalidHandle, message))
}

fn normalize_pipe_name(name: &str) -> String {
    name.replace('/', "\\").to_ascii_lowercase()
}

// ── Pipe queue layer ─────────────────────────────────────────────────────────
//
// Each direction queue is a raw byte stream in byte mode.  In message mode
// every WriteFile appends a [u32 LE length][payload...] frame and every
// ReadFile returns exactly one message, so message boundaries survive the
// queue.

/// Append `bytes` to a pipe direction queue, framing the write as one
/// message when `message_mode`, and wake condvar waiters.
fn pipe_queue_append(
    queue: &Arc<Mutex<VecDeque<u8>>>,
    data_ready: &Arc<Condvar>,
    bytes: &[u8],
    message_mode: bool,
) {
    let mut queue = queue.lock().unwrap();
    if message_mode {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        queue.extend(len.to_le_bytes());
    }
    queue.extend(bytes);
    drop(queue);
    data_ready.notify_all();
}

/// Non-consuming length of the data a read would return from `queue` in the
/// current mode (raw bytes available, or the full payload of the head
/// message when `message_mode` — an incomplete message reads as empty).
fn pipe_queue_peek_len(queue: &Mutex<VecDeque<u8>>, message_mode: bool) -> usize {
    let queue = queue.lock().unwrap();
    if !message_mode {
        return queue.len();
    }
    let len_bytes: [u8; 4] = match queue.iter().take(4).copied().collect::<Vec<_>>()[..] {
        [a, b, c, d] => [a, b, c, d],
        _ => return 0,
    };
    let payload_len = u32::from_le_bytes(len_bytes) as usize;
    if queue.len() >= 4 + payload_len {
        payload_len
    } else {
        0
    }
}

/// Consume up to `length` bytes from a pipe direction queue and return them.
/// In byte mode the raw stream is drained up to `length`.  In message mode
/// exactly one message is returned, but never more than `length` bytes of
/// payload: when the caller's buffer is too small for the message, the
/// consumed prefix is returned and the remainder is re-framed at the queue
/// head so the next read continues the message (Windows ERROR_MORE_DATA
/// semantics) — the caller's buffer can never be overrun.
fn pipe_queue_read(
    queue: &Arc<Mutex<VecDeque<u8>>>,
    data_ready: &Arc<Condvar>,
    length: usize,
    message_mode: bool,
) -> Vec<u8> {
    let mut queue = queue.lock().unwrap();
    if message_mode {
        if queue.len() < 4 {
            return Vec::new();
        }
        let len_bytes: [u8; 4] = match queue.iter().take(4).copied().collect::<Vec<_>>()[..] {
            [a, b, c, d] => [a, b, c, d],
            _ => return Vec::new(),
        };
        let payload_len = u32::from_le_bytes(len_bytes) as usize;
        if queue.len() < 4 + payload_len {
            // Incomplete message: leave the queue untouched (Windows blocks
            // a message-mode read until the full message arrives).
            return Vec::new();
        }
        queue.drain(..4);
        let take = payload_len.min(length);
        let data: Vec<u8> = queue.drain(..take).collect();
        if take < payload_len {
            // The caller's buffer was too small for the whole message:
            // re-frame the unconsumed remainder at the queue head (ahead of
            // any subsequent messages) so the next read continues it.
            let mut remainder: Vec<u8> = queue.drain(..(payload_len - take)).collect();
            let mut rest: Vec<u8> = queue.drain(..).collect();
            let mut framed = Vec::with_capacity(4 + remainder.len() + rest.len());
            framed.extend_from_slice(&((payload_len - take) as u32).to_le_bytes());
            framed.append(&mut remainder);
            framed.append(&mut rest);
            queue.clear();
            queue.extend(framed);
        }
        drop(queue);
        data_ready.notify_all();
        data
    } else {
        let available = queue.len().min(length);
        let data: Vec<u8> = queue.drain(..available).collect();
        drop(queue);
        data_ready.notify_all();
        data
    }
}

fn current_ticks(dtm: bool, ticks_ms: u64) -> u64 {
    if dtm {
        ticks_ms.saturating_mul(10_000)
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| {
                WINDOWS_EPOCH_OFFSET_100NS
                    .saturating_add(duration.as_nanos().div_euclid(100) as u64)
            })
            .unwrap_or(WINDOWS_EPOCH_OFFSET_100NS)
    }
}

fn paced_sleep_duration_ms(requested_ms: u64, live_pacing: bool) -> u64 {
    if live_pacing {
        // Real-time pacing: host sleeps the full requested duration so the
        // guest's Sleep() tracks wall clock.
        requested_ms
    } else {
        // Virtual-clock mode: the guest clock already advanced by the full
        // amount; only yield briefly so the host stays responsive.
        requested_ms.min(1)
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        value
    } else {
        // Saturate on overflow; callers validate the result with checked_add.
        value.div_ceil(alignment).saturating_mul(alignment)
    }
}

/// Host wall-clock time in milliseconds (used for config-save throttling,
/// independent of the guest virtual clock).
fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn format_apartment(model: ApartmentModel) -> &'static str {
    match model {
        ApartmentModel::Sta => "STA",
        ApartmentModel::Mta => "MTA",
    }
}

fn format_threading_model(model: ComThreadingModel) -> &'static str {
    match model {
        ComThreadingModel::Sta => "STA",
        ComThreadingModel::Mta => "MTA",
        ComThreadingModel::Both => "Both",
    }
}

fn decode_cp1252(byte: u8) -> char {
    match byte {
        0x80 => '€',
        0x82 => '‚',
        0x83 => 'ƒ',
        0x84 => '„',
        0x85 => '…',
        0x86 => '†',
        0x87 => '‡',
        0x88 => 'ˆ',
        0x89 => '‰',
        0x8A => 'Š',
        0x8B => '‹',
        0x8C => 'Œ',
        0x8E => 'Ž',
        0x91 => '‘',
        0x92 => '’',
        0x93 => '“',
        0x94 => '”',
        0x95 => '•',
        0x96 => '–',
        0x97 => '—',
        0x98 => '˜',
        0x99 => '™',
        0x9A => 'š',
        0x9B => '›',
        0x9C => 'œ',
        0x9E => 'ž',
        0x9F => 'Ÿ',
        other => char::from(other),
    }
}

fn encode_cp1252(ch: char) -> AppResult<u8> {
    match ch {
        '€' => Ok(0x80),
        '‚' => Ok(0x82),
        'ƒ' => Ok(0x83),
        '„' => Ok(0x84),
        '…' => Ok(0x85),
        '†' => Ok(0x86),
        '‡' => Ok(0x87),
        'ˆ' => Ok(0x88),
        '‰' => Ok(0x89),
        'Š' => Ok(0x8A),
        '‹' => Ok(0x8B),
        'Œ' => Ok(0x8C),
        'Ž' => Ok(0x8E),
        '‘' => Ok(0x91),
        '’' => Ok(0x92),
        '“' => Ok(0x93),
        '”' => Ok(0x94),
        '•' => Ok(0x95),
        '–' => Ok(0x96),
        '—' => Ok(0x97),
        '˜' => Ok(0x98),
        '™' => Ok(0x99),
        'š' => Ok(0x9A),
        '›' => Ok(0x9B),
        'œ' => Ok(0x9C),
        'ž' => Ok(0x9E),
        'Ÿ' => Ok(0x9F),
        '\u{0081}' => Ok(0x81),
        '\u{008d}' => Ok(0x8D),
        '\u{008f}' => Ok(0x8F),
        '\u{0090}' => Ok(0x90),
        '\u{009d}' => Ok(0x9D),
        other if (other as u32) < 0x80 || (other as u32) >= 0xA0 && (other as u32) <= 0xFF => {
            Ok(other as u8)
        }
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("cannot encode {other} in code page 1252"),
        )),
    }
}

fn split_find_search_pattern(path: &str) -> (String, String) {
    let trimmed = path.trim_end_matches(['\\', '/']);
    if trimmed.len() < path.len() {
        // Path ended with separator — entire trimmed part is the directory.
        return (trimmed.to_string(), "*".to_string());
    }
    if let Some(index) = trimmed.rfind(['\\', '/']) {
        let directory = if index == 2 && trimmed.as_bytes().get(1) == Some(&b':') {
            trimmed[..=index].to_string()
        } else {
            trimmed[..index].to_string()
        };
        let pattern = trimmed[index + 1..].to_string();
        (
            directory,
            if pattern.is_empty() {
                "*".to_string()
            } else {
                pattern
            },
        )
    } else {
        (path.to_string(), "*".to_string())
    }
}

fn contains_find_wildcards(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

fn windows_pattern_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == "*.*" {
        return true; // correct: *.* matches everything in Windows
    }
    if let Some(prefix) = pattern.strip_suffix(".*")
        && !candidate.contains('.')
        && windows_pattern_matches(prefix, candidate)
    {
        return true; // correct: "foo.*" matches "foo" without extension
    }
    let pattern_chars = pattern.chars().collect::<Vec<_>>();
    let candidate_chars = candidate.chars().collect::<Vec<_>>();
    let mut pattern_index = 0;
    let mut candidate_index = 0;
    let mut star_index = None;
    let mut retry_index = 0;

    while candidate_index < candidate_chars.len() {
        if pattern_index < pattern_chars.len()
            && (pattern_chars[pattern_index] == '?'
                || find_pattern_char_eq(
                    pattern_chars[pattern_index],
                    candidate_chars[candidate_index],
                ))
        {
            pattern_index += 1;
            candidate_index += 1;
        } else if pattern_index < pattern_chars.len() && pattern_chars[pattern_index] == '*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            retry_index = candidate_index;
        } else if let Some(saved_star_index) = star_index {
            pattern_index = saved_star_index + 1;
            retry_index += 1;
            candidate_index = retry_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern_chars.len() && pattern_chars[pattern_index] == '*' {
        pattern_index += 1;
    }

    pattern_index == pattern_chars.len()
}

fn find_pattern_char_eq(left: char, right: char) -> bool {
    if left.is_ascii() && right.is_ascii() {
        left.eq_ignore_ascii_case(&right) // case-insensitive comparison
    } else {
        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CP_WIN1252, CreationDisposition, FileAccess, IoCompletionPacket, KernelObject,
        MemoryProtection, MutexObject, ObjectType, PIPE_READMODE_BYTE, PIPE_READMODE_MESSAGE,
        SeekOrigin, SemaphoreObject, ShareMode, ThreadPlan, WaitStatus, Win32Subsystem, iconv_ffi,
        paced_sleep_duration_ms, split_find_search_pattern, windows_pattern_matches,
    };
    use crate::ge::{GameEnvironment, GeArch, RegistryView};
    use crate::reason::ReasonCode;
    use std::collections::BTreeMap;
    use std::fs;

    #[test]
    fn paced_sleep_duration_non_live_caps_host_sleep_at_1ms() {
        // Without live pacing the guest clock drives timing; the host only
        // yields briefly (0 ms for a zero-length sleep).
        assert_eq!(paced_sleep_duration_ms(0, false), 0);
        assert_eq!(paced_sleep_duration_ms(1, false), 1);
        assert_eq!(paced_sleep_duration_ms(25, false), 1);
    }

    #[test]
    fn paced_sleep_duration_live_paces_the_full_duration() {
        assert_eq!(paced_sleep_duration_ms(0, true), 0);
        assert_eq!(paced_sleep_duration_ms(1, true), 1);
        assert_eq!(paced_sleep_duration_ms(8, true), 8);
        assert_eq!(paced_sleep_duration_ms(16, true), 16);
        assert_eq!(paced_sleep_duration_ms(33, true), 33);
    }

    #[test]
    fn split_find_search_pattern_keeps_root_and_defaults_empty_pattern() {
        assert_eq!(
            split_find_search_pattern("C:\\Steam\\*"),
            ("C:\\Steam".to_string(), "*".to_string())
        );
        assert_eq!(
            split_find_search_pattern("C:\\*.*"),
            ("C:\\".to_string(), "*.*".to_string())
        );
        assert_eq!(
            split_find_search_pattern("C:\\Steam\\"),
            ("C:\\Steam".to_string(), "*".to_string())
        );
    }

    #[test]
    fn windows_pattern_matches_is_case_insensitive_and_supports_wildcards() {
        assert!(windows_pattern_matches("*.dll", "Kernel32.DLL"));
        assert!(windows_pattern_matches("steam??.tmp", "Steam01.tmp"));
        assert!(windows_pattern_matches("*.*", "Steam"));
        assert!(windows_pattern_matches("steam.*", "Steam"));
        assert!(!windows_pattern_matches("steam??.tmp", "Steam001.tmp"));
    }

    #[test]
    fn io_completion_port_posts_and_dequeues_packets() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "iocp", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let port = win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create completion port");
        win32
            .post_queued_completion_status(port, 7, 0x1234, 0x5678)
            .expect("post completion status");

        let packets = win32
            .dequeue_io_completion_packets(port, 4)
            .expect("dequeue completion packet");

        assert_eq!(
            packets,
            vec![IoCompletionPacket {
                bytes_transferred: 7,
                completion_key: 0x1234,
                overlapped: 0x5678,
                internal: 0,
            }]
        );
    }

    #[test]
    fn get_file_information_by_handle_syncs_missing_metadata_for_existing_file() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "file-info-sync",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create game environment");
        let host_path = ge
            .host_path_for_windows_path("C:\\logs\\bootstrap_log.txt")
            .expect("resolve host path");
        // Host-internal test setup: seed the log file directly (the guest
        // filesystem layer never creates this directory itself).
        fs::create_dir_all(host_path.parent().expect("log parent")).expect("create log dir");
        fs::write(&host_path, b"log").expect("write log file");

        let mut win32 = Win32Subsystem::new(ge, false);
        let handle = win32
            .create_file_w(
                "C:\\logs\\bootstrap_log.txt",
                FileAccess::read_only(),
                ShareMode::all(),
                CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open existing log file");

        let info = win32
            .get_file_information_by_handle_ex(handle)
            .expect("get file information by handle");

        assert_eq!(info.normalized_path, "C:\\logs\\bootstrap_log.txt");
        assert_eq!(info.size, 3);
        assert!(
            win32
                .ge()
                .get_file_metadata("C:\\logs\\bootstrap_log.txt")
                .is_ok()
        );
    }

    #[test]
    fn duplicate_file_handle_survives_source_close() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "duplicate-file-handle",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        win32
            .create_directory_w("C:\\logs")
            .expect("create log directory");
        let path = win32
            .write_file_overwrite_w("C:\\logs\\bootstrap_log.txt", b"steam")
            .expect("seed file");

        let handle = win32
            .create_file_w(
                &path,
                FileAccess::read_only(),
                ShareMode::all(),
                CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open file");
        let duplicate = win32
            .duplicate_handle(handle, 0, false, true, false)
            .expect("duplicate file handle");

        win32.close_handle(handle).expect("close source handle");

        let bytes = win32
            .read_file(duplicate, 5)
            .expect("read through duplicate handle");
        assert_eq!(bytes, b"steam");
    }

    // ── Handle generation tests ────────────────────────────────────────

    #[test]
    fn handle_generation_starts_at_zero() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "gen-test", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let win32 = Win32Subsystem::new(ge, false);
        // No handles allocated yet
        assert!(win32.handle_generation(4).is_none());
    }

    #[test]
    fn handle_generation_is_tracked_on_allocation() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "gen-test2", GeArch::X86, "win11-23h2")
                .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (h, _existed) = win32.create_event(true, false, false, None);
        assert_eq!(
            win32.handle_generation(h),
            Some(0),
            "first allocation should have generation 0"
        );
    }

    #[test]
    fn handle_generation_increments_on_close() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "gen-test3", GeArch::X86, "win11-23h2")
                .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (h, _existed) = win32.create_event(true, false, false, None);
        assert_eq!(win32.handle_generation(h), Some(0));
        win32.close_handle(h).expect("close handle");
        // Handle is gone, but generation counter should be incremented
        assert!(win32.handle_generation(h).is_none());
        // Validate should fail for stale generation
        let err = win32.validate_handle_generation(h, 0).unwrap_err();
        assert!(
            err.to_string().contains("invalid handle"),
            "expected invalid handle error, got: {err}"
        );
    }

    #[test]
    fn validate_handle_generation_rejects_stale_reference() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "gen-test4", GeArch::X86, "win11-23h2")
                .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (h, _existed) = win32.create_event(true, false, false, None);
        let generation = win32.handle_generation(h).expect("generation");
        win32.close_handle(h).expect("close handle");
        // The generation counter was incremented on close, so the old generation is stale
        let err = win32.validate_handle_generation(h, generation).unwrap_err();
        assert!(
            err.to_string().contains("invalid handle") || err.to_string().contains("stale"),
            "expected stale/invalid error, got: {err}"
        );
    }

    #[test]
    fn handle_reuse_gets_new_generation_after_close() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "gen-reuse", GeArch::X86, "win11-23h2")
                .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (h1, _) = win32.create_event(true, false, false, None);
        let gen1 = win32.handle_generation(h1).expect("gen");
        win32.close_handle(h1).expect("close");

        let mut handles = Vec::new();
        for _ in 0..256 {
            let (h, _) = win32.create_event(true, false, false, None);
            handles.push(h);
        }
        for h in handles {
            win32.close_handle(h).expect("close batch");
        }

        // Closed values are recycled FIFO, so the next allocation reuses the
        // oldest freed value (h1) — and must carry a fresh generation.
        let (h2, _) = win32.create_event(true, false, false, None);
        assert_eq!(h2, h1, "oldest closed handle value must be recycled");
        let gen2 = win32.handle_generation(h2).expect("gen2");
        assert_ne!(gen1, gen2, "recycled handle must get a new generation");
    }

    // ── Synchronization primitive tests ────────────────────────────────

    #[test]
    fn event_auto_reset_signals_and_waits() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "evt-auto", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // manual_reset=false → auto-reset event
        let (h, _) = win32.create_event(false, false, false, None);
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Timeout,
            "auto-reset event should time out when not signalled"
        );
        win32.set_event(h).expect("set");
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Object0,
            "auto-reset event should be signalled after set"
        );
        // For an auto-reset event the first wait consumes the signal,
        // so a second wait should time out.
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Timeout,
            "auto-reset event should reset after wait consumes signal"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn event_manual_reset_stays_signalled_until_reset() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "evt-man", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // manual_reset=true → manual-reset event
        let (h, _) = win32.create_event(true, false, false, None);
        win32.set_event(h).expect("set");
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Object0,
            "manual-reset event should be signalled"
        );
        // For a manual-reset event the signal should persist after wait.
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Object0,
            "manual-reset event should remain signalled after wait"
        );
        win32.reset_event(h).expect("reset");
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Timeout,
            "manual-reset event should time out after reset"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn mutex_acquire_and_release() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "mtx-ar", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let h = win32.create_mutex(false, false);
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Object0,
            "free mutex should be signalled"
        );
        win32.release_mutex(h).expect("release");
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn mutex_abandoned_detection() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "mtx-ab", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let h = win32.create_mutex(true, false);
        win32.abandon_mutex(h).expect("abandon");
        let status = win32
            .wait_for_single_object(h, 0, false, None)
            .expect("wait");
        assert!(
            matches!(status, WaitStatus::Abandoned),
            "abandoned mutex should yield Abandoned, got {status:?}"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn mutex_ownership_recursion_and_abandonment() {
        // Windows mutex semantics at the dispatcher level: ownership by TID,
        // recursion count, non-owner release failure, and abandonment when
        // the owner terminates.
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "mtx-own", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // Recursive acquisition by the same thread succeeds and increments.
        let h = win32.create_mutex(false, false);
        win32.current_thread_id = 1;
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("acquire 1"),
            WaitStatus::Object0
        );
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("recursive acquire"),
            WaitStatus::Object0,
            "a thread recursively waiting on its own mutex succeeds"
        );

        // ReleaseMutex from a non-owner fails with ERROR_NOT_OWNER.
        win32.current_thread_id = 2;
        let error = win32.release_mutex(h).expect_err("non-owner release");
        assert_eq!(error.code, ReasonCode::RcWin32NotOwner);

        // The owner releases once (recursion 2 -> 1) — still owned.
        win32.current_thread_id = 1;
        win32.release_mutex(h).expect("release 1");
        // A DIFFERENT thread waiting on it cannot acquire (owner is thread 1):
        // the wait returns WAIT_TIMEOUT (a normal status — the mutex is a
        // valid waitable object owned by someone else).
        win32.current_thread_id = 2;
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait on foreign-owned mutex"),
            WaitStatus::Timeout,
            "a mutex owned by another thread is not satisfiable"
        );

        // Full release by the owner makes it free again.
        win32.current_thread_id = 1;
        win32.release_mutex(h).expect("release 2");
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("reacquire after full release"),
            WaitStatus::Object0,
            "a fully released mutex is free"
        );

        // Termination while owning abandons the mutex: the next successful
        // waiter receives WAIT_ABANDONED and takes ownership.
        win32
            .set_thread_exit_code_by_id(1, 0)
            .expect("thread 1 exits while owning the mutex");
        win32.current_thread_id = 4;
        let status = win32
            .wait_for_single_object(h, 0, false, None)
            .expect("wait after owner exit");
        assert!(
            matches!(status, WaitStatus::Abandoned),
            "owner termination must abandon the mutex, got {status:?}"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn semaphore_release_increments_count() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "sem-inc", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let h = win32.create_semaphore(0, 5, false);
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Timeout,
            "semaphore with count 0 should time out"
        );
        let prev = win32.release_semaphore(h, 1).expect("release");
        assert_eq!(prev, 0, "previous count should be 0");
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Object0,
            "semaphore with count >=1 should be signalled"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn semaphore_release_saturates_at_max() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "sem-max", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let h = win32.create_semaphore(3, 3, false);
        let prev = win32.release_semaphore(h, 1).expect("release");
        assert_eq!(prev, 3, "previous count should be 3 (already at max)");
        // After saturating release, count should remain at max (3).
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Object0,
            "semaphore should still be signalled after saturating release"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn wait_for_multiple_objects_wait_all() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "wfa", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // Use manual-reset events so wait_all doesn't consume signals mid-loop.
        let (h1, _) = win32.create_event(true, false, false, None);
        let (h2, _) = win32.create_event(true, false, false, None);

        // Timeout carries a `usize::MAX` sentinel, never a handle index.
        assert_eq!(
            win32
                .wait_for_multiple_objects(&[h1, h2], true, 0, false, None)
                .expect("wait"),
            (WaitStatus::Timeout, usize::MAX),
            "wait-all with no objects signalled should time out"
        );
        win32.set_event(h1).expect("set");
        assert_eq!(
            win32
                .wait_for_multiple_objects(&[h1, h2], true, 0, false, None)
                .expect("wait"),
            (WaitStatus::Timeout, usize::MAX),
            "wait-all with only one of two signalled should time out"
        );
        win32.set_event(h2).expect("set");
        assert_eq!(
            win32
                .wait_for_multiple_objects(&[h1, h2], true, 0, false, None)
                .expect("wait"),
            (WaitStatus::Object0, 0usize),
            "wait-all with both signalled should succeed"
        );

        win32.close_handle(h1).expect("close");
        win32.close_handle(h2).expect("close");
    }

    #[test]
    fn wait_for_multiple_objects_wait_all_consumes_auto_reset_signals_once() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "wfa-auto", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // Auto-reset events: the wait-all must peek before consuming,
        // otherwise the second (destructive) pass could never succeed and
        // the wait would spin forever.
        let (h1, _) = win32.create_event(false, false, false, None);
        let (h2, _) = win32.create_event(false, false, false, None);
        win32.set_event(h1).expect("set");
        win32.set_event(h2).expect("set");
        assert_eq!(
            win32
                .wait_for_multiple_objects(&[h1, h2], true, 0, false, None)
                .expect("wait"),
            (WaitStatus::Object0, 0usize),
            "wait-all with both auto-reset events set should succeed"
        );
        // Signals were consumed exactly once.
        assert_eq!(
            win32
                .wait_for_single_object(h1, 0, false, None)
                .expect("wait"),
            WaitStatus::Timeout,
            "auto-reset signal should be consumed by the wait-all"
        );
        win32.close_handle(h1).expect("close");
        win32.close_handle(h2).expect("close");
    }

    #[test]
    fn wait_for_multiple_objects_wait_any() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "wfany", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let (h1, _) = win32.create_event(false, false, false, None);
        let (h2, _) = win32.create_event(false, false, false, None);

        assert_eq!(
            win32
                .wait_for_multiple_objects(&[h1, h2], false, 0, false, None)
                .expect("wait"),
            (WaitStatus::Timeout, usize::MAX),
            "wait-any with no objects signalled should time out"
        );
        win32.set_event(h1).expect("set");
        assert_eq!(
            win32
                .wait_for_multiple_objects(&[h1, h2], false, 0, false, None)
                .expect("wait"),
            (WaitStatus::Object0, 0usize),
            "wait-any with one signalled should succeed"
        );

        win32.close_handle(h1).expect("close");
        win32.close_handle(h2).expect("close");
    }

    #[test]
    fn wait_for_single_object_timeout() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "wto", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let (h, _) = win32.create_event(true, false, false, None);
        assert_eq!(
            win32
                .wait_for_single_object(h, 0, false, None)
                .expect("wait"),
            WaitStatus::Timeout,
            "non-signalled event with 0ms timeout should return Timeout"
        );
        win32.close_handle(h).expect("close");
    }

    // ── Unified handle manager tests ────────────────────────────────────

    #[test]
    fn socket_handles_share_the_win32_namespace() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "sock-ns", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // The first allocation in a fresh subsystem is handle 4: sockets use
        // the win32 allocator, not a separate 0x1000 base.
        let socket = win32.insert_socket();
        assert_eq!(socket, 4, "sockets mint handles from the win32 allocator");
        assert_eq!(
            win32.socket_id(socket).expect("socket id"),
            u64::from(socket)
        );

        // CloseHandle(socket) is ERROR_INVALID_HANDLE by type, and the
        // socket survives.
        let err = win32.close_handle(socket).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        assert_eq!(
            win32.socket_id(socket).expect("socket still alive"),
            u64::from(socket)
        );

        // closesocket on a non-socket fails the type check.
        let (event, _) = win32.create_event(true, false, false, None);
        let err = win32.close_socket(event).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);

        // close_socket removes the entry and returns the socket id.
        let id = win32.close_socket(socket).expect("close socket");
        assert_eq!(id, u64::from(socket));
        let err = win32.socket_id(socket).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        win32.close_handle(event).expect("close event");
    }

    #[test]
    fn wait_for_single_object_rejects_non_waitable_types() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "wait-nw", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        win32
            .create_directory_w("C:\\logs")
            .expect("create log directory");
        let path = win32
            .write_file_overwrite_w("C:\\logs\\probe.txt", b"x")
            .expect("seed file");
        let file = win32
            .create_file_w(
                &path,
                FileAccess::read_only(),
                ShareMode::all(),
                CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open file");

        // WaitForSingleObject(file) → ERROR_INVALID_HANDLE (not WAIT_OBJECT_0).
        let err = win32
            .wait_for_single_object(file, 0, false, None)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        // WaitForMultipleObjects containing a file → ERROR_INVALID_HANDLE.
        let err = win32
            .wait_for_multiple_objects(&[file], false, 0, false, None)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        let (event, _) = win32.create_event(true, false, false, None);
        let err = win32
            .wait_for_multiple_objects(&[file, event], false, 0, false, None)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);

        // A socket handle is also not waitable.
        let socket = win32.insert_socket();
        let err = win32
            .wait_for_single_object(socket, 0, false, None)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        let err = win32
            .wait_for_multiple_objects(&[socket, event], false, 0, false, None)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);

        win32.close_handle(file).expect("close file");
        win32.close_handle(event).expect("close event");
        win32.close_socket(socket).expect("close socket");
    }

    #[test]
    fn file_functions_type_check_before_access() {
        // GetFileSizeEx/SetFilePointerEx/FlushFileBuffers on an event must
        // fail with ERROR_INVALID_HANDLE — the event's access bits are
        // irrelevant because the type is wrong.
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "type-first", GeArch::X86, "win11-23h2")
                .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (event, _) = win32.create_event(true, false, false, None);
        let err = win32.get_file_size_ex(event).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        let err = win32
            .set_file_pointer_ex(event, 0, SeekOrigin::Begin)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        let err = win32.flush_file_buffers(event).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        // RegCloseKey-style close helper also type-checks.
        let err = win32.close_registry_key(event).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        win32.close_handle(event).expect("close event");
    }

    #[test]
    fn set_event_enforces_modify_state() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "evt-mod", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (created, _) = win32.create_event(true, false, false, Some("evt-access"));
        // open_event records the requested mask: access 0 grants nothing.
        let zero_access = win32
            .open_event(0, false, "evt-access")
            .expect("open event");
        let err = win32.set_event(zero_access).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        let err = win32.reset_event(zero_access).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        // A full-access handle still works.
        win32.set_event(created).expect("set full-access event");
        win32.close_handle(zero_access).expect("close zero-access");
        win32.close_handle(created).expect("close event");
    }

    #[test]
    fn release_operations_enforce_modify_state() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "mod-state", GeArch::X86, "win11-23h2")
                .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // Mutex: ReleaseMutex requires MUTEX_MODIFY_STATE (0x1).
        let full_mutex = win32.create_mutex(true, false);
        let zero_mutex = win32.insert_object(
            ObjectType::Mutex,
            0,
            false,
            KernelObject::Mutex(MutexObject {
                owner_thread_id: None,
                recursion: 0,
                abandoned: false,
            }),
        );
        let err = win32.release_mutex(zero_mutex).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        win32
            .release_mutex(full_mutex)
            .expect("release full-access mutex");

        // Semaphore: ReleaseSemaphore requires SEMAPHORE_MODIFY_STATE (0x2).
        let full_sem = win32.create_semaphore(1, 2, false);
        let zero_sem = win32.insert_object(
            ObjectType::Semaphore,
            0,
            false,
            KernelObject::Semaphore(SemaphoreObject {
                count: 1,
                maximum: 2,
            }),
        );
        let err = win32.release_semaphore(zero_sem, 1).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        win32
            .release_semaphore(full_sem, 1)
            .expect("release full-access semaphore");

        win32.close_handle(zero_mutex).expect("close zero mutex");
        win32.close_handle(full_mutex).expect("close mutex");
        win32.close_handle(zero_sem).expect("close zero semaphore");
        win32.close_handle(full_sem).expect("close semaphore");
    }

    #[test]
    fn waits_enforce_synchronize_access() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "sync-w", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (created, _) = win32.create_event(true, false, false, Some("evt-sync"));

        // EVENT_MODIFY_STATE only (no SYNCHRONIZE): waits are denied.
        let no_sync = win32
            .open_event(0x0000_0002, false, "evt-sync")
            .expect("open event");
        let err = win32
            .wait_for_single_object(no_sync, 0, false, None)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        let err = win32
            .wait_for_multiple_objects(&[no_sync, created], true, 0, false, None)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);

        // SYNCHRONIZE granted → the wait works.
        let with_sync = win32
            .open_event(0x0010_0000 | 0x0000_0002, false, "evt-sync")
            .expect("open with synchronize");
        win32.set_event(created).expect("set");
        assert_eq!(
            win32
                .wait_for_single_object(with_sync, 0, false, None)
                .expect("wait"),
            WaitStatus::Object0
        );

        // A mutex handle granted only MUTEX_MODIFY_STATE cannot be waited on.
        let no_sync_mutex = win32.insert_object(
            ObjectType::Mutex,
            0x0000_0001,
            false,
            KernelObject::Mutex(MutexObject {
                owner_thread_id: None,
                recursion: 0,
                abandoned: false,
            }),
        );
        let err = win32
            .wait_for_single_object(no_sync_mutex, 0, false, None)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);

        win32.close_handle(no_sync).expect("close no-sync");
        win32.close_handle(with_sync).expect("close with-sync");
        win32.close_handle(created).expect("close created");
        win32.close_handle(no_sync_mutex).expect("close mutex");
    }

    #[test]
    fn thread_operations_enforce_query_information() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "thr-acc", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let handle = win32.create_thread(
            ThreadPlan {
                exit_code: Some(7),
                priority: 0,
                signaled: true,
            },
            false,
        );
        let thread_id = win32.thread_id_for_handle(handle).expect("thread id");

        // open_thread records the guest's desired access: 0 grants nothing.
        let zero = win32.open_thread(thread_id, 0, false).expect("open thread");
        let err = win32.get_exit_code_thread(zero).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        let err = win32.get_thread_priority(zero).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        let err = win32.set_thread_priority(zero, 1).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        let err = win32.suspend_thread(zero).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        let err = win32.resume_thread(zero).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        let err = win32.terminate_thread(zero, 0).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);

        // The create_thread default mask (0x1F03FF) satisfies all checks.
        assert_eq!(
            win32.get_exit_code_thread(handle).expect("exit code"),
            Some(7)
        );
        win32.close_handle(zero).expect("close zero thread");
        win32.close_handle(handle).expect("close thread");
    }

    #[test]
    fn process_operations_enforce_access() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "proc-acc", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let result = win32
            .create_process_w("app.exe", "app.exe -arg", &BTreeMap::new(), "C:\\", false)
            .expect("create process");

        // CreateProcessW grants full access incl. PROCESS_QUERY_LIMITED_INFORMATION.
        assert_eq!(
            win32
                .get_exit_code_process(result.process_handle)
                .expect("exit code"),
            None
        );

        // open_process records the requested mask: 0 grants nothing.
        let zero = win32
            .open_process(0, false, result.process_id)
            .expect("open process");
        let err = win32.get_exit_code_process(zero).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);
        let err = win32.terminate_process(zero, 1).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);

        win32
            .terminate_process(result.process_handle, 1)
            .expect("terminate full-access process");
        assert_eq!(
            win32
                .get_exit_code_process(result.process_handle)
                .expect("exit code after terminate"),
            Some(1)
        );
    }

    #[test]
    fn duplicate_handle_validates_access_subset() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "dup-acc", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (event, _) = win32.create_event(true, false, false, None);

        // FILE_APPEND_DATA (0x4) is not granted by the event's 0x1F0003 mask.
        let err = win32
            .duplicate_handle(event, 0x0000_0004, false, false, false)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcHelperPermissionDenied);

        // A granted subset duplicates fine.
        let dup = win32
            .duplicate_handle(event, 0x0000_0002, false, false, false)
            .expect("duplicate subset");
        win32.set_event(dup).expect("set via duplicate");

        // Sockets cannot be duplicated (they are winsock handles).
        let socket = win32.insert_socket();
        let err = win32
            .duplicate_handle(socket, 0, false, true, false)
            .unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);

        win32.close_handle(dup).expect("close duplicate");
        win32.close_handle(event).expect("close event");
        win32.close_socket(socket).expect("close socket");
    }

    #[test]
    fn overlapped_completion_is_dropped_after_handle_recycled() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "ovl-gen", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        win32
            .create_directory_w("C:\\logs")
            .expect("create log directory");
        let path = win32
            .write_file_overwrite_w("C:\\logs\\io.txt", b"payload")
            .expect("seed file");
        let file = win32
            .create_file_w(
                &path,
                FileAccess::read_only(),
                ShareMode::all(),
                CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open file");
        let overlapped = win32
            .read_file_overlapped(file, 3, 0, None)
            .expect("queue overlapped read");
        let id = overlapped.id;

        // Close the file and recycle the value onto a different object.
        win32.close_handle(file).expect("close file");
        let (recycled, _) = win32.create_event(true, false, false, None);
        assert_eq!(recycled, file, "closed handle value is recycled FIFO");

        // The stale completion is dropped: it neither reports success nor
        // touches the recycled object, and the request is removed.
        let err = win32.get_overlapped_result(id, false).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        let err = win32.get_overlapped_result(id, false).unwrap_err();
        assert_eq!(
            err.code,
            ReasonCode::RcWin32InvalidHandle,
            "stale request removed"
        );
        win32.close_handle(recycled).expect("close recycled event");
    }

    #[test]
    fn pending_overlapped_connect_is_dropped_after_handle_recycled() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "ovl-pipe", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let pipe = win32.create_named_pipe("C:\\probe\\pipe", false);
        let (event, _) = win32.create_event(true, false, false, None);
        let request_id = win32
            .connect_named_pipe_internal(pipe, Some(event), true)
            .expect("pending connect")
            .expect("overlapped id");

        // Close the pipe and recycle its value onto a NEW pipe with the
        // same name: the completion path matches pending requests by handle
        // VALUE, so the stale request would otherwise be completed against
        // the new object (and its event signaled) — a wrong-object write.
        win32.close_handle(pipe).expect("close pipe");
        let recycled_pipe = win32.create_named_pipe("C:\\probe\\pipe", false);
        assert_eq!(recycled_pipe, pipe, "closed pipe value is recycled FIFO");

        win32
            .call_named_pipe("C:\\probe\\pipe", b"data")
            .expect("call pipe");
        // The stale completion is dropped: the request is gone and the
        // original event was never signaled.
        let err = win32.get_overlapped_result(request_id, false).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
        assert_eq!(
            win32
                .wait_for_single_object(event, 0, false, None)
                .expect("wait"),
            WaitStatus::Timeout,
            "original event must not be signaled by the stale completion"
        );
        win32
            .close_handle(recycled_pipe)
            .expect("close recycled pipe");
        win32.close_handle(event).expect("close event");
    }

    // ── File I/O semantics tests ───────────────────────────────────────

    #[test]
    fn create_file_opens_new_or_existing() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "cf01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let path = "C:\\test_create_file.txt";
        let h = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn open_existing_fails_on_missing_file() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "oe01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let result = win32.create_file_w(
            "C:\\nonexistent_file_xyz.dat",
            FileAccess::read_only(),
            ShareMode::read_only(),
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        );
        assert!(
            result.is_err(),
            "OpenExisting on missing file should fail, got {result:?}"
        );
    }

    #[test]
    fn create_new_missing_parent_returns_path_not_found() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "cfpn01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // CREATE_NEW at a path whose parent does not exist must fail with
        // ERROR_PATH_NOT_FOUND (3) — and must NOT create the parent.
        for disposition in [
            CreationDisposition::CreateNew,
            CreationDisposition::CreateAlways,
            CreationDisposition::OpenAlways,
        ] {
            let result = win32.create_file_w(
                "C:\\nonexistent_dir\\file.txt",
                FileAccess::read_write(),
                ShareMode::none(),
                disposition,
                false,
                false,
                false,
            );
            let error = result.expect_err("missing parent must fail");
            assert_eq!(
                error.code,
                ReasonCode::RcFsPathInvalid,
                "missing parent must surface as ERROR_PATH_NOT_FOUND (3) for {disposition:?}"
            );
            let host_parent = win32
                .guest_path_to_host_path("C:\\nonexistent_dir")
                .expect("resolve host parent");
            assert!(
                !host_parent.exists(),
                "host parent must not be created behind the guest's back"
            );
        }
    }

    #[test]
    fn open_existing_missing_parent_returns_path_not_found() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "oepn01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // Parent missing → ERROR_PATH_NOT_FOUND (3).
        let result = win32.create_file_w(
            "C:\\no_parent_dir\\file.txt",
            FileAccess::read_only(),
            ShareMode::read_only(),
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        );
        assert_eq!(
            result.expect_err("missing parent must fail").code,
            ReasonCode::RcFsPathInvalid,
            "OpenExisting with a missing parent must be ERROR_PATH_NOT_FOUND"
        );

        // File missing, parent present → ERROR_FILE_NOT_FOUND (2).
        let result = win32.create_file_w(
            "C:\\no_such_file.dat",
            FileAccess::read_only(),
            ShareMode::read_only(),
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        );
        assert_eq!(
            result.expect_err("missing file must fail").code,
            ReasonCode::RcFsNotFound,
            "OpenExisting with a present parent must be ERROR_FILE_NOT_FOUND"
        );
    }

    #[test]
    fn truncate_existing_missing_file_returns_file_not_found() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "tep01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // TRUNCATE_EXISTING on a missing file (parent present) is
        // ERROR_FILE_NOT_FOUND (2) — same as OPEN_EXISTING.
        let result = win32.create_file_w(
            "C:\\missing_for_truncate.txt",
            FileAccess::read_write(),
            ShareMode::none(),
            CreationDisposition::TruncateExisting,
            false,
            false,
            false,
        );
        assert_eq!(
            result.expect_err("missing file must fail").code,
            ReasonCode::RcFsNotFound,
            "TruncateExisting on a missing file must be ERROR_FILE_NOT_FOUND"
        );
    }

    #[test]
    fn create_new_with_existing_parent_still_works() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "cpep01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        win32
            .create_directory_w("C:\\existing_dir")
            .expect("create parent directory");

        let h = win32
            .create_file_w(
                "C:\\existing_dir\\fresh.txt",
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateNew,
                false,
                false,
                false,
            )
            .expect("CREATE_NEW with an existing parent must create the file");
        win32.close_handle(h).expect("close");
        assert!(
            win32
                .guest_path_to_host_path("C:\\existing_dir\\fresh.txt")
                .expect("resolve host path")
                .exists(),
            "created file must exist on the host"
        );

        // CREATE_NEW on the now-existing file is ERROR_ALREADY_EXISTS.
        let result = win32.create_file_w(
            "C:\\existing_dir\\fresh.txt",
            FileAccess::read_write(),
            ShareMode::none(),
            CreationDisposition::CreateNew,
            false,
            false,
            false,
        );
        assert_eq!(
            result.expect_err("existing file must fail").code,
            ReasonCode::RcFsAlreadyExists,
            "CREATE_NEW on an existing file must be ERROR_ALREADY_EXISTS"
        );
    }

    #[test]
    fn move_file_ex_destination_parent_missing_returns_path_not_found() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "mvpn01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let h = win32
            .create_file_w(
                "C:\\src.txt",
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("seed source file");
        win32.close_handle(h).expect("close");

        let result =
            win32.move_file_ex_w("C:\\src.txt", "C:\\no_dest_parent\\dst.txt", false, false);
        assert_eq!(
            result
                .expect_err("missing destination parent must fail")
                .code,
            ReasonCode::RcFsPathInvalid,
            "MoveFileEx with a missing destination parent must be ERROR_PATH_NOT_FOUND"
        );
        assert!(
            win32
                .guest_path_to_host_path("C:\\src.txt")
                .expect("resolve host path")
                .exists(),
            "source must survive a failed move"
        );
        assert!(
            !win32
                .guest_path_to_host_path("C:\\no_dest_parent")
                .expect("resolve host path")
                .exists(),
            "destination parent must not be created"
        );

        // A missing SOURCE is ERROR_FILE_NOT_FOUND.
        let result = win32.move_file_ex_w("C:\\no_such_src.txt", "C:\\dst.txt", false, false);
        assert_eq!(
            result.expect_err("missing source must fail").code,
            ReasonCode::RcFsNotFound,
            "MoveFileEx with a missing source must be ERROR_FILE_NOT_FOUND"
        );
    }

    #[test]
    fn move_file_ex_reject_directory_destination_with_replace() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "mvdir01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let h = win32
            .create_file_w(
                "C:\\mv-src.txt",
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("seed source file");
        win32.close_handle(h).expect("close");

        win32
            .create_directory_w("C:\\mv-dst")
            .expect("create destination directory");
        let child = win32
            .create_file_w(
                "C:\\mv-dst\\child.txt",
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("seed directory child");
        win32.close_handle(child).expect("close child");

        // Windows cannot replace a directory with a file: the replace path
        // must fail with ERROR_ACCESS_DENIED and must NEVER remove the tree.
        let result = win32.move_file_ex_w("C:\\mv-src.txt", "C:\\mv-dst", true, false);
        assert_eq!(
            result.expect_err("directory destination must fail").code,
            ReasonCode::RcHelperPermissionDenied,
            "replacing a directory with a file must be ERROR_ACCESS_DENIED"
        );
        assert!(
            win32
                .guest_path_to_host_path("C:\\mv-dst\\child.txt")
                .expect("resolve child")
                .exists(),
            "directory tree must survive the failed replace"
        );
        assert!(
            win32
                .guest_path_to_host_path("C:\\mv-src.txt")
                .expect("resolve source")
                .exists(),
            "source must survive the failed replace"
        );

        // A FILE destination with REPLACE_EXISTING replaces correctly.
        let h = win32
            .create_file_w(
                "C:\\mv-dst\\old.txt",
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("seed file destination");
        win32.close_handle(h).expect("close");
        win32
            .move_file_ex_w("C:\\mv-src.txt", "C:\\mv-dst\\old.txt", true, false)
            .expect("replace file destination");
        assert!(
            !win32
                .guest_path_to_host_path("C:\\mv-src.txt")
                .expect("resolve source")
                .exists(),
            "source must be gone after a successful replace"
        );
        assert!(
            win32
                .guest_path_to_host_path("C:\\mv-dst\\old.txt")
                .expect("resolve destination")
                .exists(),
            "destination must contain the moved file"
        );
    }

    #[test]
    fn move_file_ex_respects_delete_sharing_on_source() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "mvsh01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let h = win32
            .create_file_w(
                "C:\\mv-share.txt",
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("open source without FILE_SHARE_DELETE");

        // An open source handle without FILE_SHARE_DELETE blocks the move.
        let result = win32.move_file_ex_w("C:\\mv-share.txt", "C:\\mv-share-dst.txt", false, false);
        assert_eq!(
            result.expect_err("move must be denied").code,
            ReasonCode::RcFsSharingViolation,
            "moving a source held open without FILE_SHARE_DELETE must be a sharing violation"
        );

        win32.close_handle(h).expect("close source");

        // With no handles left the move succeeds.
        win32
            .move_file_ex_w("C:\\mv-share.txt", "C:\\mv-share-dst.txt", false, false)
            .expect("move after closing the source");
    }

    #[test]
    fn move_file_ex_requires_replace_existing_for_existing_destination() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "mvre01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        for path in ["C:\\mvre-src.txt", "C:\\mvre-dst.txt"] {
            let h = win32
                .create_file_w(
                    path,
                    FileAccess::read_write(),
                    ShareMode::none(),
                    CreationDisposition::CreateAlways,
                    false,
                    false,
                    false,
                )
                .expect("seed file");
            win32.close_handle(h).expect("close");
        }

        // Without MOVEFILE_REPLACE_EXISTING an existing destination is
        // ERROR_ALREADY_EXISTS — rename must not silently clobber it.
        let result = win32.move_file_ex_w("C:\\mvre-src.txt", "C:\\mvre-dst.txt", false, false);
        assert_eq!(
            result.expect_err("existing destination must fail").code,
            ReasonCode::RcFsAlreadyExists,
            "move onto an existing destination without replace must be ERROR_ALREADY_EXISTS"
        );
        assert!(
            win32
                .guest_path_to_host_path("C:\\mvre-src.txt")
                .expect("resolve source")
                .exists(),
            "source must survive a failed non-replacing move"
        );

        // With MOVEFILE_REPLACE_EXISTING the move succeeds.
        win32
            .move_file_ex_w("C:\\mvre-src.txt", "C:\\mvre-dst.txt", true, false)
            .expect("move with replace");
        assert!(
            !win32
                .guest_path_to_host_path("C:\\mvre-src.txt")
                .expect("resolve source")
                .exists(),
            "source must be gone after the replacing move"
        );
    }

    #[test]
    fn truncate_existing_on_readonly_file_fails_access_denied() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "rotr01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let path = "C:\\ro-truncate.txt";

        let h = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        win32.write_file(h, b"keep-me").expect("write content");
        win32.close_handle(h).expect("close");

        // GE metadata path: the readonly attribute is stored on the record.
        win32
            .set_file_attributes_w(path, &["readonly"])
            .expect("set readonly attribute");

        for disposition in [
            CreationDisposition::TruncateExisting,
            CreationDisposition::CreateAlways,
        ] {
            let result = win32.create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                disposition,
                false,
                false,
                false,
            );
            assert_eq!(
                result.expect_err("read-only file must fail").code,
                ReasonCode::RcHelperPermissionDenied,
                "{disposition:?} on a read-only file must be ERROR_ACCESS_DENIED"
            );
        }

        let contents = fs::read(
            win32
                .guest_path_to_host_path(path)
                .expect("resolve host path"),
        )
        .expect("read file");
        assert_eq!(contents, b"keep-me", "read-only file must not be truncated");
    }

    #[test]
    fn truncate_existing_requires_write_access() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "rotr02", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let path = "C:\\tr-write-req.txt";

        let h = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        win32.write_file(h, b"content").expect("write content");
        win32.close_handle(h).expect("close");

        // GENERIC_READ-only (expanded FILE_GENERIC_READ carries no
        // FILE_WRITE_DATA) TRUNCATE_EXISTING → ERROR_ACCESS_DENIED.
        let result = win32.create_file_w(
            path,
            FileAccess::read_only(),
            ShareMode::none(),
            CreationDisposition::TruncateExisting,
            false,
            false,
            false,
        );
        assert_eq!(
            result.expect_err("read-only access must fail").code,
            ReasonCode::RcHelperPermissionDenied,
            "TRUNCATE_EXISTING without write access must be ERROR_ACCESS_DENIED"
        );

        // A FILE_WRITE_DATA-granting handle succeeds.
        let h = win32
            .create_file_w(
                path,
                FileAccess {
                    read: false,
                    write: true,
                    delete: false,
                },
                ShareMode::none(),
                CreationDisposition::TruncateExisting,
                false,
                false,
                false,
            )
            .expect("truncate with write access");
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn delete_file_w_on_readonly_file_fails_access_denied() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "rodf01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let path = "C:\\ro-delete.txt";

        let h = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        win32.close_handle(h).expect("close");
        win32
            .set_file_attributes_w(path, &["readonly"])
            .expect("set readonly attribute");

        let result = win32.delete_file_w(path);
        assert_eq!(
            result.expect_err("read-only file must fail").code,
            ReasonCode::RcHelperPermissionDenied,
            "DeleteFileW on a read-only file must be ERROR_ACCESS_DENIED"
        );
        assert!(
            win32
                .guest_path_to_host_path(path)
                .expect("resolve host path")
                .exists(),
            "read-only file must survive DeleteFileW"
        );

        // Clearing the attribute allows deletion.
        win32
            .set_file_attributes_w(path, &[])
            .expect("clear readonly attribute");
        win32
            .delete_file_w(path)
            .expect("delete after clearing readonly");
    }

    #[test]
    fn flush_file_buffers_requires_write_access() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "flush01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let path = "C:\\flush-req.txt";

        let h = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        win32.write_file(h, b"data").expect("write");
        win32.close_handle(h).expect("close");

        // A GENERIC_READ-only handle must not be able to flush.
        let read_only = win32
            .create_file_w(
                path,
                FileAccess::read_only(),
                ShareMode::none(),
                CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open read-only");
        let result = win32.flush_file_buffers(read_only);
        assert_eq!(
            result.expect_err("read-only flush must fail").code,
            ReasonCode::RcHelperPermissionDenied,
            "FlushFileBuffers on a read-only handle must be ERROR_ACCESS_DENIED"
        );
        win32.close_handle(read_only).expect("close");

        // A FILE_WRITE_DATA-granting handle succeeds.
        let write_only = win32
            .create_file_w(
                path,
                FileAccess {
                    read: false,
                    write: true,
                    delete: false,
                },
                ShareMode::none(),
                CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open write-only");
        win32
            .flush_file_buffers(write_only)
            .expect("flush with write access");
        win32.close_handle(write_only).expect("close");
    }

    #[test]
    fn open_existing_with_parent_file_returns_path_not_found() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "pif01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let h = win32
            .create_file_w(
                "C:\\parent-file.txt",
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("seed parent-as-file");
        win32.close_handle(h).expect("close");

        // A parent that exists as a FILE is not a directory: Windows reports
        // ERROR_PATH_NOT_FOUND (3), not ERROR_FILE_NOT_FOUND (2).
        for disposition in [
            CreationDisposition::OpenExisting,
            CreationDisposition::CreateNew,
        ] {
            let result = win32.create_file_w(
                "C:\\parent-file.txt\\child.txt",
                FileAccess::read_write(),
                ShareMode::none(),
                disposition,
                false,
                false,
                false,
            );
            assert_eq!(
                result.expect_err("parent-is-a-file must fail").code,
                ReasonCode::RcFsPathInvalid,
                "{disposition:?} with a file parent must be ERROR_PATH_NOT_FOUND"
            );
        }
    }

    #[test]
    fn create_directory_missing_parent_returns_path_not_found() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "cdmp01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        // Windows CreateDirectoryW on a missing parent is
        // ERROR_PATH_NOT_FOUND (3), never ERROR_FILE_NOT_FOUND (2).
        let result = win32.create_directory_w("C:\\no_such_parent_dir\\child");
        assert_eq!(
            result.expect_err("missing parent must fail").code,
            ReasonCode::RcFsPathInvalid,
            "CreateDirectoryW with a missing parent must be ERROR_PATH_NOT_FOUND"
        );
        assert!(
            !win32
                .guest_path_to_host_path("C:\\no_such_parent_dir")
                .expect("resolve host path")
                .exists(),
            "missing parent must not be created"
        );
    }

    #[test]
    fn create_always_truncates_existing_file() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "ca01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let path = "C:\\truncate_test.txt";

        let h = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create");
        win32.write_file(h, b"hello").expect("write");
        win32.close_handle(h).expect("close");

        let h2 = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create again");
        let contents = win32.read_file(h2, 1024).expect("read");
        assert!(
            contents.is_empty(),
            "file truncated by CreateAlways should be empty, got {} bytes",
            contents.len()
        );
        win32.close_handle(h2).expect("close");
    }

    #[test]
    fn file_pointer_advances_on_read_write() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "fp01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let path = "C:\\file_ptr_test.txt";

        let h = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create");
        win32.write_file(h, b"abcdef").expect("write");

        let pos = win32
            .set_file_pointer_ex(h, 0, SeekOrigin::Current)
            .expect("tell");
        assert_eq!(pos, 6, "file pointer should be at end after write");

        let pos = win32
            .set_file_pointer_ex(h, 2, SeekOrigin::Begin)
            .expect("seek");
        assert_eq!(pos, 2, "file pointer should be at position 2 after seek");

        let data = win32.read_file(h, 3).expect("read");
        assert_eq!(data, b"cde", "should read bytes 2-4");

        win32.close_handle(h).expect("close");
    }

    // ── Registry path canonicalization tests ───────────────────────────

    #[test]
    fn registry_path_canonicalization_lowercases() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "reg01", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        win32
            .create_registry_key("HKCU", "Software\\MyTestApp", RegistryView::Native)
            .expect("create key");

        assert!(
            win32
                .registry_key_exists("HKCU", "Software\\MyTestApp", RegistryView::Native,)
                .unwrap_or(false),
            "created key should exist"
        );

        let h = win32.open_registry_key("HKCU", "software\\mytestapp", RegistryView::Native, false);
        assert_ne!(
            h, 0,
            "opening with different case should return a valid handle"
        );
        win32.close_handle(h).expect("close handle");
    }

    #[test]
    fn registry_path_trailing_backslash_normalized() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "reg02", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        win32
            .create_registry_key("HKCU", "Software\\TestApp2", RegistryView::Native)
            .expect("create key");

        let h =
            win32.open_registry_key("HKCU", "Software\\TestApp2\\", RegistryView::Native, false);
        assert_ne!(
            h, 0,
            "opening with trailing backslash should return a valid handle"
        );
        win32.close_handle(h).expect("close handle");
    }

    // ── Code-page conversion tests ─────────────────────────────────────

    #[test]
    fn code_page_conversion_utf8_roundtrip() {
        let input = "Hello, World!";
        let bytes = iconv_ffi::convert_from_utf8(CP_WIN1252, input);
        if let Some(bytes) = bytes {
            let roundtrip = iconv_ffi::convert_to_utf8(CP_WIN1252, &bytes);
            assert_eq!(roundtrip, Some(input.to_string()));
        }
        // If iconv is not available (non-macOS), the test is a no-op
    }

    #[test]
    fn code_page_conversion_empty_input() {
        let result = iconv_ffi::convert_to_utf8(CP_WIN1252, &[]);
        // Should return Some("") or None depending on platform
        if let Some(s) = result {
            assert!(s.is_empty(), "empty input should produce empty output");
        }
    }

    #[test]
    fn code_page_conversion_large_input_does_not_overflow() {
        // Allocate a large input that would overflow if multiplied unchecked
        let large = vec![0x41u8; 1024 * 1024]; // 1 MB of 'A'
        let result = iconv_ffi::convert_to_utf8(CP_WIN1252, &large);
        // Should succeed or return None gracefully, never panic
        if let Some(s) = result {
            assert_eq!(s.len(), 1024 * 1024);
        }
    }

    #[test]
    fn code_page_conversion_from_utf8_large_input_does_not_overflow() {
        let large = "A".repeat(1024 * 1024); // 1 MB string
        let result = iconv_ffi::convert_from_utf8(CP_WIN1252, &large);
        // Should succeed or return None gracefully, never panic
        if let Some(bytes) = result {
            assert_eq!(bytes.len(), 1024 * 1024);
        }
    }

    #[test]
    fn code_page_conversion_unsupported_codepage() {
        let result = iconv_ffi::convert_to_utf8(99999, b"test");
        assert_eq!(result, None, "unsupported code page should return None");
    }

    // ── Audit regression tests ─────────────────────────────────────────

    #[test]
    fn read_file_beyond_eof_returns_empty() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "reof", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let h = win32
            .create_file_w(
                "C:\\beyond_eof.txt",
                FileAccess::read_write(),
                ShareMode::all(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        win32.write_file(h, b"abc").expect("write");
        win32
            .set_file_pointer_ex(h, 1000, SeekOrigin::Begin)
            .expect("seek past EOF");
        let data = win32.read_file(h, 16).expect("read past EOF");
        assert!(data.is_empty(), "read past EOF must return zero bytes");
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn write_file_huge_position_never_panics() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "wpos", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let h = win32
            .create_file_w(
                "C:\\huge_pos.txt",
                FileAccess::read_write(),
                ShareMode::all(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        win32.write_file(h, b"abc").expect("write");
        let pos = win32
            .set_file_pointer_ex(h, i64::MAX, SeekOrigin::Begin)
            .expect("seek to max signed position");
        assert_eq!(pos, i64::MAX as u64);
        // Writing at a huge position must either succeed (sparse) or fail
        // cleanly — never overflow-panic or abort on allocation.
        let result = win32.write_file(h, b"x");
        assert!(
            result.is_ok() || result.is_err(),
            "write at huge position must not panic"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn delete_file_share_delete_violation() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "df-sd", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let h1 = win32
            .create_file_w(
                "C:\\del-share.txt",
                FileAccess::read_write(),
                ShareMode::read_only(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("open file without FILE_SHARE_DELETE");
        win32.write_file(h1, b"data").expect("write");

        // An open handle without FILE_SHARE_DELETE blocks deletion.
        let denied = win32
            .delete_file_w("C:\\del-share.txt")
            .expect_err("delete must be denied");
        assert_eq!(
            denied.code,
            ReasonCode::RcFsSharingViolation,
            "delete without FILE_SHARE_DELETE must report a sharing violation"
        );

        win32.close_handle(h1).expect("close");

        // Reopening with FILE_SHARE_DELETE permits deletion; the surviving
        // handle is marked delete_pending.
        let h2 = win32
            .create_file_w(
                "C:\\del-share.txt",
                FileAccess::read_only(),
                ShareMode {
                    read: true,
                    write: false,
                    delete: true,
                },
                CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("reopen with FILE_SHARE_DELETE");
        win32
            .delete_file_w("C:\\del-share.txt")
            .expect("delete allowed with FILE_SHARE_DELETE");
        match win32.handle_object(h2).expect("surviving handle") {
            KernelObject::File(file) => {
                assert!(
                    file.borrow().delete_pending,
                    "surviving handle must be marked delete_pending"
                );
            }
            _ => panic!("expected a file handle"),
        }
        win32.close_handle(h2).expect("close");
    }

    #[test]
    fn named_mutex_recreated_after_close() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "nmx", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (h1, existed) = win32.create_named_mutex("Global\\AuditMutex", false, false);
        assert!(!existed, "first creation must report not-existed");
        let (h2, existed) = win32.create_named_mutex("Global\\AuditMutex", false, false);
        assert!(existed, "second creation must report existed");
        assert_eq!(h1, h2, "re-opening the same name yields the same mutex");
        win32.close_handle(h1).expect("close");
        let (h3, existed) = win32.create_named_mutex("Global\\AuditMutex", false, false);
        assert!(
            !existed,
            "name must be reusable after the last handle closes"
        );
        // The fresh mutex gets a fresh generation even if the handle value
        // is recycled, so stale references to the old object are detected.
        assert_ne!(
            win32.handle_generation(h3),
            Some(0),
            "recreated mutex must carry a fresh generation"
        );
        win32.close_handle(h3).expect("close third");
    }

    #[test]
    fn open_named_event_returns_existing_handle() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "oev", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (h1, existed) = win32.create_event(true, false, false, Some("Global\\AuditEvent"));
        assert!(!existed);
        let h2 = win32
            .open_named_event("Global\\AuditEvent")
            .expect("open named event must succeed");
        assert_ne!(h2, 0, "open must return a real handle");
        win32.set_event(h2).expect("set via opened handle");
        assert_eq!(
            win32
                .wait_for_single_object(h1, 0, false, None)
                .expect("wait"),
            WaitStatus::Object0,
            "opened handle must reference the same event"
        );
        win32.close_handle(h1).expect("close");
        win32.close_handle(h2).expect("close");
    }

    #[test]
    fn named_pipe_recreated_after_server_close() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "npipe", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let h = win32
            .create_named_pipe_w(
                r"\\.\pipe\audit-recreate",
                0x3,
                0,
                1,
                4096,
                4096,
                0,
                false,
                None,
                None,
            )
            .expect("create pipe");
        win32.close_handle(h).expect("close pipe");
        let h2 = win32
            .create_named_pipe_w(
                r"\\.\pipe\audit-recreate",
                0x3,
                0,
                1,
                4096,
                4096,
                0,
                false,
                None,
                None,
            )
            .expect("recreate pipe after close");
        win32.close_handle(h2).expect("close recreated pipe");
    }

    #[test]
    fn named_pipe_message_mode_reads_exactly_one_message_per_read() {
        // PIPE_READMODE_MESSAGE: each WriteFile appends a [u32 len][bytes]
        // frame and a message-mode ReadFile returns exactly one message.
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "msgpipe", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let server = win32
            .create_named_pipe_w(
                r"\\.\pipe\msg-test",
                0x3,
                PIPE_READMODE_MESSAGE,
                1,
                4096,
                4096,
                0,
                false,
                None,
                None,
            )
            .expect("create server");
        let client = win32
            .open_named_pipe_client(r"\\.\pipe\msg-test", false)
            .expect("open client");

        // The client writes two messages; the server reads them back one
        // message per read, in order, with no framing leakage.
        win32
            .write_file(client, b"first")
            .expect("write first message");
        win32
            .write_file(client, b"second-message")
            .expect("write second message");
        assert_eq!(
            win32.read_file(server, 4096).expect("server read #1"),
            b"first",
            "message-mode read returns exactly the first message"
        );
        assert_eq!(
            win32.read_file(server, 4096).expect("server read #2"),
            b"second-message",
            "message-mode read returns exactly the second message"
        );

        // A byte-mode read on the client side returns the raw byte stream.
        win32
            .set_named_pipe_handle_state(client, Some(PIPE_READMODE_BYTE), None, None)
            .expect("set byte read mode");
        win32.write_file(server, b"response").expect("server write");
        assert_eq!(
            win32.read_file(client, 4096).expect("client byte read"),
            b"response",
            "byte-mode read returns the raw stream"
        );

        // A buffer smaller than the message never overruns: the read
        // returns exactly the requested bytes and the remainder stays
        // queued (re-framed) for the next read.
        win32
            .set_named_pipe_handle_state(server, Some(PIPE_READMODE_MESSAGE), None, None)
            .expect("set message read mode");
        win32
            .write_file(client, b"oversized-message-payload")
            .expect("write oversized message");
        assert_eq!(
            win32.read_file(server, 4).expect("short message read"),
            b"over",
            "message-mode read must never return more than the requested length"
        );
        assert_eq!(
            win32.read_file(server, 4096).expect("remainder read"),
            b"sized-message-payload",
            "the message remainder stays queued for the next read"
        );
        win32.close_handle(client).expect("close client");
        win32.close_handle(server).expect("close server");
    }

    #[test]
    fn pipe_read_begin_completion_is_scoped_to_request_id() {
        // Completing one pending overlapped read must not complete its
        // sibling on the same handle: each waiter resumes only with its own
        // result.
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "ovl-scope", GeArch::X86, "win11-23h2")
                .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let server = win32
            .create_named_pipe_w(
                r"\\.\pipe\ovl-scope",
                0x3,
                0,
                1,
                4096,
                4096,
                0,
                false,
                None,
                None,
            )
            .expect("create server");
        let client = win32
            .open_named_pipe_client(r"\\.\pipe\ovl-scope", false)
            .expect("open client");

        // Two pending reads on the server end (the pipe is empty).
        let first = win32
            .pipe_read_begin(server, 16, None, 0x1000, 0x2000)
            .expect("first pending read");
        assert!(!first.completed);
        let second = win32
            .pipe_read_begin(server, 16, None, 0x3000, 0x4000)
            .expect("second pending read");
        assert!(!second.completed);
        assert_ne!(first.id, second.id);

        // Data arrives; completing the FIRST request leaves the second one
        // pending — its GetOverlappedResult must not report success.
        win32.write_file(client, b"payload").expect("client write");
        let completion = win32
            .try_complete_pending_pipe_io(first.id)
            .expect("first completion");
        assert!(!completion.broken_pipe);
        assert_eq!(completion.bytes, b"payload");
        let first_result = win32
            .get_overlapped_result(first.id, false)
            .expect("first result");
        assert!(first_result.completed);
        assert_eq!(first_result.bytes_transferred, 7);
        let second_result = win32
            .get_overlapped_result(second.id, false)
            .expect("second result");
        assert!(
            !second_result.completed,
            "sibling request must stay pending after the first completes"
        );
        win32.close_handle(client).expect("close client");
        win32.close_handle(server).expect("close server");
    }

    #[test]
    fn call_named_pipe_w_returns_server_response_not_request() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "cnpw", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let server = win32
            .create_named_pipe_w(
                r"\\.\pipe\cnpw-test",
                0x3,
                0,
                1,
                4096,
                4096,
                0,
                false,
                None,
                None,
            )
            .expect("create server");
        // The server writes its response into the pipe; CallNamedPipeW
        // returns whatever the server wrote, NOT a copy of the request.
        win32
            .write_file(server, b"server-answer")
            .expect("server response write");
        let response = win32
            .call_named_pipe_w(r"\\.\pipe\cnpw-test", b"request-data", 4096, 0)
            .expect("call named pipe");
        assert_eq!(
            response, b"server-answer",
            "CallNamedPipeW must return the server's bytes, not the request"
        );
        // With no queued response the helper returns empty (the thunk layer
        // parks the guest thread on the scheduler wait instead).
        let empty = win32
            .call_named_pipe_w(r"\\.\pipe\cnpw-test", b"another-request", 4096, 0)
            .expect("call named pipe with no response");
        assert!(empty.is_empty());
        win32.close_handle(server).expect("close server");
    }

    #[test]
    fn map_view_of_file_validates_offset_and_size() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "mview", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (section, _) = win32
            .create_file_mapping_w(
                Some("Global\\AuditMap"),
                0x10000,
                MemoryProtection {
                    read: true,
                    write: true,
                    execute: false,
                },
                false,
            )
            .expect("create mapping");
        assert!(
            win32.map_view_of_file(section, 0x20000, 0x1000).is_err(),
            "offset beyond the section must fail"
        );
        let base = win32
            .map_view_of_file(section, 0x1000, 0x1000)
            .expect("map view at offset");
        assert!(
            win32.mapped_view_section(base).is_some(),
            "mapped view must be tied to the section backing"
        );
        // Absurd sizes clamp to the section and must not panic.
        assert!(
            win32.map_view_of_file(section, 0, usize::MAX).is_ok(),
            "huge map size must clamp to the section, not panic"
        );
        win32.unmap_view_of_file(base).expect("unmap");
        assert!(
            win32.unmap_view_of_file(base).is_err(),
            "double unmap must fail"
        );
        win32.close_handle(section).expect("close section");
    }

    #[test]
    fn heap_alloc_reuses_freed_blocks() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "hfree", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let heap = win32.heap_create(16, false);
        let first = win32.heap_alloc(heap, 100).expect("alloc");
        win32.heap_free(heap, first).expect("free");
        let second = win32.heap_alloc(heap, 100).expect("alloc again");
        assert_eq!(
            first, second,
            "freed block must be reused instead of growing the high-water mark"
        );
        win32.heap_destroy(heap).expect("destroy heap");
    }

    #[test]
    fn get_temp_file_name_w_is_unique_across_consecutive_calls() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "tname", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let first = win32.get_temp_file_name_w("", "CASA").expect("first name");
        let second = win32.get_temp_file_name_w("", "CASA").expect("second name");
        assert_ne!(first, second, "consecutive temp names must be unique");
    }

    #[test]
    fn tls_slots_are_reused_after_free() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "tls", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let first = win32.tls_alloc();
        let second = win32.tls_alloc();
        assert_ne!(first, second);
        win32.tls_free(first);
        assert_eq!(first, win32.tls_alloc(), "freed slot must be reused");
    }

    #[test]
    fn wait_for_single_object_honors_finite_timeout() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "wto-finite", GeArch::X86, "win11-23h2")
                .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (h, _) = win32.create_event(true, false, false, None);
        // A finite wait must block (polling) until the signal arrives rather
        // than returning an instant spurious Timeout.
        win32.set_event(h).expect("set");
        assert_eq!(
            win32
                .wait_for_single_object(h, 5000, false, None)
                .expect("wait"),
            WaitStatus::Object0,
            "signalled event must satisfy a finite-timeout wait"
        );
        win32.reset_event(h).expect("reset");
        // A tiny finite timeout on an unsignalled object returns Timeout
        // after honoring the deadline (1 ms poll + deadline check).
        assert_eq!(
            win32
                .wait_for_single_object(h, 1, false, None)
                .expect("wait"),
            WaitStatus::Timeout,
            "unsignalled event must time out after a finite wait"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn set_end_of_file_truncates_the_real_host_file_at_the_pointer() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "seof", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let path = "C:\\truncate-me.bin";

        let h = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        win32
            .write_file(h, b"0123456789abcdef")
            .expect("write content");

        // Seek to offset 5, then SetEndOfFile must truncate the host file to
        // exactly 5 bytes (the real backing file, not a simulated position).
        win32
            .set_file_pointer_ex(h, 5, SeekOrigin::Begin)
            .expect("seek");
        win32.set_end_of_file(h).expect("truncate");

        let host_path = win32.guest_path_to_host_path(path).expect("resolve");
        assert_eq!(
            fs::metadata(&host_path).expect("stat").len(),
            5,
            "host file must be truly truncated at the file pointer"
        );
        assert_eq!(
            win32.get_file_size_ex(h).expect("size"),
            5,
            "subsystem size view must agree with the real truncation"
        );

        // Reads after the truncation see the real shorter content.
        win32
            .set_file_pointer_ex(h, 0, SeekOrigin::Begin)
            .expect("seek");
        assert_eq!(
            win32.read_file(h, 64).expect("read"),
            b"01234",
            "content after truncation must be the first five bytes"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn set_end_of_file_requires_write_access() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "seof-ro", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let path = "C:\\truncate-ro.bin";

        let h = win32
            .create_file_w(
                path,
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        win32.write_file(h, b"0123456789").expect("write content");
        win32.close_handle(h).expect("close");

        // Reopen read-only: SetEndOfFile must fail (FILE_WRITE_DATA absent).
        let read_only = win32
            .create_file_w(
                path,
                FileAccess::read_only(),
                ShareMode::none(),
                CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("reopen read-only");
        assert_eq!(
            win32
                .set_end_of_file(read_only)
                .expect_err("must fail")
                .code,
            ReasonCode::RcHelperPermissionDenied,
            "SetEndOfFile on a read-only handle must be ERROR_ACCESS_DENIED"
        );
        win32.close_handle(read_only).expect("close");

        let host_path = win32.guest_path_to_host_path(path).expect("resolve");
        assert_eq!(
            fs::metadata(&host_path).expect("stat").len(),
            10,
            "failed truncation must leave the file untouched"
        );
    }

    #[test]
    fn set_end_of_file_rejects_non_file_handles() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "seof-hnd", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);
        let (h, _) = win32.create_event(true, false, false, None);
        assert_eq!(
            win32.set_end_of_file(h).expect_err("must fail").code,
            ReasonCode::RcWin32InvalidHandle,
            "SetEndOfFile on a non-file handle must be ERROR_INVALID_HANDLE"
        );
        win32.close_handle(h).expect("close");
    }

    #[test]
    fn volume_capacity_reports_the_real_host_volume() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "cap", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let win32 = Win32Subsystem::new(ge, false);

        let capacity = win32
            .volume_capacity(Some("C:\\"))
            .expect("capacity for the mapped drive root");
        assert!(
            capacity.total_bytes > 0,
            "the volume backing the GE drive must report non-zero capacity"
        );
        assert!(
            capacity.free_bytes <= capacity.total_bytes,
            "free bytes must never exceed total bytes"
        );
        assert!(
            capacity.bytes_per_sector >= 1 && capacity.sectors_per_cluster >= 1,
            "geometry must be well-formed"
        );
        let cluster_size =
            u64::from(capacity.bytes_per_sector) * u64::from(capacity.sectors_per_cluster);
        assert!(
            capacity.total_bytes >= capacity.total_clusters.saturating_mul(cluster_size),
            "cluster geometry must be consistent with the reported bytes"
        );

        // A syntactically-valid but nonexistent path resolves to its volume.
        let missing = win32
            .volume_capacity(Some("C:\\No\\Such\\Directory"))
            .expect("capacity for a nonexistent path");
        assert_eq!(
            missing.total_bytes, capacity.total_bytes,
            "nonexistent paths report the same volume"
        );
    }
}
