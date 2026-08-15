use crate::error::{AppError, AppResult};
use crate::ge::{
    FileAccess, FileHandle, FsEntryKind, FsMetadataRecord, GameEnvironment, RegistryView, ShareMode,
};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type Handle = u32;

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
            let outbuf_len = input.as_bytes().len().saturating_mul(2).saturating_add(8);
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
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
const HANDLE_FLAG_PROTECT_FROM_CLOSE: u32 = 0x0000_0002;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObjectType {
    File,
    Event,
    IoCompletionPort,
    Mutex,
    Semaphore,
    Thread,
    Process,
    Section,
    Key,
    Timer,
    Pipe,
    DirectorySearch,
}

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

#[derive(Debug, Clone)]
struct HandleEntry {
    descriptor: HandleDescriptor,
    object: KernelObject,
    /// Monotonically increasing generation counter.  Incremented every time
    /// the same handle value is reused so that stale references (cached before
    /// the handle was closed) can be detected.
    generation: u32,
}

#[derive(Debug, Clone)]
enum KernelObject {
    File(FileHandleObject),
    Event(EventHandle),
    IoCompletionPort(IoCompletionPortObject),
    Mutex(MutexObject),
    Semaphore(SemaphoreObject),
    Thread(ThreadObject),
    Process(ProcessObject),
    Section(SectionObject),
    Key(KeyObject),
    Timer(TimerObject),
    Pipe(PipeObject),
    DirectorySearch(DirectorySearchObject),
}

#[derive(Debug, Clone)]
struct FileObject {
    normalized_path: String,
    host_path: PathBuf,
    ge_handle: Option<FileHandle>,
    position: u64,
    overlapped: bool,
}

type FileHandleObject = Rc<RefCell<FileObject>>;

#[derive(Debug, Clone)]
struct EventObject {
    manual_reset: bool,
    signaled: bool,
}

type EventHandle = Rc<RefCell<EventObject>>;
type EventWeak = Weak<RefCell<EventObject>>;

/// Minimal pipe object stored directly in the kernel-object enum.
/// Used by the older `create_named_pipe` / `create_named_pipe_w` code paths;
/// the newer `NamedPipeState`-based infrastructure lives in
/// `self.named_pipes` and provides condvar-backed sync.
#[derive(Debug, Clone)]
struct PipeObject {
    name: String,
    connected: bool,
    buffer: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct IoCompletionPacket {
    pub bytes_transferred: u32,
    pub completion_key: u64,
    pub overlapped: u64,
    pub internal: u64,
}

#[derive(Debug, Clone)]
struct IoCompletionPortObject {
    concurrent_threads: u32,
    queue: VecDeque<IoCompletionPacket>,
}

#[derive(Debug, Clone)]
struct MutexObject {
    owner_thread_id: Option<u32>,
    abandoned: bool,
}

#[derive(Debug, Clone)]
struct SemaphoreObject {
    count: u32,
    maximum: u32,
}

#[derive(Debug, Clone)]
struct ThreadObject {
    thread_id: u32,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
struct ProcessObject {
    process_id: u32,
    executable: String,
    argv: Vec<String>,
    cwd: String,
    environment: BTreeMap<String, String>,
    inherited_handles: Vec<HandleDescriptor>,
    modules: Vec<String>,
    exit_code: Option<u32>,
    /// Synchronisation primitive for async child-process exit.
    /// When a child is spawned on a worker thread, the thread sets the exit
    /// code inside this condvar pair and notifies all waiters.  The parent
    /// `WaitForSingleObject` call blocks on this condvar instead of spinning.
    exit_sync: Option<Arc<(Mutex<Option<u32>>, Condvar)>>,
}

#[derive(Debug, Clone)]
struct SectionObject {
    base_address: u64,
    size: usize,
    protection: MemoryProtection,
}

#[derive(Debug, Clone)]
struct KeyObject {
    hive: String,
    key: String,
    view: RegistryView,
}

#[derive(Debug, Clone)]
struct TimerObject {
    due_tick: u64,
    signaled: bool,
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
    let safe_name = name.replace('\\', "_").replace('/', "_");
    format!("{}/{}", PIPE_SOCKET_BASE_DIR, safe_name)
}

/// State tracking for a Windows named pipe.
/// Named pipes are backed by in-memory ring buffers with condvar-based
/// synchronisation so that readers block when the buffer is empty and
/// writers wake them.
#[derive(Debug, Clone)]
struct NamedPipeState {
    /// The pipe name (e.g. `\\.\pipe\steam_service`).
    name: String,
    /// Whether a server endpoint has been created via CreateNamedPipeW.
    server_created: bool,
    /// Whether a client has connected via ConnectNamedPipe / CreateFileW.
    connected: bool,
    /// Data buffer shared between server and client ends.
    buffer: Arc<Mutex<VecDeque<u8>>>,
    /// Condition variable signalled when new data arrives or the pipe is
    /// disconnected.
    data_ready: Arc<Condvar>,
    /// Maximum pipe size (from nMaxInstances / nOutBufferSize).
    max_buffer_size: usize,
    /// Whether the server end has been disconnected.
    server_disconnected: bool,
    /// Optional security descriptor pointer (guest virtual address of the
    /// `SECURITY_DESCRIPTOR` passed via `lpSecurityAttributes`). Stored for
    /// future ACL enforcement; currently unused beyond record-keeping.
    security_descriptor: Option<u64>,
    /// Unix-domain socket path for cross-process pipe communication.
    /// Only populated when the pipe is created with cross-process intent.
    uds_socket_path: Option<String>,
    /// Pipe open mode (PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND).
    open_mode: u32,
    /// Pipe mode (PIPE_WAIT or PIPE_NOWAIT).
    pipe_mode: u32,
    /// Maximum number of pipe instances.
    max_instances: u32,
    /// Default timeout for WaitNamedPipe (in milliseconds).
    default_timeout: u32,
}

/// A simple wrapper around `libc::mmap` / `munmap` for shared memory backing.
/// When dropped, the mapping is automatically unmapped.
#[derive(Debug)]
struct MmapBacking {
    ptr: *mut u8,
    length: usize,
}

// Safety: MmapBacking is only ever accessed behind Arc<Mutex<...>>.
// SAFETY: Send is safe because the type only uses thread-safe internal state or is accessed under exclusive &mut
unsafe impl Send for MmapBacking {}
// SAFETY: Send is safe because the type only uses thread-safe internal state or is accessed under exclusive &mut
unsafe impl Sync for MmapBacking {}

impl MmapBacking {
    /// Create a new anonymous mmap of the given length.
    fn new(length: usize) -> Option<Self> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length.max(1),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            None
        } else {
            Some(MmapBacking {
                ptr: ptr as *mut u8,
                length: length.max(1),
            })
        }
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: pointer is valid and non-null, length matches the allocated region
        unsafe { std::slice::from_raw_parts(self.ptr, self.length) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: pointer is valid and non-null, length matches the allocated region
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.length) }
    }
}

impl Drop for MmapBacking {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: POSIX FFI for code page conversion and shared memory
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.length);
            }
        }
    }
}

impl Clone for MmapBacking {
    fn clone(&self) -> Self {
        // Create a new mmap and copy the data
        let mut new = MmapBacking::new(self.length).expect("clone mmap backing");
        new.as_mut_slice().copy_from_slice(self.as_slice());
        new
    }
}

/// Backing store for a shared-memory section created via CreateFileMappingW.
#[derive(Debug, Clone)]
struct SharedMemorySection {
    /// Name of the section (may be empty for anonymous).
    name: String,
    /// The actual byte storage, reference-counted so that multiple
    /// `MapViewOfFile` calls share the same backing.
    data: Arc<Mutex<Vec<u8>>>,
    /// Optional mmap backing for named sections that persist to disk.
    mmap_backing: Option<Arc<Mutex<MmapBacking>>>,
    /// Maximum size requested at creation time.
    maximum_size: usize,
    /// Protection flags at creation time.
    protection: MemoryProtection,
}

#[derive(Debug, Clone)]
struct DirectorySearchObject {
    entries: Vec<FindData>,
    index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum OverlappedState {
    Pending,
    Completed(u32),
    Cancelled,
}

#[derive(Debug, Clone)]
struct OverlappedRequest {
    handle: Handle,
    event_handle: Option<Handle>,
    state: OverlappedState,
}

#[derive(Debug, Clone, Copy)]
struct IoCompletionAssociation {
    #[allow(dead_code)]
    port_handle: Handle,
    #[allow(dead_code)]
    completion_key: u64,
}

#[derive(Debug, Clone)]
struct VirtualRegion {
    base_address: u64,
    size: usize,
    committed: BTreeSet<u64>,
    protection: MemoryProtection,
}

#[derive(Debug, Clone)]
struct HeapState {
    alignment: usize,
    next_address: u64,
    allocations: BTreeMap<u64, Vec<u8>>,
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
}

#[derive(Debug, Clone)]
struct ComRegistration {
    clsid: String,
    module_path: String,
    threading_model: ComThreadingModel,
}

#[derive(Debug, Clone)]
pub struct Win32Subsystem {
    ge: GameEnvironment,
    pub(crate) next_handle: Handle,
    next_process_id: u32,
    next_thread_id: u32,
    next_virtual_address: u64,
    next_overlapped_id: u64,
    next_tls_slot: u32,
    handles: BTreeMap<Handle, HandleEntry>,
    threads: BTreeMap<u32, ThreadState>,
    handle_history: BTreeMap<Handle, ObjectType>,
    /// Per-handle-value generation counters.  When a handle value is reused
    /// after being closed, the generation is incremented so that stale
    /// references can be detected via [`Win32Subsystem::validate_handle_generation`].
    handle_generations: BTreeMap<Handle, u32>,
    protected_close_handles: BTreeSet<Handle>,
    overlapped: BTreeMap<u64, OverlappedRequest>,
    io_completion_associations: BTreeMap<Handle, IoCompletionAssociation>,
    memory_regions: BTreeMap<u64, VirtualRegion>,
    heaps: BTreeMap<Handle, HeapState>,
    named_events: BTreeMap<String, EventWeak>,
    named_mutexes: BTreeMap<String, Handle>,
    named_semaphores: BTreeMap<String, Handle>,
    named_pipes: BTreeMap<String, NamedPipeState>,
    shared_memory_sections: BTreeMap<String, SharedMemorySection>,
    time: TimeState,
    locale: LocaleState,
    thread_apcs: BTreeMap<u32, VecDeque<String>>,
    com_apartments: BTreeMap<u32, ApartmentModel>,
    com_registrations: BTreeMap<String, ComRegistration>,
    recently_closed_handles: VecDeque<(Handle, ObjectType)>,
    current_process_id: u32,
    current_thread_id: u32,
}

impl Win32Subsystem {
    pub fn new(ge: GameEnvironment, dtm: bool) -> Self {
        Self::new_with_live_pacing(ge, dtm, false)
    }

    pub fn new_with_live_pacing(ge: GameEnvironment, dtm: bool, live_pacing: bool) -> Self {
        let current_process_id = std::process::id();
        let current_thread_id = 1;
        Self {
            ge,
            next_handle: 4,
            next_process_id: current_process_id + 1,
            next_thread_id: 2,
            next_virtual_address: 0x1_0000_0000,
            next_overlapped_id: 1,
            next_tls_slot: 0,
            handles: BTreeMap::new(),
            threads: BTreeMap::new(),
            handle_history: BTreeMap::new(),
            handle_generations: BTreeMap::new(),
            protected_close_handles: BTreeSet::new(),
            overlapped: BTreeMap::new(),
            io_completion_associations: BTreeMap::new(),
            memory_regions: BTreeMap::new(),
            heaps: BTreeMap::new(),
            named_events: BTreeMap::new(),
            named_mutexes: BTreeMap::new(),
            named_semaphores: BTreeMap::new(),
            named_pipes: BTreeMap::new(),
            shared_memory_sections: BTreeMap::new(),
            time: TimeState {
                dtm,
                live_pacing: live_pacing && !dtm,
                perf_frequency: 10_000_000,
                qpc: 0,
                ticks_ms: 0,
                drift_log: Vec::new(),
            },
            locale: LocaleState { acp: 1252 },
            thread_apcs: BTreeMap::new(),
            com_apartments: BTreeMap::new(),
            com_registrations: BTreeMap::new(),
            recently_closed_handles: VecDeque::new(),
            current_process_id,
            current_thread_id,
        }
    }

    pub fn ge(&self) -> &GameEnvironment {
        &self.ge
    }

    pub fn current_thread_id(&self) -> u32 {
        self.current_thread_id
    }

    pub fn set_current_thread_id(&mut self, thread_id: u32) -> u32 {
        let previous = self.current_thread_id;
        self.current_thread_id = thread_id;
        previous
    }

    pub fn current_thread_handle(&mut self) -> Handle {
        if let Some(handle) = self
            .handles
            .iter()
            .find_map(|(handle, entry)| match &entry.object {
                KernelObject::Thread(thread) if thread.thread_id == self.current_thread_id => {
                    Some(*handle)
                }
                _ => None,
            })
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

    pub fn current_process_handle(&mut self) -> Handle {
        if let Some(handle) = self
            .handles
            .iter()
            .find_map(|(handle, entry)| match &entry.object {
                KernelObject::Process(process) if process.process_id == self.current_process_id => {
                    Some(*handle)
                }
                _ => None,
            })
        {
            handle
        } else {
            self.insert_object(
                ObjectType::Process,
                0x1F0FFF,
                false,
                KernelObject::Process(ProcessObject {
                    process_id: self.current_process_id,
                    executable: "macwin".to_string(),
                    argv: vec!["macwin".to_string()],
                    cwd: "C:\\".to_string(),
                    environment: BTreeMap::new(),
                    inherited_handles: Vec::new(),
                    modules: vec![
                        "macwin".to_string(),
                        "kernel32.dll".to_string(),
                        "ntdll.dll".to_string(),
                    ],
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
        {
            let entry = self.handle_entry_mut(handle)?;
            if mask & HANDLE_FLAG_INHERIT != 0 {
                entry.descriptor.inheritable = flags & HANDLE_FLAG_INHERIT != 0;
            }
        }
        if mask & HANDLE_FLAG_PROTECT_FROM_CLOSE != 0 {
            if flags & HANDLE_FLAG_PROTECT_FROM_CLOSE != 0 {
                self.protected_close_handles.insert(handle);
            } else {
                self.protected_close_handles.remove(&handle);
            }
        }
        Ok(())
    }

    pub fn duplicate_handle(
        &mut self,
        source_handle: Handle,
        desired_access: u32,
        inheritable: bool,
        same_access: bool,
        close_source: bool,
    ) -> AppResult<Handle> {
        let source_entry = self.handle_entry(source_handle)?.clone();
        let access_mask = if same_access || desired_access == 0 {
            source_entry.descriptor.access_mask
        } else {
            desired_access
        };
        let duplicated_handle = self.insert_object(
            source_entry.descriptor.object_type,
            access_mask,
            inheritable,
            source_entry.object,
        );
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
        if let Some(name) = name {
            if let Some(event) = self.named_events.get(name).and_then(Weak::upgrade) {
                let handle = self.insert_object(
                    ObjectType::Event,
                    0x1F0003,
                    inheritable,
                    KernelObject::Event(event),
                );
                return (handle, true);
            }
        }

        let event = Rc::new(RefCell::new(EventObject {
            manual_reset,
            signaled: initial_state,
        }));
        if let Some(name) = name {
            self.named_events
                .insert(name.to_string(), Rc::downgrade(&event));
        }
        let handle = self.insert_object(
            ObjectType::Event,
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
        let Some(event) = self.named_events.get(name).and_then(Weak::upgrade) else {
            self.named_events.remove(name);
            return Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("event {name} not found"),
            ));
        };

        Ok(self.insert_object(
            ObjectType::Event,
            desired_access,
            inheritable,
            KernelObject::Event(event),
        ))
    }

    pub fn create_io_completion_port(
        &mut self,
        file_handle: Option<Handle>,
        existing_completion_port: Option<Handle>,
        completion_key: u64,
        concurrent_threads: u32,
    ) -> AppResult<Handle> {
        if file_handle.is_none() && existing_completion_port.is_some() {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                "CreateIoCompletionPort requires a file handle when reusing an existing port",
            ));
        }

        let port_handle = if let Some(port_handle) = existing_completion_port {
            match &self.handle_entry(port_handle)?.object {
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
            if self.io_completion_associations.contains_key(&file_handle) {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "handle {file_handle} is already associated with an I/O completion port"
                    ),
                ));
            }
            self.io_completion_associations.insert(
                file_handle,
                IoCompletionAssociation {
                    port_handle,
                    completion_key,
                },
            );
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
        let entry = self.handle_entry_mut(completion_port)?;
        match &mut entry.object {
            KernelObject::IoCompletionPort(port) => {
                let _concurrent_threads = port.concurrent_threads;
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
        let entry = self.handle_entry_mut(completion_port)?;
        match &mut entry.object {
            KernelObject::IoCompletionPort(port) => {
                let mut packets = Vec::new();
                while packets.len() < max_packets {
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
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::Event(event) => {
                event.borrow_mut().signaled = true;
                Ok(())
            }
            _ => invalid_handle("handle is not an event"),
        }
    }

    pub fn reset_event(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::Event(event) => {
                event.borrow_mut().signaled = false;
                Ok(())
            }
            _ => invalid_handle("handle is not an event"),
        }
    }

    pub fn create_mutex(&mut self, initially_owned: bool, inheritable: bool) -> Handle {
        self.insert_object(
            ObjectType::Mutex,
            0x1F0001,
            inheritable,
            KernelObject::Mutex(MutexObject {
                owner_thread_id: initially_owned.then_some(self.current_thread_id),
                abandoned: false,
            }),
        )
    }

    pub fn abandon_mutex(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::Mutex(mutex) => {
                mutex.owner_thread_id = None;
                mutex.abandoned = true;
                Ok(())
            }
            _ => invalid_handle("handle is not a mutex"),
        }
    }

    pub fn release_mutex(&mut self, handle: Handle) -> AppResult<()> {
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::Mutex(mutex) => {
                mutex.owner_thread_id = None;
                mutex.abandoned = false;
                Ok(())
            }
            _ => invalid_handle("handle is not a mutex"),
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
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::Semaphore(semaphore) => {
                let prev = semaphore.count;
                semaphore.count = semaphore
                    .count
                    .saturating_add(release_count)
                    .min(semaphore.maximum);
                Ok(prev)
            }
            _ => invalid_handle("handle is not a semaphore"),
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
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
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
            if let Some(thread_handle) = thread_handle {
                let thread_id = self.thread_id(thread_handle)?;
                if let Some(queue) = self.thread_apcs.get_mut(&thread_id) {
                    if !queue.is_empty() {
                        queue.pop_front();
                        return Ok(WaitStatus::IoCompletion);
                    }
                }
            }
        }

        let now = self.time.ticks_ms;
        let object_type = self.handle_entry(handle)?.descriptor.object_type;
        match object_type {
            ObjectType::Event => {
                let entry = self.handle_entry_mut(handle)?;
                if let KernelObject::Event(event) = &mut entry.object {
                    let mut event = event.borrow_mut();
                    if event.signaled {
                        if !event.manual_reset {
                            event.signaled = false;
                        }
                        Ok(WaitStatus::Object0)
                    } else {
                        // timeout_ms unused in non-blocking path
                        Ok(WaitStatus::Timeout)
                    }
                } else {
                    invalid_handle("handle is not an event")
                }
            }
            ObjectType::Mutex => {
                let entry = self.handle_entry_mut(handle)?;
                if let KernelObject::Mutex(mutex) = &mut entry.object {
                    if mutex.abandoned {
                        mutex.abandoned = false;
                        mutex.owner_thread_id = Some(current_thread_id);
                        Ok(WaitStatus::Abandoned)
                    } else if mutex.owner_thread_id.is_none() {
                        mutex.owner_thread_id = Some(current_thread_id);
                        Ok(WaitStatus::Object0)
                    } else {
                        // timeout_ms unused in non-blocking path
                        Ok(WaitStatus::Timeout)
                    }
                } else {
                    invalid_handle("handle is not a mutex")
                }
            }
            ObjectType::Semaphore => {
                let entry = self.handle_entry_mut(handle)?;
                if let KernelObject::Semaphore(semaphore) = &mut entry.object {
                    if semaphore.count > 0 {
                        semaphore.count -= 1;
                        Ok(WaitStatus::Object0)
                    } else {
                        // timeout_ms unused in non-blocking path
                        Ok(WaitStatus::Timeout)
                    }
                } else {
                    invalid_handle("handle is not a semaphore")
                }
            }
            ObjectType::Thread => {
                let thread_id = self.thread_id(handle)?;
                if self.thread_state(thread_id)?.exit_code.is_some() {
                    Ok(WaitStatus::Object0)
                } else {
                    // timeout_ms unused in non-blocking path
                    Ok(WaitStatus::Timeout)
                }
            }
            ObjectType::Process => {
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
                        // timeout_ms unused when no exit_sync
                        Ok(WaitStatus::Timeout)
                    }
                } else {
                    invalid_handle("handle is not a process")
                }
            }
            ObjectType::Timer => {
                let entry = self.handle_entry_mut(handle)?;
                if let KernelObject::Timer(timer) = &mut entry.object {
                    if timer.signaled || now >= timer.due_tick {
                        timer.signaled = true;
                        Ok(WaitStatus::Object0)
                    } else {
                        // timeout_ms unused in non-blocking path
                        Ok(WaitStatus::Timeout)
                    }
                } else {
                    invalid_handle("handle is not a timer")
                }
            }
            _ => Ok(WaitStatus::Object0),
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
            Some(self.time.ticks_ms + timeout_ms as u64)
        };

        if alertable && !handles.is_empty() {
            if let Some(thread_handle) = thread_handle {
                if let Ok(thread_id) = self.thread_id(thread_handle) {
                    if let Some(queue) = self.thread_apcs.get(&thread_id) {
                        if !queue.is_empty() {
                            return Ok((WaitStatus::IoCompletion, 0));
                        }
                    }
                }
            }
        }

        'outer: loop {
            for (i, &handle) in handles.iter().enumerate() {
                let status = self.wait_for_single_object(handle, 0, false, None)?;
                match status {
                    WaitStatus::Object0 => {
                        if !wait_all {
                            return Ok((WaitStatus::Object0, i));
                        }
                    }
                    WaitStatus::Abandoned => {
                        if !wait_all {
                            return Ok((WaitStatus::Abandoned, i));
                        }
                    }
                    _ => {}
                }
            }

            if wait_all {
                let all_signaled = handles.iter().all(|&h| {
                    matches!(
                        self.wait_for_single_object(h, 0, false, None),
                        Ok(WaitStatus::Object0)
                    )
                });
                if all_signaled {
                    return Ok((WaitStatus::Object0, 0));
                }
            }

            if let Some(deadline) = deadline {
                if self.time.ticks_ms >= deadline {
                    return Ok((WaitStatus::Timeout, handles.len().saturating_sub(1)));
                }
            }

            if timeout_ms != 0 {
                std::thread::sleep(Duration::from_millis(1));
                // Advance the guest clock so the finite-timeout deadline
                // check above can actually expire.  Without this the raw
                // `thread::sleep` never bumps `ticks_ms`, so a finite
                // (non-INFINITE) timeout would loop forever.
                self.record_sleep_observation(1, 1);
            } else {
                break 'outer;
            }
        }

        Ok((WaitStatus::Timeout, handles.len().saturating_sub(1)))
    }

    /// Named mutex support — maps a name to a mutex handle.
    pub fn create_named_mutex(
        &mut self,
        name: &str,
        initially_owned: bool,
        inheritable: bool,
    ) -> (Handle, bool) {
        if let Some(&handle) = self.named_mutexes.get(name) {
            (handle, false)
        } else {
            let handle = self.create_mutex(initially_owned, inheritable);
            self.named_mutexes.insert(name.to_string(), handle);
            (handle, true)
        }
    }

    pub fn open_named_mutex(&self, name: &str) -> Option<Handle> {
        self.named_mutexes.get(name).copied()
    }

    /// Named semaphore support.
    pub fn create_named_semaphore(
        &mut self,
        name: &str,
        initial_count: u32,
        maximum: u32,
        inheritable: bool,
    ) -> (Handle, bool) {
        if let Some(&handle) = self.named_semaphores.get(name) {
            (handle, false)
        } else {
            let handle = self.create_semaphore(initial_count, maximum, inheritable);
            self.named_semaphores.insert(name.to_string(), handle);
            (handle, true)
        }
    }

    pub fn open_named_semaphore(&self, name: &str) -> Option<Handle> {
        self.named_semaphores.get(name).copied()
    }

    /// Named event support (open by name).
    pub fn open_named_event(&self, name: &str) -> Option<Handle> {
        // Named events use EventWeak; attempt to upgrade
        self.named_events
            .get(name)
            .and_then(|weak| weak.upgrade())
            .and_then(|_event_rc| {
                // Return the first handle matching this named event
                // This is a simplified approach; real Windows tracks names per-event
                None
            })
    }

    pub fn queue_apc(&mut self, thread_handle: Handle, token: impl Into<String>) -> AppResult<()> {
        let thread_id = self.thread_id(thread_handle)?;
        self.thread_apcs
            .entry(thread_id)
            .or_default()
            .push_back(token.into());
        Ok(())
    }

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
        let (normalized_path, host_path) = self.resolve_host_path(path)?;
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
            return Ok(self.insert_object(
                ObjectType::File,
                0x12019f,
                inheritable,
                KernelObject::File(Rc::new(RefCell::new(FileObject {
                    normalized_path,
                    host_path,
                    ge_handle: None,
                    position: 0,
                    overlapped,
                }))),
            ));
        }
        match creation {
            CreationDisposition::CreateNew if exists => {
                return Err(AppError::new(
                    ReasonCode::RcFsAlreadyExists,
                    format!("{} already exists", normalized_path),
                ));
            }
            CreationDisposition::OpenExisting | CreationDisposition::TruncateExisting
                if !exists =>
            {
                return Err(AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!("{} does not exist", normalized_path),
                ));
            }
            CreationDisposition::CreateAlways
            | CreationDisposition::OpenAlways
            | CreationDisposition::CreateNew
                if !exists =>
            {
                self.ensure_parent_exists(&host_path)?;
                fs::write(&host_path, []).map_err(|error| {
                    AppError::from_io(
                        ReasonCode::RcIo,
                        format!("failed to create {}", host_path.display()),
                        &error,
                    )
                })?;
                self.sync_entry(&normalized_path, &host_path, false)?;
            }
            CreationDisposition::CreateAlways if exists => {
                fs::write(&host_path, []).map_err(|error| {
                    AppError::from_io(
                        ReasonCode::RcIo,
                        format!("failed to truncate {}", host_path.display()),
                        &error,
                    )
                })?;
                self.sync_entry(&normalized_path, &host_path, false)?;
            }
            CreationDisposition::TruncateExisting if exists => {
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
        let ge_handle = if host_path.exists() {
            Some(self.ge.open_file(path, desired_access, share_mode)?)
        } else {
            None
        };
        Ok(self.insert_object(
            ObjectType::File,
            0x12019f,
            inheritable,
            KernelObject::File(Rc::new(RefCell::new(FileObject {
                normalized_path,
                host_path,
                ge_handle,
                position: 0,
                overlapped,
            }))),
        ))
    }

    pub fn close_handle(&mut self, handle: Handle) -> AppResult<()> {
        if self.protected_close_handles.contains(&handle) {
            return Err(AppError::new(
                ReasonCode::RcHelperPermissionDenied,
                format!("handle {handle} is protected from close"),
            ));
        }
        let mut entry = self.handles.remove(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid handle {handle}"),
            )
        })?;
        self.protected_close_handles.remove(&handle);
        if let KernelObject::File(file) = &entry.object {
            let ge_handle = if Rc::strong_count(file) == 1 {
                file.borrow().ge_handle.clone()
            } else {
                None
            };
            if let Some(ge_handle) = ge_handle {
                self.ge.close_file_handle(&ge_handle)?;
            }
        }
        if entry.descriptor.refcount > 1 {
            entry.descriptor.refcount -= 1;
            self.handles.insert(handle, entry);
        } else {
            // Increment the generation counter so stale references to the
            // old handle value are detected by `validate_handle_generation`.
            let generation = self.handle_generations.entry(handle).or_insert(0);
            *generation = generation.saturating_add(1);
            self.record_closed_handle(handle, entry.descriptor.object_type);
            if let KernelObject::Thread(thread) = &entry.object {
                self.cleanup_exited_thread_state(thread.thread_id);
            }
        }
        Ok(())
    }

    pub fn read_file(&mut self, handle: Handle, length: usize) -> AppResult<Vec<u8>> {
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::File(file) => {
                let mut file = file.borrow_mut();
                let bytes = fs::read(&file.host_path).map_err(|error| {
                    AppError::from_io(
                        ReasonCode::RcIo,
                        format!("failed to read {}", file.host_path.display()),
                        &error,
                    )
                })?;
                let start = file.position as usize;
                let end = start.saturating_add(length).min(bytes.len());
                file.position = end as u64;
                Ok(bytes[start..end].to_vec())
            }
            KernelObject::Pipe(pipe) => {
                // Read from named pipe backing buffer
                let normalized = normalize_pipe_name(&pipe.name);
                if let Some(state) = self.named_pipes.get(&normalized) {
                    let buffer = state.buffer.lock().unwrap();
                    let available = buffer.len().min(length);
                    let data: Vec<u8> = buffer.iter().take(available).copied().collect();
                    // We consume the data from the shared buffer
                    drop(buffer);
                    if let Some(state_mut) = self.named_pipes.get_mut(&normalized) {
                        let mut buf = state_mut.buffer.lock().unwrap();
                        if available > 0 {
                            buf.drain(..available);
                        }
                    }
                    Ok(data)
                } else {
                    Ok(Vec::new())
                }
            }
            _ => invalid_handle("handle is not a file or pipe"),
        }
    }

    pub fn write_file(&mut self, handle: Handle, bytes: &[u8]) -> AppResult<u32> {
        let (normalized_path, host_path) = {
            let entry = self.handle_entry_mut(handle)?;
            match &mut entry.object {
                KernelObject::File(file) => {
                    let mut file = file.borrow_mut();
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
                    let start = file.position as usize;
                    if contents.len() < start {
                        contents.resize(start, 0);
                    }
                    if contents.len() < start + bytes.len() {
                        contents.resize(start + bytes.len(), 0);
                    }
                    contents[start..start + bytes.len()].copy_from_slice(bytes);
                    fs::write(&file.host_path, &contents).map_err(|error| {
                        AppError::from_io(
                            ReasonCode::RcIo,
                            format!("failed to write {}", file.host_path.display()),
                            &error,
                        )
                    })?;
                    file.position += bytes.len() as u64;
                    (file.normalized_path.clone(), file.host_path.clone())
                }
                KernelObject::Pipe(pipe) => {
                    // Write to named pipe backing buffer
                    let normalized = normalize_pipe_name(&pipe.name);
                    if let Some(state) = self.named_pipes.get_mut(&normalized) {
                        let mut buffer = state.buffer.lock().unwrap();
                        buffer.extend(bytes);
                        state.data_ready.notify_all();
                    }
                    (String::new(), PathBuf::new())
                }
                _ => return invalid_handle("handle is not a file or pipe"),
            }
        };
        if !normalized_path.is_empty() {
            self.sync_entry(&normalized_path, &host_path, false)?;
        }
        Ok(bytes.len() as u32)
    }

    pub fn flush_file_buffers(&mut self, handle: Handle) -> AppResult<()> {
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
        let size = self.get_file_size_ex(handle)? as i64;
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::File(file) => {
                let mut file = file.borrow_mut();
                let next = match origin {
                    SeekOrigin::Begin => distance,
                    SeekOrigin::Current => file.position as i64 + distance,
                    SeekOrigin::End => size + distance,
                };
                if next < 0 {
                    return Err(AppError::new(
                        ReasonCode::RcMemoryAccessViolation,
                        "negative file pointer is not allowed",
                    ));
                }
                file.position = next as u64;
                Ok(file.position)
            }
            _ => invalid_handle("handle is not a file"),
        }
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
        Ok(FileInformation {
            normalized_path,
            size: host.len(),
            attributes: metadata.attributes,
            creation_time_ticks: metadata.creation_time_ticks,
            last_access_time_ticks: metadata.last_access_time_ticks,
            last_write_time_ticks: metadata.last_write_time_ticks,
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
        Ok(self.ge.get_file_metadata(path)?.attributes)
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
        self.ge.save_config()
    }

    pub fn find_first_file_w(&mut self, path: &str) -> AppResult<(Handle, FindData)> {
        let (directory_path, pattern) = split_find_search_pattern(path);
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
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
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
        fs::remove_file(&host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to delete {}", host_path.display()),
                &error,
            )
        })?;
        self.ge.config.fs_state.entries.remove(&normalized_path);
        self.ge.save_config()
    }

    pub fn move_file_ex_w(
        &mut self,
        from: &str,
        to: &str,
        replace_existing: bool,
    ) -> AppResult<()> {
        let (from_norm, from_host) = self.resolve_host_path(from)?;
        let (to_norm, to_host) = self.resolve_host_path(to)?;
        self.ensure_parent_exists(&to_host)?;
        if replace_existing && to_host.exists() {
            if to_host.is_dir() {
                fs::remove_dir_all(&to_host).map_err(|error| {
                    AppError::from_io(
                        ReasonCode::RcIo,
                        format!("failed to remove {}", to_host.display()),
                        &error,
                    )
                })?;
            } else {
                fs::remove_file(&to_host).map_err(|error| {
                    AppError::from_io(
                        ReasonCode::RcIo,
                        format!("failed to remove {}", to_host.display()),
                        &error,
                    )
                })?;
            }
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
        self.ge.save_config()
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
        self.ensure_parent_exists(&to_host)?;
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
        let (_, host_path) = self.resolve_host_path(path.trim_end_matches(['\\', '/']))?;
        fs::create_dir_all(&host_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", host_path.display()),
                &error,
            )
        })?;
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
        fs::create_dir_all(&host_directory).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", host_directory.display()),
                &error,
            )
        })?;
        let name = format!("{}{:04}.tmp", prefix, self.next_handle);
        let full = format!(
            "{}\\{}",
            normalized_directory.trim_end_matches(['\\', '/']),
            name
        );
        let (normalized_path, host_path) = self.resolve_host_path(&full)?;
        self.ensure_parent_exists(&host_path)?;
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
        let end = ((offset as usize) + length).min(bytes.len());
        let transferred = end.saturating_sub(offset as usize) as u32;
        let id = self.insert_overlapped(
            handle,
            event_handle,
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
            let start = offset as usize;
            if contents.len() < start {
                contents.resize(start, 0);
            }
            if contents.len() < start + bytes.len() {
                contents.resize(start + bytes.len(), 0);
            }
            contents[start..start + bytes.len()].copy_from_slice(bytes);
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
        let request = self.overlapped.get(&id).cloned().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid overlapped id {id}"),
            )
        })?;
        match request.state {
            OverlappedState::Completed(bytes_transferred) => Ok(OverlappedResult {
                id,
                bytes_transferred,
                completed: true,
                cancelled: false,
            }),
            OverlappedState::Cancelled => Ok(OverlappedResult {
                id,
                bytes_transferred: 0,
                completed: false,
                cancelled: true,
            }),
            OverlappedState::Pending if wait => Err(AppError::new(
                ReasonCode::RcWin32Timeout,
                format!("overlapped request {id} is still pending"),
            )),
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
            }),
        )
    }

    pub fn connect_named_pipe_internal(
        &mut self,
        handle: Handle,
        event_handle: Option<Handle>,
        overlapped: bool,
    ) -> AppResult<Option<u64>> {
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::Pipe(pipe) => {
                if pipe.connected {
                    self.signal_event_if_needed(event_handle)?;
                    Ok(None)
                } else if overlapped {
                    let id = self.insert_overlapped(handle, event_handle, OverlappedState::Pending);
                    Ok(Some(id))
                } else {
                    Err(AppError::new(
                        ReasonCode::RcPipeBusy,
                        format!("{} is not connected", pipe.name),
                    ))
                }
            }
            _ => invalid_handle("handle is not a pipe"),
        }
    }

    pub fn call_named_pipe(&mut self, name: &str, request: &[u8]) -> AppResult<Vec<u8>> {
        let normalized = normalize_pipe_name(name);
        let pipe_handle = self
            .handles
            .iter()
            .find_map(|(handle, entry)| match &entry.object {
                KernelObject::Pipe(pipe) if pipe.name == normalized => Some(*handle),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcPipeBusy,
                    format!("{} is not registered", normalized),
                )
            })?;
        if let Some(entry) = self.handles.get_mut(&pipe_handle) {
            if let KernelObject::Pipe(pipe) = &mut entry.object {
                pipe.connected = true;
                pipe.buffer = request.to_vec();
            }
        }
        let pending_ids = self
            .overlapped
            .iter()
            .filter(|(_, request)| request.handle == pipe_handle)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let mut events = Vec::new();
        for id in pending_ids {
            if let Some(request) = self.overlapped.get_mut(&id) {
                request.state = OverlappedState::Completed(
                    request.len_hint(request_id_len(request, request_id_len_inner(request))) as u32,
                );
                events.push(request.event_handle);
            }
        }
        for event_handle in events {
            self.signal_event_if_needed(event_handle)?;
        }
        Ok(request.to_vec())
    }

    pub fn virtual_alloc(
        &mut self,
        base_address: Option<u64>,
        size: usize,
        allocation_type: AllocationType,
        protection: MemoryProtection,
    ) -> AppResult<u64> {
        let base = base_address.unwrap_or_else(|| {
            let current = self.next_virtual_address;
            self.next_virtual_address += align_up(size as u64, 0x1000);
            current
        });
        let region = self
            .memory_regions
            .entry(base)
            .or_insert_with(|| VirtualRegion {
                base_address: base,
                size: align_up(size as u64, 0x1000) as usize,
                committed: BTreeSet::new(),
                protection,
            });
        region.protection = protection;
        match allocation_type {
            AllocationType::Reserve => {}
            AllocationType::Commit | AllocationType::ReserveCommit => {
                let page_count = align_up(size as u64, 0x1000) / 0x1000;
                for page in 0..page_count {
                    region.committed.insert(base + page * 0x1000);
                }
            }
        }
        Ok(base)
    }

    pub fn virtual_free(&mut self, base_address: u64, free_type: FreeType) -> AppResult<()> {
        match free_type {
            FreeType::Release => {
                self.memory_regions.remove(&base_address);
            }
            FreeType::Decommit => {
                if let Some(region) = self.memory_regions.get_mut(&base_address) {
                    region.committed.clear();
                }
            }
        }
        Ok(())
    }

    pub fn virtual_protect(
        &mut self,
        base_address: u64,
        protection: MemoryProtection,
    ) -> AppResult<MemoryProtection> {
        let region = self.memory_regions.get_mut(&base_address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("unknown region {base_address:#x}"),
            )
        })?;
        let previous = region.protection;
        region.protection = protection;
        Ok(previous)
    }

    pub fn virtual_query(&self, address: u64) -> MemoryBasicInformation {
        for region in self.memory_regions.values() {
            if address >= region.base_address && address < region.base_address + region.size as u64
            {
                return MemoryBasicInformation {
                    base_address: region.base_address,
                    region_size: region.size,
                    state: if region.committed.is_empty() {
                        MemoryState::Reserved
                    } else {
                        MemoryState::Committed
                    },
                    protection: region.protection,
                };
            }
        }
        MemoryBasicInformation {
            base_address: 0,
            region_size: 0,
            state: MemoryState::Free,
            protection: MemoryProtection {
                read: false,
                write: false,
                execute: false,
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
            }),
        );
        self.heaps.insert(
            handle,
            HeapState {
                alignment: alignment.max(8),
                next_address: 0x2000_0000,
                allocations: BTreeMap::new(),
            },
        );
        handle
    }

    pub fn heap_alloc(&mut self, heap: Handle, size: usize) -> AppResult<u64> {
        let state = self.heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid heap {heap}"),
            )
        })?;
        let address = align_up(state.next_address, state.alignment as u64);
        state.next_address = address + size as u64 + state.alignment as u64;
        state.allocations.insert(address, vec![0_u8; size]);
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
        allocation.resize(new_size, 0);
        let new_address = align_up(state.next_address, state.alignment as u64);
        state.next_address = new_address + new_size as u64 + state.alignment as u64;
        state.allocations.insert(new_address, allocation);
        Ok(new_address)
    }

    pub fn heap_free(&mut self, heap: Handle, address: u64) -> AppResult<()> {
        let state = self.heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid heap {heap}"),
            )
        })?;
        state.allocations.remove(&address);
        Ok(())
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
        let process_id = self.next_process_id;
        self.next_process_id += 1;
        let thread_id = self.next_thread_id;
        self.next_thread_id += 1;
        let inherited_handles = if inherit_handles {
            self.handles
                .values()
                .filter(|entry| entry.descriptor.inheritable)
                .map(|entry| entry.descriptor.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let process_handle = self.insert_object(
            ObjectType::Process,
            0x1F0FFF,
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
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::Process(process) => {
                process.exit_code = Some(exit_code);
                Ok(())
            }
            _ => invalid_handle("handle is not a process"),
        }
    }

    /// Like `set_process_exit_code` but also notifies any thread that is
    /// blocked in `wait_for_single_object` on this process handle.
    pub fn set_process_exit_code_and_notify(
        &mut self,
        handle: Handle,
        exit_code: u32,
    ) -> AppResult<()> {
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
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
        let entry = self.handle_entry_mut(handle)?;
        match &mut entry.object {
            KernelObject::Process(process) => {
                process.exit_sync = Some(sync);
                Ok(())
            }
            _ => invalid_handle("handle is not a process"),
        }
    }

    /// `OpenProcess` — returns a new handle to an existing process object.
    /// Only `PROCESS_ALL_ACCESS` is supported; we match against our internal
    /// process-id table.
    pub fn open_process(
        &mut self,
        desired_access: u32,
        inherit_handle: bool,
        process_id: u32,
    ) -> AppResult<Handle> {
        let existing = self
            .handles
            .values()
            .find_map(|entry| match &entry.object {
                KernelObject::Process(p) if p.process_id == process_id => {
                    Some(entry.object.clone())
                }
                _ => None,
            })
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("no process with id {process_id}"),
                )
            })?;
        Ok(self.insert_object(
            ObjectType::Process,
            desired_access,
            inherit_handle,
            existing,
        ))
    }

    // -----------------------------------------------------------------------
    // Named pipe helpers
    // -----------------------------------------------------------------------

    /// `CreateNamedPipeW` — creates a named-pipe server endpoint.
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
        security_descriptor: Option<u64>,
        uds_socket_path: Option<String>,
    ) -> AppResult<Handle> {
        let normalized = normalize_pipe_name(name);
        if self.named_pipes.contains_key(&normalized) {
            return Err(AppError::new(
                ReasonCode::RcFsAlreadyExists,
                format!("named pipe already exists: {name}"),
            ));
        }
        let buf_size = out_buffer_size.max(in_buffer_size).max(4096) as usize;

        // Compute UDS path if not explicitly provided
        let uds_path = uds_socket_path.unwrap_or_else(|| pipe_name_to_uds_path(&normalized));

        // Ensure the socket base directory exists
        if let Err(e) = std::fs::create_dir_all(PIPE_SOCKET_BASE_DIR) {
            eprintln!(
                "[win32] failed to create pipe socket base dir '{}': {e}",
                PIPE_SOCKET_BASE_DIR
            );
        }

        let state = NamedPipeState {
            name: normalized.clone(),
            server_created: true,
            connected: false,
            buffer: Arc::new(Mutex::new(VecDeque::with_capacity(buf_size))),
            data_ready: Arc::new(Condvar::new()),
            max_buffer_size: buf_size,
            server_disconnected: false,
            security_descriptor,
            uds_socket_path: Some(uds_path),
            open_mode,
            pipe_mode: pipe_mode & 0x0000_0003, // PIPE_WAIT or PIPE_NOWAIT
            max_instances,
            default_timeout,
        };
        self.named_pipes.insert(normalized.clone(), state.clone());

        Ok(self.insert_object(
            ObjectType::Pipe,
            0x1F0FFF,
            inheritable,
            KernelObject::Pipe(PipeObject {
                name: normalized,
                connected: false,
                buffer: Vec::new(),
            }),
        ))
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
        // with `\\.\pipe\...`) will set `connected`.
        if let Some(state) = self.named_pipes.get_mut(&normalized) {
            state.server_created = true;
        }
        Ok(())
    }

    /// `GetNamedPipeInfo` — retrieve information about a named pipe.
    pub fn get_named_pipe_info(&mut self, handle: Handle) -> AppResult<(u32, u32, u32, u32)> {
        let entry = self.handle_entry(handle)?;
        match &entry.object {
            KernelObject::Pipe(pipe) => {
                let normalized = normalize_pipe_name(&pipe.name);
                let state = self.named_pipes.get(&normalized);
                let (max_size, _cur_size) = if let Some(s) = state {
                    let cur = s.buffer.lock().unwrap().len();
                    (s.max_buffer_size as u32, cur as u32)
                } else {
                    (4096, 0)
                };
                // (pipe_mode, max_instances, out_buffer_size, in_buffer_size)
                Ok((1, 1, max_size, max_size))
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
        if let Some(state) = self.named_pipes.get_mut(&normalized) {
            if let Some(mode) = mode {
                state.pipe_mode = mode;
            }
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
                let state = self.named_pipes.get(&normalized).ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcFsNotFound,
                        format!("peek_named_pipe: pipe not found: {}", pipe.name),
                    )
                })?;
                let buf = state.buffer.lock().unwrap();
                let available = buf.len() as u32;
                let to_copy = buffer.len().min(available as usize);
                for (i, b) in buf.iter().take(to_copy).enumerate() {
                    buffer[i] = *b;
                }
                // Return (bytes_read, total_bytes_avail, bytes_left_this_message)
                Ok((to_copy as u32, available, available))
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
        if let Some(state) = self.named_pipes.get_mut(&normalized) {
            state.connected = false;
            state.server_disconnected = true;
            state.data_ready.notify_all();
        }
        Ok(())
    }

    /// `CallNamedPipeW` — convenience: connect, write, read, disconnect.
    ///
    /// Writes the request data into the shared pipe buffer and returns
    /// immediately.  In a shared-buffer model we cannot block for a
    /// server response in a single-threaded context, so the request is
    /// left in the buffer for the server to process.  The returned
    /// `Vec<u8>` is always empty; callers should use separate
    /// `read_file` / `write_file` calls for the response.
    pub fn call_named_pipe_w(
        &mut self,
        pipe_name: &str,
        write_data: &[u8],
        _read_buffer_size: u32,
        _timeout_ms: u32,
    ) -> AppResult<Vec<u8>> {
        let normalized = normalize_pipe_name(pipe_name);
        // Find the pipe state
        let state = self.named_pipes.get(&normalized).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcFsNotFound,
                format!("named pipe not found: {pipe_name}"),
            )
        })?;
        let buf = state.buffer.clone();
        let ready = state.data_ready.clone();
        // Write data (client → server direction) and notify the server.
        {
            let mut buffer = buf.lock().unwrap();
            buffer.extend(write_data);
            ready.notify_all();
        }
        // Do NOT drain the buffer — the request data stays for the
        // server to read via `read_file`.  Return empty to the caller.
        Ok(Vec::new())
    }

    /// `WaitNamedPipeW` — wait for a named pipe to become available.
    pub fn wait_named_pipe_w(&mut self, pipe_name: &str, _timeout_ms: u32) -> AppResult<()> {
        let normalized = normalize_pipe_name(pipe_name);
        if self.named_pipes.contains_key(&normalized) {
            Ok(())
        } else {
            Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("named pipe not found: {pipe_name}"),
            ))
        }
    }

    /// Open a pipe client endpoint: called from `CreateFileW` when the path
    /// starts with `\\.\pipe\`.
    pub fn open_named_pipe_client(
        &mut self,
        pipe_name: &str,
        inheritable: bool,
    ) -> AppResult<Handle> {
        let normalized = normalize_pipe_name(pipe_name);
        let (_buf, _ready) = {
            let state = self.named_pipes.get_mut(&normalized).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!("named pipe not found: {pipe_name}"),
                )
            })?;
            // Mark as connected
            state.connected = true;
            (state.buffer.clone(), state.data_ready.clone())
        };
        // Return a pipe handle that shares the same buffer
        Ok(self.insert_object(
            ObjectType::Pipe,
            0x1F0FFF,
            inheritable,
            KernelObject::Pipe(PipeObject {
                name: normalized,
                connected: true,
                buffer: Vec::new(),
            }),
        ))
    }

    // -----------------------------------------------------------------------
    // Shared memory helpers (CreateFileMappingW / MapViewOfFile)
    // -----------------------------------------------------------------------

    /// `CreateFileMappingW` — create or open a named shared-memory section.
    pub fn create_file_mapping_w(
        &mut self,
        name: Option<&str>,
        maximum_size: usize,
        protection: MemoryProtection,
        inheritable: bool,
    ) -> AppResult<(Handle, bool)> {
        let key = name.unwrap_or("").to_string();
        if !key.is_empty() {
            // Check existence before borrowing self mutably
            let exists = self.shared_memory_sections.contains_key(&key);
            if exists {
                // Already exists — return a new handle to it
                let section = self.shared_memory_sections.get(&key).unwrap();
                let size = section.data.lock().unwrap().len();
                let prot = section.protection;
                // The section reference is no longer needed; the borrow ends here naturally
                let _ = section;
                let handle = self.insert_object(
                    ObjectType::Section,
                    0x1F0FFF,
                    inheritable,
                    KernelObject::Section(SectionObject {
                        base_address: 0,
                        size,
                        protection: prot,
                    }),
                );
                return Ok((handle, true));
            }
        }
        let data = Arc::new(Mutex::new(vec![0_u8; maximum_size.max(1)]));
        let mmap_backing = if !key.is_empty() {
            // For named sections, optionally create an mmap backing
            MmapBacking::new(maximum_size.max(1)).map(|m| Arc::new(Mutex::new(m)))
        } else {
            None
        };
        let section = SharedMemorySection {
            name: key.clone(),
            data,
            mmap_backing,
            maximum_size,
            protection,
        };
        if !key.is_empty() {
            self.shared_memory_sections.insert(key, section.clone());
        }
        let handle = self.insert_object(
            ObjectType::Section,
            0x1F0FFF,
            inheritable,
            KernelObject::Section(SectionObject {
                base_address: 0,
                size: maximum_size,
                protection,
            }),
        );
        Ok((handle, false))
    }

    /// `MapViewOfFile` — return a base address for the shared memory section.
    /// We allocate a virtual address range in the guest's address space and
    /// store the mapping.
    pub fn map_view_of_file(
        &mut self,
        handle: Handle,
        offset: u64,
        bytes_to_map: usize,
    ) -> AppResult<u64> {
        let entry = self.handle_entry(handle)?;
        let (_protection, _) = match &entry.object {
            KernelObject::Section(section) => (section.protection, section.size),
            _ => return invalid_handle("handle is not a section"),
        };
        let _offset = offset;
        let _bytes_to_map = bytes_to_map;
        // Allocate a virtual address for the mapping
        let base = self.next_virtual_address;
        let size = bytes_to_map.max(0x1000).next_power_of_two();
        self.next_virtual_address = self.next_virtual_address.saturating_add(size as u64);
        self.memory_regions.insert(
            base,
            VirtualRegion {
                base_address: base,
                size,
                committed: BTreeSet::from([base]),
                protection: MemoryProtection {
                    read: true,
                    write: true,
                    execute: false,
                },
            },
        );
        Ok(base)
    }

    /// `UnmapViewOfFile` — release a previously mapped view.
    pub fn unmap_view_of_file(&mut self, base_address: u64) -> AppResult<()> {
        self.memory_regions.remove(&base_address);
        Ok(())
    }

    pub fn set_thread_exit_code(&mut self, handle: Handle, exit_code: u32) -> AppResult<()> {
        let thread_id = self.thread_id(handle)?;
        self.set_thread_exit_code_by_id(thread_id, exit_code)
    }

    pub fn set_thread_exit_code_by_id(&mut self, thread_id: u32, exit_code: u32) -> AppResult<()> {
        self.ensure_thread_state(thread_id);
        self.thread_state_mut(thread_id)?.exit_code = Some(exit_code);
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
        let thread_id = self.thread_id(handle)?;
        Ok(self.thread_state(thread_id)?.exit_code)
    }

    pub fn set_thread_priority(&mut self, handle: Handle, priority: i32) -> AppResult<()> {
        let thread_id = self.thread_id(handle)?;
        self.thread_state_mut(thread_id)?.priority = priority;
        Ok(())
    }

    pub fn get_thread_priority(&self, handle: Handle) -> AppResult<i32> {
        let thread_id = self.thread_id(handle)?;
        Ok(self.thread_state(thread_id)?.priority)
    }

    pub fn open_thread(&mut self, thread_id: u32, inheritable: bool) -> Handle {
        self.ensure_thread_state(thread_id);
        self.insert_object(
            ObjectType::Thread,
            0x1F03FF,
            inheritable,
            KernelObject::Thread(ThreadObject { thread_id }),
        )
    }

    pub fn suspend_thread(&mut self, handle: Handle) -> AppResult<u32> {
        let thread_id = self.thread_id(handle)?;
        let state = self.thread_state_mut(thread_id)?;
        let prev = state.suspend_count;
        state.suspend_count = state.suspend_count.saturating_add(1);
        Ok(prev)
    }

    pub fn resume_thread(&mut self, handle: Handle) -> AppResult<u32> {
        let thread_id = self.thread_id(handle)?;
        let state = self.thread_state_mut(thread_id)?;
        let prev = state.suspend_count;
        state.suspend_count = state.suspend_count.saturating_sub(1);
        Ok(prev)
    }

    pub fn terminate_thread(&mut self, handle: Handle, exit_code: u32) -> AppResult<()> {
        let thread_id = self.thread_id(handle)?;
        let state = self.thread_state_mut(thread_id)?;
        state.exit_code = Some(exit_code);
        state.terminated = true;
        Ok(())
    }

    pub fn tls_alloc(&mut self) -> u32 {
        let index = self.next_tls_slot;
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
    }

    pub fn create_toolhelp_snapshot(&self) -> ToolhelpSnapshot {
        let mut processes = vec![ProcessSnapshot {
            process_id: self.current_process_id,
            executable: "macwin".to_string(),
            argv: vec!["macwin".to_string()],
        }];
        let mut modules = vec![ModuleSnapshot {
            process_id: self.current_process_id,
            module_name: "macwin".to_string(),
        }];
        for entry in self.handles.values() {
            if let KernelObject::Process(process) = &entry.object {
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
        processes.sort_by(|left, right| left.process_id.cmp(&right.process_id));
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

    pub fn sleep(&mut self, milliseconds: u64) {
        // Advance the guest virtual clock by the full requested duration.
        // Cap the actual host sleep to 1ms maximum — the guest's Sleep()
        // should advance virtual time without blocking the host thread
        // for the full duration (which would make the emulator unusably slow).
        self.record_sleep_observation(milliseconds, milliseconds);
        // Only sleep 1ms max on the host to yield the CPU.
        std::thread::sleep(Duration::from_millis(1));
    }

    pub fn sleep_ex(
        &mut self,
        milliseconds: u64,
        alertable: bool,
        thread_handle: Option<Handle>,
    ) -> AppResult<WaitStatus> {
        if alertable {
            if let Some(thread_handle) = thread_handle {
                let thread_id = self.thread_id(thread_handle)?;
                if let Some(queue) = self.thread_apcs.get_mut(&thread_id) {
                    if !queue.is_empty() {
                        queue.pop_front();
                        return Ok(WaitStatus::IoCompletion);
                    }
                }
            }
        }
        // Advance guest clock, cap host sleep to 1ms.
        self.record_sleep_observation(milliseconds, milliseconds);
        std::thread::sleep(Duration::from_millis(1));
        Ok(WaitStatus::Object0)
    }

    pub fn record_sleep_observation(&mut self, requested_ms: u64, observed_ms: u64) {
        self.time.ticks_ms = self.time.ticks_ms.saturating_add(observed_ms);
        self.time.qpc = self
            .time
            .qpc
            .saturating_add(observed_ms.saturating_mul(self.time.perf_frequency / 1000));
        let drift_ms = observed_ms as i64 - requested_ms as i64;
        if !self.time.dtm && requested_ms >= 10 && drift_ms.abs() > 2 {
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
        self.ge.save_config()
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
        if self.handles.values().any(|entry| {
            matches!(&entry.object, KernelObject::Thread(thread) if thread.thread_id == thread_id)
        }) {
            return;
        }
        if self
            .threads
            .get(&thread_id)
            .is_some_and(|state| state.exit_code.is_some())
        {
            self.threads.remove(&thread_id);
        }
    }

    fn insert_object(
        &mut self,
        object_type: ObjectType,
        access_mask: u32,
        inheritable: bool,
        object: KernelObject,
    ) -> Handle {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(4);
        let generation = *self.handle_generations.get(&handle).unwrap_or(&0);
        self.handle_history.insert(handle, object_type);
        self.handles.insert(
            handle,
            HandleEntry {
                descriptor: HandleDescriptor {
                    object_type,
                    access_mask,
                    refcount: 1,
                    inheritable,
                },
                object,
                generation,
            },
        );
        handle
    }

    /// Return the current generation counter for a handle value.
    /// Returns `None` if the handle is not currently allocated.
    pub fn handle_generation(&self, handle: Handle) -> Option<u32> {
        self.handles.get(&handle).map(|e| e.generation)
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
        match self.handles.get(&handle) {
            Some(entry) if entry.generation == expected_generation => Ok(()),
            Some(_) => Err(AppError::new(
                ReasonCode::RcHandleStaleOrInvalid,
                format!("handle {handle} generation mismatch — stale reference detected"),
            )),
            None => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid handle {handle}"),
            )),
        }
    }

    fn insert_overlapped(
        &mut self,
        handle: Handle,
        event_handle: Option<Handle>,
        state: OverlappedState,
    ) -> u64 {
        let id = self.next_overlapped_id;
        self.next_overlapped_id += 1;
        self.overlapped.insert(
            id,
            OverlappedRequest {
                handle,
                event_handle,
                state,
            },
        );
        id
    }

    fn signal_event_if_needed(&mut self, event_handle: Option<Handle>) -> AppResult<()> {
        if let Some(event_handle) = event_handle {
            self.set_event(event_handle)?;
        }
        Ok(())
    }

    fn handle_entry(&self, handle: Handle) -> AppResult<&HandleEntry> {
        self.handles
            .get(&handle)
            .ok_or_else(|| self.invalid_handle_error(handle))
    }

    fn handle_entry_mut(&mut self, handle: Handle) -> AppResult<&mut HandleEntry> {
        if self.handles.contains_key(&handle) {
            Ok(self.handles.get_mut(&handle).expect("checked contains_key"))
        } else {
            Err(self.invalid_handle_error(handle))
        }
    }

    fn record_closed_handle(&mut self, handle: Handle, object_type: ObjectType) {
        self.recently_closed_handles
            .push_back((handle, object_type));
        while self.recently_closed_handles.len() > 32 {
            self.recently_closed_handles.pop_front();
        }
    }

    fn invalid_handle_error(&self, handle: Handle) -> AppError {
        let mut message = format!("invalid handle {handle}");
        if let Some(object_type) = self.handle_history.get(&handle) {
            message.push_str(&format!(" (known as {object_type:?})"));
        } else if let Some((_, object_type)) = self
            .recently_closed_handles
            .iter()
            .rev()
            .find(|(closed_handle, _)| *closed_handle == handle)
        {
            message.push_str(&format!(" (recently closed {object_type:?})"));
        }
        AppError::new(ReasonCode::RcWin32InvalidHandle, message)
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
                    if backslashes % 2 == 0 {
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

fn invalid_handle<T>(message: &str) -> AppResult<T> {
    Err(AppError::new(ReasonCode::RcWin32InvalidHandle, message))
}

fn normalize_pipe_name(name: &str) -> String {
    name.replace('/', "\\").to_ascii_lowercase()
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

fn paced_sleep_duration_ms(requested_ms: u64, _live_pacing: bool) -> u64 {
    requested_ms
}

fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        value
    } else {
        value.div_ceil(alignment) * alignment
    }
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

trait PipeRequestLen {
    fn len_hint(&self, default: usize) -> usize;
}

impl PipeRequestLen for OverlappedRequest {
    fn len_hint(&self, default: usize) -> usize {
        default
    }
}

fn request_id_len(request: &OverlappedRequest, default: usize) -> usize {
    request.len_hint(default)
}

fn request_id_len_inner(_request: &OverlappedRequest) -> usize {
    0
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
    if let Some(prefix) = pattern.strip_suffix(".*") {
        if !candidate.contains('.') && windows_pattern_matches(prefix, candidate) {
            return true; // correct: "foo.*" matches "foo" without extension
        }
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
        CP_WIN1252, CreationDisposition, FileAccess, IoCompletionPacket, SeekOrigin, ShareMode,
        WaitStatus, Win32Subsystem, iconv_ffi, paced_sleep_duration_ms, split_find_search_pattern,
        windows_pattern_matches,
    };
    use crate::ge::{GameEnvironment, GeArch, RegistryView};
    use std::fs;

    #[test]
    fn paced_sleep_duration_preserves_non_live_requests() {
        assert_eq!(paced_sleep_duration_ms(0, false), 0);
        assert_eq!(paced_sleep_duration_ms(1, false), 1);
        assert_eq!(paced_sleep_duration_ms(25, false), 25);
    }

    #[test]
    fn paced_sleep_duration_preserves_live_requests() {
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

        let (h2, _) = win32.create_event(true, false, false, None);
        if h2 == h1 {
            let gen2 = win32.handle_generation(h2).expect("gen2");
            assert_ne!(gen1, gen2, "recycled handle must get a new generation");
        }
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

        // Timeout returns index = handles.len().saturating_sub(1) = 1 for 2 handles
        assert_eq!(
            win32
                .wait_for_multiple_objects(&[h1, h2], true, 0, false, None)
                .expect("wait"),
            (WaitStatus::Timeout, 1usize),
            "wait-all with no objects signalled should time out"
        );
        win32.set_event(h1).expect("set");
        // Timeout returns index = handles.len().saturating_sub(1) = 1 for 2 handles
        assert_eq!(
            win32
                .wait_for_multiple_objects(&[h1, h2], true, 0, false, None)
                .expect("wait"),
            (WaitStatus::Timeout, 1usize),
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
    fn wait_for_multiple_objects_wait_any() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "wfany", GeArch::X86, "win11-23h2")
            .expect("create game environment");
        let mut win32 = Win32Subsystem::new(ge, false);

        let (h1, _) = win32.create_event(false, false, false, None);
        let (h2, _) = win32.create_event(false, false, false, None);

        // Timeout returns index = handles.len().saturating_sub(1) = 1 for 2 handles
        assert_eq!(
            win32
                .wait_for_multiple_objects(&[h1, h2], false, 0, false, None)
                .expect("wait"),
            (WaitStatus::Timeout, 1usize),
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
        match result {
            Some(s) => assert!(s.is_empty(), "empty input should produce empty output"),
            None => {} // iconv not available
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
}
