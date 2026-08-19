//! Generic runtime-events layer.
//!
//! The PE runtime publishes structured, workload-agnostic events about guest
//! execution — file, registry, process, thread, pipe, socket, HTTP, window,
//! frame, audio and failure observability — through a small observer
//! registry.  The runtime itself never interprets the events: workloads
//! (e.g. the Steam bootstrap milestones in [`crate::workloads::steam`])
//! subscribe as [`RuntimeObserver`]s and derive their own semantics from the
//! generic stream.  The default runtime has NO observer attached and must
//! work perfectly without one — event emission is a no-op then.
//!
//! Subsystems that live outside the runtime (the global CEF bridge, the
//! real-audio backend) publish through the process-wide current-observer
//! registry; the runtime registers its observer list there for the duration
//! of its lifetime.

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;

/// One structured runtime observation.  All fields are typed; workloads
/// match on the variant and never re-parse strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEvent {
    /// A PE image was mapped into the guest address space.
    ImageLoaded {
        /// Module file name, e.g. `Steam.exe`.
        module: String,
        /// Guest base address of the mapped image.
        base: u64,
        /// Size of the mapped image in bytes.
        size: usize,
    },
    /// A guest import was resolved to an export.
    ExportResolved {
        /// Requested module (API-set resolved), e.g. `kernel32.dll`.
        module: String,
        /// Export name, or `ordinal#N` when resolved by ordinal.
        name: String,
        /// The export ordinal when the import resolved by ordinal.
        ordinal: Option<u16>,
    },
    /// A guest API call was dispatched to a host thunk.
    ApiCalled {
        /// Guest module the call was made from (main module base name).
        module: String,
        /// Host thunk name, e.g. `CreateFileW`.
        api: String,
        /// Guest program counter at the dispatch site.
        guest_pc: u64,
        /// Guest thread id at the dispatch site.
        thread_id: u32,
    },
    /// A `CreateFileW/A` open was requested against the file layer.
    FileOpened {
        /// Normalized Windows path.
        path: String,
        /// Raw Win32 desired-access mask (expanded `FILE_*` bits).
        desired_access: u32,
        /// Raw Win32 share-mode mask.
        share_mode: u32,
        /// Raw Win32 creation disposition.
        disposition: u32,
    },
    /// A file read completed (the bytes actually transferred).
    FileRead {
        /// Normalized Windows path.
        path: String,
        /// Bytes read from the file.
        bytes: Vec<u8>,
    },
    /// A file write completed (the bytes actually written).
    FileWritten {
        /// Normalized Windows path.
        path: String,
        /// Bytes written to the file.
        bytes: Vec<u8>,
    },
    /// A file deletion was requested and accepted by the file layer.
    FileDeleted {
        /// Normalized Windows path.
        path: String,
    },
    /// A registry key was opened.
    RegistryOpened {
        /// Key name, e.g. `HKCU\Software\Valve\Steam`.
        key: String,
    },
    /// A registry value was read.
    RegistryRead {
        /// Key name.
        key: String,
        /// Value name.
        value: String,
    },
    /// A registry value was written.
    RegistryWritten {
        /// Key name.
        key: String,
        /// Value name.
        value: String,
    },
    /// A guest process spawn was requested (`CreateProcessW/A`).
    ProcessSpawnRequested {
        /// Application/image name passed to the spawn call.
        image: String,
        /// Full command line passed to the spawn call.
        command_line: String,
        /// Guest-visible parent process id.
        parent_pid: u32,
    },
    /// A spawned child PE image was loaded into a guest process.
    ProcessImageLoaded {
        /// Guest process id of the loading process.
        pid: u32,
        /// Module file name of the loaded child image.
        image: String,
    },
    /// The first block of a guest process was dispatched — the
    /// process-first-instruction marker proving the PE actually executed.
    ProcessFirstInstruction {
        /// Guest process id.
        pid: u32,
        /// Module file name of the executing image.
        image: String,
    },
    /// A guest process exited.
    ProcessExited {
        /// Guest process id.
        pid: u32,
        /// Guest exit code.
        exit_code: i32,
    },
    /// A guest thread was created (`CreateThread` / `_beginthread`).
    ThreadCreated {
        /// Guest thread id.
        thread_id: u32,
    },
    /// A guest thread began dispatching blocks.
    ThreadStarted {
        /// Guest thread id.
        thread_id: u32,
    },
    /// A guest thread exited cleanly.
    ThreadExited {
        /// Guest thread id.
        thread_id: u32,
    },
    /// A named pipe server endpoint was created (`CreateNamedPipeW`).
    PipeCreated {
        /// Pipe name, e.g. `\\.\pipe\steam_service`.
        name: String,
    },
    /// A named pipe client connected (`CreateFileW`/`CallNamedPipe` on a
    /// `\\.\pipe\...` name).
    PipeConnected {
        /// Pipe name.
        name: String,
    },
    /// A TCP connection was established to a host.
    SocketConnected {
        /// Destination host.
        host: String,
        /// Destination port.
        port: u16,
    },
    /// An HTTP request was sent.
    HttpRequest {
        /// Request host.
        host: String,
        /// Request method, e.g. `GET`.
        method: String,
        /// Request path.
        path: String,
    },
    /// An HTTP response was received.
    HttpResponse {
        /// Response host.
        host: String,
        /// HTTP status code.
        status: u16,
        /// Response body bytes received.
        bytes: usize,
    },
    /// A guest window was created.
    WindowCreated {
        /// Window handle (hwnd).
        hwnd: u32,
        /// Window class name.
        class: String,
    },
    /// A frame was presented to the compositor.
    FramePresented {
        /// Producer label, e.g. `dxgi`, `gdi`, `cef_software`,
        /// `cef_accelerated`, `host_placeholder`.
        producer: String,
        /// Frame width in pixels.
        width: u32,
        /// Frame height in pixels.
        height: u32,
        /// Monotonic sequence number of the presented frame.
        sequence: u64,
    },
    /// A real host audio device was opened for output.
    AudioDeviceOpened {
        /// Host device name.
        device: String,
        /// Backend API label, e.g. `RealAudioBackend::ensure_stream (cpal)`.
        api: String,
    },
    /// An unhandled guest exception terminated (or was raised in) the guest.
    GuestException {
        /// Exception code, e.g. `0xC0000005`.
        code: u32,
        /// Guest program counter at the exception site.
        guest_pc: u64,
        /// Guest thread id at the exception site.
        thread_id: u32,
    },
    /// Runtime dispatch reached an unsupported/partial fallback (unknown
    /// thunk, unimplemented COM/D3D method, unknown IOCTL, unsupported CPU
    /// instruction or shader operation).  Every unsupported call must be
    /// observable and recorded in the run evidence.
    UnsupportedCall {
        /// Module the call was attributed to (`<unknown>` when the thunk
        /// was never registered).
        module: String,
        /// API name or thunk identifier.
        api: String,
        /// Guest program counter at the dispatch site.
        guest_pc: u64,
        /// Guest thread id at the dispatch site.
        thread_id: u32,
        /// Implementation level, e.g. `unsupported`, `partial`, `stub`.
        implementation_level: String,
        /// Human-readable reason.
        reason: String,
    },
}

/// A consumer of the generic runtime event stream.
pub trait RuntimeObserver: Send + Debug {
    /// Called for every event emitted by the runtime (or a subsystem it
    /// hosts).  Implementations must not mutate the runtime.
    fn on_event(&mut self, event: &RuntimeEvent);
}

/// The shared, thread-safe observer registry carried by the runtime and its
/// subsystems (win32/user32 file and window layers).
pub(crate) type ObserverList = Arc<Mutex<Vec<Box<dyn RuntimeObserver>>>>;

/// Create an empty observer list (the default: no observers attached).
pub(crate) fn new_observer_list() -> ObserverList {
    Arc::new(Mutex::new(Vec::new()))
}

/// Dispatch one event to every observer in `list`.  With an empty list this
/// is a no-op — the runtime works perfectly with no observer attached.
pub(crate) fn dispatch(observers: &ObserverList, event: &RuntimeEvent) {
    let Ok(mut guard) = observers.lock() else {
        return;
    };
    for observer in guard.iter_mut() {
        observer.on_event(event);
    }
}

/// Number of attached observers (used to skip event construction on the hot
/// dispatch path when nobody is listening).
pub(crate) fn observer_count(observers: &ObserverList) -> usize {
    observers.lock().map(|guard| guard.len()).unwrap_or(0)
}

/// Process-wide registry of the CURRENT runtime's observer list.
///
/// Global-context emitters (the CEF bridge and the real-audio backend live
/// outside any runtime field and cannot hold a per-runtime list) publish
/// through [`emit_global`]; the runtime registers its list for the duration
/// of its lifetime and unregisters on drop (only when the slot still points
/// at its own list, so a concurrently-created runtime is never clobbered).
static CURRENT_OBSERVERS: LazyLock<Mutex<Option<ObserverList>>> =
    LazyLock::new(|| Mutex::new(None));

/// Install `list` as the process-wide current observer registry.
pub(crate) fn register_current_observers(list: ObserverList) {
    *CURRENT_OBSERVERS.lock().unwrap() = Some(list);
}

/// Clear the process-wide registry when it still holds `list`.
pub(crate) fn clear_current_observers(list: &ObserverList) {
    let mut guard = CURRENT_OBSERVERS.lock().unwrap();
    if guard
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, list))
    {
        *guard = None;
    }
}

/// Emit `event` to the currently-registered observer list (if any).
pub(crate) fn emit_global(event: &RuntimeEvent) {
    if let Some(list) = CURRENT_OBSERVERS.lock().unwrap().as_ref() {
        dispatch(list, event);
    }
}
