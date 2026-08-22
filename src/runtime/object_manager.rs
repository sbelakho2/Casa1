//! Canonical kernel object manager.
//!
//! ONE authoritative owner of kernel objects (files, events, mutexes,
//! semaphores, threads, processes, keys, timers, pipes, sections, I/O
//! completion ports, directory searches and sockets), their identity
//! ([`ObjectId`]), their headers ([`ObjectHeader`]), their reference counts,
//! their per-object handle counts and the NAMED-OBJECT NAMESPACE: a single
//! `name -> ObjectId` map covering `\BaseNamedObjects\`, `Global\`, `Local\`
//! and `\Sessions\<n>\BaseNamedObjects\` — named events, mutexes, semaphores,
//! sections and pipes all resolve through it (there are no separate
//! `named_*` maps anywhere).
//!
//! The [`Win32Subsystem`](crate::win32::Win32Subsystem) owns exactly ONE
//! [`ObjectManager`] and one
//! [`HandleTable`](crate::runtime::handle_table::HandleTable); a handle is a
//! table entry that references an object by [`ObjectId`].  An object lives as
//! long as at least one handle references it; closing the last handle drops
//! the object and forgets its name (Windows named-object semantics).
//!
//! The wait-state queries (satisfiability probes, consuming acquisitions,
//! event signal/reset, mutex release and abandonment) live here with the
//! object state they inspect.

use crate::real_win32::SecurityDescriptor;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};

/// Global object-id counter: every object in every subsystem gets its id
/// from ONE counter (a guest-visible identity, never a host pointer).
static NEXT_OBJECT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Identity of a kernel object in the canonical object manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(pub u64);

impl ObjectId {
    fn next() -> Self {
        Self(NEXT_OBJECT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// The full set of kernel object types.  Every handle's type is the type of
/// the object it references (from the object manager, never duplicated in the
/// handle table).
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
    Socket,
    WindowStation,
}

/// Non-consuming satisfiability result for scheduler wait evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitSatisfaction {
    NotSignaled,
    Signaled,
    Abandoned,
}

/// Result of a consuming wait on a waitable object.
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
            Self::Object0 => 0x0000_0000,
            Self::Abandoned => 0x0000_0080,
            Self::IoCompletion => 0x0000_00C0,
            Self::Timeout => 0x0000_0102,
        }
    }
}

/// Cached wait-state summary of a waitable object, maintained by the
/// object-manager wait operations ([`ObjectManager::consume_wait`],
/// [`ObjectManager::signal_event`], [`ObjectManager::reset_event`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum WaitableState {
    #[default]
    NotSignaled,
    Signaled,
    Abandoned,
}

/// Header of a kernel object: identity, type, optional name, reference
/// count, the PARSED security descriptor (a copy — never a naked guest
/// pointer) and the cached wait state.
#[derive(Debug, Clone)]
#[allow(dead_code)] // id/security_descriptor retained as record-keeping fields
pub(crate) struct ObjectHeader {
    pub id: ObjectId,
    pub ty: ObjectType,
    pub name: Option<String>,
    /// Number of open handles referencing the object.
    pub refcount: u32,
    pub security_descriptor: Option<SecurityDescriptor>,
    pub wait_state: WaitableState,
}

// ── Kernel object payloads ──────────────────────────────────────────────────

/// A winsock socket.  The payload is the socket's id, which is ALWAYS the
/// win32 handle value itself: sockets live in the SAME handle namespace as
/// every other kernel object, so a socket value can never alias a live win32
/// object (and vice versa).  The per-socket transport state lives in the
/// `NetworkStack`, keyed by this id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocketObject {
    pub id: u64,
}

#[derive(Debug)]
#[allow(dead_code)] // file-object state retained for future share-mode enforcement
pub(crate) struct FileObject {
    pub(crate) normalized_path: String,
    pub(crate) host_path: PathBuf,
    pub(crate) ge_handle: Option<crate::ge::FileHandle>,
    pub(crate) position: u64,
    pub(crate) overlapped: bool,
    /// Open host file descriptor used for positional reads/writes.  `None`
    /// for directory handles or files that could not be opened; those fall
    /// back to whole-file I/O.
    pub(crate) host_file: Option<std::fs::File>,
    /// The expanded Win32 desired-access mask (generic bits already replaced
    /// by their concrete `FILE_*` equivalents) this handle was granted at
    /// open time.  Per-operation access checks evaluate against this.
    pub(crate) granted_access: u32,
    /// The raw `FILE_SHARE_*` share-mode value supplied at open time.
    pub(crate) share_mode: u32,
    /// True when the file has been deleted (via DeleteFileW) while this
    /// handle is still open (the handle survived because it was opened with
    /// FILE_SHARE_DELETE).  The file is already gone from the filesystem;
    /// there is nothing to clean up at close time.
    pub(crate) delete_pending: bool,
    /// True for directory handles, recorded at open time (never recomputed
    /// via `is_dir()` afterwards, so a deleted directory does not turn into
    /// a file handle).
    pub(crate) is_directory: bool,
    /// FILE_FLAG_DELETE_ON_CLOSE semantics: the file is removed when this
    /// handle is closed.
    pub(crate) delete_on_close: bool,
}

pub(crate) type FileHandleObject = Rc<RefCell<FileObject>>;

#[derive(Debug, Clone)]
pub(crate) struct EventObject {
    pub(crate) manual_reset: bool,
    pub(crate) signaled: bool,
}

pub(crate) type EventHandle = Rc<RefCell<EventObject>>;

/// Minimal pipe object stored directly in the kernel-object enum.
/// Used by the older `create_named_pipe` / `create_named_pipe_w` code paths;
/// the newer condvar-backed `NamedPipeState`-based infrastructure lives in
/// [`PipeObject::state`] (server-created named pipes) and provides
/// condvar-backed sync.
#[derive(Debug, Clone)]
pub(crate) struct PipeObject {
    pub(crate) name: String,
    pub(crate) connected: bool,
    pub(crate) buffer: Vec<u8>,
    /// Rich condvar-backed named-pipe state.  `Some` for pipes created via
    /// `CreateNamedPipeW` (registered in the named-object namespace); `None`
    /// for legacy anonymous pipes that buffer on the object itself.
    pub(crate) state: Option<NamedPipeState>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct IoCompletionPacket {
    pub bytes_transferred: u32,
    pub completion_key: u64,
    pub overlapped: u64,
    pub internal: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct IoCompletionPortObject {
    pub(crate) concurrent_threads: u32,
    pub(crate) queue: std::collections::VecDeque<IoCompletionPacket>,
}

#[derive(Debug, Clone)]
pub(crate) struct MutexObject {
    pub(crate) owner_thread_id: Option<u32>,
    /// Recursion count: a thread waiting on its own mutex succeeds and
    /// increments recursion; ReleaseMutex decrements and only releases the
    /// ownership at recursion 0.  This is Windows mutex semantics — a mutex
    /// is not a Boolean signal.
    pub(crate) recursion: u32,
    pub(crate) abandoned: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SemaphoreObject {
    pub(crate) count: u32,
    pub(crate) maximum: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ThreadObject {
    pub(crate) thread_id: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessObject {
    pub(crate) process_id: u32,
    pub(crate) executable: String,
    pub(crate) argv: Vec<String>,
    pub(crate) cwd: String,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) inherited_handles: Vec<crate::win32::HandleDescriptor>,
    pub(crate) modules: Vec<String>,
    pub(crate) exit_code: Option<u32>,
    /// Synchronisation primitive for async child-process exit.
    /// When a child is spawned on a worker thread, the thread sets the exit
    /// code inside this condvar pair and notifies all waiters.  The parent
    /// `WaitForSingleObject` call blocks on this condvar instead of spinning.
    pub(crate) exit_sync: Option<Arc<(Mutex<Option<u32>>, Condvar)>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // section name retained for record-keeping; the namespace key lives in the object header
pub(crate) struct SectionObject {
    pub(crate) base_address: u64,
    pub(crate) size: usize,
    pub(crate) protection: crate::win32::MemoryProtection,
    /// Name of the section (None for anonymous sections created via
    /// `create_section` / `heap_create`).  Names resolve through the
    /// object-manager namespace.
    pub(crate) name: Option<String>,
    /// Shared byte storage for file-mapping sections, so that every
    /// `MapViewOfFile` view shares the same backing.  Sections own their
    /// backing storage; the mapping state lives in the canonical
    /// `VirtualMemory` (region `backing` + `backing_offset`).
    pub(crate) backing: Option<Arc<Mutex<Vec<u8>>>>,
}

#[derive(Debug, Clone)]
pub(crate) struct KeyObject {
    pub(crate) hive: String,
    pub(crate) key: String,
    pub(crate) view: crate::ge::RegistryView,
}

#[derive(Debug, Clone)]
pub(crate) struct TimerObject {
    pub(crate) due_tick: u64,
    pub(crate) signaled: bool,
}

/// State tracking for a Windows named pipe.
///
/// A pipe has two real ends with independent direction queues:
/// server-to-client (bytes written by the server, read by the client) and
/// client-to-server (bytes written by the client, read by the server).
/// Reads consume from the peer's write queue; writes append to the
/// opposite direction's queue and notify the condvar.
#[derive(Debug, Clone)]
#[allow(dead_code)] // named-pipe state fields retained for future pipe APIs
pub(crate) struct NamedPipeState {
    /// The pipe name (e.g. `\\.\pipe\steam_service`).
    pub(crate) name: String,
    /// Whether a server endpoint has been created via CreateNamedPipeW.
    pub(crate) server_created: bool,
    /// Server writes append here; client-side reads consume it.
    pub(crate) server_to_client: Arc<Mutex<std::collections::VecDeque<u8>>>,
    /// Client writes append here; server-side reads consume it.
    pub(crate) client_to_server: Arc<Mutex<std::collections::VecDeque<u8>>>,
    /// Condition variable signalled when new data arrives or the pipe is
    /// disconnected.
    pub(crate) data_ready: Arc<Condvar>,
    /// Maximum pipe size (from nMaxInstances / nOutBufferSize).
    pub(crate) max_buffer_size: usize,
    /// Whether the server end has been disconnected (DisconnectNamedPipe).
    pub(crate) server_disconnected: bool,
    /// Whether the client end has been disconnected (the server called
    /// DisconnectNamedPipe, or the server handle was closed while a client
    /// was connected).  A waiting CallNamedPipe / pipe reader observes this
    /// as ERROR_BROKEN_PIPE.
    pub(crate) client_disconnected: bool,
    /// Parsed security descriptor copy supplied via `lpSecurityAttributes`
    /// at creation time (never a naked guest pointer).  Stored for future
    /// ACL enforcement; currently unused beyond record-keeping.
    pub(crate) security_descriptor: Option<SecurityDescriptor>,
    /// Unix-domain socket path for cross-process pipe communication.
    /// Only populated when the pipe is created with cross-process intent.
    pub(crate) uds_socket_path: Option<String>,
    /// Pipe open mode (PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND).
    pub(crate) open_mode: u32,
    /// Pipe mode (PIPE_WAIT or PIPE_NOWAIT).
    pub(crate) pipe_mode: u32,
    /// Maximum number of pipe instances.
    pub(crate) max_instances: u32,
    /// Default timeout for WaitNamedPipe (in milliseconds).
    pub(crate) default_timeout: u32,
    /// Outbound buffer size as requested at creation time.
    pub(crate) out_buffer_size: u32,
    /// Inbound buffer size as requested at creation time.
    pub(crate) in_buffer_size: u32,
    /// The server-end handle (from CreateNamedPipeW), when open.
    pub(crate) server_handle: Option<crate::runtime::handle_table::Handle>,
    /// The client-end handle (from CreateFileW on `\\.\pipe\NAME`), when
    /// connected.
    pub(crate) client_handle: Option<crate::runtime::handle_table::Handle>,
    /// PIPE_READMODE_MESSAGE: writes append a [u32 length][bytes...] frame
    /// and reads return exactly one message.
    pub(crate) message_mode: bool,
    /// Whether a client has connected (ConnectNamedPipe completes).
    pub(crate) client_connected: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct DirectorySearchObject {
    pub(crate) entries: Vec<crate::win32::FindData>,
    pub(crate) index: usize,
}

/// The kernel object payload enum: the full object-state set owned by the
/// object manager.
#[derive(Debug, Clone)]
pub(crate) enum KernelObject {
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
    Socket(SocketObject),
    WindowStation(WindowStationObject),
}

/// A window station object (`WinSta0`).  The runtime models the single
/// interactive window station every process is attached to; the name is the
/// object's only payload (the USER object hierarchy it names is the
/// [`crate::user32::User32Subsystem`] window tree).
#[derive(Debug, Clone)]
pub(crate) struct WindowStationObject {
    pub(crate) name: String,
}

/// Canonicalize a named-object string for the unified namespace: strips the
/// `\BaseNamedObjects\`, `Global\`, `Local\` and `\Sessions\<n>\BaseNamedObjects\`
/// prefixes (in Windows they all name the same session-local object).
/// Pipe names arrive pre-normalized (`\\.\pipe\...`) and are untouched.
pub fn canonical_object_name(name: &str) -> String {
    let mut current = name;
    loop {
        let next = current
            .strip_prefix("\\BaseNamedObjects\\")
            .or_else(|| current.strip_prefix("Global\\"))
            .or_else(|| current.strip_prefix("Local\\"))
            .or_else(|| {
                current.strip_prefix("\\Sessions\\").and_then(|rest| {
                    let digits = rest.chars().take_while(|ch| ch.is_ascii_digit()).count();
                    if digits == 0 {
                        return None;
                    }
                    rest[digits..].strip_prefix("\\BaseNamedObjects\\")
                })
            });
        match next {
            Some(rest) if !rest.is_empty() && rest != current => current = rest,
            _ => break,
        }
    }
    current.to_string()
}

/// The canonical kernel object manager.
#[derive(Debug, Clone)]
pub(crate) struct ObjectManager {
    objects: BTreeMap<ObjectId, KernelObject>,
    headers: BTreeMap<ObjectId, ObjectHeader>,
    /// The unified named-object namespace: canonical name -> object id.
    /// Named events, mutexes, semaphores, sections and pipes all resolve
    /// through this single map.
    names: BTreeMap<String, ObjectId>,
    /// Per-object open-handle counts (refcount tracking).
    handle_counts: BTreeMap<ObjectId, u32>,
}

impl Default for ObjectManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectManager {
    pub(crate) fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            headers: BTreeMap::new(),
            names: BTreeMap::new(),
            handle_counts: BTreeMap::new(),
        }
    }

    /// Insert a kernel object and return its id.  A `Some(name)` registers
    /// the object in the unified named-object namespace.
    pub(crate) fn insert(
        &mut self,
        ty: ObjectType,
        name: Option<String>,
        security_descriptor: Option<SecurityDescriptor>,
        object: KernelObject,
    ) -> ObjectId {
        let id = ObjectId::next();
        let canonical = name.map(|name| canonical_object_name(&name));
        if let Some(canonical) = &canonical {
            self.names.insert(canonical.clone(), id);
        }
        self.objects.insert(id, object);
        self.headers.insert(
            id,
            ObjectHeader {
                id,
                ty,
                name: canonical,
                refcount: 0,
                security_descriptor,
                wait_state: WaitableState::NotSignaled,
            },
        );
        self.handle_counts.insert(id, 0);
        id
    }

    /// Resolve a name through the unified namespace.
    pub(crate) fn resolve(&self, name: &str) -> Option<ObjectId> {
        self.names.get(&canonical_object_name(name)).copied()
    }

    /// True when the object is currently alive (at least one handle
    /// references it).
    #[allow(dead_code)] // exercised by the object-manager unit tests
    pub(crate) fn is_live(&self, id: ObjectId) -> bool {
        self.objects.contains_key(&id)
    }

    /// The object payload.  Invariant: while a handle references an object,
    /// the object is alive — callers only reach this through live entries.
    pub(crate) fn object(&self, id: ObjectId) -> &KernelObject {
        self.objects
            .get(&id)
            .expect("object manager: object referenced by a live handle")
    }

    /// Mutable access to the object payload (see [`Self::object`]).
    pub(crate) fn object_mut(&mut self, id: ObjectId) -> &mut KernelObject {
        self.objects
            .get_mut(&id)
            .expect("object manager: object referenced by a live handle")
    }

    /// Iterate every live object (id, payload).
    pub(crate) fn objects_iter(&self) -> impl Iterator<Item = (ObjectId, &KernelObject)> {
        self.objects.iter().map(|(id, object)| (*id, object))
    }

    /// Iterate every live object payload mutably.
    pub(crate) fn objects_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (ObjectId, &mut KernelObject)> {
        self.objects.iter_mut().map(|(id, object)| (*id, object))
    }

    /// The type of a live object.
    pub(crate) fn object_type(&self, id: ObjectId) -> ObjectType {
        self.headers
            .get(&id)
            .map(|header| header.ty)
            .expect("object manager: header of a live object")
    }

    /// The object header (identity / type / name / refcount / descriptor).
    #[allow(dead_code)] // exercised by the object-manager unit tests
    pub(crate) fn header(&self, id: ObjectId) -> &ObjectHeader {
        self.headers
            .get(&id)
            .expect("object manager: header of a live object")
    }

    /// Number of open handles referencing the object.
    pub(crate) fn handle_count(&self, id: ObjectId) -> u32 {
        self.handle_counts.get(&id).copied().unwrap_or(0)
    }

    /// Record a new handle referencing the object.
    pub(crate) fn handle_added(&mut self, id: ObjectId) {
        let count = self.handle_counts.entry(id).or_insert(0);
        *count = count.saturating_add(1);
        if let Some(header) = self.headers.get_mut(&id) {
            header.refcount = *count;
        }
    }

    /// Remove one handle reference.  Returns `true` when the object's LAST
    /// handle closed: the object and its namespace entry are dropped
    /// (Windows forgets named objects once the last handle closes).
    pub(crate) fn handle_removed(&mut self, id: ObjectId) -> bool {
        let count = match self.handle_counts.get_mut(&id) {
            Some(count) => {
                *count = count.saturating_sub(1);
                *count
            }
            None => 0,
        };
        if let Some(header) = self.headers.get_mut(&id) {
            header.refcount = count;
        }
        if count > 0 {
            return false;
        }
        if let Some(header) = self.headers.get(&id)
            && let Some(name) = &header.name
        {
            self.names.remove(name);
        }
        self.objects.remove(&id);
        self.headers.remove(&id);
        self.handle_counts.remove(&id);
        true
    }

    // ── Wait-state queries ───────────────────────────────────────────────────

    /// Non-consuming satisfiability of a waitable object (Event / Mutex /
    /// Semaphore / Timer).  Thread and process objects consult their own
    /// exit state at the subsystem layer; their satisfaction is evaluated
    /// from the object payload there.
    pub(crate) fn wait_satisfaction(
        &self,
        id: ObjectId,
        current_thread_id: u32,
        now: u64,
    ) -> WaitSatisfaction {
        match self.objects.get(&id) {
            Some(KernelObject::Event(event)) => {
                if event.borrow().signaled {
                    WaitSatisfaction::Signaled
                } else {
                    WaitSatisfaction::NotSignaled
                }
            }
            Some(KernelObject::Mutex(mutex)) => {
                if mutex.abandoned {
                    WaitSatisfaction::Abandoned
                } else if mutex.owner_thread_id.is_none()
                    || mutex.owner_thread_id == Some(current_thread_id)
                {
                    // Unlocked, or already owned by the waiting thread
                    // (recursive acquisition always succeeds).
                    WaitSatisfaction::Signaled
                } else {
                    WaitSatisfaction::NotSignaled
                }
            }
            Some(KernelObject::Semaphore(semaphore)) => {
                if semaphore.count > 0 {
                    WaitSatisfaction::Signaled
                } else {
                    WaitSatisfaction::NotSignaled
                }
            }
            Some(KernelObject::Timer(timer)) => {
                if timer.signaled || now >= timer.due_tick {
                    WaitSatisfaction::Signaled
                } else {
                    WaitSatisfaction::NotSignaled
                }
            }
            _ => WaitSatisfaction::NotSignaled,
        }
    }

    /// Non-destructive signal-state probe (Event / Mutex / Semaphore /
    /// Timer) used by the wait-all path so that auto-reset signals are not
    /// consumed before the final acquiring pass.
    pub(crate) fn object_is_signaled(
        &self,
        id: ObjectId,
        current_thread_id: u32,
        now: u64,
    ) -> bool {
        match self.objects.get(&id) {
            Some(KernelObject::Event(event)) => event.borrow().signaled,
            Some(KernelObject::Mutex(mutex)) => {
                mutex.abandoned
                    || mutex.owner_thread_id.is_none()
                    || mutex.owner_thread_id == Some(current_thread_id)
            }
            Some(KernelObject::Semaphore(semaphore)) => semaphore.count > 0,
            Some(KernelObject::Timer(timer)) => timer.signaled || now >= timer.due_tick,
            _ => false,
        }
    }

    /// CONSUMING wait on an Event / Mutex / Semaphore / Timer: auto-reset
    /// events are reset, mutexes are acquired (recursively or with
    /// WAIT_ABANDONED), semaphores are decremented and timers latch their
    /// signal.  `WaitStatus::Timeout` for unsatisfied objects.
    pub(crate) fn consume_wait(
        &mut self,
        id: ObjectId,
        current_thread_id: u32,
        now: u64,
    ) -> WaitStatus {
        let status = match self.objects.get_mut(&id) {
            Some(KernelObject::Event(event)) => {
                let mut event = event.borrow_mut();
                if event.signaled {
                    if !event.manual_reset {
                        event.signaled = false;
                    }
                    WaitStatus::Object0
                } else {
                    WaitStatus::Timeout
                }
            }
            Some(KernelObject::Mutex(mutex)) => {
                if mutex.abandoned {
                    // The previous owner terminated without releasing; the
                    // next successful waiter receives WAIT_ABANDONED and
                    // takes ownership.
                    mutex.abandoned = false;
                    mutex.owner_thread_id = Some(current_thread_id);
                    mutex.recursion = 1;
                    WaitStatus::Abandoned
                } else if let Some(owner) = mutex.owner_thread_id {
                    if owner == current_thread_id {
                        // Recursive acquisition succeeds and increments.
                        mutex.recursion += 1;
                        WaitStatus::Object0
                    } else {
                        WaitStatus::Timeout
                    }
                } else {
                    mutex.owner_thread_id = Some(current_thread_id);
                    mutex.recursion = 1;
                    WaitStatus::Object0
                }
            }
            Some(KernelObject::Semaphore(semaphore)) => {
                if semaphore.count > 0 {
                    semaphore.count -= 1;
                    WaitStatus::Object0
                } else {
                    WaitStatus::Timeout
                }
            }
            Some(KernelObject::Timer(timer)) => {
                if timer.signaled || now >= timer.due_tick {
                    timer.signaled = true;
                    WaitStatus::Object0
                } else {
                    WaitStatus::Timeout
                }
            }
            _ => WaitStatus::Timeout,
        };
        let wait_state = match status {
            WaitStatus::Abandoned => WaitableState::Abandoned,
            WaitStatus::Object0 => WaitableState::Signaled,
            _ => WaitableState::NotSignaled,
        };
        if let Some(header) = self.headers.get_mut(&id) {
            header.wait_state = wait_state;
        }
        status
    }

    // ── Object state mutations ───────────────────────────────────────────────

    /// `SetEvent` — signal an event object.  Returns `false` when the object
    /// is not an event.
    pub(crate) fn signal_event(&mut self, id: ObjectId) -> bool {
        let Some(KernelObject::Event(event)) = self.objects.get_mut(&id) else {
            return false;
        };
        event.borrow_mut().signaled = true;
        if let Some(header) = self.headers.get_mut(&id) {
            header.wait_state = WaitableState::Signaled;
        }
        true
    }

    /// `ResetEvent` — clear an event object's signal.  Returns `false` when
    /// the object is not an event.
    pub(crate) fn reset_event(&mut self, id: ObjectId) -> bool {
        let Some(KernelObject::Event(event)) = self.objects.get_mut(&id) else {
            return false;
        };
        event.borrow_mut().signaled = false;
        if let Some(header) = self.headers.get_mut(&id) {
            header.wait_state = WaitableState::NotSignaled;
        }
        true
    }

    /// `ReleaseMutex` — decrement the recursion of the mutex owned by
    /// `thread_id`; ownership is released at recursion 0.  Returns `false`
    /// when the object is not a mutex or the caller does not own it.
    pub(crate) fn release_mutex(&mut self, id: ObjectId, thread_id: u32) -> bool {
        let Some(KernelObject::Mutex(mutex)) = self.objects.get_mut(&id) else {
            return false;
        };
        if mutex.owner_thread_id != Some(thread_id) {
            return false;
        }
        if mutex.recursion > 1 {
            mutex.recursion -= 1;
            return true;
        }
        mutex.recursion = 0;
        mutex.owner_thread_id = None;
        mutex.abandoned = false;
        if let Some(header) = self.headers.get_mut(&id) {
            header.wait_state = WaitableState::Signaled;
        }
        true
    }

    /// `ReleaseSemaphore` — bump the count (saturating at the maximum).
    /// Returns the previous count, or `None` when the object is not a
    /// semaphore.
    pub(crate) fn release_semaphore(&mut self, id: ObjectId, release_count: u32) -> Option<u32> {
        let Some(KernelObject::Semaphore(semaphore)) = self.objects.get_mut(&id) else {
            return None;
        };
        let previous = semaphore.count;
        semaphore.count = semaphore
            .count
            .saturating_add(release_count)
            .min(semaphore.maximum);
        Some(previous)
    }

    /// Windows mutex semantics: a thread that terminates while owning a
    /// mutex abandons it — the next successful waiter receives
    /// WAIT_ABANDONED and takes ownership.
    pub(crate) fn mark_mutexes_abandoned_by_thread(&mut self, thread_id: u32) {
        let mut abandoned_ids = Vec::new();
        for (id, object) in self.objects.iter_mut() {
            if let KernelObject::Mutex(mutex) = object
                && mutex.owner_thread_id == Some(thread_id)
            {
                mutex.owner_thread_id = None;
                mutex.abandoned = true;
                abandoned_ids.push(*id);
            }
        }
        for id in abandoned_ids {
            if let Some(header) = self.headers.get_mut(&id) {
                header.wait_state = WaitableState::Abandoned;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_object(signaled: bool) -> KernelObject {
        KernelObject::Event(Rc::new(RefCell::new(EventObject {
            manual_reset: false,
            signaled,
        })))
    }

    #[test]
    fn object_ids_come_from_one_global_counter() {
        let mut first = ObjectManager::new();
        let mut second = ObjectManager::new();
        let a = first.insert(ObjectType::Event, None, None, event_object(false));
        let b = first.insert(
            ObjectType::Mutex,
            None,
            None,
            KernelObject::Mutex(MutexObject {
                owner_thread_id: None,
                recursion: 0,
                abandoned: false,
            }),
        );
        let c = second.insert(
            ObjectType::Timer,
            None,
            None,
            KernelObject::Timer(TimerObject {
                due_tick: 0,
                signaled: false,
            }),
        );
        let mut ids = vec![a, b, c];
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 3, "ids from every manager are globally unique");
    }

    #[test]
    fn unified_namespace_resolves_events_mutexes_semaphores_sections_pipes() {
        let mut manager = ObjectManager::new();
        let event_id = manager.insert(
            ObjectType::Event,
            Some("MyEvent".to_string()),
            None,
            event_object(false),
        );
        let mutex_id = manager.insert(
            ObjectType::Mutex,
            Some("Local\\MyMutex".to_string()),
            None,
            KernelObject::Mutex(MutexObject {
                owner_thread_id: None,
                recursion: 0,
                abandoned: false,
            }),
        );
        let semaphore_id = manager.insert(
            ObjectType::Semaphore,
            Some("Global\\MySemaphore".to_string()),
            None,
            KernelObject::Semaphore(SemaphoreObject {
                count: 1,
                maximum: 1,
            }),
        );
        let section_id = manager.insert(
            ObjectType::Section,
            Some("\\BaseNamedObjects\\MySection".to_string()),
            None,
            KernelObject::Section(SectionObject {
                base_address: 0,
                size: 0x1000,
                protection: crate::win32::MemoryProtection {
                    read: true,
                    write: true,
                    execute: false,
                },
                name: None,
                backing: None,
            }),
        );
        let pipe_id = manager.insert(
            ObjectType::Pipe,
            Some("\\.\\pipe\\MyPipe".to_string()),
            None,
            KernelObject::Pipe(PipeObject {
                name: "\\.\\pipe\\mypipe".to_string(),
                connected: false,
                buffer: Vec::new(),
                state: None,
            }),
        );
        // The same canonical object is found under every prefix spelling.
        assert_eq!(manager.resolve("MyEvent"), Some(event_id));
        assert_eq!(manager.resolve("Local\\MyMutex"), Some(mutex_id));
        assert_eq!(
            manager.resolve("\\BaseNamedObjects\\MyMutex"),
            Some(mutex_id)
        );
        assert_eq!(manager.resolve("Global\\MySemaphore"), Some(semaphore_id));
        assert_eq!(
            manager.resolve("\\Sessions\\1\\BaseNamedObjects\\MySection"),
            Some(section_id)
        );
        assert_eq!(manager.resolve("\\.\\pipe\\MyPipe"), Some(pipe_id));
        assert_eq!(manager.resolve("NoSuchObject"), None);
        assert_eq!(manager.object_type(event_id), ObjectType::Event);
        assert_eq!(manager.object_type(section_id), ObjectType::Section);
    }

    #[test]
    fn refcount_tracks_handles_and_last_close_drops_object_and_name() {
        let mut manager = ObjectManager::new();
        let id = manager.insert(
            ObjectType::Event,
            Some("RefCountedEvent".to_string()),
            None,
            event_object(false),
        );
        assert_eq!(manager.handle_count(id), 0);
        assert!(manager.is_live(id));
        manager.handle_added(id);
        manager.handle_added(id);
        assert_eq!(manager.handle_count(id), 2);
        assert_eq!(manager.header(id).refcount, 2);
        assert!(!manager.handle_removed(id), "one handle remains");
        assert!(manager.is_live(id));
        assert_eq!(manager.resolve("RefCountedEvent"), Some(id));
        assert!(
            manager.handle_removed(id),
            "last handle close drops the object"
        );
        assert!(!manager.is_live(id));
        assert_eq!(manager.resolve("RefCountedEvent"), None, "name forgotten");
    }

    #[test]
    fn consume_wait_implements_event_mutex_semaphore_timer_semantics() {
        let mut manager = ObjectManager::new();

        // Auto-reset event: consumed.
        let event_id = manager.insert(ObjectType::Event, None, None, event_object(true));
        assert_eq!(manager.consume_wait(event_id, 7, 0), WaitStatus::Object0);
        assert_eq!(manager.consume_wait(event_id, 7, 0), WaitStatus::Timeout);

        // Mutex: acquisition, recursion, release, abandonment.
        let mutex_id = manager.insert(
            ObjectType::Mutex,
            None,
            None,
            KernelObject::Mutex(MutexObject {
                owner_thread_id: None,
                recursion: 0,
                abandoned: false,
            }),
        );
        assert_eq!(manager.consume_wait(mutex_id, 7, 0), WaitStatus::Object0);
        assert_eq!(
            manager.consume_wait(mutex_id, 7, 0),
            WaitStatus::Object0,
            "recursive acquisition"
        );
        assert_eq!(
            manager.consume_wait(mutex_id, 8, 0),
            WaitStatus::Timeout,
            "another thread cannot acquire"
        );
        assert!(manager.release_mutex(mutex_id, 7));
        assert!(manager.release_mutex(mutex_id, 7));
        assert!(!manager.release_mutex(mutex_id, 7), "not owned anymore");
        // An unowned mutex is satisfiable: any thread can acquire it.
        assert_eq!(
            manager.wait_satisfaction(mutex_id, 9, 0),
            WaitSatisfaction::Signaled
        );
        // Abandon by a fake owner:
        manager.consume_wait(mutex_id, 9, 0);
        manager.mark_mutexes_abandoned_by_thread(9);
        assert_eq!(
            manager.wait_satisfaction(mutex_id, 9, 0),
            WaitSatisfaction::Abandoned
        );
        assert_eq!(manager.consume_wait(mutex_id, 10, 0), WaitStatus::Abandoned);

        // Semaphore: decrement on consume, saturating release.
        let semaphore_id = manager.insert(
            ObjectType::Semaphore,
            None,
            None,
            KernelObject::Semaphore(SemaphoreObject {
                count: 1,
                maximum: 2,
            }),
        );
        assert_eq!(
            manager.consume_wait(semaphore_id, 0, 0),
            WaitStatus::Object0
        );
        assert_eq!(
            manager.consume_wait(semaphore_id, 0, 0),
            WaitStatus::Timeout
        );
        assert_eq!(manager.release_semaphore(semaphore_id, 5), Some(0));
        assert_eq!(manager.release_semaphore(semaphore_id, 5), Some(2));

        // Timer: latches when due, resets by re-arming.
        let timer_id = manager.insert(
            ObjectType::Timer,
            None,
            None,
            KernelObject::Timer(TimerObject {
                due_tick: 100,
                signaled: false,
            }),
        );
        assert_eq!(manager.consume_wait(timer_id, 0, 50), WaitStatus::Timeout);
        assert_eq!(manager.consume_wait(timer_id, 0, 100), WaitStatus::Object0);
        assert_eq!(
            manager.consume_wait(timer_id, 0, 1000),
            WaitStatus::Object0,
            "latched until re-armed"
        );
    }

    #[test]
    fn signal_and_reset_event_update_wait_state() {
        let mut manager = ObjectManager::new();
        let id = manager.insert(ObjectType::Event, None, None, event_object(false));
        assert!(manager.signal_event(id));
        assert_eq!(manager.header(id).wait_state, WaitableState::Signaled);
        assert_eq!(
            manager.wait_satisfaction(id, 0, 0),
            WaitSatisfaction::Signaled
        );
        assert!(manager.reset_event(id));
        assert_eq!(manager.header(id).wait_state, WaitableState::NotSignaled);
        assert!(!manager.signal_event(ObjectId(999_999)), "not an event");
    }
}
