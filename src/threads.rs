//! Real multi-threading support for Casa1 guest threads.
//!
//! Each Windows guest thread is backed by a real OS thread with its own CPU state.
//! Thread synchronization primitives use real OS primitives for correct behavior.

use crate::cpu::{CpuEngineConfig, CpuState, GuestArch, MemoryImage};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Barrier as StdBarrier, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use libc;
// ---------------------------------------------------------------------------
// Mutex poisoning recovery helpers
// ---------------------------------------------------------------------------

/// Acquire a lock on a `Mutex`, automatically recovering from a poisoned state.
///
/// If the mutex is poisoned (because a previous holder panicked), the poison
/// error is consumed via [`into_inner`](PoisonError::into_inner) and the
/// underlying data is still returned.  This prevents a single poisoned thread
/// from cascading into a full process panic.
///
/// # SAFETY
///
/// The caller must be prepared for potentially inconsistent state if the mutex
/// was poisoned.  In Casa1's threading primitives this is acceptable because
/// the locked data structures (`MutexState`, `EventState`, counters, etc.) are
/// designed to tolerate a panic in a previous holder — at worst an abandoned
/// mutex is detected and handled at the guest level via `WAIT_ABANDONED`.
pub fn lock_with_recovery<T>(mtx: &Mutex<T>) -> MutexGuard<'_, T> {
    mtx.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Thread ID allocation
// ---------------------------------------------------------------------------

#[allow(dead_code)] // guest TID allocation (thread ID table); not yet wired
static NEXT_GUEST_TID: AtomicU32 = AtomicU32::new(1);

#[allow(dead_code)] // guest TID allocation (thread ID table); not yet wired
fn allocate_thread_id() -> u32 {
    NEXT_GUEST_TID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Guest thread state
// ---------------------------------------------------------------------------

/// State for a single guest thread.
#[derive(Debug)]
pub struct GuestThreadState {
    /// Unique guest thread ID.
    pub thread_id: u32,
    /// Guest architecture.
    pub arch: GuestArch,
    /// CPU state for this thread.
    pub cpu_state: CpuState,
    /// Thread exit code (set when thread exits).
    pub exit_code: Arc<AtomicU32>,
    /// Whether this thread is still running.
    pub running: Arc<AtomicBool>,
    /// Thread priority (mapped to OS scheduling hints).
    pub priority: i32,
    /// TLS slots (per-thread local storage).
    pub tls_slots: BTreeMap<u32, u64>,
    /// Pause flag for SuspendThread.
    pub paused: Arc<AtomicBool>,
    /// Terminate flag for TerminateThread.
    pub terminated: Arc<AtomicBool>,
}

// ---------------------------------------------------------------------------
// Thread Scheduling / Priorities
// ---------------------------------------------------------------------------

/// Windows thread priority constants.
pub const THREAD_PRIORITY_LOWEST: i32 = -2;
pub const THREAD_PRIORITY_BELOW_NORMAL: i32 = -1;
pub const THREAD_PRIORITY_NORMAL: i32 = 0;
pub const THREAD_PRIORITY_ABOVE_NORMAL: i32 = 1;
pub const THREAD_PRIORITY_HIGHEST: i32 = 2;
pub const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;
pub const THREAD_PRIORITY_IDLE: i32 = -15;

/// Default time slice for guest threads (in milliseconds, matching Windows ~30ms).
pub const DEFAULT_TIME_SLICE_MS: u64 = 30;

/// Describes a suspend/resume request for a guest thread.
#[derive(Debug, Clone, Copy)]
pub struct ThreadSchedulingInfo {
    pub suspend_count: u32,
    pub priority: i32,
}

// ---------------------------------------------------------------------------
// Fiber support
// ---------------------------------------------------------------------------

/// A guest fiber (cooperative execution context).
#[derive(Debug)]
pub struct GuestFiber {
    pub fiber_id: u32,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub start_address: u64,
    pub parameter: u64,
    pub state: Option<CpuState>,
    pub is_executing: bool,
}

/// Fiber-local storage slot value.
#[derive(Debug, Default)]
pub struct FlsSlot {
    pub value: u64,
}

// ---------------------------------------------------------------------------
// Thread pool support
// ---------------------------------------------------------------------------

/// A work item queued via QueueUserWorkItem or the thread pool API.
#[derive(Debug, Clone)]
pub struct ThreadPoolWorkItem {
    pub callback: u64,
    pub context: u64,
    pub flags: u32,
}

/// A thread pool timer.
#[derive(Debug)]
pub struct ThreadPoolTimer {
    pub callback: u64,
    pub context: u64,
    pub due_time_ms: u64,
    pub period_ms: u64,
    pub active: bool,
}

/// A thread pool wait registration.
#[derive(Debug)]
pub struct ThreadPoolWait {
    pub callback: u64,
    pub context: u64,
    pub handle: u32,
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Synchronization primitives
// ---------------------------------------------------------------------------

/// A real mutex with ownership tracking (Windows mutex semantics).
pub struct GuestMutex {
    /// Inner mutex protecting the state.
    inner: std::sync::Mutex<MutexState>,
    /// Condition variable for waiting.
    condvar: Condvar,
}

struct MutexState {
    /// Thread ID of the owner (0 if unowned).
    owner_tid: u32,
    /// Recursion count.
    recursion_count: u32,
    /// Whether the mutex is abandoned (owner died).
    abandoned: bool,
}

impl GuestMutex {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(MutexState {
                owner_tid: 0,
                recursion_count: 0,
                abandoned: false,
            }),
            condvar: Condvar::new(),
        }
    }

    /// Try to acquire the mutex. Returns true if acquired.
    pub fn try_acquire(&self, thread_id: u32) -> bool {
        let mut state = lock_with_recovery(&self.inner);
        if state.owner_tid == 0 {
            state.abandoned = false;
            state.owner_tid = thread_id;
            state.recursion_count = 1;
            true
        } else if state.owner_tid == thread_id {
            state.recursion_count = state.recursion_count.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Acquire the mutex, blocking until available.
    pub fn acquire(&self, thread_id: u32) {
        let mut state = lock_with_recovery(&self.inner);
        loop {
            if state.owner_tid == 0 {
                state.abandoned = false;
                state.owner_tid = thread_id;
                state.recursion_count = 1;
                return;
            } else if state.owner_tid == thread_id {
                state.recursion_count = state.recursion_count.saturating_add(1);
                return;
            }
            // Condvar::wait re-locks the (possibly poisoned) mutex; recover
            // from poison instead of panicking every subsequent waiter.
            state = self
                .condvar
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Release the mutex. Returns false if the thread doesn't own it.
    pub fn release(&self, thread_id: u32) -> bool {
        let mut state = lock_with_recovery(&self.inner);
        if state.owner_tid != thread_id {
            return false;
        }
        state.recursion_count = state.recursion_count.saturating_sub(1);
        if state.recursion_count == 0 {
            state.owner_tid = 0;
            self.condvar.notify_one();
        }
        true
    }

    /// Mark the mutex abandoned because its owner thread terminated without
    /// releasing it. Returns `true` if `thread_id` actually owned the mutex.
    ///
    /// The next acquirer observes `is_abandoned()` and can surface
    /// `WAIT_ABANDONED` at the guest level.
    pub fn mark_abandoned(&self, thread_id: u32) -> bool {
        let mut state = lock_with_recovery(&self.inner);
        if state.owner_tid == thread_id {
            state.owner_tid = 0;
            state.recursion_count = 0;
            state.abandoned = true;
            self.condvar.notify_all();
            true
        } else {
            false
        }
    }

    /// Check if abandoned (owner thread died without releasing).
    pub fn is_abandoned(&self) -> bool {
        lock_with_recovery(&self.inner).abandoned
    }
}

impl Default for GuestMutex {
    fn default() -> Self {
        Self::new()
    }
}

/// A real semaphore with count tracking.
pub struct GuestSemaphore {
    inner: std::sync::Mutex<u32>,
    condvar: Condvar,
    max_count: u32,
}

impl GuestSemaphore {
    pub fn new(initial_count: u32, max_count: u32) -> Self {
        Self {
            inner: std::sync::Mutex::new(initial_count),
            condvar: Condvar::new(),
            max_count,
        }
    }

    /// Wait on the semaphore (decrement count, blocking if zero).
    pub fn wait(&self) {
        let mut count = lock_with_recovery(&self.inner);
        while *count == 0 {
            count = self
                .condvar
                .wait(count)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *count -= 1;
    }

    /// Release the semaphore (increment count). Returns the previous count.
    pub fn release(&self, release_count: u32) -> AppResult<u32> {
        let mut count = lock_with_recovery(&self.inner);
        let prev = *count;
        // checked_add rejects overflow instead of saturating: a saturating
        // add at u32::MAX silently "succeeds" without incrementing and still
        // notifies waiters (spurious wakeup, wrong return value).
        let new_count = match count.checked_add(release_count) {
            Some(n) => n,
            None => {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    "semaphore count overflow on release",
                ));
            }
        };
        if new_count > self.max_count {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                "semaphore release would exceed maximum count",
            ));
        }
        *count = new_count;
        for _ in 0..release_count {
            self.condvar.notify_one();
        }
        Ok(prev)
    }

    /// Get current count.
    pub fn count(&self) -> u32 {
        *lock_with_recovery(&self.inner)
    }
}

/// A real event (auto-reset or manual-reset).
pub struct GuestEvent {
    inner: std::sync::Mutex<EventState>,
    condvar: Condvar,
}

struct EventState {
    signaled: bool,
    auto_reset: bool,
}

impl GuestEvent {
    pub fn new(initial_state: bool, auto_reset: bool) -> Self {
        Self {
            inner: std::sync::Mutex::new(EventState {
                signaled: initial_state,
                auto_reset,
            }),
            condvar: Condvar::new(),
        }
    }

    /// Set the event to signaled state.
    pub fn set(&self) {
        let mut state = lock_with_recovery(&self.inner);
        state.signaled = true;
        self.condvar.notify_all();
    }

    /// Reset the event to non-signaled state.
    pub fn reset(&self) {
        lock_with_recovery(&self.inner).signaled = false;
    }

    /// Wait for the event to be signaled.
    pub fn wait(&self) {
        let mut state = lock_with_recovery(&self.inner);
        while !state.signaled {
            state = self
                .condvar
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        if state.auto_reset {
            state.signaled = false;
        }
    }

    /// Check if currently signaled (non-blocking).
    pub fn is_signaled(&self) -> bool {
        let mut state = lock_with_recovery(&self.inner);
        let result = state.signaled;
        if result && state.auto_reset {
            state.signaled = false;
        }
        result
    }
}

/// A real SRWLock (slim reader-writer lock) with proper ownership tracking.
///
/// Unlike `std::sync::RwLock`, Windows SRW locks are "slim" — they are
/// user-mode constructs that do not use RAII guards. This implementation
/// uses a counter guarded by a mutex to track state:
///   - `readers == 0` → unlocked
///   - `readers > 0` → held in shared mode (reader count)
///   - `readers == -1` → held exclusively
///     plus a `Condvar` for blocking contention. Pending exclusive waiters
///     are counted so that new readers are blocked while a writer is waiting
///     (writer preference, matching Windows SRW fairness).
pub struct GuestSRWLock {
    state: std::sync::Mutex<SrwLockState>,
    shared_waiters: Condvar,
    exclusive_waiters: Condvar,
}

struct SrwLockState {
    /// 0 unlocked, >0 reader count, -1 exclusive.
    readers: i32,
    /// Number of blocked exclusive-acquire waiters.
    writers_waiting: u32,
}

impl GuestSRWLock {
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(SrwLockState {
                readers: 0,
                writers_waiting: 0,
            }),
            shared_waiters: Condvar::new(),
            exclusive_waiters: Condvar::new(),
        }
    }

    /// Acquire the SRW lock exclusively (write lock). Blocks until exclusive
    /// access is granted. Once granted, the lock is *held exclusively* until
    /// [`release_exclusive`] is called.
    pub fn acquire_exclusive(&self) {
        let mut state = lock_with_recovery(&self.state);
        if state.readers == 0 {
            state.readers = -1; // exclusive owner
            return;
        }
        loop {
            state.writers_waiting = state.writers_waiting.saturating_add(1);
            state = self
                .exclusive_waiters
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
            state.writers_waiting = state.writers_waiting.saturating_sub(1);
            if state.readers == 0 {
                state.readers = -1; // exclusive owner
                return;
            }
        }
    }

    /// Release the exclusive lock. Wakes one exclusive waiter and all shared
    /// waiters so they can re-check.
    pub fn release_exclusive(&self) {
        let mut state = lock_with_recovery(&self.state);
        if state.readers != -1 {
            // Misuse (release without acquire): do not corrupt the state —
            // otherwise a bogus release could unblock waiters on a lock that
            // is still held.
            eprintln!(
                "[threads] GuestSRWLock::release_exclusive without exclusive ownership (readers={})",
                state.readers
            );
            return;
        }
        state.readers = 0;
        self.exclusive_waiters.notify_one();
        self.shared_waiters.notify_all();
    }

    /// Acquire the SRW lock in shared mode (read lock). Multiple readers are
    /// allowed concurrently; an exclusive owner blocks all readers. While an
    /// exclusive waiter is pending, new readers are blocked (writer
    /// preference) so a stream of readers cannot starve the writer.
    pub fn acquire_shared(&self) {
        let mut state = lock_with_recovery(&self.state);
        while state.readers < 0 || state.writers_waiting > 0 {
            state = self
                .shared_waiters
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        state.readers += 1;
    }

    /// Release a shared lock. When the last reader releases, wakes one
    /// exclusive waiter.
    pub fn release_shared(&self) {
        let mut state = lock_with_recovery(&self.state);
        if state.readers <= 0 {
            // Misuse (double release, release without acquire, or release on
            // an exclusively-held lock): clamp instead of underflowing into a
            // negative count that would deadlock every subsequent waiter
            // forever.
            eprintln!(
                "[threads] GuestSRWLock::release_shared underflow (readers={})",
                state.readers
            );
            return;
        }
        state.readers -= 1;
        if state.readers == 0 {
            self.exclusive_waiters.notify_one();
            self.shared_waiters.notify_all();
        }
    }

    /// Try to acquire the SRW lock exclusively (non-blocking).
    /// Returns `true` if the lock was acquired, `false` if it was already held.
    pub fn try_acquire_exclusive(&self) -> bool {
        let mut state = lock_with_recovery(&self.state);
        if state.readers == 0 {
            state.readers = -1;
            true
        } else {
            false
        }
    }

    /// Try to acquire the SRW lock in shared mode (non-blocking).
    /// Returns `true` if the lock was acquired, `false` if held exclusively
    /// or an exclusive waiter is pending.
    pub fn try_acquire_shared(&self) -> bool {
        let mut state = lock_with_recovery(&self.state);
        if state.readers >= 0 && state.writers_waiting == 0 {
            state.readers += 1;
            true
        } else {
            false
        }
    }
}

impl Default for GuestSRWLock {
    fn default() -> Self {
        Self::new()
    }
}

/// A real initialization once (one-time initialization).
pub struct GuestInitOnce {
    inner: std::sync::Once,
    completed: AtomicBool,
    failed: AtomicBool,
}

impl GuestInitOnce {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Once::new(),
            completed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        }
    }

    /// Run the init closure exactly once.
    ///
    /// A panicking closure is caught: `std::sync::Once` would otherwise
    /// replay the panic for every subsequent `call_once` caller, cascading
    /// one faulty guest callback into a host panic on every later caller.
    /// The failure is recorded and reported via [`is_failed`](Self::is_failed)
    /// so the guest shim can surface an error instead of re-running.
    pub fn call_once<F: FnOnce()>(&self, f: F) {
        self.inner.call_once(|| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            if result.is_err() {
                self.failed.store(true, Ordering::Release);
            } else {
                self.completed.store(true, Ordering::Release);
            }
        });
    }

    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    /// Whether the init closure panicked on its (only) run.
    pub fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
}

impl Default for GuestInitOnce {
    fn default() -> Self {
        Self::new()
    }
}

/// A real barrier for thread synchronization.
pub struct GuestBarrier {
    inner: Option<StdBarrier>,
    participant_count: u32,
}

impl GuestBarrier {
    pub fn new(participant_count: u32) -> Self {
        // StdBarrier::new(0) never releases: every `wait` increments a count
        // that can never reach 0, hanging all callers forever. Treat a
        // zero-participant barrier as an immediate no-op instead.
        let inner = if participant_count == 0 {
            None
        } else {
            Some(StdBarrier::new(participant_count as usize))
        };
        Self {
            inner,
            participant_count,
        }
    }

    pub fn wait(&self) {
        if let Some(inner) = &self.inner {
            let _result = inner.wait();
        }
    }

    pub fn participant_count(&self) -> u32 {
        self.participant_count
    }
}

// ---------------------------------------------------------------------------
// IO Completion Port
// ---------------------------------------------------------------------------

/// A real IO completion port using crossbeam channels.
pub struct GuestIoCompletionPort {
    sender: crossbeam_channel::Sender<IoCompletionPacket>,
    receiver: crossbeam_channel::Receiver<IoCompletionPacket>,
    concurrent_thread_count: u32,
}

/// Maximum number of queued completion packets before `post` fails. Bounds
/// memory use when producers outpace consumers.
const IOCP_MAX_QUEUED: usize = 4096;

#[derive(Debug, Clone)]
pub struct IoCompletionPacket {
    pub completion_key: u64,
    pub overlapped: u64,
    pub bytes_transferred: u32,
    pub error_code: u32,
}

impl GuestIoCompletionPort {
    pub fn new(concurrent_thread_count: u32) -> Self {
        let (sender, receiver) = crossbeam_channel::bounded(IOCP_MAX_QUEUED);
        Self {
            sender,
            receiver,
            concurrent_thread_count,
        }
    }

    /// Post a completion packet.
    pub fn post(&self, packet: IoCompletionPacket) -> AppResult<()> {
        self.sender.send(packet).map_err(|_| {
            AppError::new(
                ReasonCode::RcOutOfMemory,
                "IOCP completion queue full — packet dropped",
            )
        })
    }

    /// Dequeue a completion packet (blocking).
    pub fn dequeue(&self, timeout_ms: Option<u64>) -> Option<IoCompletionPacket> {
        match timeout_ms {
            Some(ms) => self
                .receiver
                .recv_timeout(std::time::Duration::from_millis(ms))
                .ok(),
            None => self.receiver.recv().ok(),
        }
    }

    pub fn concurrent_thread_count(&self) -> u32 {
        self.concurrent_thread_count
    }
}

// ---------------------------------------------------------------------------
// Thread-safe shared state
// ---------------------------------------------------------------------------

/// Thread-safe wrapper for shared guest state that multiple threads can access.
pub struct SharedGuestState {
    /// Shared memory image (protected by mutex for writes).
    pub memory: Arc<Mutex<MemoryImage>>,
    /// CPU engine config (immutable after creation).
    pub engine_config: CpuEngineConfig,
    /// Thread registry (maps thread_id to thread state).
    pub threads: Arc<Mutex<BTreeMap<u32, GuestThreadState>>>,
    /// Whether the process is exiting.
    pub process_exiting: Arc<AtomicBool>,
}

// ---------------------------------------------------------------------------
// Thread pool worker management
// ---------------------------------------------------------------------------

/// Manages native OS threads that back the Win32 thread pool.
///
/// Work items are queued into an inbound queue and moved to a completed
/// queue by a **fixed** set of worker threads (spawned lazily on the first
/// queued item). The single-threaded Casa1 VM cannot execute guest callbacks
/// directly on pool threads, so `dequeue_work()` hands completed items to
/// the runtime's dispatch loop, which invokes the guest callback. Workers
/// block on a condvar when idle — no polling, and only one consumer (the
/// pool worker) pops the inbound queue.
pub struct GuestThreadPool {
    /// Inbound work items, consumed only by pool workers.
    active_work: Arc<Mutex<VecDeque<ThreadPoolWorkItem>>>,
    /// Items moved here by workers, consumed only by `dequeue_work`.
    completed_work: Arc<Mutex<VecDeque<ThreadPoolWorkItem>>>,
    /// Signals workers that a work item arrived (or shutdown).
    work_available: Arc<Condvar>,
    /// Pool of native threads.
    threads: Vec<std::thread::JoinHandle<()>>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Whether the worker threads have been spawned.
    started: bool,
}

/// Number of worker threads in the fixed pool.
const THREAD_POOL_WORKERS: usize = 4;
/// Cap on the completed queue: if the runtime does not drain it, growth is
/// bounded (items are dropped with a diagnostic instead of leaking memory).
const THREAD_POOL_COMPLETED_CAP: usize = 4096;

impl GuestThreadPool {
    pub fn new() -> Self {
        Self {
            active_work: Arc::new(Mutex::new(VecDeque::new())),
            completed_work: Arc::new(Mutex::new(VecDeque::new())),
            work_available: Arc::new(Condvar::new()),
            threads: Vec::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            started: false,
        }
    }

    /// Queue a work item to be executed by a thread from the pool.
    ///
    /// Spawns the fixed worker set on first use (lazy), so an idle pool never
    /// burns threads. The item is handed to the runtime via `dequeue_work()`.
    pub fn queue_work(&mut self, callback: u64, context: u64, flags: u32) {
        lock_with_recovery(&self.active_work).push_back(ThreadPoolWorkItem {
            callback,
            context,
            flags,
        });
        if !self.started {
            self.started = true;
            for _ in 0..THREAD_POOL_WORKERS {
                let active_work = self.active_work.clone();
                let completed_work = self.completed_work.clone();
                let work_available = self.work_available.clone();
                let shutdown = self.shutdown.clone();
                self.threads.push(std::thread::spawn(move || {
                    loop {
                        if shutdown.load(Ordering::Acquire) {
                            return;
                        }
                        let item = {
                            let mut queue = lock_with_recovery(&active_work);
                            while queue.is_empty() && !shutdown.load(Ordering::Acquire) {
                                queue = work_available
                                    .wait(queue)
                                    .unwrap_or_else(PoisonError::into_inner);
                            }
                            queue.pop_front()
                        };
                        if let Some(item) = item {
                            // Hand the item to the runtime's dispatch loop instead
                            // of discarding it — the guest callback must never be
                            // silently lost.
                            let mut completed = lock_with_recovery(&completed_work);
                            if completed.len() >= THREAD_POOL_COMPLETED_CAP {
                                eprintln!(
                                    "[threads] completed work queue full; dropping callback={:#x}",
                                    item.callback
                                );
                            } else {
                                completed.push_back(item);
                            }
                        }
                    }
                }));
            }
        }
        self.work_available.notify_one();
    }

    /// Dequeue a completed work item (called from pe_runtime's dispatch loop).
    pub fn dequeue_work(&self) -> Option<ThreadPoolWorkItem> {
        lock_with_recovery(&self.completed_work).pop_front()
    }

    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.work_available.notify_all();
    }
}

impl Drop for GuestThreadPool {
    fn drop(&mut self) {
        self.shutdown();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Default for GuestThreadPool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// APC — Asynchronous Procedure Call infrastructure
// ---------------------------------------------------------------------------

/// An APC entry queued for a guest thread.
#[derive(Debug, Clone)]
pub struct ApcEntry {
    /// The APC callback function address.
    pub callback: u64,
    /// The context parameter passed to the callback.
    pub context: u64,
    /// Whether this is a kernel-mode APC (vs user-mode).
    pub kernel_mode: bool,
}

/// Per-thread APC queue.
#[derive(Debug, Default)]
pub struct GuestApcQueue {
    /// User-mode APCs.
    pub user_apcs: VecDeque<ApcEntry>,
    /// Kernel-mode APCs (simulated for I/O completion).
    pub kernel_apcs: VecDeque<ApcEntry>,
    /// Whether APCs are disabled (during DLL init, etc.).
    pub disabled: bool,
}

impl GuestApcQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a user-mode APC.
    pub fn queue_user_apc(&mut self, callback: u64, context: u64) {
        self.user_apcs.push_back(ApcEntry {
            callback,
            context,
            kernel_mode: false,
        });
    }

    /// Queue a kernel-mode APC (for I/O completion simulation).
    pub fn queue_kernel_apc(&mut self, callback: u64, context: u64) {
        self.kernel_apcs.push_back(ApcEntry {
            callback,
            context,
            kernel_mode: true,
        });
    }

    /// Deliver pending APCs, returning the entries for execution by the
    /// runtime (which invokes the guest callbacks).
    ///
    /// Should be called at alertable wait points. This is a compatibility
    /// alias for [`deliver_apcs`](Self::deliver_apcs) — unlike the old
    /// implementation it never discards APCs; callers must execute (or
    /// re-queue) the returned entries.
    pub fn deliver(&mut self, max_count: usize) -> Vec<ApcEntry> {
        self.deliver_apcs(max_count)
    }

    /// Check if any APCs are pending.
    pub fn has_pending(&self) -> bool {
        if self.disabled {
            return false;
        }
        !self.user_apcs.is_empty() || !self.kernel_apcs.is_empty()
    }

    /// Disable APC delivery (during DLL initialization).
    pub fn disable(&mut self) {
        self.disabled = true;
    }

    /// Enable APC delivery.
    pub fn enable(&mut self) {
        self.disabled = false;
    }
}

// ---------------------------------------------------------------------------
// Timer queue support (for CreateTimerQueueTimer)
// ---------------------------------------------------------------------------

/// A registered timer queue timer.
#[derive(Debug, Clone)]
pub struct TimerQueueEntry {
    pub callback: u64,
    pub context: u64,
    pub due_time_ms: u64,
    pub period_ms: u64,
    pub active: bool,
}

/// Manages a collection of timer queue entries.
#[derive(Debug, Default)]
pub struct GuestTimerQueue {
    pub timers: BTreeMap<u64, TimerQueueEntry>,
}

impl GuestTimerQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_timer(
        &mut self,
        handle: u64,
        callback: u64,
        context: u64,
        due_time_ms: u64,
        period_ms: u64,
    ) {
        self.timers.insert(
            handle,
            TimerQueueEntry {
                callback,
                context,
                due_time_ms,
                period_ms,
                active: true,
            },
        );
    }

    pub fn delete_timer(&mut self, handle: u64) {
        self.timers.remove(&handle);
    }
}

// ---------------------------------------------------------------------------
// N4 — Condition Variable (Windows CONDITION_VARIABLE semantics)
// ---------------------------------------------------------------------------

/// A Windows-style condition variable that works with both critical sections
/// (GuestMutex) and SRW locks (GuestSRWLock).
///
/// Unlike `std::sync::Condvar`, Windows condition variables are not associated
/// with a specific mutex at creation time — the association happens at wait time.
///
/// This implementation uses an internal `Condvar` for actual blocking and a
/// `wake_generation` counter that lets waiters snapshot the state before
/// blocking and re-check it after a wake.  Waiters block on the condvar until
/// a real state change (wake or deadline) — there is no interval ticking.
pub struct GuestConditionVariable {
    inner: Condvar,
    /// Monotonically increasing counter incremented on each wake.  Waiters
    /// snapshot this value before blocking and compare afterwards to detect
    /// wake events.
    wake_generation: AtomicU64,
    /// Tracks the number of threads currently waiting (for diagnostics).
    waiter_count: AtomicU32,
    /// Number of `wake`/`wake_all` notifications issued (diagnostics/tests).
    wake_count: AtomicU64,
    /// Number of iterations executed by `sleep_with_polling` across all
    /// callers (diagnostics/tests; used to prove waits are wake-driven rather
    /// than interval-driven).
    poll_iterations: AtomicU64,
}

impl GuestConditionVariable {
    pub fn new() -> Self {
        Self {
            inner: Condvar::new(),
            wake_generation: AtomicU64::new(0),
            waiter_count: AtomicU32::new(0),
            wake_count: AtomicU64::new(0),
            poll_iterations: AtomicU64::new(0),
        }
    }

    /// Return the current wake generation count.
    ///
    /// Callers can snapshot this value before entering a polling wait loop and
    /// compare after each iteration to see if a wake occurred.
    pub fn generation(&self) -> u64 {
        self.wake_generation.load(Ordering::Acquire)
    }

    /// Return the number of threads currently waiting on this condition variable.
    pub fn waiter_count(&self) -> u32 {
        self.waiter_count.load(Ordering::Relaxed)
    }

    /// Number of wake notifications issued via [`wake`](Self::wake) or
    /// [`wake_all`](Self::wake_all) (diagnostics/tests).
    pub fn wake_count(&self) -> u64 {
        self.wake_count.load(Ordering::Relaxed)
    }

    /// Number of iterations executed by [`sleep_with_polling`](Self::sleep_with_polling)
    /// across all callers (diagnostics/tests).  A genuinely event-driven wait
    /// stays at a small constant count regardless of the timeout length.
    pub fn poll_iterations(&self) -> u64 {
        self.poll_iterations.load(Ordering::Relaxed)
    }

    /// Sleep on the condition variable while releasing the associated critical
    /// section (GuestMutex).  The mutex is released atomically with the wait,
    /// and re-acquired before returning.
    ///
    /// Returns `true` if the wait completed normally (wake), `false` on timeout.
    pub fn sleep_cs(&self, mutex: &GuestMutex, thread_id: u32, timeout_ms: Option<u64>) -> bool {
        // Release the guest mutex before waiting
        mutex.release(thread_id);

        // Snapshot the generation before waiting
        let generation = self.wake_generation.load(Ordering::Acquire);
        self.waiter_count.fetch_add(1, Ordering::Relaxed);

        // Wait for a wake or timeout using the internal condvar
        let lock = std::sync::Mutex::new(());
        let result = match timeout_ms {
            Some(ms) => {
                let (guard, timeout_result) = self
                    .inner
                    .wait_timeout_while(
                        lock_with_recovery(&lock),
                        Duration::from_millis(ms),
                        |_| self.wake_generation.load(Ordering::Acquire) == generation,
                    )
                    .unwrap_or_else(PoisonError::into_inner);
                drop(guard);
                !timeout_result.timed_out()
            }
            None => {
                let guard = self
                    .inner
                    .wait_while(lock_with_recovery(&lock), |_| {
                        self.wake_generation.load(Ordering::Acquire) == generation
                    })
                    .unwrap_or_else(PoisonError::into_inner);
                drop(guard);
                true
            }
        };
        self.waiter_count.fetch_sub(1, Ordering::Relaxed);

        // Re-acquire the guest mutex
        mutex.acquire(thread_id);
        result
    }

    /// Event-driven wait: snapshots the wake generation, pumps pending work
    /// once, then blocks on the condition variable until a wake is delivered
    /// or the monotonic deadline expires.
    ///
    /// This is designed for the pe_runtime dispatch loop which needs to pump
    /// pending guest threads while waiting on a condition variable.  There is
    /// no fixed tick: a quiet wait blocks for the whole remaining duration and
    /// performs a small constant number of iterations.  A `pump` that reports
    /// progress (`true`) is re-invoked immediately, because that is real work,
    /// not polling.
    pub fn sleep_with_polling<F: FnMut() -> bool>(
        &self,
        timeout_ms: Option<u64>,
        mut pump: F,
    ) -> bool {
        let generation = self.wake_generation.load(Ordering::Acquire);
        self.waiter_count.fetch_add(1, Ordering::Relaxed);

        let deadline = timeout_ms.map(|ms| std::time::Instant::now() + Duration::from_millis(ms));
        let lock = std::sync::Mutex::new(());

        let result = loop {
            self.poll_iterations.fetch_add(1, Ordering::Relaxed);

            if self.wake_generation.load(Ordering::Acquire) != generation {
                break true;
            }

            let remaining = match deadline {
                Some(dl) => {
                    let now = std::time::Instant::now();
                    if now >= dl {
                        break false;
                    }
                    dl - now
                }
                // No deadline: block until a real wake.  The predicate below
                // re-arms on spurious wakeups, so the ceiling is only a
                // defensive bound, not a polling tick.
                None => Duration::from_secs(24 * 60 * 60),
            };

            if pump() {
                // The pump made progress; re-check state without blocking.
                continue;
            }

            let (guard, wait_result) = self
                .inner
                .wait_timeout_while(lock_with_recovery(&lock), remaining, |_| {
                    self.wake_generation.load(Ordering::Acquire) == generation
                })
                .unwrap_or_else(PoisonError::into_inner);
            drop(guard);
            if !wait_result.timed_out() {
                break true;
            }
        };

        self.waiter_count.fetch_sub(1, Ordering::Relaxed);
        result
    }

    /// Wake one waiting thread.
    pub fn wake(&self) {
        self.wake_count.fetch_add(1, Ordering::Relaxed);
        self.wake_generation.fetch_add(1, Ordering::Release);
        self.inner.notify_one();
    }

    /// Wake all waiting threads.
    pub fn wake_all(&self) {
        self.wake_count.fetch_add(1, Ordering::Relaxed);
        self.wake_generation.fetch_add(1, Ordering::Release);
        self.inner.notify_all();
    }
}

impl Default for GuestConditionVariable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// N1 — Real Fiber Implementation (Box-based handles with thread-local tracking)
// ---------------------------------------------------------------------------

/// Fiber-local storage (FLS) slot array.
const FLS_MAXIMUM_AVAILABLE: usize = 128;

/// A guard-page-protected stack allocation backed by [`mmap`].
///
/// The first 4 KiB page is mapped `PROT_NONE` so that a stack overflow
/// causes an immediate segfault instead of silently corrupting adjacent
/// heap memory.
pub struct MmapStack {
    /// Pointer returned by [`mmap`]; includes the guard page at the bottom.
    ptr: *mut u8,
    /// Total size of the mmapʼd region (guard page + usable stack).
    size: usize,
}

impl MmapStack {
    /// Create a new guard-page-protected stack with at least `stack_size`
    /// bytes of usable space.
    ///
    /// Returns `None` (with a diagnostic) when the OS refuses the allocation
    /// or the requested size overflows — the guest controls `stack_size`, so
    /// an absurd request must surface as a failure, not a host panic.
    fn new(stack_size: usize) -> Option<Self> {
        let guard_size = 4096usize;
        let total_size = stack_size.checked_add(guard_size)?;

        // SAFETY: `mmap` allocates anonymous writable memory.  The kernel
        // zeroes newly-mapped pages (MAP_ANONYMOUS).
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(), // let the kernel choose the address
                total_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1, // fd (ignored for MAP_ANONYMOUS)
                0,  // offset
            )
        };

        if ptr == libc::MAP_FAILED {
            eprintln!(
                "[threads] mmap({total_size}) failed for fiber stack: {}",
                std::io::Error::last_os_error()
            );
            return None;
        }

        // SAFETY: `mprotect` marks the first page as inaccessible (guard).
        let ret = unsafe { libc::mprotect(ptr, guard_size, libc::PROT_NONE) };
        if ret != 0 {
            // Unmap before failing to avoid leaking the mapping.
            unsafe {
                libc::munmap(ptr, total_size);
            }
            eprintln!(
                "[threads] mprotect guard page failed: {}",
                std::io::Error::last_os_error()
            );
            return None;
        }

        Some(Self {
            ptr: ptr as *mut u8,
            size: total_size,
        })
    }

    /// Pointer to the start of the *usable* stack (just above the guard page).
    fn usable_ptr(&self) -> *mut u8 {
        // SAFETY: `ptr + 4096` is within the mmapʼd region (we allocated
        // `stack_size + 4096` bytes), so the offset is valid.
        unsafe { self.ptr.add(4096) }
    }
}

// SAFETY: `MmapStack` exclusively owns its mmapʼd region.  Moving the
// struct between threads is safe because the `Drop` impl always calls
// `munmap` from whichever thread owns the value.  Access to the region
// is through `&self` methods that only return pointers; the caller is
// responsible for using them correctly (as they already were for the
// old `Vec<u8>` stack).
unsafe impl Send for MmapStack {}
unsafe impl Sync for MmapStack {}

impl Drop for MmapStack {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `size` were obtained from a successful `mmap`
        // call, and we havenʼt freed them before.
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size);
        }
    }
}

/// A fully functional guest fiber with allocated stack and context save area.
///
/// Fibers are cooperative execution contexts that share the same OS thread.
/// `SwitchToFiber` saves the current CPU state into the running fiber and
/// restores the target fiber's state, then jumps to its entry/resume point.
pub struct GuestFiberContext {
    /// Unique fiber ID.
    pub fiber_id: u32,
    /// Allocated stack memory (mmapʼd with a guard page).
    pub stack_allocation: Option<MmapStack>,
    /// Stack base address (guest virtual address).
    pub stack_base: u64,
    /// Stack limit (guest virtual address).
    pub stack_limit: u64,
    /// Fiber entry point (guest virtual address).
    pub start_address: u64,
    /// Parameter passed to fiber entry.
    pub parameter: u64,
    /// Saved CPU state (registers, etc.) for resumption.
    pub state: Option<CpuState>,
    /// Whether this fiber is currently executing.
    pub is_executing: bool,
    /// Fiber-local storage slots.
    pub fls_slots: [u64; FLS_MAXIMUM_AVAILABLE],
    /// FLS callback list (called on fiber deletion).
    pub fls_callbacks: [Option<u64>; FLS_MAXIMUM_AVAILABLE],
    /// Whether this fiber has been deleted.
    pub deleted: bool,
    /// The previous fiber that was running before switching to this one.
    pub previous_fiber: Option<u32>,
}

impl GuestFiberContext {
    /// Create a new fiber context with the specified stack size and entry point.
    ///
    /// The stack is allocated via [`mmap`] with a 4 KiB guard page at the
    /// bottom so that a stack overflow triggers a segfault instead of
    /// silently corrupting adjacent heap memory. Returns `None` if the
    /// allocation fails (the caller maps this to a NULL fiber handle).
    pub fn new(
        fiber_id: u32,
        stack_size: usize,
        start_address: u64,
        parameter: u64,
    ) -> Option<Self> {
        let mmap_stack = MmapStack::new(stack_size)?;
        let stack_limit = mmap_stack.usable_ptr() as u64;
        // Align stack base to 16 bytes
        let stack_base = (stack_limit.wrapping_add(stack_size as u64)) & !0xF;

        Some(Self {
            fiber_id,
            stack_allocation: Some(mmap_stack),
            stack_base,
            stack_limit,
            start_address,
            parameter,
            state: None,
            is_executing: false,
            fls_slots: [0u64; FLS_MAXIMUM_AVAILABLE],
            fls_callbacks: [None; FLS_MAXIMUM_AVAILABLE],
            deleted: false,
            previous_fiber: None,
        })
    }

    /// Convert the current thread into a fiber (used for the "primary" fiber).
    ///
    /// The primary fiber does **not** own a separate stack — it runs on the
    /// OS thread's own stack, so `stack_allocation` is `None`.
    pub fn new_from_thread(fiber_id: u32) -> Self {
        Self {
            fiber_id,
            stack_allocation: None, // No allocated stack — uses thread's own stack
            stack_base: 0,
            stack_limit: 0,
            start_address: 0,
            parameter: 0,
            state: None,
            is_executing: true,
            fls_slots: [0u64; FLS_MAXIMUM_AVAILABLE],
            fls_callbacks: [None; FLS_MAXIMUM_AVAILABLE],
            deleted: false,
            previous_fiber: None,
        }
    }

    /// Initialize the CPU state for first execution.
    /// Sets up the stack pointer and instruction pointer.
    pub fn initialize_state(&mut self, state: &mut CpuState) {
        // The primary fiber (new_from_thread) runs on the OS thread's own
        // stack, so there is nothing to set up — and its `stack_base` of 0
        // must not underflow the guest RSP.
        if self.stack_allocation.is_none() {
            return;
        }
        // Set the guest stack pointer to the top of the allocated stack.
        // The stack grows downward, so SP = stack_base - 8 (for return address).
        // x64 GPR index: RSP=4, RCX=1, RIP is a separate field.
        state.gpr[4] = self.stack_base.wrapping_sub(8); // RSP
        state.rip = self.start_address;
        // First parameter (RCX on x64) = fiber parameter
        state.gpr[1] = self.parameter;
    }

    /// Set a fiber-local storage slot value.
    pub fn set_fls(&mut self, index: usize, value: u64) -> bool {
        if index < FLS_MAXIMUM_AVAILABLE {
            self.fls_slots[index] = value;
            true
        } else {
            false
        }
    }

    /// Get a fiber-local storage slot value.
    pub fn get_fls(&self, index: usize) -> Option<u64> {
        if index < FLS_MAXIMUM_AVAILABLE {
            Some(self.fls_slots[index])
        } else {
            None
        }
    }

    /// Set a FLS callback (invoked when fiber is deleted or FLS slot is freed).
    pub fn set_fls_callback(&mut self, index: usize, callback: u64) -> bool {
        if index < FLS_MAXIMUM_AVAILABLE {
            self.fls_callbacks[index] = Some(callback);
            true
        } else {
            false
        }
    }
}

/// A closure-based fiber handle that wraps a boxed entry-point closure.
///
/// Each fiber handle is a `u64` that wraps a `Box<dyn FnOnce()>` pointer via
/// `Box::into_raw` / `Box::from_raw`.  The closure captures the guest entry
/// point and parameter so that when the fiber is first switched to, the entry
/// function is called.
pub type FiberHandle = u64;

// Thread-local tracker for the currently running fiber on this OS thread.
//
// Windows fibers are per-thread: each guest thread (backed 1:1 by an OS
// thread) has its own "current fiber". Keeping the current-fiber identity in
// TLS means two guest threads switching fibers concurrently on different
// host threads can never observe or mutate each other's current-fiber state.
thread_local! {
    pub static CURRENT_FIBER: RefCell<Option<FiberHandle>> = const { RefCell::new(None) };
}

fn current_fiber_handle() -> Option<FiberHandle> {
    CURRENT_FIBER.try_with(|cf| *cf.borrow()).unwrap_or(None)
}

fn set_current_fiber(handle: FiberHandle) {
    let _ = CURRENT_FIBER.try_with(|cf| cf.borrow_mut().replace(handle));
}

fn clear_current_fiber() {
    let _ = CURRENT_FIBER.try_with(|cf| cf.borrow_mut().take());
}

// Global fiber registry, shared across all host thunks. The registry itself
// (creation/deletion/lookup) is process-global; per-thread "current fiber"
// state lives in the thread-local above.
lazy_static::lazy_static! {
    pub static ref FIBER_MANAGER: Mutex<GuestFiberManager> = Mutex::new(GuestFiberManager::new());
}

/// Manages all active fibers for a guest process.
pub struct GuestFiberManager {
    /// All active fibers indexed by fiber_id.
    fibers: BTreeMap<u32, GuestFiberContext>,
    /// Next fiber ID.
    next_fiber_id: u32,
}

impl GuestFiberManager {
    pub fn new() -> Self {
        Self {
            fibers: BTreeMap::new(),
            next_fiber_id: 1,
        }
    }

    /// Allocate a new fiber ID.
    fn allocate_id(&mut self) -> u32 {
        let id = self.next_fiber_id;
        self.next_fiber_id += 1;
        id
    }

    /// Create a new fiber with the specified stack size and entry point.
    /// Returns a `FiberHandle` (u64) that wraps the fiber ID and is used
    /// by the runtime to reference the fiber, or `0` (NULL) if the guest-
    /// supplied stack could not be allocated.
    pub fn create_fiber(
        &mut self,
        stack_size: usize,
        start_address: u64,
        parameter: u64,
    ) -> FiberHandle {
        let id = self.allocate_id();
        match GuestFiberContext::new(id, stack_size, start_address, parameter) {
            Some(fiber) => {
                self.fibers.insert(id, fiber);
                id as FiberHandle
            }
            None => {
                eprintln!(
                    "[threads] create_fiber: stack allocation failed (size={stack_size}); returning NULL"
                );
                0
            }
        }
    }

    /// Convert the current thread to a fiber. Returns the fiber handle.
    pub fn convert_thread_to_fiber(&mut self) -> FiberHandle {
        let id = self.allocate_id();
        let fiber = GuestFiberContext::new_from_thread(id);
        self.fibers.insert(id, fiber);
        // Track the current fiber in thread-local storage so each host
        // thread keeps independent fiber state.
        set_current_fiber(id as FiberHandle);
        id as FiberHandle
    }

    /// Get the current fiber handle (for the calling thread).
    pub fn current_fiber(&self) -> Option<FiberHandle> {
        current_fiber_handle()
    }

    /// Mark the current fiber's CpuState as saved and switch to the target.
    ///
    /// Returns `(current_fiber_id, target_fiber_id)` so the caller can
    /// save/restore `CpuState` accordingly.
    pub fn switch_to(&mut self, target_handle: FiberHandle) -> Option<(u32, u32)> {
        let target_id = target_handle as u32;
        let current_id = current_fiber_handle()? as u32;

        if !self.fibers.contains_key(&target_id) {
            return None;
        }

        // Mark current fiber as not executing
        if let Some(current) = self.fibers.get_mut(&current_id) {
            current.is_executing = false;
        }

        // Mark target fiber as executing; record which fiber ran before it
        // (the fiber being switched away from), so `previous_fiber` is not
        // inverted.
        if let Some(target) = self.fibers.get_mut(&target_id) {
            target.is_executing = true;
            target.previous_fiber = Some(current_id);
        }

        set_current_fiber(target_handle);

        Some((current_id, target_id))
    }

    /// Delete a fiber. Returns FLS callbacks that should be invoked.
    pub fn delete_fiber(&mut self, fiber_id: FiberHandle) -> Vec<u64> {
        let fid = fiber_id as u32;
        let mut callbacks = Vec::new();
        if let Some(mut fiber) = self.fibers.remove(&fid) {
            fiber.deleted = true;
            callbacks.extend(fiber.fls_callbacks.iter().flatten().copied());
        }
        // If the deleted fiber was this thread's current fiber, clear the
        // thread-local tracker so `save_current_state` cannot target a
        // stale (dangling) fiber ID.
        if current_fiber_handle() == Some(fiber_id) {
            clear_current_fiber();
        }
        callbacks
    }

    /// Get a reference to a fiber context.
    pub fn get_fiber(&self, fiber_id: FiberHandle) -> Option<&GuestFiberContext> {
        self.fibers.get(&(fiber_id as u32))
    }

    /// Get a mutable reference to a fiber context.
    pub fn get_fiber_mut(&mut self, fiber_id: FiberHandle) -> Option<&mut GuestFiberContext> {
        self.fibers.get_mut(&(fiber_id as u32))
    }

    /// Save the current CpuState into the currently executing fiber (of the
    /// calling thread).
    pub fn save_current_state(&mut self, state: &CpuState) {
        if let Some(fiber) = current_fiber_handle().and_then(|h| self.fibers.get_mut(&(h as u32))) {
            fiber.state = Some(state.clone());
        }
    }

    /// Restore CpuState from a fiber (or set RIP for first-time execution).
    pub fn restore_state(&self, fiber_handle: FiberHandle, state: &mut CpuState) -> bool {
        if let Some(fiber) = self.fibers.get(&(fiber_handle as u32)) {
            if let Some(ref saved) = fiber.state {
                *state = saved.clone();
            } else {
                // First execution — set RIP to start_address
                state.rip = fiber.start_address;
            }
            true
        } else {
            false
        }
    }
}

impl Default for GuestFiberManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// N2 — Enhanced Thread Pool with real dispatch
// ---------------------------------------------------------------------------

/// Enhanced thread pool that actually dispatches work items to native threads.
///
/// Each work item carries a guest callback address and context. The pool
/// maintains a fixed number of worker threads that dequeue and process items:
/// workers move whole `ThreadPoolWorkItem`s (callback **and** context/flags)
/// to a completed queue that the runtime drains, and service due timers.
/// Workers block on a condvar when idle — no polling.  When timers are
/// pending, the wait is a monotonic deadline computed from the earliest due
/// time (never a fixed tick); queue/timer/shutdown changes notify the workers
/// immediately.
pub struct EnhancedGuestThreadPool {
    /// Shared work queue.
    work_queue: Arc<Mutex<VecDeque<ThreadPoolWorkItem>>>,
    /// Timer queue for delayed work items.
    timer_queue: Arc<Mutex<GuestTimerQueue>>,
    /// Wait registrations (serviced by the runtime — the pool cannot poll
    /// guest handles).
    wait_registrations: Arc<Mutex<Vec<WaitRegistration>>>,
    /// Signals workers that work arrived (or shutdown).
    work_available: Arc<Condvar>,
    /// Pool thread handles.
    threads: Vec<std::thread::JoinHandle<()>>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Number of worker threads.
    num_workers: usize,
    /// Completed work items (whole items: callback + context + flags).
    completed_queue: Arc<Mutex<VecDeque<ThreadPoolWorkItem>>>,
    /// Signals that a completed item was pushed, so `dequeue_completed_timeout`
    /// blocks until work is actually available.
    completed_available: Arc<Condvar>,
    /// Monotonic clock epoch for timer due-time computation.
    epoch: std::time::Instant,
    /// Bumped whenever the timer queue changes (create/delete), so idle
    /// workers re-evaluate their timer deadline instead of sleeping past a
    /// newly-created timer.
    timer_generation: Arc<AtomicU64>,
}

/// Cap on the completed queue and wait-registration list.
const ENHANCED_POOL_CAP: usize = 4096;

/// A wait registration (for RegisterWaitForSingleObject).
#[derive(Debug, Clone)]
#[allow(dead_code)] // alertable-wait registration state; not yet wired
struct WaitRegistration {
    /// Handle being waited on.
    pub handle: u32,
    /// Callback to invoke when signaled.
    pub callback: u64,
    /// Context parameter.
    pub context: u64,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Whether this is a one-shot wait.
    pub one_shot: bool,
    /// Whether still active.
    pub active: bool,
}

/// Push an item to the completed queue, bounding growth if the runtime does
/// not drain it, and wake a blocked `dequeue_completed_timeout` waiter.
fn push_completed_item(
    queue: &Mutex<VecDeque<ThreadPoolWorkItem>>,
    available: &Condvar,
    item: ThreadPoolWorkItem,
) {
    let mut q = lock_with_recovery(queue);
    if q.len() >= ENHANCED_POOL_CAP {
        eprintln!(
            "[threads] completed queue full; dropping work item callback={:#x}",
            item.callback
        );
        return;
    }
    q.push_back(item);
    drop(q);
    available.notify_one();
}

impl EnhancedGuestThreadPool {
    pub fn new(num_workers: usize) -> Self {
        Self {
            work_queue: Arc::new(Mutex::new(VecDeque::new())),
            timer_queue: Arc::new(Mutex::new(GuestTimerQueue::new())),
            wait_registrations: Arc::new(Mutex::new(Vec::new())),
            work_available: Arc::new(Condvar::new()),
            threads: Vec::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            num_workers,
            completed_queue: Arc::new(Mutex::new(VecDeque::new())),
            completed_available: Arc::new(Condvar::new()),
            epoch: std::time::Instant::now(),
            timer_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start the worker threads.
    pub fn start(&mut self) {
        if self.threads.is_empty() {
            for _ in 0..self.num_workers {
                let work_queue = self.work_queue.clone();
                let timer_queue = self.timer_queue.clone();
                let completed_queue = self.completed_queue.clone();
                let work_available = self.work_available.clone();
                let completed_available = self.completed_available.clone();
                let shutdown = self.shutdown.clone();
                let timer_generation = self.timer_generation.clone();
                let epoch = self.epoch;

                let handle = std::thread::spawn(move || {
                    loop {
                        if shutdown.load(Ordering::Acquire) {
                            return;
                        }

                        // Snapshot the timer generation *before* evaluating
                        // due timers: a concurrent create/delete bumps the
                        // generation and notifies, and the wait predicate below
                        // re-checks it so a wake cannot be missed between the
                        // evaluation and the blocking wait.
                        let timer_gen = timer_generation.load(Ordering::Acquire);

                        // Service due timers in due-time order (ties broken by
                        // handle). Removal/rescheduling happens under the same
                        // lock as collection, so a due timer is delivered
                        // exactly once even with several workers. Their
                        // callbacks are delivered through the completed queue
                        // like ordinary work.
                        let now_ms = epoch.elapsed().as_millis() as u64;
                        let (due_items, next_due_ms) = {
                            let mut tq = lock_with_recovery(&timer_queue);
                            let mut due = Vec::new();
                            let mut removals = Vec::new();
                            let mut reschedules = Vec::new();
                            for (&handle, timer) in &tq.timers {
                                if !timer.active || timer.due_time_ms > now_ms {
                                    continue;
                                }
                                due.push((
                                    timer.due_time_ms,
                                    handle,
                                    ThreadPoolWorkItem {
                                        callback: timer.callback,
                                        context: timer.context,
                                        flags: 0,
                                    },
                                ));
                                if timer.period_ms > 0 {
                                    let mut next = timer.due_time_ms;
                                    while next <= now_ms {
                                        next = next.saturating_add(timer.period_ms);
                                    }
                                    reschedules.push((handle, next));
                                } else {
                                    removals.push(handle);
                                }
                            }
                            for h in &removals {
                                tq.timers.remove(h);
                            }
                            for (h, next) in &reschedules {
                                if let Some(t) = tq.timers.get_mut(h) {
                                    t.due_time_ms = *next;
                                }
                            }
                            due.sort_by_key(|(due_ms, handle, _)| (*due_ms, *handle));
                            let next_due_ms = tq
                                .timers
                                .values()
                                .filter(|t| t.active)
                                .map(|t| t.due_time_ms)
                                .min();
                            (
                                due.into_iter().map(|(_, _, item)| item).collect::<Vec<_>>(),
                                next_due_ms,
                            )
                        };
                        for item in due_items {
                            push_completed_item(&completed_queue, &completed_available, item);
                        }

                        // Dequeue a work item; the whole item (callback,
                        // context, flags) is handed to the runtime.
                        let work = {
                            let mut queue = lock_with_recovery(&work_queue);
                            queue.pop_front()
                        };
                        if let Some(item) = work {
                            push_completed_item(&completed_queue, &completed_available, item);
                            continue;
                        }

                        // Nothing to do: block until work arrives, the timer
                        // queue changes, shutdown, or the next timer deadline
                        // (a monotonic `due - now` duration, never a fixed
                        // tick). With no timers this waits indefinitely and is
                        // woken by queue_work/create_timer/shutdown.
                        let wait = match next_due_ms {
                            Some(due_ms) => {
                                let elapsed_ms = epoch.elapsed().as_millis() as u64;
                                Duration::from_millis(due_ms.saturating_sub(elapsed_ms))
                            }
                            None => Duration::from_secs(24 * 60 * 60),
                        };
                        let queue = lock_with_recovery(&work_queue);
                        let (guard, _) = work_available
                            .wait_timeout_while(queue, wait, |q| {
                                q.is_empty()
                                    && !shutdown.load(Ordering::Acquire)
                                    && timer_generation.load(Ordering::Acquire) == timer_gen
                            })
                            .unwrap_or_else(PoisonError::into_inner);
                        drop(guard);
                    }
                });

                self.threads.push(handle);
            }
        }
    }

    /// Queue a work item for execution.
    pub fn queue_work(&self, callback: u64, context: u64, flags: u32) {
        lock_with_recovery(&self.work_queue).push_back(ThreadPoolWorkItem {
            callback,
            context,
            flags,
        });
        self.work_available.notify_one();
    }

    /// Dequeue a completed work item (whole item, including context/flags).
    pub fn dequeue_completed(&self) -> Option<ThreadPoolWorkItem> {
        lock_with_recovery(&self.completed_queue).pop_front()
    }

    /// Block until a completed work item is available or `timeout_ms` elapses.
    ///
    /// Uses a monotonic deadline and the completed-queue condvar, so the
    /// caller is woken by an actual completion rather than polling.
    pub fn dequeue_completed_timeout(&self, timeout_ms: u64) -> Option<ThreadPoolWorkItem> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        let mut queue = lock_with_recovery(&self.completed_queue);
        loop {
            if let Some(item) = queue.pop_front() {
                return Some(item);
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, wait_result) = self
                .completed_available
                .wait_timeout(queue, deadline - now)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
            if wait_result.timed_out() && queue.is_empty() {
                return None;
            }
        }
    }

    /// Create a timer that fires at the specified due time and period.
    pub fn create_timer(
        &self,
        handle: u64,
        callback: u64,
        context: u64,
        due_time_ms: u64,
        period_ms: u64,
    ) {
        lock_with_recovery(&self.timer_queue).create_timer(
            handle,
            callback,
            context,
            due_time_ms,
            period_ms,
        );
        self.timer_generation.fetch_add(1, Ordering::Release);
        self.work_available.notify_one();
    }

    /// Delete a timer. Idle workers are woken so a pending deadline for the
    /// cancelled timer is recomputed immediately.
    pub fn delete_timer(&self, handle: u64) {
        lock_with_recovery(&self.timer_queue).delete_timer(handle);
        self.timer_generation.fetch_add(1, Ordering::Release);
        self.work_available.notify_one();
    }

    /// Register a wait for a handle.
    ///
    /// The pool cannot poll guest handles — the runtime must service the
    /// registration (evaluate signal state, invoke the callback) and call
    /// `unregister_wait`. The list is bounded so a guest registering waits in
    /// a loop cannot grow memory without bound.
    pub fn register_wait(
        &self,
        handle: u32,
        callback: u64,
        context: u64,
        timeout_ms: u64,
        one_shot: bool,
    ) {
        let mut registrations = lock_with_recovery(&self.wait_registrations);
        if registrations.len() >= ENHANCED_POOL_CAP {
            eprintln!(
                "[threads] wait registration list full ({}); rejecting handle {handle:#x}",
                ENHANCED_POOL_CAP
            );
            return;
        }
        registrations.push(WaitRegistration {
            handle,
            callback,
            context,
            timeout_ms,
            one_shot,
            active: true,
        });
    }

    /// Remove a previously registered wait.
    pub fn unregister_wait(&self, handle: u32) {
        lock_with_recovery(&self.wait_registrations).retain(|w| w.handle != handle);
    }

    /// Shutdown the thread pool.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.work_available.notify_all();
    }

    /// Get the number of pending work items.
    pub fn pending_count(&self) -> usize {
        lock_with_recovery(&self.work_queue).len()
    }
}

impl Drop for EnhancedGuestThreadPool {
    fn drop(&mut self) {
        self.shutdown();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// N7 — Enhanced APC delivery with callback return
// ---------------------------------------------------------------------------

impl GuestApcQueue {
    /// Deliver pending APCs and return them for execution by the runtime.
    ///
    /// Unlike `deliver()` which silently discards APCs, this method returns
    /// the actual APC entries so the pe_runtime can invoke the guest callbacks.
    pub fn deliver_apcs(&mut self, max_count: usize) -> Vec<ApcEntry> {
        if self.disabled {
            return Vec::new();
        }
        let mut result = Vec::with_capacity(max_count);

        // Deliver kernel-mode APCs first (higher priority)
        while result.len() < max_count {
            if let Some(apc) = self.kernel_apcs.pop_front() {
                result.push(apc);
            } else {
                break;
            }
        }

        // Then deliver user-mode APCs
        while result.len() < max_count {
            if let Some(apc) = self.user_apcs.pop_front() {
                result.push(apc);
            } else {
                break;
            }
        }

        result
    }

    /// Peek at the next pending APC without removing it.
    pub fn peek_next(&self) -> Option<&ApcEntry> {
        if self.disabled {
            return None;
        }
        if let Some(apc) = self.kernel_apcs.front() {
            Some(apc)
        } else {
            self.user_apcs.front()
        }
    }

    /// Get the count of pending APCs.
    pub fn pending_count(&self) -> usize {
        if self.disabled {
            0
        } else {
            self.kernel_apcs.len() + self.user_apcs.len()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_mutex_acquire_and_release() {
        let mutex = GuestMutex::new();
        assert!(mutex.try_acquire(1));
        assert!(!mutex.try_acquire(2)); // Thread 2 can't acquire
        assert!(mutex.release(1));
        assert!(mutex.try_acquire(2)); // Now thread 2 can
    }

    #[test]
    fn evidence_core_fiber_manager_create_switch_delete() {
        // Evidence for the CreateFiber/SwitchToFiber/DeleteFiber thunks:
        // the runtime's dispatch arms are thin wrappers over this manager,
        // so these assertions pin the guest-visible fiber semantics.
        let mut mgr = GuestFiberManager::new();
        let primary = mgr.convert_thread_to_fiber();
        assert_ne!(primary, 0);
        assert_eq!(mgr.current_fiber(), Some(primary));

        // CreateFiber allocates a real guard-page-protected stack and
        // records the guest start address + parameter.
        let fiber = mgr.create_fiber(64 * 1024, 0x0040_1000, 0xDEAD_BEEF);
        assert_ne!(fiber, 0);
        assert_ne!(fiber, primary);
        let context = mgr.get_fiber(fiber).expect("fiber context");
        assert!(context.stack_allocation.is_some(), "a stack is allocated");
        assert_eq!(context.start_address, 0x0040_1000);
        assert_eq!(context.parameter, 0xDEAD_BEEF);
        assert!(!context.is_executing);
        let stack_limit = context.stack_limit;
        let stack_base = context.stack_base;
        assert!(stack_base > stack_limit, "stack grows down from the base");

        // SwitchToFiber marks the target executing, records the previous
        // fiber, and moves the thread-local current-fiber tracker.
        let switched = mgr.switch_to(fiber).expect("switch");
        assert_eq!(switched, (primary as u32, fiber as u32));
        assert_eq!(mgr.current_fiber(), Some(fiber));
        assert!(mgr.get_fiber(fiber).expect("target").is_executing);
        assert!(!mgr.get_fiber(primary).expect("primary").is_executing);
        assert_eq!(
            mgr.get_fiber(fiber).expect("target").previous_fiber,
            Some(primary as u32),
            "the fiber records the fiber that ran before it"
        );

        // DeleteFiber removes the fiber and its stack; the deleted fiber is
        // gone from the registry and a stale switch target is refused.
        mgr.delete_fiber(fiber);
        assert!(mgr.get_fiber(fiber).is_none(), "fiber is deleted");
        assert!(mgr.switch_to(fiber).is_none(), "stale target is refused");
    }

    #[test]
    fn guest_semaphore_exceeds_max() {
        let sem = GuestSemaphore::new(0, 2);
        let _result = sem.release(2);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let _result = sem.release(1);
        assert!(_result.is_err(), "expected Err, got {_result:?}"); // Would exceed max
    }

    #[test]
    fn guest_event_manual_reset() {
        let event = GuestEvent::new(false, false); // manual reset
        assert!(!event.is_signaled());
        event.set();
        assert!(event.is_signaled());
        assert!(event.is_signaled()); // Still signaled
        event.reset();
        assert!(!event.is_signaled());
    }

    #[test]
    fn guest_event_auto_reset() {
        let event = GuestEvent::new(false, true); // auto reset
        event.set();
        assert!(event.is_signaled()); // First check consumes signal
        assert!(!event.is_signaled()); // Now not signaled
    }

    #[test]
    fn guest_init_once() {
        let init = GuestInitOnce::new();
        assert!(!init.is_completed());
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();
        init.call_once(move || {
            called_clone.store(true, Ordering::SeqCst);
        });
        assert!(init.is_completed());
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn guest_mutex_blocking_acquire() {
        use std::sync::Arc;
        use std::thread;

        let mutex = Arc::new(GuestMutex::new());
        mutex.acquire(1);

        let mutex_clone = mutex.clone();
        let acquired = Arc::new(AtomicBool::new(false));
        let acquired_clone = acquired.clone();
        let (waiting_tx, waiting_rx) = crossbeam_channel::bounded::<()>(1);

        let handle = thread::spawn(move || {
            waiting_tx.send(()).unwrap();
            mutex_clone.acquire(2);
            acquired_clone.store(true, Ordering::SeqCst);
            mutex_clone.release(2);
        });

        // The worker is committed to acquiring; while thread 1 owns the mutex
        // neither the worker nor another try_acquire can proceed. No timing
        // assumption is needed.
        waiting_rx.recv().unwrap();
        assert!(!acquired.load(Ordering::SeqCst));
        assert!(!mutex.try_acquire(3), "mutex still owned by thread 1");

        // Release from thread 1 — the worker is woken by the condvar.
        let t0 = std::time::Instant::now();
        mutex.release(1);
        handle.join().unwrap();
        assert!(acquired.load(Ordering::SeqCst));
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "mutex handoff latency too high: {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn guest_semaphore_blocking_wait() {
        use std::sync::Arc;
        use std::thread;

        let sem = Arc::new(GuestSemaphore::new(0, 5));
        let sem_clone = sem.clone();
        let waited = Arc::new(AtomicBool::new(false));
        let waited_clone = waited.clone();
        let (waiting_tx, waiting_rx) = crossbeam_channel::bounded::<()>(1);
        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);

        let handle = thread::spawn(move || {
            waiting_tx.send(()).unwrap();
            sem_clone.wait();
            waited_clone.store(true, Ordering::SeqCst);
            done_tx.send(()).unwrap();
        });

        waiting_rx.recv().unwrap();
        // No release yet: the waiter must still be blocked (negative check
        // with a bounded timeout, not a fixed tick loop).
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(!waited.load(Ordering::SeqCst));

        let t0 = std::time::Instant::now();
        sem.release(1).unwrap();
        done_rx
            .recv_timeout(Duration::from_millis(1000))
            .expect("release must wake the waiter promptly");
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "semaphore wake latency too high: {:?}",
            t0.elapsed()
        );
        handle.join().unwrap();
        assert!(waited.load(Ordering::SeqCst));
    }

    // ── Phase N tests ──────────────────────────────────────────────────────

    #[test]
    fn srwlock_exclusive_and_shared() {
        let lock = GuestSRWLock::new();
        assert!(lock.try_acquire_exclusive());
        assert!(!lock.try_acquire_shared()); // exclusive blocks shared
        lock.release_exclusive();

        assert!(lock.try_acquire_shared());
        assert!(lock.try_acquire_shared()); // multiple readers ok
        lock.release_shared();
        lock.release_shared();
    }

    #[test]
    fn condition_variable_timeout_honours_deadline() {
        let cv = GuestConditionVariable::new();
        let t0 = std::time::Instant::now();
        let woke = cv.sleep_with_polling(Some(200), || false);
        let elapsed = t0.elapsed();

        assert!(!woke, "quiet wait must report a timeout");
        assert!(
            elapsed >= Duration::from_millis(185),
            "deadline returned early: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(400),
            "deadline drifted late: {elapsed:?}"
        );
        assert!(
            cv.poll_iterations() <= 4,
            "quiet wait must be event-driven, took {} iterations",
            cv.poll_iterations()
        );
        assert_eq!(cv.wake_count(), 0, "no wake was delivered");
        assert_eq!(cv.waiter_count(), 0, "waiter must deregister");
    }

    #[test]
    fn condition_variable_quiet_wait_does_not_poll() {
        let cv = GuestConditionVariable::new();
        let pump_calls = AtomicU64::new(0);
        let woke = cv.sleep_with_polling(Some(200), || {
            pump_calls.fetch_add(1, Ordering::Relaxed);
            false
        });
        assert!(!woke);

        let iterations = cv.poll_iterations();
        let pumps = pump_calls.load(Ordering::Relaxed);
        assert!(
            iterations <= 4,
            "quiet 200 ms wait performed {iterations} iterations (interval-driven?)"
        );
        assert!(
            pumps <= 2,
            "quiet 200 ms wait pumped {pumps} times (interval-driven?)"
        );
        assert_eq!(cv.wake_count(), 0);
    }

    #[test]
    fn apc_queue_deliver_returns_entries() {
        let mut queue = GuestApcQueue::new();
        queue.queue_user_apc(0x1000, 0x2000);
        queue.queue_user_apc(0x1001, 0x2001);
        queue.queue_kernel_apc(0x3000, 0x4000);

        let apcs = queue.deliver_apcs(10);
        assert_eq!(apcs.len(), 3);
        // Kernel APC first
        assert!(apcs[0].kernel_mode);
        assert_eq!(apcs[0].callback, 0x3000);
        assert!(!apcs[1].kernel_mode);
        assert_eq!(apcs[1].callback, 0x1000);
    }

    #[test]
    fn enhanced_thread_pool_timer_delete_cancels() {
        let mut pool = EnhancedGuestThreadPool::new(1);
        pool.start();
        pool.create_timer(1, 0xBAD, 0, 60, 0);
        pool.delete_timer(1);
        assert!(
            pool.dequeue_completed_timeout(250).is_none(),
            "cancelled timer must not fire"
        );
        assert!(pool.dequeue_completed().is_none());
    }

    #[test]
    fn enhanced_thread_pool_periodic_timer_repeats_and_cancels() {
        let mut pool = EnhancedGuestThreadPool::new(1);
        pool.start();
        pool.create_timer(1, 0x777, 0, 20, 40);

        let first = pool
            .dequeue_completed_timeout(1_000)
            .expect("first period must fire");
        let second = pool
            .dequeue_completed_timeout(1_000)
            .expect("second period must fire");
        assert_eq!(first.callback, 0x777);
        assert_eq!(second.callback, 0x777);

        pool.delete_timer(1);
        assert!(
            pool.dequeue_completed_timeout(150).is_none(),
            "periodic timer must stop after delete"
        );
    }

    // ------------------------------------------------------------------
    // Concurrency stress tests (Q6)
    // ------------------------------------------------------------------

    #[test]
    fn concurrency_guest_semaphore_multi_thread() {
        let sem = Arc::new(GuestSemaphore::new(4, 10));
        let mut handles = Vec::new();
        let num_threads = 8;
        let (passed_tx, passed_rx) = crossbeam_channel::unbounded::<()>();

        for _ in 0..num_threads {
            let s = Arc::clone(&sem);
            let tx = passed_tx.clone();
            handles.push(std::thread::spawn(move || {
                s.wait();
                let _ = tx.send(());
                // Don't release – tests that wait blocks correctly
            }));
        }
        drop(passed_tx);

        // Exactly the initial count (4) gets through; the rest stay blocked.
        // Event-driven: each pass is reported over a channel, no sleep tick.
        let mut passed = 0u32;
        while passed < 4 {
            passed_rx
                .recv_timeout(Duration::from_millis(1_000))
                .expect("initial semaphore count must admit 4 waiters");
            passed += 1;
        }
        assert!(
            passed_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "more threads passed the semaphore than its initial count"
        );
        for h in handles {
            // Remaining waiters stay blocked by design; detach them.
            let _ = h;
        }
    }

    #[test]
    fn concurrency_guest_barrier_stress() {
        let num_threads: u32 = 10;
        let barrier = Arc::new(GuestBarrier::new(num_threads));
        let mut handles = Vec::with_capacity(num_threads as usize);

        for _ in 0..num_threads {
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }
        // Barrier does not deadlock = success
    }

    // ── Mutex behavior tests ───────────────────────────────────────────

    #[test]
    fn mutex_release_from_non_owner_fails() {
        let mx = GuestMutex::new();
        assert!(mx.try_acquire(1));
        assert!(!mx.release(2), "release from non-owner should fail");
        assert!(mx.release(1)); // clean up
    }

    #[test]
    fn mutex_try_acquire_fails_when_owned() {
        let mx = GuestMutex::new();
        assert!(mx.try_acquire(1));
        assert!(
            !mx.try_acquire(2),
            "try_acquire from another thread should fail"
        );
        assert!(mx.release(1));
        assert!(mx.try_acquire(2), "after release, acquire should succeed");
        assert!(mx.release(2));
    }

    #[test]
    fn mutex_blocking_acquire() {
        let mx = Arc::new(GuestMutex::new());
        mx.acquire(1);

        let (started_tx, started_rx) = crossbeam_channel::bounded::<()>(1);
        let mx2 = Arc::clone(&mx);
        let h = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            mx2.acquire(2);
            mx2.release(2);
        });

        // The worker is committed to acquiring; while thread 1 owns the mutex
        // the worker cannot proceed. Release wakes it via the condvar.
        started_rx.recv().unwrap();
        assert!(!mx.try_acquire(3), "mutex still owned by thread 1");
        let t0 = std::time::Instant::now();
        mx.release(1);
        h.join().expect("thread should complete");
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "mutex handoff latency too high: {:?}",
            t0.elapsed()
        );
    }

    // ── Event behavior tests ───────────────────────────────────────────

    #[test]
    fn event_auto_reset_clears_after_wait() {
        let ev = GuestEvent::new(false, true); // auto-reset
        ev.set();
        ev.wait(); // should not block
        // Auto-reset clears after wait
        assert!(!ev.is_signaled(), "auto-reset should clear after wait");
    }

    #[test]
    fn event_reset_clears_signaled_state() {
        let ev = GuestEvent::new(true, false); // initially signaled, manual-reset
        assert!(ev.is_signaled());
        ev.reset();
        assert!(!ev.is_signaled(), "reset should clear signaled state");
    }

    #[test]
    fn event_auto_reset_is_signaled_clears() {
        let ev = GuestEvent::new(true, true); // initially signaled, auto-reset
        // is_signaled on auto-reset consumes the signal
        assert!(ev.is_signaled(), "first check should be signaled");
        assert!(!ev.is_signaled(), "second check should not be signaled");
    }

    // ── Semaphore behavior tests ───────────────────────────────────────

    #[test]
    fn semaphore_release_exceeds_max_fails() {
        let sem = GuestSemaphore::new(2, 3);
        let result = sem.release(2);
        assert!(result.is_err(), "releasing beyond max should fail");
    }
}
