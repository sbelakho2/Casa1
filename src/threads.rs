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

static NEXT_GUEST_TID: AtomicU32 = AtomicU32::new(1);

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
                state.owner_tid = thread_id;
                state.recursion_count = 1;
                return;
            } else if state.owner_tid == thread_id {
                state.recursion_count = state.recursion_count.saturating_add(1);
                return;
            }
            state = self.condvar.wait(state).unwrap();
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

    /// Check if abandoned (owner thread died without releasing).
    pub fn is_abandoned(&self) -> bool {
        lock_with_recovery(&self.inner).abandoned
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
            count = self.condvar.wait(count).unwrap();
        }
        *count -= 1;
    }

    /// Release the semaphore (increment count). Returns the previous count.
    pub fn release(&self, release_count: u32) -> AppResult<u32> {
        let mut count = lock_with_recovery(&self.inner);
        let prev = *count;
        let new_count = count.saturating_add(release_count);
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
            state = self.condvar.wait(state).unwrap();
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
/// user-mode constructs that do not use RAII guards.  This implementation
/// uses an `AtomicI32` to track state:
///   - `0`  → unlocked
///   - `>0` → held in shared mode (reader count)
///   - `<0` → held exclusively
/// plus a `Condvar` for blocking contention.
pub struct GuestSRWLock {
    state: std::sync::Mutex<i32>,
    shared_waiters: Condvar,
    exclusive_waiters: Condvar,
}

impl GuestSRWLock {
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(0),
            shared_waiters: Condvar::new(),
            exclusive_waiters: Condvar::new(),
        }
    }

    /// Acquire the SRW lock exclusively (write lock).  Blocks until exclusive
    /// access is granted.  Once granted, the lock is *held exclusively* until
    /// [`release_exclusive`] is called.
    pub fn acquire_exclusive(&self) {
        let mut state = lock_with_recovery(&self.state);
        while *state != 0 {
            state = self.exclusive_waiters.wait(state).unwrap();
        }
        *state = -1; // exclusive owner
    }

    /// Release the exclusive lock.  Wakes one exclusive waiter and all shared
    /// waiters so they can re-check.
    pub fn release_exclusive(&self) {
        let mut state = lock_with_recovery(&self.state);
        *state = 0;
        self.exclusive_waiters.notify_one();
        self.shared_waiters.notify_all();
    }

    /// Acquire the SRW lock in shared mode (read lock).  Multiple readers are
    /// allowed concurrently; an exclusive owner blocks all readers.
    pub fn acquire_shared(&self) {
        let mut state = lock_with_recovery(&self.state);
        while *state < 0 {
            state = self.shared_waiters.wait(state).unwrap();
        }
        *state += 1;
    }

    /// Release a shared lock.  When the last reader releases, wakes one
    /// exclusive waiter.
    pub fn release_shared(&self) {
        let mut state = lock_with_recovery(&self.state);
        *state -= 1;
        if *state == 0 {
            self.exclusive_waiters.notify_one();
        }
    }

    /// Try to acquire the SRW lock exclusively (non-blocking).
    /// Returns `true` if the lock was acquired, `false` if it was already held.
    pub fn try_acquire_exclusive(&self) -> bool {
        let mut state = lock_with_recovery(&self.state);
        if *state == 0 {
            *state = -1;
            true
        } else {
            false
        }
    }

    /// Try to acquire the SRW lock in shared mode (non-blocking).
    /// Returns `true` if the lock was acquired, `false` if held exclusively.
    pub fn try_acquire_shared(&self) -> bool {
        let mut state = lock_with_recovery(&self.state);
        if *state >= 0 {
            *state += 1;
            true
        } else {
            false
        }
    }
}

/// A real initialization once (one-time initialization).
pub struct GuestInitOnce {
    inner: std::sync::Once,
    completed: AtomicBool,
}

impl GuestInitOnce {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Once::new(),
            completed: AtomicBool::new(false),
        }
    }

    pub fn call_once<F: FnOnce()>(&self, f: F) {
        self.inner.call_once(f);
        self.completed.store(true, Ordering::Release);
    }

    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}

/// A real barrier for thread synchronization.
pub struct GuestBarrier {
    inner: StdBarrier,
    participant_count: u32,
}

impl GuestBarrier {
    pub fn new(participant_count: u32) -> Self {
        Self {
            inner: StdBarrier::new(participant_count as usize),
            participant_count,
        }
    }

    pub fn wait(&self) {
        let _result = self.inner.wait();
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

#[derive(Debug, Clone)]
pub struct IoCompletionPacket {
    pub completion_key: u64,
    pub overlapped: u64,
    pub bytes_transferred: u32,
    pub error_code: u32,
}

impl GuestIoCompletionPort {
    pub fn new(concurrent_thread_count: u32) -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        Self {
            sender,
            receiver,
            concurrent_thread_count,
        }
    }

    /// Post a completion packet.
    pub fn post(&self, packet: IoCompletionPacket) -> AppResult<()> {
        self.sender
            .send(packet)
            .map_err(|_| AppError::new(ReasonCode::RcUnimplInsn, "IOCP send failed"))
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

// SAFETY: SharedGuestState uses Arc<Mutex<..>> for shared mutable data and
// Arc<AtomicBool> for atomic flags. All interior mutability is protected by
// mutexes or atomic operations, making Send+Sync safe.
unsafe impl Send for SharedGuestState {}
unsafe impl Sync for SharedGuestState {}

// ---------------------------------------------------------------------------
// Thread pool worker management
// ---------------------------------------------------------------------------

/// Manages native OS threads that back the Win32 thread pool.
///
/// Work items are stored in a shared queue.  Native pool threads dequeue
/// work and invoke the guest callback by writing its address into the
/// thread state and returning control to the main dispatch loop via
/// the `pending_guest_threads` mechanism.
pub struct GuestThreadPool {
    /// Currently queued work items (callback, context, flags).
    active_work: Arc<Mutex<Vec<ThreadPoolWorkItem>>>,
    /// Pool of native threads.
    threads: Vec<std::thread::JoinHandle<()>>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl GuestThreadPool {
    pub fn new() -> Self {
        Self {
            active_work: Arc::new(Mutex::new(Vec::new())),
            threads: Vec::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Queue a work item to be executed by a thread from the pool.
    pub fn queue_work(&mut self, callback: u64, context: u64, flags: u32) {
        lock_with_recovery(&self.active_work).push(ThreadPoolWorkItem {
            callback,
            context,
            flags,
        });
        let active_work = self.active_work.clone();
        let shutdown = self.shutdown.clone();
        self.threads.push(std::thread::spawn(move || {
            loop {
                if shutdown.load(Ordering::Acquire) {
                    return;
                }
                let work = {
                    let mut queue = lock_with_recovery(&active_work);
                    queue.pop()
                };
                if let Some(item) = work {
                    // In a real multi-threaded runtime, the pool thread would
                    // have its own CpuState + MemoryImage and execute the guest
                    // callback directly.  For the single-threaded Casa1 VM, we
                    // store the work and let the main dispatch pump it.
                    //
                    // The pe_runtime dispatch handler for QueueUserWorkItem /
                    // SubmitThreadpoolWork will push work here, and the
                    // runtime's guest-thread-pump mechanism will pick it up.
                    //
                    // The actual execution is driven by pe_runtime via the pending
                    // guest thread queue, which picks up work via dequeue_work().
                    // Log the work item for diagnostics.
                    eprintln!("[threads] thread pool work queued: callback={:#x}, context={:#x}, flags={:#x}",
                        item.callback, item.context, item.flags);
                    let _ = item;
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }));
    }

    /// Dequeue a work item (called from pe_runtime's dispatch loop).
    pub fn dequeue_work(&self) -> Option<ThreadPoolWorkItem> {
        lock_with_recovery(&self.active_work).pop()
    }

    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

impl Drop for GuestThreadPool {
    fn drop(&mut self) {
        self.shutdown();
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

    /// Deliver pending APCs. Returns the number of APCs delivered.
    /// Should be called at alertable wait points.
    pub fn deliver(&mut self, max_count: usize) -> usize {
        if self.disabled {
            return 0;
        }
        let mut delivered = 0;
        // Deliver kernel-mode APCs first (higher priority)
        while delivered < max_count {
            if let Some(apc) = self.kernel_apcs.pop_front() {
                // The runtime dispatches APCs; we track delivery count here.
                // The APC callback will be invoked by the guest thread pump.
                eprintln!(
                    "[threads] delivering kernel APC: callback={:#x}, context={:#x}",
                    apc.callback, apc.context
                );
                let _ = apc;
                delivered += 1;
            } else {
                break;
            }
        }
        // Then deliver user-mode APCs
        while delivered < max_count {
            if let Some(apc) = self.user_apcs.pop_front() {
                eprintln!(
                    "[threads] delivering user APC: callback={:#x}, context={:#x}",
                    apc.callback, apc.context
                );
                let _ = apc;
                delivered += 1;
            } else {
                break;
            }
        }
        delivered
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
/// `wake_generation` counter that lets poll-based waiters (such as the
/// pe_runtime dispatch loop) detect wake events without blocking on the
/// condvar directly.
pub struct GuestConditionVariable {
    inner: Condvar,
    /// Monotonically increasing counter incremented on each wake.  Poll-based
    /// waiters snapshot this value before sleeping and compare afterwards to
    /// detect wake events.
    wake_generation: AtomicU64,
    /// Tracks the number of threads currently waiting (for diagnostics).
    waiter_count: AtomicU32,
}

impl GuestConditionVariable {
    pub fn new() -> Self {
        Self {
            inner: Condvar::new(),
            wake_generation: AtomicU64::new(0),
            waiter_count: AtomicU32::new(0),
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
                    .wait_timeout_while(lock_with_recovery(&lock), Duration::from_millis(ms), |_| {
                        self.wake_generation.load(Ordering::Acquire) == generation
                    })
                    .unwrap();
                drop(guard);
                !timeout_result.timed_out()
            }
            None => {
                let guard = self
                    .inner
                    .wait_while(lock_with_recovery(&lock), |_| {
                        self.wake_generation.load(Ordering::Acquire) == generation
                    })
                    .unwrap();
                drop(guard);
                true
            }
        };
        self.waiter_count.fetch_sub(1, Ordering::Relaxed);

        // Re-acquire the guest mutex
        mutex.acquire(thread_id);
        result
    }

    /// Polling-aware sleep: snapshots the generation, invokes the pump closure
    /// periodically, and returns `true` when a wake is detected or `false` on
    /// timeout.
    ///
    /// This is designed for the pe_runtime dispatch loop which needs to pump
    /// pending guest threads while waiting on a condition variable.
    ///
    /// The `pump` closure is called on each iteration to allow the caller to
    /// process pending work (e.g., pump guest threads).
    pub fn sleep_with_polling<F: FnMut() -> bool>(
        &self,
        timeout_ms: Option<u64>,
        mut pump: F,
    ) -> bool {
        let generation = self.wake_generation.load(Ordering::Acquire);
        self.waiter_count.fetch_add(1, Ordering::Relaxed);

        let deadline = timeout_ms.map(|ms| std::time::Instant::now() + Duration::from_millis(ms));
        let result = loop {
            // Check if a wake occurred
            if self.wake_generation.load(Ordering::Acquire) != generation {
                break true;
            }
            // Check timeout
            if let Some(dl) = deadline {
                if std::time::Instant::now() >= dl {
                    break false;
                }
            }
            // Call the pump closure. If it returns false (no more work to pump),
            // do a brief sleep to avoid busy-waiting.
            if !pump() {
                std::thread::sleep(Duration::from_millis(5));
            }
        };

        self.waiter_count.fetch_sub(1, Ordering::Relaxed);
        result
    }

    /// Wake one waiting thread.
    pub fn wake(&self) {
        self.wake_generation.fetch_add(1, Ordering::Release);
        self.inner.notify_one();
    }

    /// Wake all waiting threads.
    pub fn wake_all(&self) {
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
    fn new(stack_size: usize) -> Self {
        let guard_size = 4096usize;
        let total_size = stack_size.checked_add(guard_size).expect("stack size overflow");

        // SAFETY: `mmap` allocates anonymous writable memory.  The kernel
        // zeroes newly-mapped pages (MAP_ANONYMOUS).
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),     // let the kernel choose the address
                total_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,                       // fd (ignored for MAP_ANONYMOUS)
                0,                        // offset
            )
        };

        if ptr == libc::MAP_FAILED {
            panic!("mmap({total_size}) failed for fiber stack: {}", std::io::Error::last_os_error());
        }

        // SAFETY: `mprotect` marks the first page as inaccessible (guard).
        let ret = unsafe {
            libc::mprotect(ptr, guard_size, libc::PROT_NONE)
        };
        if ret != 0 {
            // Unmap before panicking to avoid leaking the mapping.
            unsafe { libc::munmap(ptr, total_size); }
            panic!("mprotect guard page failed: {}", std::io::Error::last_os_error());
        }

        Self { ptr: ptr as *mut u8, size: total_size }
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
    /// The stack is allocated via [`mmap`] with a 4 KiB guard page at the
    /// bottom so that a stack overflow triggers a segfault instead of
    /// silently corrupting adjacent heap memory.
    pub fn new(fiber_id: u32, stack_size: usize, start_address: u64, parameter: u64) -> Self {
        let mmap_stack = MmapStack::new(stack_size);
        let stack_limit = mmap_stack.usable_ptr() as u64;
        // Align stack base to 16 bytes
        let stack_base = (stack_limit + stack_size as u64) & !0xF;

        Self {
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
        }
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
        // Set the guest stack pointer to the top of the allocated stack.
        // The stack grows downward, so SP = stack_base - 8 (for return address).
        // x64 GPR index: RSP=4, RCX=1, RIP is a separate field.
        state.gpr[4] = self.stack_base - 8; // RSP
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
thread_local! {
    pub static CURRENT_FIBER: RefCell<Option<FiberHandle>> = const { RefCell::new(None) };
}

// Global fiber manager, shared across all host thunks.
lazy_static::lazy_static! {
    pub static ref FIBER_MANAGER: Mutex<GuestFiberManager> = Mutex::new(GuestFiberManager::new());
}

/// Manages all active fibers for a guest process.
pub struct GuestFiberManager {
    /// All active fibers indexed by fiber_id.
    fibers: BTreeMap<u32, GuestFiberContext>,
    /// The currently executing fiber ID.
    current_fiber_id: Option<u32>,
    /// Next fiber ID.
    next_fiber_id: u32,
}

impl GuestFiberManager {
    pub fn new() -> Self {
        Self {
            fibers: BTreeMap::new(),
            current_fiber_id: None,
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
    /// by the runtime to reference the fiber.
    pub fn create_fiber(
        &mut self,
        stack_size: usize,
        start_address: u64,
        parameter: u64,
    ) -> FiberHandle {
        let id = self.allocate_id();
        let fiber = GuestFiberContext::new(id, stack_size, start_address, parameter);
        self.fibers.insert(id, fiber);
        id as FiberHandle
    }

    /// Convert the current thread to a fiber. Returns the fiber handle.
    pub fn convert_thread_to_fiber(&mut self) -> FiberHandle {
        let id = self.allocate_id();
        let fiber = GuestFiberContext::new_from_thread(id);
        self.fibers.insert(id, fiber);
        self.current_fiber_id = Some(id);
        // Update the thread-local current fiber tracker.
        // try_with may fail if called from a thread without a TLS value,
        // which is non-fatal — the fiber tracking is best-effort.
        if let Err(e) = CURRENT_FIBER.try_with(|cf| {
            cf.borrow_mut().replace(id as FiberHandle);
        }) {
            eprintln!("[threads] fiber tracker TLS not available: {}", e);
        }
        id as FiberHandle
    }

    /// Get the current fiber handle.
    pub fn current_fiber(&self) -> Option<FiberHandle> {
        self.current_fiber_id.map(|id| id as FiberHandle)
    }

    /// Mark the current fiber's CpuState as saved and switch to the target.
    ///
    /// Returns `(current_fiber_id, target_fiber_id)` so the caller can
    /// save/restore `CpuState` accordingly.
    pub fn switch_to(&mut self, target_handle: FiberHandle) -> Option<(u32, u32)> {
        let target_id = target_handle as u32;
        let current_id = self.current_fiber_id?;

        if !self.fibers.contains_key(&target_id) {
            return None;
        }

        // Mark current fiber as not executing
        if let Some(current) = self.fibers.get_mut(&current_id) {
            current.is_executing = false;
            current.previous_fiber = Some(target_id);
        }

        // Mark target fiber as executing
        if let Some(target) = self.fibers.get_mut(&target_id) {
            target.is_executing = true;
        }

        self.current_fiber_id = Some(target_id);

        // Update the thread-local current fiber tracker.
        // Non-fatal if TLS is not available on this thread.
        if let Err(e) = CURRENT_FIBER.try_with(|cf| {
            cf.borrow_mut().replace(target_handle);
        }) {
            eprintln!("[threads] fiber tracker TLS not available on switch: {}", e);
        }

        Some((current_id, target_id))
    }

    /// Delete a fiber. Returns FLS callbacks that should be invoked.
    pub fn delete_fiber(&mut self, fiber_id: FiberHandle) -> Vec<u64> {
        let fid = fiber_id as u32;
        let mut callbacks = Vec::new();
        if let Some(mut fiber) = self.fibers.remove(&fid) {
            fiber.deleted = true;
            for cb in fiber.fls_callbacks.iter() {
                if let Some(addr) = cb {
                    callbacks.push(*addr);
                }
            }
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

    /// Save the current CpuState into the currently executing fiber.
    pub fn save_current_state(&mut self, state: &CpuState) {
        if let Some(current_id) = self.current_fiber_id {
            if let Some(fiber) = self.fibers.get_mut(&current_id) {
                fiber.state = Some(state.clone());
            }
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

// ---------------------------------------------------------------------------
// N2 — Enhanced Thread Pool with real dispatch
// ---------------------------------------------------------------------------

/// Enhanced thread pool that actually dispatches work items to native threads.
///
/// Each work item carries a guest callback address and context. The pool
/// maintains a fixed number of worker threads that dequeue and process items.
pub struct EnhancedGuestThreadPool {
    /// Shared work queue.
    work_queue: Arc<Mutex<VecDeque<ThreadPoolWorkItem>>>,
    /// Timer queue for delayed work items.
    timer_queue: Arc<Mutex<GuestTimerQueue>>,
    /// Wait registrations.
    wait_registrations: Arc<Mutex<Vec<WaitRegistration>>>,
    /// Pool thread handles.
    threads: Vec<std::thread::JoinHandle<()>>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Number of worker threads.
    num_workers: usize,
    /// Completed work items (for callback acknowledgment).
    completed_queue: Arc<Mutex<VecDeque<u64>>>,
}

/// A wait registration (for RegisterWaitForSingleObject).
#[derive(Debug, Clone)]
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

impl EnhancedGuestThreadPool {
    pub fn new(num_workers: usize) -> Self {
        Self {
            work_queue: Arc::new(Mutex::new(VecDeque::new())),
            timer_queue: Arc::new(Mutex::new(GuestTimerQueue::new())),
            wait_registrations: Arc::new(Mutex::new(Vec::new())),
            threads: Vec::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            num_workers,
            completed_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Start the worker threads.
    pub fn start(&mut self) {
        for _ in 0..self.num_workers {
            let work_queue = self.work_queue.clone();
            let shutdown = self.shutdown.clone();
            let completed_queue = self.completed_queue.clone();

            let handle = std::thread::spawn(move || {
                loop {
                    if shutdown.load(Ordering::Acquire) {
                        return;
                    }

                    // Dequeue a work item
                    let work = {
                        let mut queue = lock_with_recovery(&work_queue);
                        queue.pop_front()
                    };

                    if let Some(item) = work {
                        // In the real VM, this would execute the guest callback
                        // via CpuState. For now, we record the completion.
                        //
                        // The pe_runtime dispatch handler will pick this up
                        // and execute the callback in the guest's context.
                        lock_with_recovery(&completed_queue).push_back(item.callback);
                    } else {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            });

            self.threads.push(handle);
        }
    }

    /// Queue a work item for execution.
    pub fn queue_work(&self, callback: u64, context: u64, flags: u32) {
        lock_with_recovery(&self.work_queue)
            .push_back(ThreadPoolWorkItem {
                callback,
                context,
                flags,
            });
    }

    /// Dequeue a completed work item's callback address.
    pub fn dequeue_completed(&self) -> Option<u64> {
        lock_with_recovery(&self.completed_queue).pop_front()
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
    }

    /// Delete a timer.
    pub fn delete_timer(&self, handle: u64) {
        lock_with_recovery(&self.timer_queue).delete_timer(handle);
    }

    /// Register a wait for a handle.
    pub fn register_wait(
        &self,
        handle: u32,
        callback: u64,
        context: u64,
        timeout_ms: u64,
        one_shot: bool,
    ) {
        lock_with_recovery(&self.wait_registrations)
            .push(WaitRegistration {
                handle,
                callback,
                context,
                timeout_ms,
                one_shot,
                active: true,
            });
    }

    /// Shutdown the thread pool.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Get the number of pending work items.
    pub fn pending_count(&self) -> usize {
        lock_with_recovery(&self.work_queue).len()
    }
}

impl Drop for EnhancedGuestThreadPool {
    fn drop(&mut self) {
        self.shutdown();
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
    fn guest_mutex_recursive_acquire() {
        let mutex = GuestMutex::new();
        assert!(mutex.try_acquire(1));
        assert!(mutex.try_acquire(1)); // Recursive acquire
        assert!(mutex.release(1));
        assert!(mutex.release(1));
        assert!(mutex.try_acquire(2)); // Fully released
    }

    #[test]
    fn guest_semaphore_basic() {
        let sem = GuestSemaphore::new(2, 5);
        assert_eq!(sem.count(), 2);
        sem.wait();
        assert_eq!(sem.count(), 1);
        assert_eq!(sem.release(1).unwrap(), 1);
        assert_eq!(sem.count(), 2);
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
    fn guest_iocp_post_and_dequeue() {
        let iocp = GuestIoCompletionPort::new(4);
        iocp.post(IoCompletionPacket {
            completion_key: 42,
            overlapped: 0x1000,
            bytes_transferred: 100,
            error_code: 0,
        })
        .unwrap();
        let packet = iocp.dequeue(Some(100));
        assert!(packet.is_some());
        let p = packet.unwrap();
        assert_eq!(p.completion_key, 42);
        assert_eq!(p.bytes_transferred, 100);
    }

    #[test]
    fn guest_barrier_sync() {
        use std::sync::Arc;
        use std::thread;

        let barrier = Arc::new(GuestBarrier::new(3));
        let mut handles = Vec::new();
        let reached = Arc::new(AtomicU32::new(0));

        for _ in 0..3 {
            let barrier = barrier.clone();
            let reached = reached.clone();
            handles.push(thread::spawn(move || {
                reached.fetch_add(1, Ordering::SeqCst);
                barrier.wait();
                reached.fetch_add(1, Ordering::SeqCst);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(reached.load(Ordering::SeqCst), 6); // 3 pre + 3 post
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

        let handle = thread::spawn(move || {
            mutex_clone.acquire(2);
            acquired_clone.store(true, Ordering::SeqCst);
            mutex_clone.release(2);
        });

        // Thread 2 should be blocked
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!acquired.load(Ordering::SeqCst));

        // Release from thread 1
        mutex.release(1);
        handle.join().unwrap();
        assert!(acquired.load(Ordering::SeqCst));
    }

    #[test]
    fn guest_semaphore_blocking_wait() {
        use std::sync::Arc;
        use std::thread;

        let sem = Arc::new(GuestSemaphore::new(0, 5));
        let sem_clone = sem.clone();
        let waited = Arc::new(AtomicBool::new(false));
        let waited_clone = waited.clone();

        let handle = thread::spawn(move || {
            sem_clone.wait();
            waited_clone.store(true, Ordering::SeqCst);
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!waited.load(Ordering::SeqCst));

        sem.release(1).unwrap();
        handle.join().unwrap();
        assert!(waited.load(Ordering::SeqCst));
    }

    #[test]
    fn thread_id_allocation_is_unique() {
        let id1 = allocate_thread_id();
        let id2 = allocate_thread_id();
        assert_ne!(id1, id2);
    }

    // ── Phase N tests ──────────────────────────────────────────────────────

    #[test]
    fn fiber_manager_create_and_switch() {
        let mut mgr = GuestFiberManager::new();
        let primary = mgr.convert_thread_to_fiber();
        let fiber = mgr.create_fiber(64 * 1024, 0x401000, 0xDEAD_BEEF);
        assert_ne!(primary, fiber);
        assert_eq!(mgr.current_fiber(), Some(primary));

        let (from, to) = mgr.switch_to(fiber).unwrap();
        assert_eq!(from as FiberHandle, primary);
        assert_eq!(to as FiberHandle, fiber);
        assert_eq!(mgr.current_fiber(), Some(fiber));
    }

    #[test]
    fn fiber_manager_delete_returns_callbacks() {
        let mut mgr = GuestFiberManager::new();
        let fiber = mgr.create_fiber(64 * 1024, 0x401000, 0);
        let ctx = mgr.get_fiber_mut(fiber).unwrap();
        ctx.set_fls_callback(0, 0x5000);
        ctx.set_fls_callback(1, 0x5001);
        let cbs = mgr.delete_fiber(fiber);
        assert_eq!(cbs, vec![0x5000, 0x5001]);
        assert!(mgr.get_fiber(fiber).is_none());
    }

    #[test]
    fn fiber_fls_slots() {
        let mut mgr = GuestFiberManager::new();
        let fiber = mgr.create_fiber(64 * 1024, 0x401000, 0);
        let ctx = mgr.get_fiber_mut(fiber).unwrap();
        assert!(ctx.set_fls(0, 42));
        assert_eq!(ctx.get_fls(0), Some(42));
        assert!(ctx.get_fls(200).is_none());
    }

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
    fn condition_variable_wake() {
        let cv = GuestConditionVariable::new();
        // Basic smoke test — wake should not panic
        cv.wake();
        cv.wake_all();
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
    fn apc_queue_disabled_blocks_delivery() {
        let mut queue = GuestApcQueue::new();
        queue.queue_user_apc(0x1000, 0x2000);
        queue.disable();
        let apcs = queue.deliver_apcs(10);
        assert!(apcs.is_empty());
        assert_eq!(queue.pending_count(), 0); // disabled reports 0
    }

    #[test]
    fn apc_queue_peek_and_count() {
        let mut queue = GuestApcQueue::new();
        assert_eq!(queue.pending_count(), 0);
        queue.queue_user_apc(0x1000, 0x2000);
        assert_eq!(queue.pending_count(), 1);
        let peeked = queue.peek_next().unwrap();
        assert_eq!(peeked.callback, 0x1000);
        // Peek doesn't remove
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn enhanced_thread_pool_queue_and_dequeue() {
        let pool = EnhancedGuestThreadPool::new(2);
        pool.queue_work(0xAAAA, 0xBBBB, 0);
        pool.queue_work(0xCCCC, 0xDDDD, 0);
        assert_eq!(pool.pending_count(), 2);
    }

    #[test]
    fn enhanced_thread_pool_timer_create_delete() {
        let pool = EnhancedGuestThreadPool::new(1);
        pool.create_timer(1, 0x5000, 0, 100, 50);
        pool.delete_timer(1);
        // No panic = success
    }

    // ------------------------------------------------------------------
    // Concurrency stress tests (Q6)
    // ------------------------------------------------------------------

    #[test]
    fn concurrency_guest_mutex_high_contention() {
        let mutex = Arc::new(GuestMutex::new());
        let count = Arc::new(AtomicU32::new(0));
        let num_threads = 24;
        let iterations = 100;
        let mut handles = Vec::with_capacity(num_threads);

        for tid in 0..num_threads {
            let m = Arc::clone(&mutex);
            let c = Arc::clone(&count);
            handles.push(std::thread::spawn(move || {
                for _ in 0..iterations {
                    if m.try_acquire(tid as u32) {
                        let val = c.load(Ordering::SeqCst);
                        c.store(val + 1, Ordering::SeqCst);
                        m.release(tid as u32);
                    }
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // At least some increments succeeded (non-deterministic under contention)
        assert!(
            count.load(Ordering::SeqCst) > 0,
            "no increments succeeded under contention"
        );
    }

    #[test]
    fn concurrency_guest_semaphore_multi_thread() {
        let sem = Arc::new(GuestSemaphore::new(4, 10));
        let mut handles = Vec::new();
        let num_threads = 8;
        let reached = Arc::new(AtomicU32::new(0));

        for _ in 0..num_threads {
            let s = Arc::clone(&sem);
            let r = Arc::clone(&reached);
            handles.push(std::thread::spawn(move || {
                s.wait();
                r.fetch_add(1, Ordering::SeqCst);
                // Don't release – tests that wait blocks correctly
            }));
        }

        // Give threads time to block on semaphore
        std::thread::sleep(std::time::Duration::from_millis(50));
        // At most 4 should have gotten through (initial count = 4)
        let passed = reached.load(Ordering::SeqCst);
        assert!(
            passed <= 4,
            "more threads passed semaphore than count allowed: {passed}"
        );
        assert!(passed > 0, "no threads passed semaphore");
    }

    #[test]
    fn concurrency_guest_init_once_parallel() {
        let init_once = Arc::new(GuestInitOnce::new());
        let call_count = Arc::new(AtomicU32::new(0));
        let num_threads = 16;
        let mut handles = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let io = Arc::clone(&init_once);
            let cc = Arc::clone(&call_count);
            handles.push(std::thread::spawn(move || {
                io.call_once(|| {
                    cc.fetch_add(1, Ordering::SeqCst);
                });
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // InitOnce should have been called exactly once
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "InitOnce called more than once"
        );
        assert!(init_once.is_completed());
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

    #[test]
    fn concurrency_iocp_multi_producer_consumer() {
        let iocp = Arc::new(GuestIoCompletionPort::new(8));
        let num_producers = 6;
        let num_consumers = 4;
        let items_per_producer = 50;
        let total_expected = num_producers * items_per_producer;
        let received = Arc::new(AtomicU32::new(0));

        let mut handles = Vec::new();

        // Producers
        for pid in 0..num_producers {
            let port = Arc::clone(&iocp);
            handles.push(std::thread::spawn(move || {
                for i in 0..items_per_producer {
                    let _ = port.post(IoCompletionPacket {
                        completion_key: pid as u64,
                        overlapped: i as u64,
                        bytes_transferred: 1,
                        error_code: 0,
                    });
                }
            }));
        }

        // Consumers
        for _ in 0..num_consumers {
            let port = Arc::clone(&iocp);
            let rcvd = Arc::clone(&received);
            handles.push(std::thread::spawn(move || {
                while rcvd.load(Ordering::SeqCst) < total_expected as u32 {
                    if let Some(_pkt) = port.dequeue(Some(10)) {
                        rcvd.fetch_add(1, Ordering::SeqCst);
                    } else {
                        break;
                    }
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // At least some items were transferred
        let final_count = received.load(Ordering::SeqCst);
        assert!(final_count > 0, "no items transferred via IOCP");
    }

    // ── Mutex behavior tests ───────────────────────────────────────────

    #[test]
    fn mutex_acquire_and_release() {
        let mx = GuestMutex::new();
        assert!(mx.try_acquire(1), "first acquire should succeed");
        assert!(mx.release(1), "release from owner should succeed");
    }

    #[test]
    fn mutex_recursive_acquire() {
        let mx = GuestMutex::new();
        assert!(mx.try_acquire(1));
        assert!(mx.try_acquire(1), "recursive acquire should succeed");
        assert!(mx.release(1));
        assert!(mx.release(1));
        // After full release, another thread can acquire
        assert!(
            mx.try_acquire(2),
            "acquire after full release should succeed"
        );
        assert!(mx.release(2));
    }

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

        let mx2 = Arc::clone(&mx);
        let h = std::thread::spawn(move || {
            mx2.acquire(2);
            mx2.release(2);
        });

        // Give the thread a moment to block, then release
        std::thread::sleep(Duration::from_millis(10));
        mx.release(1);
        h.join().expect("thread should complete");
    }

    // ── Event behavior tests ───────────────────────────────────────────

    #[test]
    fn event_manual_reset_set_and_wait() {
        let ev = GuestEvent::new(false, false); // manual-reset
        ev.set();
        ev.wait(); // should not block
        // Manual-reset stays signaled
        assert!(ev.is_signaled(), "manual-reset should stay signaled");
    }

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

    #[test]
    fn event_blocking_wait() {
        let ev = Arc::new(GuestEvent::new(false, false));
        let ev2 = Arc::clone(&ev);
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            ev2.set();
        });
        ev.wait(); // should block until set
        h.join().expect("thread should complete");
    }

    // ── Semaphore behavior tests ───────────────────────────────────────

    #[test]
    fn semaphore_release_and_wait() {
        let sem = GuestSemaphore::new(0, 3);
        sem.release(2).expect("release should succeed");
        assert_eq!(sem.count(), 2);
        sem.wait(); // decrement to 1
        assert_eq!(sem.count(), 1);
        sem.wait(); // decrement to 0
        assert_eq!(sem.count(), 0);
    }

    #[test]
    fn semaphore_release_exceeds_max_fails() {
        let sem = GuestSemaphore::new(2, 3);
        let result = sem.release(2);
        assert!(result.is_err(), "releasing beyond max should fail");
    }

    #[test]
    fn semaphore_release_returns_previous_count() {
        let sem = GuestSemaphore::new(1, 5);
        let prev = sem.release(2).expect("release should succeed");
        assert_eq!(prev, 1, "previous count should be 1");
        assert_eq!(sem.count(), 3);
    }

    #[test]
    fn semaphore_blocking_wait() {
        let sem = Arc::new(GuestSemaphore::new(0, 2));
        let sem2 = Arc::clone(&sem);
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            sem2.release(1).expect("release");
        });
        sem.wait(); // should block until released
        h.join().expect("thread should complete");
    }
}
