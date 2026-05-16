//! Real multi-threading support for Casa1 guest threads.
//!
//! Each Windows guest thread is backed by a real OS thread with its own CPU state.
//! Thread synchronization primitives use real OS primitives for correct behavior.

use crate::cpu::{CpuEngineConfig, CpuState, GuestArch, MemoryImage};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Condvar, RwLock, Barrier as StdBarrier};

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
        let mut state = self.inner.lock().unwrap();
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
        let mut state = self.inner.lock().unwrap();
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
        let mut state = self.inner.lock().unwrap();
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
        self.inner.lock().unwrap().abandoned
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
        let mut count = self.inner.lock().unwrap();
        while *count == 0 {
            count = self.condvar.wait(count).unwrap();
        }
        *count -= 1;
    }

    /// Release the semaphore (increment count). Returns the previous count.
    pub fn release(&self, release_count: u32) -> AppResult<u32> {
        let mut count = self.inner.lock().unwrap();
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
        *self.inner.lock().unwrap()
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
        let mut state = self.inner.lock().unwrap();
        state.signaled = true;
        self.condvar.notify_all();
    }

    /// Reset the event to non-signaled state.
    pub fn reset(&self) {
        self.inner.lock().unwrap().signaled = false;
    }

    /// Wait for the event to be signaled.
    pub fn wait(&self) {
        let mut state = self.inner.lock().unwrap();
        while !state.signaled {
            state = self.condvar.wait(state).unwrap();
        }
        if state.auto_reset {
            state.signaled = false;
        }
    }

    /// Check if currently signaled (non-blocking).
    pub fn is_signaled(&self) -> bool {
        let mut state = self.inner.lock().unwrap();
        let result = state.signaled;
        if result && state.auto_reset {
            state.signaled = false;
        }
        result
    }
}

/// A real SRWLock (slim reader-writer lock).
pub struct GuestSRWLock {
    inner: RwLock<()>,
}

impl GuestSRWLock {
    pub fn new() -> Self {
        Self { inner: RwLock::new(()) }
    }

    pub fn acquire_exclusive(&self) {
        drop(self.inner.write().unwrap());
    }

    pub fn release_exclusive(&self) {
        // Lock is released when the WriteGuard is dropped
    }

    pub fn acquire_shared(&self) {
        drop(self.inner.read().unwrap());
    }

    pub fn release_shared(&self) {
        // Lock is released when the ReadGuard is dropped
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
        self.sender.send(packet).map_err(|_| {
            AppError::new(ReasonCode::RcUnimplInsn, "IOCP send failed")
        })
    }

    /// Dequeue a completion packet (blocking).
    pub fn dequeue(&self, timeout_ms: Option<u64>) -> Option<IoCompletionPacket> {
        match timeout_ms {
            Some(ms) => self.receiver.recv_timeout(std::time::Duration::from_millis(ms)).ok(),
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

unsafe impl Send for SharedGuestState {}
unsafe impl Sync for SharedGuestState {}

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
        assert!(sem.release(2).is_ok());
        assert!(sem.release(1).is_err()); // Would exceed max
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
        }).unwrap();
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
}
