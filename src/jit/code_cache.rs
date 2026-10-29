#![allow(unused_imports)]

use super::*;
use crate::cpu::{
    ConditionCode, CpuState, GuestArch, GuestMemoryFault, GuestMemoryStore, IrInstruction,
    MemoryImage, Register,
};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

// ---------------------------------------------------------------------------
// SIGBUS handler for on-demand guest memory page sync during JIT execution
// ---------------------------------------------------------------------------

/// Stored as raw pointers for signal-safe access from the SIGBUS handler.
///
/// # Lifetime Safety Protocol
/// These pointers are set with `Ordering::Release` by
/// [`JitRuntime::install_sigbus_handler`] before JIT execution begins, and
/// cleared (set to null) with `Ordering::Release` by
/// [`JitRuntime::remove_sigbus_handler`] after execution completes.
///
/// Additionally, [`JitRuntime::Drop`] calls `remove_sigbus_handler_session`,
/// ensuring the pointers are nullified before the `JitRuntime` is dropped.
/// This prevents the SIGBUS handler from dereferencing a dangling pointer
/// after the runtime has been freed. The handler loads with `Ordering::Acquire`
/// and checks for null before dereferencing, so a null value is always safe.
///
/// The `MemoryImage` pointer is similarly cleared in `remove_sigbus_handler`
/// and `remove_sigbus_handler_session`, ensuring it cannot outlive the
/// referenced `MemoryImage`.
pub(super) static SIGBUS_JIT_RUNTIME: AtomicPtr<JitRuntime> = AtomicPtr::new(std::ptr::null_mut());
pub(super) static SIGBUS_JIT_MEMORY: AtomicPtr<MemoryImage> = AtomicPtr::new(std::ptr::null_mut());

/// PeHostRuntime pointer, stored as a raw c_void pointer so that
/// JIT-compiled ARM64 code can load it and pass it as the first
/// argument (runtime_ptr) to the fast-thunk bridge function.
/// Set by pe_runtime.rs before calling `execute_with_jit`.
pub(super) static SIGBUS_PE_RUNTIME: AtomicPtr<libc::c_void> = AtomicPtr::new(std::ptr::null_mut());
/// Publish the live `PeHostRuntime` pointer for JIT call sites that service
/// Win32 APIs directly (fast thunks and inlined trivial APIs).  The caller
/// must clear it with a null pointer when the runtime borrow ends.
pub fn set_pe_runtime_pointer(pointer: *mut libc::c_void) {
    SIGBUS_PE_RUNTIME.store(pointer, Ordering::Release);
}

/// SIGBUS loop detection: tracks the last fault address and a consecutive
/// hit counter. If the same page faults more than MAX_CONSECUTIVE_FAULTS
/// times, the handler disables itself to break the infinite loop.
pub(super) static SIGBUS_LAST_FAULT_ADDR: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub(super) static SIGBUS_CONSECUTIVE_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
pub(super) const MAX_CONSECUTIVE_FAULTS: usize = 32;

/// Total SIGBUS events for diagnostics (monotonic counter).
pub static SIGBUS_TOTAL_EVENTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Once `true`, JIT native execution is disabled for the rest of the process
/// and all blocks fall back to the IR interpreter.  Set by the SIGBUS handler
/// when a single block execution generates an excessive number of page faults
/// (a "fault storm") — the signature of a compiled block walking across many
/// uncommitted guest pages (or a block that landed in non-code data) such that
/// it would otherwise fault forever without ever returning to the dispatcher.
/// Graceful degradation: the program keeps running, just via the interpreter.
pub static JIT_FAULT_STORM_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Threshold of total SIGBUS events after which the JIT is permanently
/// disabled for the process.  A correctly-running block faults a handful of
/// times at most (a few uncommitted pages); reaching thousands means the
/// block is diverging through guest memory and would never return.
pub(super) const SIGBUS_FAULT_STORM_THRESHOLD: u64 = 4096;

/// Diagnostic counters for SIGBUS handler analysis.
pub static SIGBUS_PAGE_FOUND: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static SIGBUS_PAGE_NOT_FOUND: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub static SIGBUS_DISABLED_EVENTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Diagnostic: SIGBUS fault address was within FlatGuestMemory range.
pub static SIGBUS_IN_FLAT_RANGE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Diagnostic: SIGBUS fault address was OUTSIDE FlatGuestMemory range.
pub static SIGBUS_OUT_FLAT_RANGE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Diagnostic: SIGBUS handler re-entered (recursive SIGBUS from write_volatile).
pub static SIGBUS_RECURSIVE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Diagnostic: first fault address seen (for debugging).
pub static SIGBUS_FIRST_FAULT_ADDR: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Diagnostic: handler entry depth (detects recursive SIGBUS).
pub(super) static SIGBUS_HANDLER_DEPTH: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub fn write_diag_file(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/casa1_jit_diag.txt")
    {
        let _ = writeln!(f, "{}", msg);
    }
}

/// Re-entrancy guard for the SIGBUS handler. Set to `true` on entry with
/// `Ordering::Acquire`, cleared on exit with `Ordering::Release`. If the
/// handler is re-entered (e.g., `write_volatile` triggers another SIGBUS),
/// the guard is already `true` and the handler returns immediately, preventing
/// infinite recursion and potential memory corruption.
///
/// # Protocol
/// - Entry: `swap(true, Acquire)` — if the previous value was `true`, another
///   invocation is already active; return immediately.
/// - Exit: `store(false, Release)` — ensures all writes made during the handler
///   are visible before another invocation can proceed.
pub(super) static SIGBUS_IN_HANDLER: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Signal-safe SIGBUS fallback for a page the guest has not materialised.
///
/// # Behavior
/// - **Shared pages**: committed bytes already live in the mapping both views
///   alias; touching one byte forces the kernel to back the page, and the
///   retried instruction proceeds without any copy.
/// - **Uncommitted pages**: a single lossless zero write backs the page.
/// - **Loop detection**: if the same page faults more than
///   `MAX_CONSECUTIVE_FAULTS` times, the handler disables itself (stores
///   null pointers) to break an infinite SIGBUS loop.
///
/// # Safety
/// - Must be async-signal-safe: no heap allocation, no locks, no non-reentrant
///   libc functions. Only async-signal-safe operations are used: atomic loads/
///   stores and volatile loads/stores.
/// - The handler reads the fault address from `siginfo_t`, aligns it to a page
///   boundary, and backs that page in place: committed pages are already in
///   the shared canonical mapping (one volatile read forces residency), and
///   uncommitted pages get a lossless zero write.
/// - After the handler returns, the kernel retries the faulting instruction.
///
/// # Acquire/Release Protocol for `SIGBUS_JIT_RUNTIME` and `SIGBUS_JIT_MEMORY`
/// - Pointers are stored via `AtomicPtr` with `Ordering::Release` by the host
///   thread before JIT execution begins (`install_sigbus_handler`).
/// - This handler loads them with `Ordering::Acquire` to synchronise with the
///   Release store, establishing a happens-before relationship so that all
///   writes to `JitRuntime`/`MemoryImage` fields prior to the Release are
///   visible to the signal handler.
/// - Pointers are cleared (set to null) with `Ordering::Release` when JIT
///   execution ends (`remove_sigbus_handler`), ensuring no stale references.
///
/// # Recursive SIGBUS Handling
/// - Recursive SIGBUS (e.g., from `write_volatile` touching an unmapped page)
///   is detected via `SIGBUS_IN_HANDLER` AtomicBool with Acquire/Release
///   ordering. If the guard is already set, the handler immediately returns
///   without touching any memory, preventing infinite recursion and corrupted
///   state. The `SA_NODEFER` flag allows re-entry so we can detect it.
///   `SIGBUS_HANDLER_DEPTH` is kept as a secondary diagnostic counter.
pub(super) extern "C" fn sigbus_sa_handler(
    sig: i32,
    info: *mut libc::siginfo_t,
    _ctx: *mut c_void,
) {
    // ── Re-entrancy guard (AtomicBool with Acquire/Release) ───────────
    // swap(true, Acquire) atomically sets the flag and returns the previous
    // value. If it was already true, another invocation is active (e.g.,
    // write_volatile in the pre-fault code triggered another SIGBUS).
    // Return immediately to prevent infinite recursion and state corruption.
    if SIGBUS_IN_HANDLER.swap(true, Ordering::Acquire) {
        SIGBUS_RECURSIVE.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // ── Depth tracking (diagnostic only) ──────────────────────────────
    let _depth = SIGBUS_HANDLER_DEPTH.fetch_add(1, Ordering::Relaxed);

    // SAFETY: `info` is a valid `siginfo_t*` provided by the kernel when
    // SA_SIGINFO is set. The kernel guarantees it points to a properly
    // initialized siginfo structure for SIGBUS.
    let fault_addr = unsafe { (*info).si_addr() as u64 };
    let page = fault_addr & !0xfff;

    // Record first fault address for diagnostics
    if SIGBUS_FIRST_FAULT_ADDR.load(Ordering::Relaxed) == 0 {
        SIGBUS_FIRST_FAULT_ADDR.store(fault_addr, Ordering::Relaxed);
    }

    // ── Loop detection ────────────────────────────────────────────────
    let last = SIGBUS_LAST_FAULT_ADDR.load(Ordering::Relaxed);
    if last == page {
        let count = SIGBUS_CONSECUTIVE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= MAX_CONSECUTIVE_FAULTS {
            // Same page faulted too many times.  Previously this branch
            // disabled the handler and returned WITHOUT committing the page,
            // which left the faulting instruction to retry forever (each
            // retry hit the now-null runtime path and returned immediately) —
            // an infinite hang with the SIGBUS counter frozen.  Instead, we
            // permanently switch the runtime to the IR interpreter (so this
            // is the last JIT-compiled block we ever run) and COMMIT the
            // faulting page so this instruction succeeds and execution can
            // proceed to the block epilogue and return to the dispatcher,
            // where the interpreter takes over.
            JIT_FAULT_STORM_DISABLED.store(true, Ordering::Relaxed);
            let runtime_ptr = SIGBUS_JIT_RUNTIME.load(Ordering::Acquire);
            if !runtime_ptr.is_null() {
                // SAFETY: runtime_ptr was set with Release by
                // install_sigbus_handler before JIT execution; we hold the
                // IN_HANDLER guard so it cannot be torn down concurrently.
                let runtime = unsafe { &*runtime_ptr };
                let flat_base = runtime.flat_memory.base() as *mut u8;
                let flat_size = runtime.flat_memory.size();
                // Zero-fill the whole faulting page in the flat mirror so the
                // retrying load/store succeeds.  The page is within the
                // direct-window mmap (fault_addr was validated in-range for prior
                // faults; defensively bounds-check here too).
                let page_off = page as usize;
                if page_off
                    .checked_add(4096)
                    .map(|e| e <= flat_size)
                    .unwrap_or(false)
                {
                    unsafe {
                        std::ptr::write_bytes(flat_base.add(page_off), 0, 4096);
                    }
                }
            }
            SIGBUS_HANDLER_DEPTH.fetch_sub(1, Ordering::Relaxed);
            SIGBUS_IN_HANDLER.store(false, Ordering::Release);
            return;
        }
    } else {
        SIGBUS_LAST_FAULT_ADDR.store(page, Ordering::Relaxed);
        SIGBUS_CONSECUTIVE_COUNT.store(1, Ordering::Relaxed);
    }

    let total = SIGBUS_TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;

    // ── Fault-storm circuit breaker ──────────────────────────────────
    // If a single process has accumulated an enormous number of SIGBUS
    // events, a compiled block is diverging through guest memory (e.g. a
    // block that landed in a data section and is walking pages) and would
    // otherwise fault forever.  Permanently disable JIT native execution so
    // all subsequent blocks use the IR interpreter (which handles every
    // memory access via the safe MemoryImage API and cannot fault-loop).
    if total >= SIGBUS_FAULT_STORM_THRESHOLD {
        JIT_FAULT_STORM_DISABLED.store(true, Ordering::Relaxed);
    }

    // ── Acquire/Release protocol for static pointers ──────────────────
    // Load pointers with Acquire ordering to synchronize with the Release
    // store in `install_sigbus_handler`. This establishes a happens-before
    // relationship: all writes to JitRuntime/MemoryImage fields that
    // occurred before the Release store are visible to this handler.
    let runtime_ptr = SIGBUS_JIT_RUNTIME.load(Ordering::Acquire);
    let memory_ptr = SIGBUS_JIT_MEMORY.load(Ordering::Acquire);

    if runtime_ptr.is_null() || memory_ptr.is_null() {
        SIGBUS_DISABLED_EVENTS.fetch_add(1, Ordering::Relaxed);
        SIGBUS_HANDLER_DEPTH.fetch_sub(1, Ordering::Relaxed);
        SIGBUS_IN_HANDLER.store(false, Ordering::Release);
        return; // No handler active — let default SIGBUS handler take over
    }

    // SAFETY: `runtime_ptr` was set by `install_sigbus_handler` with
    // `Ordering::Release` before JIT execution. We loaded it with
    // `Ordering::Acquire` and validated as non-null above. The referenced
    // `JitRuntime` remains alive for the entire duration of JIT execution
    // (cleared only in `remove_sigbus_handler`/`Drop` after execution
    // completes, which stores null with `Ordering::Release`).
    let runtime = unsafe { &*runtime_ptr };
    // SAFETY: Same as `runtime_ptr` — `memory_ptr` was set with
    // `Ordering::Release` and loaded with `Ordering::Acquire`. The
    // `MemoryImage` remains alive for the entire JIT execution.
    let memory = unsafe { &*memory_ptr };

    // ── Diagnostic: check if fault is within FlatGuestMemory range ────
    let flat_base = runtime.flat_memory.base();
    let flat_size = runtime.flat_memory.size() as u64;
    // Use saturating arithmetic to prevent u64 overflow when flat_base is
    // near the top of the address space (defensive, unlikely on 64-bit macOS).
    let flat_end = flat_base.saturating_add(flat_size);
    if fault_addr >= flat_base && fault_addr < flat_end {
        SIGBUS_IN_FLAT_RANGE.fetch_add(1, Ordering::Relaxed);
    } else {
        // ── Fail-fast on OUT-OF-RANGE faults ─────────────────────────────
        // A fault outside the flat guest memory region is NOT a guest page
        // sync: it is either a failure to execute the compiled code page
        // (the faulting instruction is the branch into JIT code) or a wild
        // pointer inside compiled code.  Neither is recoverable by syncing
        // guest pages: returning would retry the faulting instruction
        // forever (an infinite SIGBUS spin).  Restore the default SIGBUS
        // disposition and re-raise so the process dies with the honest
        // signal — the caller (JIT self-test parent, runner) reports the
        // failure instead of hanging.
        SIGBUS_OUT_FLAT_RANGE.fetch_add(1, Ordering::Relaxed);
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut());
            libc::raise(libc::SIGBUS);
        }
        // Unreachable when the raise terminated the process; keep a final
        // guard so the handler never returns into the faulting instruction.
        std::process::abort();
    }

    // ── Faulting-page fallback ─────────────────────────────────────────
    //
    // The flat view and the interpreter now share the same canonical pages,
    // so a committed page needs no copy: reading one byte forces the kernel
    // to back the page that the canonical store already owns.  A page with no
    // committed bytes is backed with a lossless zero write so the retried
    // instruction can proceed.  This path is a safety net for pages the guest
    // has not committed yet, never routine synchronisation.
    let flat_base_ptr = runtime.flat_memory.base() as *mut u8;
    service_faulting_page(runtime, memory, page, flat_base_ptr, flat_size as usize);
    SIGBUS_HANDLER_DEPTH.fetch_sub(1, Ordering::Relaxed);
    // Clear re-entrancy guard with Release ordering to ensure all writes
    // made during the handler are visible before another invocation proceeds.
    SIGBUS_IN_HANDLER.store(false, Ordering::Release);
    _ = sig; // suppress unused variable warning
}

/// Back a faulting flat page without copying canonical data.
///
/// Split out of the signal handler so the three fallback cases (fully mapped,
/// partially mapped, uncommitted) are unit-testable and every accounting
/// branch is covered by adversarial tests.
pub(super) fn service_faulting_page(
    runtime: &JitRuntime,
    memory: &MemoryImage,
    page: u64,
    flat_base_ptr: *mut u8,
    flat_size: usize,
) {
    let mut materialised_pages = 0u64;
    let mut sync_operations = 0u64;
    let mut copied_bytes = 0u64;
    if memory.page_is_fully_mapped(page) {
        // SAFETY: `page` is in the flat window (validated by the caller) and
        // the byte belongs to the canonical store shared by both views.
        unsafe {
            let _ = std::ptr::read_volatile(flat_base_ptr.add(page as usize));
        }
        runtime.flat_memory.mark_page_materialised_signal_safe(page);
        SIGBUS_PAGE_FOUND.fetch_add(1, Ordering::Relaxed);
        materialised_pages = 1;
        sync_operations = 1;
        copied_bytes = 4096;
    } else if memory.page_exists(page) {
        // Partially mapped page: touch a mapped byte if one exists.  A fully
        // unmapped tail is left alone; writing zero there is lossless but is
        // not needed for a page the kernel has already backed.
        SIGBUS_PAGE_NOT_FOUND.fetch_add(1, Ordering::Relaxed);
        if memory.page_byte_is_mapped(page, 0) {
            // SAFETY: byte 0 is inside the mapped, shared page.
            unsafe {
                let _ = std::ptr::read_volatile(flat_base_ptr.add(page as usize));
            }
        } else if memory.page_byte_is_mapped(page, 4095) {
            // SAFETY: the last byte is inside the mapped, shared page.
            unsafe {
                let _ = std::ptr::read_volatile(flat_base_ptr.add(page as usize + 4095));
            }
        }
    } else {
        SIGBUS_PAGE_NOT_FOUND.fetch_add(1, Ordering::Relaxed);
        let offset = page as usize;
        if let Some(end_offset) = offset.checked_add(4095)
            && end_offset < flat_size
        {
            // SAFETY: end_offset < flat_size keeps the write inside the flat
            // window.  The page holds no guest bytes, so zero is lossless.
            unsafe {
                std::ptr::write_volatile(flat_base_ptr.add(end_offset), 0u8);
            }
            runtime.flat_memory.mark_page_materialised_signal_safe(page);
        }
    }
    GUEST_PAGES_MATERIALISED.fetch_add(materialised_pages, Ordering::Relaxed);
    GUEST_SYNC_OPERATIONS.fetch_add(sync_operations, Ordering::Relaxed);
    GUEST_SYNC_BYTES_COPIED.fetch_add(copied_bytes, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// JIT memory management
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Executable memory manager
// ---------------------------------------------------------------------------

// Test-only fault-injection seams (`JIT_TEST_*`) and `test_seam_fails` are
// defined once in the parent `jit` module (src/jit.rs).  Re-declaring them
// here would create disjoint `LocalKey`s: tests would arm one copy while the
// implementation checked another, so injections would silently never fire.

/// Manages executable memory for JIT-compiled code using MAP_JIT on Apple Silicon.
pub struct JitMemoryManager {
    pub(super) pages: Vec<(*mut u8, usize)>,
    pub(super) write_offset: usize,
    /// Executable-memory mechanism selected by the runtime capability probe.
    pub(super) mechanism: JitExecMechanism,
    pub(super) total_allocated: AtomicUsize,
    pub(super) total_used: AtomicUsize,
}

// SAFETY: JitMemoryManager contains raw mmap'd pointers that are only
// accessed through &mut methods (allocate_code_space) or atomic counters.
// The pages vector is only modified under &mut self. The mmap'd memory
// itself is thread-safe (the kernel manages page tables independently).
unsafe impl Send for JitMemoryManager {}
// SAFETY: All shared state uses atomic operations (total_allocated,
// total_used). Mutable operations (allocate_code_space) require &mut self.
// The mmap'd pointers are only read through raw pointers, not through
// shared references that could create data races.
unsafe impl Sync for JitMemoryManager {}

impl Default for JitMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl JitMemoryManager {
    pub fn new() -> Self {
        Self::with_capability(jit_execution_capability())
    }

    /// Construct a manager for an explicit capability matrix.  Used by tests
    /// that need to exercise the unavailable/fallback path deterministically.
    pub(super) fn with_capability(capability: JitExecProbeMatrix) -> Self {
        Self {
            pages: Vec::new(),
            write_offset: 0,
            mechanism: capability.selected,
            total_allocated: AtomicUsize::new(0),
            total_used: AtomicUsize::new(0),
        }
    }

    /// The executable-memory mechanism this manager uses.
    pub fn mechanism(&self) -> JitExecMechanism {
        self.mechanism
    }

    pub(super) unsafe fn allocate_page(&mut self, size: usize) -> *mut u8 {
        let aligned = size.div_ceil(JIT_PAGE_SIZE) * JIT_PAGE_SIZE;

        // MAP_JIT RWX is the canonical Apple Silicon W^X mapping:
        // pthread_jit_write_protect_np(0) makes it writable, (1) makes it
        // executable.  PROT_EXEC is required in the mmap request — the
        // write-protect toggle cannot add execute permission to an RW-only
        // mapping (that was the SIGBUS blocker).
        let ptr = match self.mechanism {
            JitExecMechanism::MapJitWx => {
                #[cfg(target_arch = "aarch64")]
                {
                    unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            aligned,
                            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT,
                            -1,
                            0,
                        )
                    }
                }
                #[cfg(not(target_arch = "aarch64"))]
                {
                    return std::ptr::null_mut();
                }
            }
            JitExecMechanism::MprotectRx => unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    aligned,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            },
            JitExecMechanism::RwxMmap => unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    aligned,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            },
            JitExecMechanism::Unavailable => return std::ptr::null_mut(),
        };

        if ptr == libc::MAP_FAILED {
            return std::ptr::null_mut();
        }

        self.pages.push((ptr as *mut u8, aligned));
        self.total_allocated.fetch_add(aligned, Ordering::Relaxed);
        ptr as *mut u8
    }

    /// Allocate code space and return a writable pointer.
    pub fn allocate_code_space(&mut self, size: usize) -> *mut u8 {
        #[cfg(test)]
        if test_seam_fails(&JIT_TEST_ALLOC_CALLS, &JIT_TEST_FAIL_ALLOC_AT) {
            return std::ptr::null_mut();
        }
        let aligned = size.div_ceil(64) * 64;

        if let Some(&(page_ptr, page_size)) = self.pages.last()
            && self.write_offset + aligned <= page_size
        {
            // SAFETY: page_ptr is a valid mmap'd pointer and
            // write_offset + aligned <= page_size was checked above,
            // so the resulting pointer is within the allocated region.
            let ptr = unsafe { page_ptr.add(self.write_offset) };
            self.write_offset += aligned;
            self.total_used.fetch_add(aligned, Ordering::Relaxed);
            return ptr;
        }

        let new_size = aligned.max(JIT_PAGE_SIZE);
        // SAFETY: allocate_page is an unsafe method that performs mmap.
        // The caller ensures this is called from a single-threaded context
        // (&mut self). The returned pointer is validated for null before use.
        unsafe {
            let ptr = self.allocate_page(new_size);
            if ptr.is_null() {
                return std::ptr::null_mut();
            }
            self.write_offset = aligned;
            self.total_used.fetch_add(aligned, Ordering::Relaxed);
            ptr
        }
    }

    /// Find the mapping that contains `ptr` (used for page-granular mprotect).
    pub(super) fn mapping_containing(&self, ptr: *mut u8) -> Option<(*mut u8, usize)> {
        self.pages.iter().copied().find(|(base, size)| {
            let address = ptr as usize;
            address >= *base as usize && address < *base as usize + *size
        })
    }

    /// Finalize code: flush icache and set executable permissions.
    ///
    /// Returns `false` when the selected mechanism cannot make the block
    /// executable (the caller then reports a compilation error and the
    /// interpreter handles the block).
    ///
    /// # Safety
    /// Caller must ensure `ptr` points to a valid code region of `size` bytes
    /// that was allocated by this memory manager.
    pub unsafe fn finalize_code(&self, ptr: *mut u8, size: usize) -> bool {
        if matches!(self.mechanism, JitExecMechanism::Unavailable) || ptr.is_null() || size == 0 {
            return false;
        }
        #[cfg(test)]
        if test_seam_fails(&JIT_TEST_FINALIZE_CALLS, &JIT_TEST_DENY_FINALIZE_AT) {
            return false;
        }
        unsafe {
            Self::flush_icache(ptr, size);
        }
        match self.mechanism {
            JitExecMechanism::MapJitWx => {
                #[cfg(target_arch = "aarch64")]
                unsafe {
                    libc::pthread_jit_write_protect_np(1);
                }
                true
            }
            JitExecMechanism::MprotectRx => match self.mapping_containing(ptr) {
                // SAFETY: `base`/`mapping_size` are the exact anonymous mapping
                // returned by mmap and are page-aligned by the kernel.
                Some((base, mapping_size)) => unsafe {
                    libc::mprotect(
                        base as *mut c_void,
                        mapping_size,
                        libc::PROT_READ | libc::PROT_EXEC,
                    ) == 0
                },
                None => false,
            },
            JitExecMechanism::RwxMmap => true,
            JitExecMechanism::Unavailable => false, // coverage: unreachable — finalize_code returns early when mechanism is Unavailable
        }
    }

    /// Make the JIT code zone writable for patching.
    ///
    /// Returns `false` when the mechanism cannot provide writable code memory.
    ///
    /// # Safety
    ///
    /// `ptr` must point into the JIT code zone owned by this manager (or be
    /// null) and the caller must ensure no other thread is executing code in
    /// that zone while it is made writable.
    pub unsafe fn make_writable(&self, ptr: *mut u8, _size: usize) -> bool {
        #[cfg(test)]
        if test_seam_fails(&JIT_TEST_WRITE_CALLS, &JIT_TEST_DENY_WRITE_AT) {
            return false;
        }
        match self.mechanism {
            JitExecMechanism::MapJitWx => {
                #[cfg(target_arch = "aarch64")]
                unsafe {
                    libc::pthread_jit_write_protect_np(0);
                }
                true
            }
            JitExecMechanism::MprotectRx => match self.mapping_containing(ptr) {
                // SAFETY: same mapping invariant as finalize_code.
                Some((base, mapping_size)) => unsafe {
                    libc::mprotect(
                        base as *mut c_void,
                        mapping_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                    ) == 0
                },
                None => false,
            },
            JitExecMechanism::RwxMmap => true,
            JitExecMechanism::Unavailable => false,
        }
    }

    /// Ensure the calling thread may execute MAP_JIT code before dispatching a
    /// compiled block.  The write-protect toggle is per-thread on Apple
    /// Silicon, so a compilation or chain-patch performed by another thread
    /// must not leave this thread's execute view disabled.
    ///
    /// # Safety
    /// Safe to call on any thread; it only toggles the thread-local JIT
    /// write-protection state.
    pub unsafe fn prepare_execution(&self) {
        Self::prepare_execution_for_mechanism(self.mechanism);
    }

    /// Switch the CALLING THREAD into execute mode for the selected
    /// executable-memory mechanism.  Production workers call this directly
    /// (they do not own the runtime's `JitMemoryManager`); the toggle is
    /// per-thread, so every worker must do it for itself.
    pub(crate) fn prepare_execution_for_mechanism(mechanism: JitExecMechanism) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if matches!(mechanism, JitExecMechanism::MapJitWx) {
            unsafe {
                libc::pthread_jit_write_protect_np(1);
            }
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let _ = mechanism;
    }

    /// # Safety
    /// Caller must ensure `ptr` is valid and `size` bytes are accessible.
    pub(super) unsafe fn flush_icache(ptr: *mut u8, size: usize) {
        // SAFETY: On aarch64, the data cache (dc cvau) and instruction cache
        // (ic ivau) must be manually invalidated after writing code.
        // `addr` iterates in 64-byte cache-line-aligned steps within
        // [ptr, ptr+size), which is safe given the caller's guarantees.
        // dsb ish and isb ensure ordering of cache maintenance operations.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let mut addr = ptr as usize & !63;
            let end = ptr as usize + size;
            while addr < end {
                core::arch::asm!("dc cvau, {}", in(reg) addr);
                addr += 64;
            }
            core::arch::asm!("dsb ish");
            addr = ptr as usize & !63;
            while addr < end {
                core::arch::asm!("ic ivau, {}", in(reg) addr);
                addr += 64;
            }
            core::arch::asm!("isb");
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            // No icache flush needed on non-ARM64 architectures
            let _ = (ptr, size);
        }
    }

    pub fn total_allocated(&self) -> usize {
        self.total_allocated.load(Ordering::Relaxed)
    }
    pub fn total_used(&self) -> usize {
        self.total_used.load(Ordering::Relaxed)
    }
}

impl Drop for JitMemoryManager {
    fn drop(&mut self) {
        for (ptr, size) in &self.pages {
            // SAFETY: Each (ptr, size) pair was returned by a successful
            // mmap call in allocate_page. munmap releases the mapping.
            // No other code accesses these pages after Drop runs.
            unsafe {
                libc::munmap(*ptr as *mut libc::c_void, *size);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Flat guest memory for direct JIT access
// ---------------------------------------------------------------------------

/// The JIT's flat view of the canonical guest address space.
///
/// This is **not** a mirror: it aliases the very same large `mmap` owned by
/// [`crate::cpu::GuestMemoryStore`].  A guest store executed by JIT-compiled
/// code and a store performed through the interpreter's [`MemoryImage`] touch
/// the same bytes, so no post-execution copy-back exists.
///
/// `materialised` is a one-bit-per-4-KiB-page record of which pages this view
/// has been told about (fully mapped pages seen by a sync/materialisation
/// pass).  It is diagnostic only: even a page not marked here is already
/// coherent, because the bytes live in the shared store.
pub struct FlatGuestMemory {
    pub(super) store: Arc<GuestMemoryStore>,
    /// One bit per 4 KiB page of the flat window.  Atomics keep the SIGBUS
    /// fast path async-signal-safe.
    pub(super) materialised: Box<[AtomicU64]>,
}

// SAFETY: FlatGuestMemory contains only an Arc to the canonical store (which
// is Send+Sync) and an atomic bitmap.
unsafe impl Send for FlatGuestMemory {}
// SAFETY: all shared state is atomic or behind the store's own synchronisation.
unsafe impl Sync for FlatGuestMemory {}

impl FlatGuestMemory {
    pub fn new(_arch: GuestArch) -> Self {
        let store = Arc::new(GuestMemoryStore::new());
        // One bit per page; the window is at most 256 GiB (8 MiB bitmap).
        let bitmap_words = store.flat_size().div_ceil(4096 * 64);
        let materialised = (0..bitmap_words)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            store,
            materialised,
        }
    }

    /// Point this view at `store` (the store owned by the live MemoryImage).
    ///
    /// This is the only "sync" the hot path performs: an `Arc` identity check.
    /// When the store changes (first attachment, or a different image), the
    /// diagnostic bitmap is reset because the pages refer to different bytes.
    pub(crate) fn attach_store(&mut self, store: &Arc<GuestMemoryStore>) {
        if Arc::ptr_eq(&self.store, store) {
            return;
        }
        self.store = Arc::clone(store);
        let required_words = store.flat_size().div_ceil(4096 * 64);
        if self.materialised.len() != required_words {
            self.materialised = (0..required_words)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice();
        } else {
            for word in &self.materialised {
                word.store(0, Ordering::Relaxed);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn store(&self) -> &Arc<GuestMemoryStore> {
        &self.store
    }

    #[inline]
    pub fn base(&self) -> u64 {
        self.store.flat_base()
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.store.is_valid()
    }

    /// Number of 4 KiB pages in the flat window (the whole direct range).
    pub fn total_page_count(&self) -> u64 {
        (self.store.flat_size() / 4096) as u64
    }

    /// Bitmap index/bit for a page base address, or `None` when the page is
    /// outside the flat region.
    pub(super) fn materialised_bit(&self, page_addr: u64) -> Option<(usize, u64)> {
        if !self.is_valid() {
            return None;
        }
        let offset = page_addr as usize;
        if offset % 4096 != 0 || offset >= self.size() {
            return None;
        }
        let page = offset / 4096;
        let word = page / 64;
        let bit = 1u64 << (page % 64);
        Some((word, bit))
    }

    /// Record that `page_addr` has been made visible to this view.
    /// Async-signal-safe: a single lock-free atomic OR with no allocation.
    #[inline]
    pub fn mark_page_materialised_signal_safe(&self, page_addr: u64) {
        if let Some((word, bit)) = self.materialised_bit(page_addr) {
            self.materialised[word].fetch_or(bit, Ordering::Relaxed);
        }
    }

    /// Returns `true` when `page_addr` has been materialised into this view.
    pub fn is_page_materialised(&self, page_addr: u64) -> bool {
        match self.materialised_bit(page_addr) {
            Some((word, bit)) => self.materialised[word].load(Ordering::Relaxed) & bit != 0,
            None => false,
        }
    }

    /// Number of guest pages materialised in this view so far.
    pub fn materialised_page_count(&self) -> u64 {
        self.materialised
            .iter()
            .map(|word| word.load(Ordering::Relaxed).count_ones() as u64)
            .sum()
    }

    /// Copy `data` into the canonical store at a flat guest address.
    ///
    /// Kept for explicit producer paths; routine JIT execution never calls
    /// this because both views already alias the same bytes.
    pub fn sync_from_memory_image(&self, guest_addr: u64, data: &[u8]) {
        if !self.is_valid() {
            return;
        }
        let offset = guest_addr as usize;
        if offset.saturating_add(data.len()) <= self.size() {
            // SAFETY: offset + data.len() <= size (checked above), so the
            // destination is inside the shared flat window. `data` is a
            // separate host buffer.
            unsafe {
                ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    (self.base() as *mut u8).add(offset),
                    data.len(),
                );
            }
        }
    }

    /// Read bytes from the canonical flat window.
    pub fn read(&self, guest_addr: u64, buf: &mut [u8]) {
        if !self.is_valid() {
            return;
        }
        let offset = guest_addr as usize;
        if offset.saturating_add(buf.len()) <= self.size() {
            // SAFETY: the source is inside the shared flat window and `buf`
            // is a distinct host allocation.
            unsafe {
                ptr::copy_nonoverlapping(
                    (self.base() as *const u8).add(offset),
                    buf.as_mut_ptr(),
                    buf.len(),
                );
            }
        }
    }

    /// Materialise the given guest pages into this view.
    ///
    /// Because the view aliases the canonical store, **no bytes are copied**:
    /// a page is marked materialised only after confirming that the
    /// `MemoryImage` has it fully mapped.  The per-page telemetry is retained
    /// for the sync-path benchmark and diagnostics; `bytes_copied` counts the
    /// bytes whose transfer this design eliminated.
    pub fn materialise_pages(&self, memory: &MemoryImage, pages: &[u64]) -> GuestMemoryTelemetry {
        let mut stats = GuestMemoryTelemetry::default();
        if !self.is_valid() || pages.is_empty() {
            return stats;
        }
        if !Arc::ptr_eq(&self.store, memory.canonical_store()) {
            // The view must be attached before it can describe the image.
            // Callers attach first; refusing here keeps byte identity a hard
            // invariant rather than silently reporting another store's pages.
            return stats;
        }

        // Page-aligned, in-bounds, sorted, deduplicated page list.
        let mut sorted: Vec<u64> = pages
            .iter()
            .filter_map(|&page| {
                let aligned = page & !0xfff;
                ((aligned as usize) < self.size()).then_some(aligned)
            })
            .collect();
        if sorted.is_empty() {
            return stats;
        }
        sorted.sort_unstable();
        sorted.dedup();

        let mut index = 0usize;
        while index < sorted.len() {
            let mut run_end_index = index;
            while run_end_index < sorted.len() {
                let page = sorted[run_end_index];
                if !memory.page_is_fully_mapped(page) {
                    break;
                }
                self.mark_page_materialised_signal_safe(page);
                stats.pages_materialised += 1;
                stats.bytes_copied += 4096;
                run_end_index += 1;
                if run_end_index < sorted.len() && sorted[run_end_index] != page + 4096 {
                    break;
                }
            }
            if run_end_index > index {
                stats.sync_operations += 1;
            } else {
                // Partially mapped page: not visible to JIT direct access.
                run_end_index = index + 1;
            }
            index = run_end_index;
        }

        GUEST_PAGES_MATERIALISED.fetch_add(stats.pages_materialised, Ordering::Relaxed);
        GUEST_SYNC_OPERATIONS.fetch_add(stats.sync_operations, Ordering::Relaxed);
        GUEST_SYNC_BYTES_COPIED.fetch_add(stats.bytes_copied, Ordering::Relaxed);
        stats
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.store.flat_size()
    }
}

// ---------------------------------------------------------------------------
// Production worker-slice memory and program
// ---------------------------------------------------------------------------

/// A worker-safe view of the canonical guest memory.
///
/// Workers must not touch the runtime's `MemoryImage` (its page table is
/// mutable and owned by the runtime thread), but they must run against the
/// *same* canonical bytes.  This view aliases the canonical store's flat
/// window and snapshots which pages are fully mapped.  Accesses to any other
/// page fail (and are reported as a guest fault) so the runtime owner can
/// service them with the full page table/VM.
///
/// Aligned word accesses use `AtomicU64` operations so two workers touching
/// neighbouring bytes in the same word can never tear or lose each other's
/// writes; unaligned accesses are merged with the same atomic RMW, giving
/// x86-style byte-preserving semantics.
pub(crate) struct GuestSliceMemory {
    pub(super) store: Arc<GuestMemoryStore>,
    pub(super) fully_mapped: BTreeSet<u64>,
    pub(super) code_pages: BTreeSet<u64>,
    /// Guest code-page writes observed by workers, drained by the runtime
    /// owner to invalidate stale compiled blocks before the next dispatch.
    pub(super) code_writes: Mutex<Vec<(u64, usize)>>,
    /// Serializes RMW operations that span more than one canonical word.
    /// Naturally aligned 1/2/4/8-byte read-modify-writes stay lock-free on
    /// their word's atomic value.
    pub(super) rmw_lock: Mutex<()>,
}

impl GuestSliceMemory {
    pub(super) fn new(memory: &MemoryImage, code_pages: BTreeSet<u64>) -> Self {
        let fully_mapped = memory
            .committed_page_addresses()
            .into_iter()
            .filter(|page| memory.page_is_fully_mapped(*page))
            .collect();
        Self {
            store: Arc::clone(memory.canonical_store()),
            fully_mapped,
            code_pages,
            code_writes: Mutex::new(Vec::new()),
            rmw_lock: Mutex::new(()),
        }
    }

    pub(crate) fn flat_base(&self) -> u64 {
        self.store.flat_base()
    }

    pub(crate) fn flat_size(&self) -> u64 {
        self.store.flat_size() as u64
    }

    pub(super) fn range_available(&self, address: u64, len: usize) -> bool {
        if len == 0 || self.store.flat_base() == 0 {
            return false;
        }
        let Some(end) = address.checked_add(len as u64) else {
            return false;
        };
        if end > self.flat_size() {
            return false;
        }
        let mut page = address & !0xfff;
        let last = (end - 1) & !0xfff;
        loop {
            if !self.fully_mapped.contains(&page) {
                return false;
            }
            if page == last {
                return true;
            }
            page = page.saturating_add(0x1000);
        }
    }

    pub(super) fn first_fault(&self, address: u64, len: usize, write: bool) -> GuestMemoryFault {
        let mut current = address;
        let end = address.saturating_add(len as u64);
        while current < end {
            let page = current & !0xfff;
            if !self.fully_mapped.contains(&page) || current >= self.flat_size() {
                return GuestMemoryFault {
                    address: current,
                    write,
                    read_len: len,
                };
            }
            current = page.saturating_add(0x1000);
        }
        GuestMemoryFault {
            address,
            write,
            read_len: len,
        }
    }

    #[inline]
    pub(super) fn atomic_word(&self, word_base: u64) -> &AtomicU64 {
        // SAFETY: `range_available` validated that the word lies inside the
        // canonical flat mapping; the mapping is stable for the store's
        // lifetime and word_base is 8-byte aligned.
        unsafe { &*((self.store.flat_base() + word_base) as *const AtomicU64) }
    }

    /// Read 1..=8 guest bytes through the shared canonical store.
    pub(crate) fn load(&self, address: u64, len: usize) -> Result<u64, GuestMemoryFault> {
        if len == 0 || len > 8 || !self.range_available(address, len) {
            return Err(self.first_fault(address, len, false));
        }
        let mut value = 0_u64;
        let mut done = 0_usize;
        while done < len {
            let current = address + done as u64;
            let word_base = current & !7;
            let word = self.atomic_word(word_base).load(Ordering::SeqCst);
            let offset = (current - word_base) as usize;
            let take = (8 - offset).min(len - done);
            let mask = if take == 8 {
                u64::MAX
            } else {
                (1_u64 << (take * 8)) - 1
            };
            value |= ((word >> (offset * 8)) & mask) << (done * 8);
            done += take;
        }
        Ok(value)
    }

    /// Write 1..=8 guest bytes through the shared canonical store.  Returns
    /// `true` when the write touched a compiled-code page (the runtime owner
    /// must invalidate stale blocks before the next slice).
    pub(crate) fn store(&self, address: u64, bytes: &[u8]) -> Result<bool, GuestMemoryFault> {
        let len = bytes.len();
        if len == 0 || len > 8 || !self.range_available(address, len) {
            return Err(self.first_fault(address, len, true));
        }
        let mut value = 0_u64;
        for (index, byte) in bytes.iter().enumerate() {
            value |= u64::from(*byte) << (index * 8);
        }
        let mut done = 0_usize;
        while done < len {
            let current = address + done as u64;
            let word_base = current & !7;
            let offset = (current - word_base) as usize;
            let take = (8 - offset).min(len - done);
            let mask = if take == 8 {
                u64::MAX
            } else {
                (1_u64 << (take * 8)) - 1
            };
            let bits = ((value >> (done * 8)) & mask) << (offset * 8);
            let field_mask = mask << (offset * 8);
            self.atomic_word(word_base)
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
                    Some((old & !field_mask) | bits)
                })
                .expect("atomic guest-word update never fails");
            done += take;
        }
        let touches_code = self
            .code_pages
            .range((address & !0xfff)..=((address + len as u64 - 1) & !0xfff))
            .next()
            .is_some();
        if touches_code {
            self.code_writes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((address, len));
        }
        Ok(touches_code)
    }

    /// Atomic read-modify-write add through the shared canonical store.
    ///
    /// Returns the value BEFORE the add (x86 `xadd` semantics) and whether the
    /// modified range touched a compiled-code page.  A naturally aligned
    /// access inside one canonical 8-byte word is a single lock-free atomic
    /// update, so two guest threads executing `lock xadd [shared], reg`
    /// concurrently can never lose an increment.  An access that spans two
    /// words falls back to a process-wide RMW mutex.
    pub(crate) fn atomic_fetch_add(
        &self,
        address: u64,
        value: u64,
        len: usize,
    ) -> Result<(u64, bool), GuestMemoryFault> {
        use std::sync::atomic::Ordering;
        if len == 0 || len > 8 || !self.range_available(address, len) {
            return Err(self.first_fault(address, len, true));
        }
        let word_base = address & !7;
        let offset = (address - word_base) as usize;
        let mask = if len == 8 {
            u64::MAX
        } else {
            (1_u64 << (len * 8)) - 1
        };
        let within_word = offset + len <= 8;
        let original = if within_word {
            let field_mask = mask << (offset * 8);
            let field_bits = value & mask;
            let word = self.atomic_word(word_base);
            if offset == 0 && len == 8 {
                word.fetch_add(field_bits, Ordering::SeqCst)
            } else {
                let mut previous = 0_u64;
                word.try_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
                    previous = old;
                    let field = (old >> (offset * 8)) & mask;
                    let next = field.wrapping_add(field_bits) & mask;
                    Some((old & !field_mask) | (next << (offset * 8)))
                })
                .expect("atomic guest-word update never fails");
                (previous >> (offset * 8)) & mask
            }
        } else {
            let _guard = self
                .rmw_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = self.load(address, len)?;
            self.store(address, &previous.wrapping_add(value).to_le_bytes()[..len])?;
            previous
        };
        let touches_code = self
            .code_pages
            .range((address & !0xfff)..=((address + len as u64 - 1) & !0xfff))
            .next()
            .is_some();
        if touches_code {
            self.code_writes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((address, len));
        }
        Ok((original, touches_code))
    }

    pub(crate) fn take_code_writes(&self) -> Vec<(u64, usize)> {
        std::mem::take(
            &mut *self
                .code_writes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
}

/// Immutable execution plan handed to a production worker.
///
/// The blocks are compiled into a dedicated, deliberately unlinked cache:
/// the worker resolves control flow itself (budget, safepoint, per-block SMC
/// checks and host-thunk barriers stay exact), while calls, returns and
/// indirect transfers continue inside the same worker job.  The program is
/// `Send + Sync` because every field is immutable shared state;
/// `JitCompiledBlock` stores its entry as an address and the code pages are
/// immutable after `finalize_code`.
pub(crate) struct GuestSliceProgram {
    pub(crate) blocks: HashMap<u64, JitCompiledBlock>,
    pub(crate) memory: Arc<GuestSliceMemory>,
    pub(crate) flat_base: u64,
    pub(crate) mechanism: JitExecMechanism,
    /// Generation of the runtime's slice-block cache.  A persistent worker
    /// slot resets its predictor/inline caches when this changes, because
    /// cached code entries could otherwise point at invalidated blocks.
    pub(crate) epoch: u64,
}

impl GuestSliceProgram {
    pub(crate) fn block(&self, rip: u64) -> Option<&JitCompiledBlock> {
        self.blocks.get(&rip)
    }
}

/// Result of one worker block execution: the dispatcher-visible exit plus the
/// address of the block that actually produced it (a chain can end in a
/// different block than the one entered).
pub(crate) struct SliceBlockOutcome {
    pub(crate) reason: JitExitReason,
    pub(crate) final_block: u64,
}

/// Execute one compiled block on a production worker.
///
/// # Safety
/// `block` must have been produced by this runtime's compiler and finalized,
/// `program.flat_base` must address the canonical guest store, and the
/// worker must not share guest state with the runtime owner (each slice owns
/// its `CpuState`).
pub(crate) unsafe fn execute_slice_block(
    program: &GuestSliceProgram,
    block: &JitCompiledBlock,
    state: &mut CpuState,
    chain: &mut ChainState,
) -> SliceBlockOutcome {
    JitMemoryManager::prepare_execution_for_mechanism(program.mechanism);
    let entry = block.published_entry();
    if entry.is_null() {
        return SliceBlockOutcome {
            reason: JitExitReason::Safepoint,
            final_block: block.guest_address,
        };
    }
    chain.current_block = block.guest_address;
    // SAFETY: the caller guarantees the entry points at finalized immutable
    // code.  The ABI is the block entry ABI (state, flat base, unused
    // MemoryImage pointer, per-chain state).
    let entry_fn: unsafe extern "C" fn(
        *mut CpuState,
        u64,
        *mut MemoryImage,
        *mut ChainState,
    ) -> u64 = unsafe { std::mem::transmute(entry) };
    let result = unsafe {
        entry_fn(
            state as *mut CpuState,
            program.flat_base,
            ptr::null_mut(),
            chain as *mut ChainState,
        )
    };
    let final_block = chain.current_block;
    let payload = chain.payload;
    // Every native exit reports the block that actually ran; callers may
    // still override this with a control-flow successor.
    state.rip = final_block;
    let exit_info = program
        .blocks
        .get(&final_block)
        .map(|final_block| final_block.last_exit_info)
        .unwrap_or(block.last_exit_info);
    SliceBlockOutcome {
        reason: map_exit_reason(result, state, result, exit_info, payload),
        final_block,
    }
}

// ---------------------------------------------------------------------------
// Persistent production-worker control-flow state and slice driver
// ---------------------------------------------------------------------------

/// Number of polymorphic ways a worker indirect-site cache holds before it
/// becomes megamorphic.
pub(crate) const INDIRECT_POLY_WAYS: usize = 4;

/// Return-stack predictor for guest `ret`.
///
/// Every worker `call` pushes its statically known return address; every
/// `ret` predicts the top entry and compares it with the real address loaded
/// from guest `[rsp]`.  A misprediction is counted, the predictor is
/// resynchronised to the real return address, and execution continues at the
/// *guest* value — the prediction is only a hint, never the authority.
#[derive(Debug, Clone)]
pub(crate) struct ReturnPredictor {
    pub(super) stack: VecDeque<u64>,
    pub(super) capacity: usize,
    pub(super) hits: u64,
    pub(super) misses: u64,
    pub(super) mispredictions: u64,
}

impl Default for ReturnPredictor {
    fn default() -> Self {
        Self::new(64)
    }
}

impl ReturnPredictor {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            stack: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
            hits: 0,
            misses: 0,
            mispredictions: 0,
        }
    }

    pub(crate) fn on_call(&mut self, return_address: u64) {
        if self.stack.len() == self.capacity {
            self.stack.pop_front();
        }
        self.stack.push_back(return_address);
    }

    /// Account for a `ret` whose real guest return address is `actual`.
    /// Returns whether the top-of-stack prediction matched.
    pub(crate) fn on_return(&mut self, actual: u64) -> bool {
        let prediction = self.stack.pop_back();
        match prediction {
            Some(predicted) if predicted == actual => {
                self.hits += 1;
                true
            }
            Some(_) => {
                self.misses += 1;
                self.mispredictions += 1;
                // A mismatched return means the guest stack and the predictor
                // diverged (e.g. a non-local unwind).  Re-synchronise when the
                // real return address is still on the predicted stack.
                if let Some(position) = self.stack.iter().rposition(|entry| *entry == actual) {
                    self.stack.truncate(position + 1);
                }
                false
            }
            None => {
                self.misses += 1;
                false
            }
        }
    }

    pub(crate) fn hits(&self) -> u64 {
        self.hits
    }

    pub(crate) fn misses(&self) -> u64 {
        self.misses
    }

    pub(crate) fn mispredictions(&self) -> u64 {
        self.mispredictions
    }

    pub(crate) fn reset(&mut self) {
        self.stack.clear();
        self.hits = 0;
        self.misses = 0;
        self.mispredictions = 0;
    }
}

/// One indirect-site inline cache: monomorphic until a second target appears,
/// then 2..=[`INDIRECT_POLY_WAYS`]-way polymorphic, then a hash-table
/// megamorphic fallback.  Entries map a guest target address to the compiled
/// block entry so a hit can dispatch without touching the program map.
#[derive(Debug, Default)]
pub(super) struct IndirectSiteCache {
    pub(super) targets: [u64; INDIRECT_POLY_WAYS],
    pub(super) entries: [usize; INDIRECT_POLY_WAYS],
    pub(super) len: u8,
    pub(super) megamorphic: bool,
    pub(super) mega: HashMap<u64, usize>,
    pub(super) hits: u64,
    pub(super) misses: u64,
    pub(super) megamorphic_hits: u64,
}

impl IndirectSiteCache {
    pub(super) fn lookup(&mut self, target: u64) -> Option<usize> {
        if self.megamorphic {
            return match self.mega.get(&target) {
                Some(entry) => {
                    self.megamorphic_hits += 1;
                    Some(*entry)
                }
                None => {
                    self.misses += 1;
                    None
                }
            };
        }
        for index in 0..self.len as usize {
            if self.targets[index] == target {
                self.hits += 1;
                return Some(self.entries[index]);
            }
        }
        self.misses += 1;
        None
    }

    pub(super) fn insert(&mut self, target: u64, entry: usize) {
        if self.megamorphic {
            self.mega.insert(target, entry);
            return;
        }
        if (self.len as usize) < INDIRECT_POLY_WAYS {
            let index = self.len as usize;
            self.targets[index] = target;
            self.entries[index] = entry;
            self.len += 1;
            return;
        }
        self.megamorphic = true;
        for index in 0..INDIRECT_POLY_WAYS {
            self.mega.insert(self.targets[index], self.entries[index]);
        }
        self.mega.insert(target, entry);
    }
}

/// Per-worker-slot indirect call/jump cache, keyed by the block that performed
/// the transfer.  A site is monomorphic for one target, polymorphic for 2-4,
/// and megamorphic beyond that.
#[derive(Debug, Default)]
pub(crate) struct IndirectInlineCache {
    pub(super) sites: HashMap<u64, IndirectSiteCache>,
}

impl IndirectInlineCache {
    pub(crate) fn lookup(&mut self, site: u64, target: u64) -> Option<usize> {
        let cache = self.sites.entry(site).or_default();
        cache.lookup(target)
    }

    pub(crate) fn insert(&mut self, site: u64, target: u64, entry: usize) {
        let cache = self.sites.entry(site).or_default();
        cache.insert(target, entry);
    }

    pub(crate) fn hits(&self) -> u64 {
        self.sites.values().map(|cache| cache.hits).sum()
    }

    pub(crate) fn misses(&self) -> u64 {
        self.sites.values().map(|cache| cache.misses).sum()
    }

    pub(crate) fn megamorphic_sites(&self) -> u64 {
        self.sites
            .values()
            .filter(|cache| cache.megamorphic)
            .count() as u64
    }

    pub(crate) fn megamorphic_hits(&self) -> u64 {
        self.sites
            .values()
            .map(|cache| cache.megamorphic_hits)
            .sum()
    }

    #[allow(dead_code)] // diagnostics/tests
    pub(crate) fn is_megamorphic(&self, site: u64) -> bool {
        self.sites.get(&site).is_some_and(|cache| cache.megamorphic)
    }

    pub(crate) fn reset(&mut self) {
        self.sites.clear();
    }
}

/// Cumulative control-flow metrics for one persistent worker slot.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SliceMetrics {
    pub blocks_executed: u64,
    pub instructions_executed: u64,
    pub dispatcher_exits: u64,
    pub native_chains: u64,
    pub return_predictions: u64,
    pub return_hits: u64,
    pub return_misses: u64,
    pub return_mispredictions: u64,
    pub indirect_ic_hits: u64,
    pub indirect_ic_misses: u64,
    pub indirect_megamorphic_sites: u64,
    pub indirect_megamorphic_hits: u64,
}

#[allow(dead_code)] // rates are the scheduler/benchmark diagnostic surface
impl SliceMetrics {
    /// Compiled-code exits back to the worker dispatcher per 1000 guest IR
    /// instructions (0 when nothing ran).
    pub(crate) fn dispatcher_exits_per_1000_instructions(&self) -> f64 {
        if self.instructions_executed == 0 {
            0.0
        } else {
            self.dispatcher_exits as f64 * 1000.0 / self.instructions_executed as f64
        }
    }

    /// Fraction of executed blocks that were reached as a native chain (i.e.
    /// without returning to a *scheduler* round).  A single-block slice is 0.
    pub(crate) fn native_chaining_rate(&self) -> f64 {
        if self.blocks_executed == 0 {
            0.0
        } else {
            self.native_chains as f64 / self.blocks_executed as f64
        }
    }

    pub(crate) fn return_hit_rate(&self) -> f64 {
        if self.return_predictions == 0 {
            0.0
        } else {
            self.return_hits as f64 / self.return_predictions as f64
        }
    }

    pub(crate) fn indirect_ic_hit_rate(&self) -> f64 {
        let total = self.indirect_ic_hits + self.indirect_ic_misses;
        if total == 0 {
            0.0
        } else {
            self.indirect_ic_hits as f64 / total as f64
        }
    }

    pub(crate) fn indirect_megamorphic_rate(&self) -> f64 {
        let total = self.indirect_ic_hits + self.indirect_ic_misses;
        if total == 0 {
            0.0
        } else {
            self.indirect_megamorphic_hits as f64 / total as f64
        }
    }

    pub(crate) fn delta_since(self, earlier: Self) -> Self {
        Self {
            blocks_executed: self.blocks_executed - earlier.blocks_executed,
            instructions_executed: self.instructions_executed - earlier.instructions_executed,
            dispatcher_exits: self.dispatcher_exits - earlier.dispatcher_exits,
            native_chains: self.native_chains - earlier.native_chains,
            return_predictions: self.return_predictions - earlier.return_predictions,
            return_hits: self.return_hits - earlier.return_hits,
            return_misses: self.return_misses - earlier.return_misses,
            return_mispredictions: self.return_mispredictions - earlier.return_mispredictions,
            indirect_ic_hits: self.indirect_ic_hits - earlier.indirect_ic_hits,
            indirect_ic_misses: self.indirect_ic_misses - earlier.indirect_ic_misses,
            indirect_megamorphic_sites: self.indirect_megamorphic_sites
                - earlier.indirect_megamorphic_sites,
            indirect_megamorphic_hits: self.indirect_megamorphic_hits
                - earlier.indirect_megamorphic_hits,
        }
    }
}

/// Persistent per-guest-thread execution state owned by a worker slot.
#[derive(Debug, Default)]
pub(crate) struct SliceThreadState {
    pub(super) epoch: u64,
    pub(super) initialised: bool,
    pub(crate) return_predictor: ReturnPredictor,
    pub(crate) indirect_cache: IndirectInlineCache,
    pub(crate) metrics: SliceMetrics,
    /// Return accounting performed entirely inside native chains (calls and
    /// returns that never re-entered the worker loop).
    pub(super) native_return_hits: u64,
    pub(super) native_return_misses: u64,
    pub(super) native_return_mispredicts: u64,
}

impl SliceThreadState {
    /// Drop cached code-entry state when the runtime invalidated slice blocks.
    /// Cumulative metrics survive because they describe guest behaviour, not
    /// code addresses.
    pub(crate) fn prepare(&mut self, epoch: u64) {
        if !self.initialised || self.epoch != epoch {
            self.epoch = epoch;
            self.initialised = true;
            self.return_predictor.reset();
            self.indirect_cache.reset();
            self.native_return_hits = 0;
            self.native_return_misses = 0;
            self.native_return_mispredicts = 0;
            // Cached-entry counters restart with the caches.
            self.metrics.return_predictions = 0;
            self.metrics.return_hits = 0;
            self.metrics.return_misses = 0;
            self.metrics.return_mispredictions = 0;
            self.metrics.indirect_ic_hits = 0;
            self.metrics.indirect_ic_misses = 0;
            self.metrics.indirect_megamorphic_sites = 0;
            self.metrics.indirect_megamorphic_hits = 0;
        }
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(super) fn refresh_cache_metrics(&mut self) {
        self.metrics.return_hits = self.return_predictor.hits() + self.native_return_hits;
        self.metrics.return_misses = self.return_predictor.misses() + self.native_return_misses;
        self.metrics.return_predictions = self.metrics.return_hits + self.metrics.return_misses;
        self.metrics.return_mispredictions =
            self.return_predictor.mispredictions() + self.native_return_mispredicts;
        self.metrics.indirect_ic_hits = self.indirect_cache.hits();
        self.metrics.indirect_ic_misses = self.indirect_cache.misses();
        self.metrics.indirect_megamorphic_sites = self.indirect_cache.megamorphic_sites();
        self.metrics.indirect_megamorphic_hits = self.indirect_cache.megamorphic_hits();
    }
}

/// Why a worker slice stopped.  Mirrors the scheduler's `GuestSliceExit`
/// without making the JIT depend on the runtime module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SliceStop {
    Budget,
    HostBarrier { rip: u64 },
    GuestFault { address: u64, write: bool },
    CodeWrite,
    Safepoint,
    Shutdown,
}

/// Result of [`run_slice`].
#[derive(Debug)]
pub(crate) struct SliceRunReport {
    pub(crate) stop: SliceStop,
    pub(crate) blocks_executed: u64,
    pub(crate) metrics: SliceMetrics,
    pub(crate) code_writes: Vec<(u64, usize)>,
}

pub(super) fn slice_push_return(
    program: &GuestSliceProgram,
    state: &mut CpuState,
    return_address: u64,
) -> Result<(), (u64, bool)> {
    let pointer_bytes = state.arch.pointer_bytes();
    let rsp = state.get(Register::Rsp).wrapping_sub(pointer_bytes as u64);
    let bytes = return_address.to_le_bytes();
    let touched_code = program
        .memory
        .store(rsp, &bytes[..pointer_bytes])
        .map_err(|fault| (fault.address, fault.write))?;
    if touched_code {
        WORKER_SLICE_CODE_WRITTEN.with(|flag| flag.set(true));
        JIT_CODE_EPOCH.fetch_add(1, Ordering::AcqRel);
    }
    state.set(Register::Rsp, rsp);
    Ok(())
}

pub(super) fn slice_resolve_target(
    program: &GuestSliceProgram,
    state: &CpuState,
    target: u64,
    target_is_pointer: bool,
) -> Result<u64, (u64, bool)> {
    if !target_is_pointer {
        return Ok(target);
    }
    let pointer_bytes = state.arch.pointer_bytes();
    program
        .memory
        .load(target, pointer_bytes)
        .map_err(|fault| (fault.address, fault.write))
}

/// Run one production worker slice: execute compiled worker blocks until the
/// budget, a host barrier, a safepoint, a guest fault, a code write, or pool
/// shutdown.  Direct/conditional jumps, calls, indirect transfers and returns
/// are resolved here and continue in the same native worker — they never yield
/// to the runtime owner merely for control flow.
///
/// # Safety
/// `program` must outlive the call, its blocks must be finalized worker
/// blocks, and `state` must be exclusively owned by this worker.
pub(crate) unsafe fn run_slice(
    program: &GuestSliceProgram,
    state: &mut CpuState,
    thread: &mut SliceThreadState,
    budget: u64,
    shutdown: &std::sync::atomic::AtomicBool,
) -> SliceRunReport {
    use std::sync::atomic::Ordering;
    thread.prepare(program.epoch);
    let metrics_before = thread.metrics;
    let guard = WorkerSliceGuard::install(&program.memory);
    let mut chain = ChainState::new(program.flat_base, state.rip, budget.min(LINK_BUDGET));
    let mut blocks_executed = 0_u64;
    let mut dispatches = 0_u64;
    let stop = loop {
        if shutdown.load(Ordering::Acquire) {
            break SliceStop::Shutdown;
        }
        if blocks_executed >= budget {
            break SliceStop::Budget;
        }
        let Some(block) = program.block(state.rip) else {
            break SliceStop::HostBarrier { rip: state.rip };
        };
        if !block.worker_safe {
            break SliceStop::HostBarrier { rip: state.rip };
        }
        // Never let a native chain outlive the slice budget or the link
        // budget.  `link_budget` is also the check counter that guarantees a
        // dispatch boundary (safepoint + SMC re-evaluation) even in a loop of
        // direct branches.
        chain.link_budget = (budget - blocks_executed).min(LINK_BUDGET);
        let before_blocks = chain.blocks;
        let before_instructions = chain.instructions;
        // SAFETY: the block came from the caller's finalized worker program
        // and the worker owns `state` and `chain`.
        let outcome = unsafe { execute_slice_block(program, block, state, &mut chain) };
        let delta_blocks = chain.blocks - before_blocks;
        let delta_instructions = chain.instructions - before_instructions;
        blocks_executed += delta_blocks;
        thread.metrics.blocks_executed += delta_blocks;
        thread.metrics.instructions_executed += delta_instructions;
        if delta_blocks > 0 {
            dispatches += 1;
            thread.metrics.dispatcher_exits += 1;
            thread.metrics.native_chains += delta_blocks.saturating_sub(1);
        }
        let code_written = guard.code_written();
        let SliceBlockOutcome {
            reason,
            final_block,
        } = outcome;
        let final_exit_info = program
            .blocks
            .get(&final_block)
            .and_then(|block| block.last_exit_info)
            .or(block.last_exit_info);
        let conditional_taken = match &reason {
            JitExitReason::ConditionalBranch { taken, .. } => Some(*taken),
            JitExitReason::ConditionalTaken { .. } => Some(true),
            JitExitReason::ConditionalNotTaken { .. } => Some(false),
            _ => None,
        };
        match reason {
            JitExitReason::Jump { target } => {
                state.rip = target;
            }
            JitExitReason::ConditionalBranch { .. }
            | JitExitReason::ConditionalTaken { .. }
            | JitExitReason::ConditionalNotTaken { .. } => {
                let taken = conditional_taken.unwrap_or(false);
                let Some(BlockExitInfo::JumpIf {
                    target,
                    fallthrough,
                    ..
                }) = final_exit_info
                else {
                    break SliceStop::HostBarrier { rip: state.rip };
                };
                state.rip = if taken { target } else { fallthrough };
            }
            JitExitReason::DirectCall {
                target,
                return_address,
            } => {
                if let Err((address, write)) = slice_push_return(program, state, return_address) {
                    break SliceStop::GuestFault { address, write };
                }
                thread.return_predictor.on_call(return_address);
                state.rip = target;
            }
            JitExitReason::DirectCallPushed {
                target,
                return_address: _,
            } => {
                // The compiled block already pushed the guest return address
                // and recorded the call in the chain's native return stack.
                state.rip = target;
            }
            JitExitReason::IndirectCall {
                target,
                return_address,
                target_is_pointer,
            } => {
                let target = match slice_resolve_target(program, state, target, target_is_pointer) {
                    Ok(target) => target,
                    Err((address, write)) => break SliceStop::GuestFault { address, write },
                };
                if let Err((address, write)) = slice_push_return(program, state, return_address) {
                    break SliceStop::GuestFault { address, write };
                }
                thread.return_predictor.on_call(return_address);
                if thread.indirect_cache.lookup(final_block, target).is_none()
                    && let Some(callee) = program.blocks.get(&target)
                {
                    thread
                        .indirect_cache
                        .insert(final_block, target, callee.entry() as usize);
                }
                state.rip = target;
            }
            JitExitReason::IndirectJump {
                target,
                target_is_pointer,
            } => {
                let target = match slice_resolve_target(program, state, target, target_is_pointer) {
                    Ok(target) => target,
                    Err((address, write)) => break SliceStop::GuestFault { address, write },
                };
                if thread.indirect_cache.lookup(final_block, target).is_none()
                    && let Some(target_block) = program.blocks.get(&target)
                {
                    thread.indirect_cache.insert(
                        final_block,
                        target,
                        target_block.entry() as usize,
                    );
                }
                state.rip = target;
            }
            JitExitReason::Return { .. } => {
                let pointer_bytes = state.arch.pointer_bytes();
                let rsp = state.get(Register::Rsp);
                let actual = match program.memory.load(rsp, pointer_bytes) {
                    Ok(actual) => actual,
                    Err(fault) => {
                        break SliceStop::GuestFault {
                            address: fault.address,
                            write: fault.write,
                        };
                    }
                };
                let stack_adjust = match final_exit_info {
                    Some(BlockExitInfo::Return { stack_adjust }) => stack_adjust,
                    _ => 0,
                };
                thread.return_predictor.on_return(actual);
                state.set(
                    Register::Rsp,
                    rsp.wrapping_add(pointer_bytes as u64 + stack_adjust),
                );
                // Warm the chain return stack so the next visit can link
                // natively without leaving the worker.
                let entry = program
                    .blocks
                    .get(&actual)
                    .filter(|block| block.worker_safe)
                    .map(|block| block.entry() as u64)
                    .unwrap_or(0);
                chain.push_return(actual, entry);
                state.rip = actual;
            }
            JitExitReason::ReturnResolved { target } => {
                // Native return prediction/accounting already ran inside the
                // compiled block (see the chain counters merged below).
                state.rip = target;
            }
            JitExitReason::Safepoint => {
                state.rip = final_block;
                break SliceStop::Safepoint;
            }
            JitExitReason::LinkBudget { .. } => {
                // The block at `final_block` did not execute.  Re-enter it
                // with a fresh check budget, unless the slice budget is spent.
                state.rip = final_block;
                if blocks_executed >= budget {
                    break SliceStop::Budget;
                }
            }
            JitExitReason::CodeEpoch { .. } => {
                state.rip = final_block;
                break SliceStop::CodeWrite;
            }
            JitExitReason::GuestFault => {
                let address = state.jit_pending_fault.take().unwrap_or(state.rip);
                let write = std::mem::take(&mut state.jit_pending_fault_write);
                break SliceStop::GuestFault { address, write };
            }
            JitExitReason::Normal { .. }
            | JitExitReason::ThunkDispatch { .. }
            | JitExitReason::UnimplementedInstruction { .. }
            | JitExitReason::MemoryAccess { .. }
            | JitExitReason::Cpuid
            | JitExitReason::Exception { .. } => {
                // A straight-line worker block has no static successor.  Stop
                // at the block that actually ran and let the owner re-decode
                // (this is the documented host barrier for these blocks).
                state.rip = final_block;
                break SliceStop::HostBarrier { rip: state.rip };
            }
        }
        if code_written {
            break SliceStop::CodeWrite;
        }
        if program
            .block(state.rip)
            .map_or(true, |block| !block.worker_safe)
        {
            break SliceStop::HostBarrier { rip: state.rip };
        }
    };
    let _ = dispatches;
    thread.native_return_hits += chain.native_return_hits;
    thread.native_return_misses += chain.native_return_misses;
    thread.native_return_mispredicts += chain.native_return_mispredicts;
    thread.refresh_cache_metrics();
    let code_writes = program.memory.take_code_writes();
    drop(guard);
    SliceRunReport {
        stop,
        blocks_executed,
        metrics: thread.metrics.delta_since(metrics_before),
        code_writes,
    }
}

// ---------------------------------------------------------------------------
// JIT compilation result
// ---------------------------------------------------------------------------

/// Result of JIT-compiling a block of IR instructions.
///
/// The compiled-code descriptor is immutable after construction and contains
/// no raw pointers: the executable entry is stored as a `usize` address (plus
/// the `entry_atomic` publication slot).  That makes the descriptor genuinely
/// `Send + Sync`; the safety invariant is that the underlying code page is
/// immutable and executable after `finalize_code`, and every executor obtains
/// the entry through [`Self::published_entry`] (acquire).
pub struct JitCompiledBlock {
    /// Address of the compiled ARM64 code entry point.  Callers that publish a
    /// block to another thread must use [`Self::published_entry`] (acquire) so
    /// the code bytes written before publication are visible.
    pub(super) entry_addr: usize,
    /// Atomic publication of the entry address.  Installers store with Release
    /// after `finalize_code` (icache flush); executors load with Acquire.
    pub(super) entry_atomic: AtomicPtr<u8>,
    /// Size of compiled code in bytes.
    pub code_size: usize,
    /// Guest address this block was compiled from.
    pub guest_address: u64,
    /// Number of guest instructions compiled.
    pub instruction_count: usize,
    /// Hash of the source IR instructions at compile time, used to detect
    /// self-modifying code on subsequent `get_or_compile` calls.
    /// A hash of 0 means integrity verification is disabled for this block.
    pub source_hash: u64,
    /// Control-flow metadata for the block's final instruction (the JIT
    /// never writes `state.rip` for jump-family exits, so the dispatcher
    /// reconstructs it from this metadata — see
    /// [`map_exit_reason`](crate::jit::map_exit_reason)).
    pub last_exit_info: Option<BlockExitInfo>,
    /// Compilation tier that produced this block.
    pub compile_tier: CompilationTier,
    /// True when the final IR instruction controls RIP (jump/call/ret
    /// family).  A chain may only target such a block: chaining into a
    /// straight-line block would leave the dispatcher advancing RIP by
    /// the *source* block's end address.
    pub ends_in_control_flow: bool,
    /// Atomic link slot read by the block's compiled jump exit.  Zero means
    /// "not linked"; a non-zero value is the target block entry.  Linking
    /// never patches code — it publishes a pointer with Release, so no other
    /// thread can observe a torn instruction sequence.
    pub link_target: Arc<AtomicU64>,
    /// `Jcc` taken/fallthrough successor entries (worker slices).
    pub(crate) taken_link: Arc<AtomicU64>,
    pub(crate) fallthrough_link: Arc<AtomicU64>,
    /// Direct-call successor entry (worker slices).
    pub(crate) call_link: Arc<AtomicU64>,
    /// Entry of the statically known return successor of a direct call.
    /// Emitted call sites push this into the chain return stack.
    pub(crate) return_entry_link: Arc<AtomicU64>,
    /// True when a production worker may execute this block without touching
    /// runtime-owned host state: no interpreter fallback, no host call/return
    /// terminator, and no unresolved jump target.  Worker slices execute only
    /// these blocks; everything else is a thunk/host barrier.
    pub worker_safe: bool,
}

impl Clone for JitCompiledBlock {
    fn clone(&self) -> Self {
        Self {
            entry_addr: self.entry_addr,
            entry_atomic: AtomicPtr::new(self.entry_atomic.load(Ordering::Acquire)),
            code_size: self.code_size,
            guest_address: self.guest_address,
            instruction_count: self.instruction_count,
            source_hash: self.source_hash,
            last_exit_info: self.last_exit_info,
            compile_tier: self.compile_tier,
            ends_in_control_flow: self.ends_in_control_flow,
            link_target: Arc::clone(&self.link_target),
            taken_link: Arc::clone(&self.taken_link),
            fallthrough_link: Arc::clone(&self.fallthrough_link),
            call_link: Arc::clone(&self.call_link),
            return_entry_link: Arc::clone(&self.return_entry_link),
            worker_safe: self.worker_safe,
        }
    }
}

impl JitCompiledBlock {
    /// Acquire-load the published executable entry point.
    pub fn published_entry(&self) -> *const u8 {
        self.entry_atomic.load(Ordering::Acquire)
    }

    /// The immutable entry address captured at compilation time.
    pub fn entry(&self) -> *const u8 {
        self.entry_addr as *const u8
    }
}

/// True when `insn` transfers control (and therefore establishes RIP itself
/// or asks the dispatcher to do so).
pub(super) fn instruction_controls_rip(insn: &IrInstruction) -> bool {
    matches!(
        insn,
        IrInstruction::Jump { .. }
            | IrInstruction::JumpIf { .. }
            | IrInstruction::JumpRegister { .. }
            | IrInstruction::JumpMemory { .. }
            | IrInstruction::Return { .. }
            | IrInstruction::Call { .. }
            | IrInstruction::CallRegister { .. }
            | IrInstruction::CallMemory { .. }
    )
}

pub(super) fn block_ends_in_control_flow(ir: &[IrInstruction]) -> bool {
    ir.last().is_some_and(instruction_controls_rip)
}

/// Conservative guest-byte extent of a translated block.
///
/// IR does not retain each x86 instruction's encoded length, so the extent is
/// bounded by the architectural maximum (15 bytes) per instruction.  This is
/// used only for self-modifying-code page attribution; over-approximating can
/// invalidate a neighbouring block conservatively, never miss a real write.
pub(super) fn block_guest_span(block: &JitCompiledBlock) -> u64 {
    (block.instruction_count as u64).saturating_mul(15).max(1)
}

/// A production worker slice may execute a block only when it is fully
/// self-contained: no interpreter-helper fallback (which needs a live
/// `MemoryImage`), and no instruction that exits the block MID-WAY for the
/// interpreter to re-run (which would double-execute the already-run prefix).
///
/// Guest `call`/`ret`/indirect `jmp` are NOT barriers any more: the
/// worker-program compiler lowers them to self-contained native exits whose
/// target is carried in the per-thread exit cell, and the worker resolves the
/// continuation itself (return-stack predictor / inline cache).  A direct
/// `Call` whose target is a HOST thunk still yields at run time, because the
/// worker finds no compiled block for it and reports a host barrier — the
/// runtime owner then executes the thunk exactly once.
pub(super) fn block_is_worker_safe(ir: &[IrInstruction], used_interpreter_helper: bool) -> bool {
    if used_interpreter_helper {
        return false;
    }
    !ir.iter().any(|insn| {
        matches!(
            insn,
            IrInstruction::Cpuid
                | IrInstruction::Xgetbv
                | IrInstruction::Fxsave { .. }
                | IrInstruction::Fxrstor { .. }
        )
    })
}

/// Result of executing a JIT-compiled block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitExitReason {
    /// Block completed normally; RIP has been updated.
    Normal { new_rip: u64 },
    /// Block hit a thunk/import that needs host dispatch.
    ThunkDispatch { target_rip: u64, return_rip: u64 },
    /// Block hit an unimplemented instruction.
    UnimplementedInstruction { rip: u64, opcode: u8 },
    /// Block hit a conditional branch (needs host flag computation).
    ConditionalBranch { rip: u64, taken: bool },
    /// Block hit a direct CALL to a known guest address.
    ///
    /// The worker pushes `return_address` on the guest stack and continues at
    /// `target` when that address has a compiled worker block; when it does
    /// not (e.g. a host thunk), the worker reports a host barrier with the
    /// thunk as RIP so the runtime owner executes it exactly once.
    DirectCall { target: u64, return_address: u64 },
    /// Block hit a CALL instruction to an indirect target.
    ///
    /// `target` is the resolved callee address.  When `target_is_pointer` is
    /// true the compiled block could not dereference the memory operand itself
    /// (no live `MemoryImage` on a production worker), so the worker must load
    /// the callee address from guest memory at `target` before transferring.
    IndirectCall {
        target: u64,
        return_address: u64,
        target_is_pointer: bool,
    },
    /// Block hit an indirect JMP (register or memory operand).  See
    /// [`Self::IndirectCall`] for the `target_is_pointer` convention.
    IndirectJump {
        target: u64,
        target_is_pointer: bool,
    },
    /// Block hit a RET instruction.  The compiled gate stores the raw exit
    /// code in `return_rip`; a production worker reads the real return address
    /// from guest `[rsp]` (via the slice memory view) and pops the stack, so
    /// this field is diagnostic only on the worker path.
    Return { return_rip: u64 },
    /// Block needs host-side memory access (slow path).
    MemoryAccess {
        address: u64,
        is_write: bool,
        width: usize,
    },
    /// Block hit CPUID.
    Cpuid,
    /// Block needs host-side exception handling.
    Exception { code: u32, address: u64 },
    /// Block ended in an unconditional Jump: the JIT never writes
    /// state.rip for jumps, so the dispatcher must set RIP to `target`
    /// and dispatch the target block next.
    Jump { target: u64 },
    /// A native `Jcc` decided the branch was taken.  `rip` is the block's
    /// address; the dispatcher derives target/fallthrough from the block's
    /// static [`BlockExitInfo`].
    ConditionalTaken { rip: u64 },
    /// A native `Jcc` decided the branch was not taken.
    ConditionalNotTaken { rip: u64 },
    /// The link budget was exhausted at a block entry.  The block did not run;
    /// the dispatcher refills the budget and re-dispatches `rip`.
    LinkBudget { rip: u64 },
    /// A guest store changed compiled-code bytes.  The block at `rip` did not
    /// run; the dispatcher must invalidate stale translations before
    /// re-dispatching it.
    CodeEpoch { rip: u64 },
    /// A direct call whose return address was already pushed by the compiled
    /// block.  The worker must not push again.
    DirectCallPushed { target: u64, return_address: u64 },
    /// A native worker return that already popped the guest stack.  `target`
    /// is the return address read from guest `[rsp]`.
    ReturnResolved { target: u64 },
    /// Block hit the host safepoint flag (see `JIT_SAFEPOINT_REQUESTED`):
    /// the dispatcher must run the host-side safepoint body (pump pending
    /// guest threads, drain timers/APCs, advance the guest clock) and then
    /// re-dispatch the block.
    Safepoint,
    /// A guest load/store faulted on unmapped memory.  The block aborted at
    /// the faulting instruction (the emitted post-helper fault test branched
    /// here before any later instruction ran); the dispatcher must raise the
    /// access violation immediately, using `state.jit_pending_fault` (the
    /// precise fault address) and `state.jit_pending_fault_write` (the
    /// access type).
    GuestFault,
}

/// Static control-flow metadata captured at compile time for a block's
/// final instruction, so the dispatcher can reconstruct guest RIP for
/// jump-family JIT exits — the compiled code records only an exit code
/// and never writes `state.rip` for these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockExitInfo {
    /// Last instruction was an unconditional `Jump`.
    Jump { target: u64 },
    /// Last instruction was a `JumpIf` — the dispatcher evaluates the
    /// condition against `state.flags` and sets RIP to `target` or
    /// `fallthrough`.
    JumpIf {
        condition: ConditionCode,
        target: u64,
        fallthrough: u64,
    },
    /// Last instruction was a `Return` (guest `ret [imm16]`).  The worker pops
    /// the return address from guest `[rsp]` and adds `8 + stack_adjust` to
    /// `rsp`, matching the interpreter.
    Return { stack_adjust: u64 },
    /// Last instruction was a direct `Call` to `target`.  The worker pushes
    /// `return_address` (already the address after the `call`) so a matching
    /// `Return` can pop it from the return-stack predictor / guest stack.
    Call { target: u64, return_address: u64 },
    /// Last instruction was an indirect `CallRegister` / `CallMemory`.  The
    /// callee target arrives in the [`JitExitReason::IndirectCall`] payload;
    /// `return_address` is static.
    CallIndirect { return_address: u64 },
}

/// Extract the [`BlockExitInfo`] for a compiled IR sequence, if its final
/// instruction is a jump-family instruction.
pub(super) fn block_exit_info(ir: &[IrInstruction]) -> Option<BlockExitInfo> {
    match ir.last() {
        Some(IrInstruction::Jump { target }) => Some(BlockExitInfo::Jump { target: *target }),
        Some(IrInstruction::JumpIf {
            condition,
            target,
            fallthrough,
        }) => Some(BlockExitInfo::JumpIf {
            condition: *condition,
            target: *target,
            fallthrough: *fallthrough,
        }),
        Some(IrInstruction::Return { stack_adjust }) => Some(BlockExitInfo::Return {
            stack_adjust: *stack_adjust,
        }),
        Some(IrInstruction::Call {
            target,
            return_address,
        }) => Some(BlockExitInfo::Call {
            target: *target,
            return_address: *return_address,
        }),
        Some(IrInstruction::CallRegister { return_address, .. })
        | Some(IrInstruction::CallMemory { return_address, .. }) => {
            Some(BlockExitInfo::CallIndirect {
                return_address: *return_address,
            })
        }
        _ => None,
    }
}

/// Compute a simple hash of IR instructions for self-modifying code detection.
/// This is used as a lightweight integrity check: if the guest modifies the
/// source bytes, the new IR will differ and produce a different hash.
///
/// Hashes the guest address and the Debug representation of each instruction,
/// which captures both the opcode AND its operand values (registers, immediates,
/// etc.). This ensures that changing any operand (e.g., `MovImm { value: 42 }`
/// vs `MovImm { value: 99 }`) produces a different hash.
pub(super) fn compute_ir_hash(ir: &[IrInstruction], guest_address: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    guest_address.hash(&mut hasher);
    for insn in ir {
        // Use the full Debug output to capture both the variant AND all fields.
        let repr = format!("{:?}", insn);
        repr.len().hash(&mut hasher);
        for b in repr.bytes() {
            b.hash(&mut hasher);
        }
    }
    hasher.finish()
}

// ---------------------------------------------------------------------------
// JIT runtime: manages compiled blocks and dispatches execution
// ---------------------------------------------------------------------------

/// Runtime state for JIT execution.
pub struct JitRuntime {
    pub compiler: JitCompiler,
    pub flat_memory: FlatGuestMemory,
    /// Cache of compiled blocks keyed by guest address.
    pub block_cache: HashMap<u64, JitCompiledBlock>,
    /// Deliberately unlinked blocks compiled for production worker slices.
    /// Kept separate from `block_cache` so worker execution never inherits a
    /// published chain that could bypass the per-slice budget/thunk barrier.
    pub(crate) slice_block_cache: HashMap<u64, JitCompiledBlock>,
    /// Monotonic generation of the worker slice cache.  Bumped whenever a
    /// cached worker block is removed, so a persistent worker slot can drop
    /// stale return-predictor/inline-cache entries before reusing them.
    pub(super) slice_epoch: u64,
    /// FIFO access-order queue for LRU eviction of compiled blocks.
    /// Front = least recently used (next to evict), back = most recently used.
    pub block_access_order: VecDeque<u64>,
    /// Maximum number of compiled blocks allowed in the cache before eviction.
    pub max_blocks: usize,
    /// Number of blocks compiled.
    pub blocks_compiled: u64,
    /// Number of blocks executed via JIT.
    pub blocks_executed: u64,
    /// Number of fallbacks to IR interpreter — incremented when JIT cannot
    /// compile a block, causing fall-through to the IR interpreter.
    pub interpreter_fallbacks: u64,
    /// Compiled blocks removed by self-modifying-code invalidation.
    pub code_invalidations: u64,
    /// Number of SMC drain cycles that invalidated at least one block.
    pub smc_invalidation_events: u64,
    /// Blocks compiled at each tier.
    pub tier0_compiles: u64,
    pub tier1_compiles: u64,
    pub tier2_compiles: u64,
    /// Whole-function Tier-2 promotions (multi-block SSA compiles).
    pub tier2_function_compiles: u64,
    /// Tier-2 function attempts that fell back to Tier-0.
    pub tier2_function_fallbacks: u64,
    /// Links published / cleared in this runtime.
    pub chain_links_formed: u64,
    pub chain_links_broken: u64,
    /// Blocks that took the fault-equivalent fallback path (invalid block
    /// installation / faulted entry) and were handed to the interpreter.
    pub fault_fallbacks: u64,
    /// Persistent AOT translated-code cache counters.
    pub aot_hits: u64,
    pub aot_misses: u64,
    pub aot_rejected: u64,
    /// Directory used to persist/reload translated worker blocks.  `None`
    /// disables the cache (useful for deterministic tests).
    pub(crate) aot_cache_dir: Option<std::path::PathBuf>,
    /// Guest addresses permanently barred from native compilation after a
    /// fault-equivalent event; the interpreter handles them for the rest of
    /// the run.
    pub faulted_blocks: BTreeSet<u64>,
    /// Block chain entries keyed by (from_address, to_address).
    pub block_chains: BTreeMap<(u64, u64), BlockChainEntry>,
    /// Fast thunk table: ARM64 trampolines for direct host-function calls
    /// from JIT-compiled guest code, bypassing the full dispatch loop.
    pub fast_thunk_table: FastThunkTable,
    /// Unwind table for JIT-compiled blocks, enabling SEH stack walks
    /// through JIT frames via `RtlVirtualUnwind`.
    pub unwind_table: JitUnwindTable,
    /// Tracks which 4K guest pages have one or more compiled blocks.
    /// Used for self-modifying code detection: when guest code writes to a
    /// page in this set, the affected blocks must be invalidated and recompiled.
    pub code_pages: BTreeSet<u64>,
    /// Lock-free watch/dirty state read by `jit_helper_store` while this
    /// runtime is executing on the current thread.
    pub(super) smc: Box<SmcState>,
    /// Set of guest page addresses (4K-aligned) that have been synced from
    /// MemoryImage into the flat memory region. Used for incremental sync:
    /// only new pages are copied on each block execution instead of all
    /// committed pages, reducing per-block overhead from O(N) to O(delta).
    pub(super) synced_pages: BTreeSet<u64>,
    /// Whether the SIGBUS handler is currently installed for this runtime.
    /// Kept persistent across block executions to eliminate per-block
    /// sigaction syscalls (two per block × thousands of blocks = significant
    /// overhead).
    pub(super) sigbus_installed: bool,
}

impl JitRuntime {
    pub fn new(arch: GuestArch) -> Self {
        let aot_cache_dir = match std::env::var("CASA1_AOT_CACHE_DIR") {
            Ok(value) if value.eq_ignore_ascii_case("off") => None,
            Ok(value) if !value.is_empty() => Some(std::path::PathBuf::from(value)),
            // Tests opt into the cache explicitly with a fresh directory, so a
            // run can never observe code persisted by an older build.
            #[cfg(test)]
            _ => None,
            #[cfg(not(test))]
            _ => Some(std::env::temp_dir().join(format!("casa1-aot-v{AOT_TRANSLATOR_VERSION}"))),
        };
        Self {
            compiler: JitCompiler::new(),
            flat_memory: FlatGuestMemory::new(arch),
            block_cache: HashMap::new(),
            slice_block_cache: HashMap::new(),
            slice_epoch: 0,
            block_access_order: VecDeque::new(),
            max_blocks: 8192,
            blocks_compiled: 0,
            blocks_executed: 0,
            interpreter_fallbacks: 0, // Initialized to zero; incremented on each JIT fallback
            code_invalidations: 0,
            smc_invalidation_events: 0,
            tier0_compiles: 0,
            tier1_compiles: 0,
            tier2_compiles: 0,
            tier2_function_compiles: 0,
            tier2_function_fallbacks: 0,
            chain_links_formed: 0,
            chain_links_broken: 0,
            fault_fallbacks: 0,
            aot_hits: 0,
            aot_misses: 0,
            aot_rejected: 0,
            aot_cache_dir,
            faulted_blocks: BTreeSet::new(),
            block_chains: BTreeMap::new(),
            fast_thunk_table: FastThunkTable::new(),
            unwind_table: JitUnwindTable::new(),
            code_pages: BTreeSet::new(),
            smc: Box::new(SmcState::new()),
            synced_pages: BTreeSet::new(),
            sigbus_installed: false,
        }
    }

    /// Override (or disable) the persistent AOT cache directory.
    pub fn set_aot_cache_dir(&mut self, directory: Option<std::path::PathBuf>) {
        self.aot_cache_dir = directory;
    }

    /// `(hits, misses, rejected)` for the persistent AOT cache.
    pub fn aot_metrics(&self) -> (u64, u64, u64) {
        (self.aot_hits, self.aot_misses, self.aot_rejected)
    }

    /// Get or compile a JIT block for the given guest address.
    ///
    /// After compiling a new block, attempts to auto-chain if the last
    /// IR instruction is an unconditional `Jump { target }` and the
    /// target block is already compiled.
    /// `fast_thunk_addrs` — optional set of guest thunk addresses that have
    /// fast-thunk ARM64 trampolines registered (see [`FastThunkTable`]).
    /// Passed through to the compiler so that `Call` instructions whose target
    /// is a registered host thunk can emit direct trampoline calls.
    pub fn get_or_compile(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
    ) -> AppResult<&JitCompiledBlock> {
        self.get_or_compile_at_tier(
            ir,
            guest_address,
            arch,
            CompilationTier::Tier0,
            fast_thunk_addrs,
        )
    }

    /// Compile (or reuse) a whole hot function at Tier-2.
    ///
    /// `blocks` is ordered with the entry block first, exactly as produced by
    /// [`crate::jit_ssa::optimize_function`].  Returns `None` when the SSA
    /// front end rejected the function (unsupported construct); the caller
    /// then keeps per-block Tier-0/Tier-1 code.
    pub fn get_or_compile_function_tier2(
        &mut self,
        blocks: &[crate::jit_ssa::FunctionBlock],
        arch: GuestArch,
    ) -> AppResult<Option<&JitCompiledBlock>> {
        let Some(entry) = blocks.first().map(|block| block.guest_address) else {
            return Ok(None);
        };
        if let Some(existing) = self.block_cache.get(&entry)
            && existing.compile_tier == CompilationTier::Tier2
        {
            return Ok(self.block_cache.get(&entry));
        }
        let compiled = self.compiler.compile_function_tier2(blocks, arch)?;
        if compiled.compile_tier != CompilationTier::Tier2 {
            self.tier2_function_fallbacks += 1;
            return Ok(None);
        }
        self.tier2_function_compiles += 1;
        self.blocks_compiled += 1;
        for block in blocks {
            let page = block.guest_address & !0xfff;
            self.code_pages.insert(page);
        }
        self.block_access_order.retain(|address| *address != entry);
        self.block_access_order.push_back(entry);
        let guest_end = blocks
            .iter()
            .map(|block| block.guest_address + (block.instructions.len() as u64) * 15)
            .max()
            .unwrap_or(entry + 1);
        self.unwind_table.register_block(entry, guest_end);
        self.block_cache.insert(entry, compiled);
        self.smc.rebuild_watch(self.code_pages.iter());
        Ok(self.block_cache.get(&entry))
    }

    /// Snapshot of the global SSA metrics plus this runtime's Tier-2 function
    /// counters.
    pub fn tier2_metrics_snapshot(&self) -> crate::jit_ssa::Tier2Metrics {
        let mut metrics = crate::jit_ssa::tier2_metrics();
        metrics.functions_compiled = self.tier2_function_compiles;
        metrics.functions_fallback = self.tier2_function_fallbacks;
        metrics
    }

    /// Get or compile a block at an explicit optimization tier.
    ///
    /// The PE dispatcher calls this when [`TieredCompiler::record_execution`]
    /// crosses a threshold (Tier0 at 50 dispatches, Tier1 at 500): an already
    /// cached block compiled at a lower tier is invalidated and recompiled
    /// with the real optimizer (`constant_fold` + DCE at Tier1; whole-block
    /// SSA with GVN/SCCP/DCE/LICM and load-store forwarding at Tier2) instead
    /// of returning the identical Tier0 code.
    pub fn get_or_compile_at_tier(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
        tier: CompilationTier,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
    ) -> AppResult<&JitCompiledBlock> {
        // A block that faulted (invalid installation / unwind path) stays on
        // the interpreter for the rest of the run: refusing compilation here
        // makes the dispatcher's `.is_ok()` check fail and fall through to
        // the AOT path for exactly this block.
        if self.faulted_blocks.contains(&guest_address) {
            #[cfg(test)]
            let ignore_bar = JIT_TEST_IGNORE_FAULTED_BLOCKS.with(|ignore| ignore.replace(false));
            #[cfg(not(test))]
            let ignore_bar = false;
            if !ignore_bar {
                self.interpreter_fallbacks += 1;
                return Err(AppError::new(
                    ReasonCode::RcJitCompilationError,
                    format!("JIT block {guest_address:#x} previously faulted; using interpreter"),
                ));
            }
        }

        // Self-modifying code: invalidate every block whose guest page was
        // written by a native guest store before deciding whether this block
        // is still current.
        self.drain_smc_invalidations();

        // Check for self-modifying code: if a block already exists but its
        // source hash doesn't match the current IR, the guest has modified
        // the code since compilation — invalidate and recompile.
        let mut recompile = false;
        if let Some(existing) = self.block_cache.get(&guest_address) {
            let current_hash = compute_ir_hash(ir, guest_address);
            if existing.source_hash != 0 && existing.source_hash != current_hash {
                eprintln!(
                    "[jit] self-modifying code detected at {:#x}: recompiling (hash mismatch)",
                    guest_address
                );
                recompile = true;
            } else if existing.compile_tier < tier {
                // Real tier promotion: replace the cached block with the
                // optimized compilation.
                recompile = true;
            } else {
                // Block is valid and being accessed — promote to back of
                // the LRU access-order queue.
                self.record_block_access(guest_address);
            }
        }
        if recompile {
            self.invalidate_block(guest_address);
        }

        let is_new = !self.block_cache.contains_key(&guest_address);
        if is_new {
            // ── Whole-block compilability check ──────────────────────────
            // Only compile a block if EVERY instruction can be JIT-compiled.
            // If any instruction can't, leave the block uncompiled (is_compiled
            // stays false) so the interpreter runs the WHOLE block cleanly.
            // Partially-compiled blocks double-execute (JIT runs the prefix,
            // then EXIT_UNIMPL re-runs the whole block in the interpreter),
            // corrupting guest state.
            if !crate::jit::JitCompiler::can_compile_block(ir) {
                self.interpreter_fallbacks += 1;
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    "block contains an instruction the JIT cannot compile",
                ));
            }

            // Resolved thunk addresses: unknown callers pass `None`, so the
            // runtime's own registration table is the source of truth.  This
            // is what turns a registered guest thunk into a direct native
            // call instead of an EXIT_THUNK dispatcher round-trip.
            let resolved_thunks = match fast_thunk_addrs {
                Some(addrs) => Some(addrs.clone()),
                None => {
                    let addrs = self.fast_thunk_table.guest_addrs();
                    (!addrs.is_empty()).then_some(addrs)
                }
            };

            // Persistent AOT first: a validated record bound to this exact
            // IR + address + translator/CPU generation avoids recompilation.
            // Only unlinked Tier-0 records are installed here; hot-path tier
            // promotion still recompiles from IR.
            let mut aot_block = None;
            if matches!(tier, CompilationTier::Tier0) && self.aot_cache_dir.is_some() {
                let source_hash = compute_ir_hash(ir, guest_address);
                match self.load_aot_slice_block(ir, guest_address, source_hash, arch) {
                    Ok(Some(block)) => {
                        self.aot_hits += 1;
                        aot_block = Some(block);
                    }
                    Ok(None) => self.aot_misses += 1,
                    Err(error) => {
                        self.aot_rejected += 1;
                        eprintln!("[jit] AOT cache rejected for {guest_address:#x}: {error}");
                        if let Some(path) = self.aot_path(source_hash, guest_address) {
                            let _ = std::fs::remove_file(path);
                        }
                    }
                }
            }
            let loaded_aot = aot_block.is_some();
            let block = if let Some(block) = aot_block {
                block
            } else {
                match tier {
                    CompilationTier::Tier0 => {
                        self.tier0_compiles += 1;
                        self.compiler.compile_block(
                            ir,
                            guest_address,
                            arch,
                            resolved_thunks.as_ref(),
                        )?
                    }
                    CompilationTier::Tier1 => {
                        self.tier1_compiles += 1;
                        self.compiler.compile_tier1(
                            ir,
                            guest_address,
                            arch,
                            resolved_thunks.as_ref(),
                        )?
                    }
                    CompilationTier::Tier2 => {
                        self.tier2_compiles += 1;
                        self.compiler.compile_tier2(
                            ir,
                            guest_address,
                            arch,
                            resolved_thunks.as_ref(),
                        )?
                    }
                }
            };
            if !loaded_aot {
                self.blocks_compiled += 1;
            }

            // Track which 4K guest pages this compiled block occupies,
            // for self-modifying code detection.
            let guest_end = guest_address + (ir.len() as u64).saturating_mul(15).max(1);
            let start_page = guest_address & !0xfff;
            let end_page = (guest_end - 1) & !0xfff;
            let mut page = start_page;
            while page <= end_page {
                self.code_pages.insert(page);
                page += 0x1000;
            }
            self.smc.rebuild_watch(self.code_pages.iter());

            // Register this block's address range with the unwind table
            // so that SEH stack walks can unwind through JIT frames.
            self.unwind_table.register_block(guest_address, guest_end);

            self.block_cache.insert(guest_address, block);
            // New block is the most recently used — add to back of access order.
            self.block_access_order.push_back(guest_address);

            // Evict the least-recently-used block if the cache exceeds max_blocks.
            self.evict_if_needed();

            // Auto-chain: if the last instruction is an unconditional jump
            // to a block that is already compiled, chain them.  Backward
            // (loop) edges are allowed — the target prologue polls the host
            // safepoint, and the source block pops its own host frame before
            // the branch, so a chained loop neither loses interruptibility
            // nor drifts the host stack pointer.
            if let Some(last_ir) = ir.last()
                && let IrInstruction::Jump { target } = last_ir
            {
                // Skip auto-chaining when a chain break has been
                // requested — see JIT_CHAIN_BREAK_REQUESTED.
                if !JIT_CHAIN_BREAK_REQUESTED.load(Ordering::Relaxed)
                    && self.block_cache.contains_key(target)
                    && let Err(e) = self.chain_blocks(guest_address, *target)
                {
                    eprintln!(
                        "[jit] failed to chain block {:#x} -> {:#x}: {}",
                        guest_address, target, e
                    );
                }
            }
        }
        Ok(self.block_cache.get(&guest_address).unwrap())
    }

    /// Compile (or fetch) a deliberately unlinked block for production worker
    /// slices.
    ///
    /// The persistent AOT cache is consulted first: a record keyed by guest
    /// code hash + translator version + target CPU + optimization profile is
    /// loaded, validated and re-bound to this process.  A missing record
    /// compiles normally and is persisted; a corrupt/incompatible record is
    /// counted as `aot_rejected` and compilation proceeds from IR.
    pub(crate) fn get_or_compile_slice_block(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
    ) -> AppResult<&JitCompiledBlock> {
        if !self.slice_block_cache.contains_key(&guest_address) {
            let source_hash = compute_ir_hash(ir, guest_address);
            let cache_enabled = self.aot_cache_dir.is_some();
            if cache_enabled {
                match self.load_aot_slice_block(ir, guest_address, source_hash, arch) {
                    Ok(Some(block)) => {
                        self.aot_hits += 1;
                        self.note_slice_code_pages(&block);
                        self.slice_block_cache.insert(guest_address, block);
                    }
                    Ok(None) => {
                        self.aot_misses += 1;
                        let block = self
                            .compiler
                            .compile_worker_block(ir, guest_address, arch)?;
                        self.persist_aot_slice_block(&block, source_hash);
                        self.slice_block_cache.insert(guest_address, block);
                    }
                    Err(error) => {
                        self.aot_rejected += 1;
                        eprintln!("[jit] AOT cache rejected for {guest_address:#x}: {error}");
                        if let Some(path) = self.aot_path(source_hash, guest_address) {
                            let _ = std::fs::remove_file(path);
                        }
                        let block = self
                            .compiler
                            .compile_worker_block(ir, guest_address, arch)?;
                        self.persist_aot_slice_block(&block, source_hash);
                        self.note_slice_code_pages(&block);
                        self.slice_block_cache.insert(guest_address, block);
                    }
                }
            } else {
                let block = self
                    .compiler
                    .compile_worker_block(ir, guest_address, arch)?;
                self.note_slice_code_pages(&block);
                self.slice_block_cache.insert(guest_address, block);
            }
        }
        Ok(self
            .slice_block_cache
            .get(&guest_address)
            .expect("slice block inserted above"))
    }

    pub(super) fn note_slice_code_pages(&mut self, block: &JitCompiledBlock) {
        let end = block.guest_address.saturating_add(block_guest_span(block));
        let mut page = block.guest_address & !0xfff;
        let last = end.saturating_sub(1) & !0xfff;
        while page <= last {
            self.code_pages.insert(page);
            page = page.saturating_add(0x1000);
        }
        self.smc.rebuild_watch(self.code_pages.iter());
    }

    pub(super) fn aot_path(
        &self,
        code_hash: u64,
        guest_address: u64,
    ) -> Option<std::path::PathBuf> {
        self.aot_cache_dir.as_ref().map(|directory| {
            directory.join(format!(
                "aot-{code_hash:016x}-{guest_address:016x}-t{}-c{:016x}-o{}.bin",
                AOT_TRANSLATOR_VERSION,
                aot_target_cpu_profile(),
                AOT_SLICE_OPT_PROFILE
            ))
        })
    }

    pub(super) fn load_aot_slice_block(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        source_hash: u64,
        _arch: GuestArch,
    ) -> AppResult<Option<JitCompiledBlock>> {
        let Some(path) = self.aot_path(source_hash, guest_address) else {
            return Ok(None);
        };
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(AppError::new(
                    ReasonCode::RcJitCompilationError,
                    format!("AOT cache read failed: {error}"),
                ));
            }
        };
        // Bound the read before decoding; a cache file is code-sized.
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "AOT cache record is implausibly large",
            ));
        }
        let record = AotRecord::decode(&bytes).map_err(|reason| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("malformed AOT cache record: {reason}"),
            )
        })?;
        if record.optimization_profile != AOT_SLICE_OPT_PROFILE
            || record.guest_address != guest_address
            || record.code_hash != source_hash
            || record.instruction_count != ir.len() as u64
        {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "AOT cache record does not match this translation",
            ));
        }
        self.compiler.install_aot_record(&record).map(Some)
    }

    pub(super) fn persist_aot_slice_block(&mut self, block: &JitCompiledBlock, source_hash: u64) {
        if !block.worker_safe {
            return;
        }
        let Some(path) = self.aot_path(source_hash, block.guest_address) else {
            return;
        };
        let Some(directory) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(directory).is_err() {
            return;
        }
        let entry = block.published_entry();
        if entry.is_null() {
            return;
        }
        // SAFETY: the entry was produced by this runtime and finalized; its
        // code_size bytes remain mapped and immutable for the block lifetime.
        let code =
            unsafe { std::slice::from_raw_parts(entry as *const u8, block.code_size) }.to_vec();
        let relocations = self.compiler.relocations.clone();
        if relocations
            .iter()
            .any(|relocation| relocation.offset as usize + 16 > code.len())
        {
            return;
        }
        let mut logical = code.clone();
        for relocation in &relocations {
            let offset = relocation.offset as usize;
            logical[offset..offset + 16].fill(0);
        }
        let record = AotRecord {
            format: AOT_FORMAT_VERSION,
            translator: AOT_TRANSLATOR_VERSION,
            machine: AotRecord::machine_tag(),
            cpu_profile: aot_target_cpu_profile(),
            optimization_profile: AOT_SLICE_OPT_PROFILE,
            guest_address: block.guest_address,
            code_hash: source_hash,
            logical_code_hash: fnv1a(&logical),
            instruction_count: block.instruction_count as u64,
            code_size: code.len() as u32,
            worker_safe: block.worker_safe,
            exit_info: block.last_exit_info,
            code,
            relocations,
        };
        let encoded = record.encode();
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        if std::fs::write(&temporary, encoded).is_ok() {
            let _ = std::fs::rename(&temporary, &path);
        }
    }

    pub(crate) fn slice_block(&self, guest_address: u64) -> Option<&JitCompiledBlock> {
        self.slice_block_cache.get(&guest_address)
    }

    pub(crate) fn clear_slice_blocks(&mut self) {
        for block in self.slice_block_cache.values() {
            block.link_target.store(0, Ordering::Release);
            block.taken_link.store(0, Ordering::Release);
            block.fallthrough_link.store(0, Ordering::Release);
            block.call_link.store(0, Ordering::Release);
            block.return_entry_link.store(0, Ordering::Release);
        }
        self.slice_block_cache.clear();
        self.slice_epoch = self.slice_epoch.wrapping_add(1);
        JIT_CODE_EPOCH.fetch_add(1, Ordering::AcqRel);
    }

    /// Publish every static successor edge between cached worker blocks.
    ///
    /// Direct jumps, both `Jcc` arms, direct calls and their static return
    /// successors get independent atomic link slots.  Nothing here patches
    /// instruction memory: an executor either observes the old zero slot or
    /// the new entry, and invalidation clears the slots before the cache is
    /// dropped.
    pub(super) fn publish_slice_links(&self) {
        // Only blocks whose terminator is statically described may be a
        // native link target: entering a straight-line block would leave the
        // worker without a successor RIP and force a re-dispatch of code it
        // already executed.
        let entries: HashMap<u64, u64> = self
            .slice_block_cache
            .iter()
            .filter(|(_, block)| block.worker_safe && block.last_exit_info.is_some())
            .map(|(address, block)| (*address, block.entry() as u64))
            .collect();
        for block in self.slice_block_cache.values() {
            if !block.worker_safe {
                continue;
            }
            let entry = |target: &u64| entries.get(target).copied().unwrap_or(0);
            match block.last_exit_info {
                Some(BlockExitInfo::Jump { target }) => {
                    block.link_target.store(entry(&target), Ordering::Release);
                }
                Some(BlockExitInfo::JumpIf {
                    target,
                    fallthrough,
                    ..
                }) => {
                    block.taken_link.store(entry(&target), Ordering::Release);
                    block
                        .fallthrough_link
                        .store(entry(&fallthrough), Ordering::Release);
                }
                Some(BlockExitInfo::Call {
                    target,
                    return_address,
                }) => {
                    block.call_link.store(entry(&target), Ordering::Release);
                    block
                        .return_entry_link
                        .store(entry(&return_address), Ordering::Release);
                }
                Some(BlockExitInfo::CallIndirect { return_address }) => {
                    block
                        .return_entry_link
                        .store(entry(&return_address), Ordering::Release);
                }
                _ => {}
            }
        }
    }

    /// Build the immutable program a production worker executes.  The
    /// memory view aliases the canonical store; no bytes are copied.
    pub(crate) fn build_slice_program(&self, memory: &MemoryImage) -> GuestSliceProgram {
        self.publish_slice_links();
        let view = Arc::new(GuestSliceMemory::new(memory, self.code_pages.clone()));
        GuestSliceProgram {
            blocks: self.slice_block_cache.clone(),
            flat_base: view.flat_base(),
            memory: view,
            mechanism: self.compiler.memory_manager.mechanism(),
            epoch: self.slice_epoch,
        }
    }

    /// Drain self-modifying-code dirty pages and invalidate every cached
    /// block that overlaps them.  Returns the invalidated guest addresses.
    pub fn drain_smc_invalidations(&mut self) -> Vec<u64> {
        let (pages, overflow) = self.smc.take_dirty();
        #[cfg(test)]
        if !pages.is_empty() || overflow {
            match JIT_TEST_SMC_FAULT.with(|fault| fault.replace(0)) {
                1 => return Vec::new(),
                2 => {
                    self.block_cache.clear();
                    self.block_access_order.clear();
                    return Vec::new();
                }
                _ => {}
            }
        }
        if pages.is_empty() && !overflow {
            return Vec::new();
        }
        // Overflow means the bounded dirty ring wrapped: some written page is
        // unknown, so conservative whole-cache invalidation is required.
        let affected: Vec<u64> = if overflow {
            let all: Vec<u64> = self.block_cache.keys().copied().collect();
            for address in &all {
                self.invalidate_block(*address);
            }
            all
        } else {
            let dirty: BTreeSet<u64> = pages.into_iter().collect();
            self.invalidate_blocks_on_pages(&dirty)
        };
        if !affected.is_empty() || overflow {
            self.smc_invalidation_events += 1;
        }
        affected
    }

    /// Fault-equivalent fallback: a block that could not be installed safely
    /// (or whose entry faulted) is removed from the cache and permanently
    /// barred from native compilation.  The dispatcher then executes that
    /// block through the IR interpreter; nothing aborts.
    pub fn report_block_fault(&mut self, guest_address: u64) {
        self.fault_fallbacks += 1;
        self.faulted_blocks.insert(guest_address);
        if self.is_compiled(guest_address) {
            self.invalidate_block(guest_address);
        }
        eprintln!(
            "[jit] block {:#x} faulted; falling back to the interpreter for this block",
            guest_address
        );
    }

    /// Invalidate a compiled block, removing it from the block cache and
    /// unregistering its unwind info from the unwind table.
    ///
    /// This should be called when a block needs to be recompiled (e.g., due
    /// to self-modifying code). After invalidation, [`get_or_compile()`] will
    /// recompile the block on the next execution.
    ///
    /// The caller is responsible for syncing the updated unwind table to the
    /// SEH subsystem via [`JitUnwindTable::register_with_seh`].
    pub fn invalidate_block(&mut self, guest_address: u64) {
        if let Some(block) = self.slice_block_cache.remove(&guest_address) {
            block.link_target.store(0, Ordering::Release);
            block.taken_link.store(0, Ordering::Release);
            block.fallthrough_link.store(0, Ordering::Release);
            block.call_link.store(0, Ordering::Release);
            block.return_entry_link.store(0, Ordering::Release);
            self.slice_epoch = self.slice_epoch.wrapping_add(1);
        }
        if let Some(block) = self.block_cache.remove(&guest_address) {
            // Remove from the access-order queue so stale entries don't
            // accumulate and cause incorrect evictions.
            self.block_access_order.retain(|&a| a != guest_address);

            // Unchaining is best-effort cleanup; failure means no chain existed
            if let Err(error) = self.unchain_target(guest_address) {
                eprintln!(
                    "[jit] failed to unchain invalidated block {:#x}: {}",
                    guest_address, error
                );
            }
            // A block that is no longer cached can never be entered through
            // its own link slot; clear it so no stale target can be observed.
            if block.link_target.swap(0, Ordering::AcqRel) != 0 {
                self.chain_links_broken += 1;
            }
            self.unwind_table.unregister_block(guest_address);
            // Rebuild code_pages from remaining blocks so we don't leave
            // stale page entries after invalidation.
            self.rebuild_code_pages();
            self.smc.rebuild_watch(self.code_pages.iter());
            self.code_invalidations += 1;
            eprintln!(
                "[jit] invalidated block {:#x}: removed from cache and unwind table (code_size={})",
                guest_address, block.code_size
            );
        }
    }

    /// Record that a block was accessed, promoting it to the back of the
    /// LRU access-order queue.  If the block is not already in the queue
    /// (shouldn't normally happen for valid blocks), it is appended.
    ///
    /// This is O(n) in the number of cached blocks (bounded by `max_blocks`),
    /// but block compilation and invalidation dominate actual costs.
    pub(super) fn record_block_access(&mut self, guest_address: u64) {
        if let Some(pos) = self
            .block_access_order
            .iter()
            .position(|&a| a == guest_address)
        {
            self.block_access_order.remove(pos);
        }
        self.block_access_order.push_back(guest_address);
    }

    /// If the block cache has exceeded `max_blocks`, evict the
    /// least-recently-used block (front of `block_access_order`).
    ///
    /// Stale entries (addresses no longer in `block_cache`) are cleaned up
    /// opportunistically during eviction.
    pub(super) fn evict_if_needed(&mut self) {
        while self.block_cache.len() > self.max_blocks {
            let evict_addr = match self.block_access_order.pop_front() {
                Some(addr) => addr,
                None => break, // safety: queue is empty but cache isn't — should not happen
            };
            if self.block_cache.contains_key(&evict_addr) {
                eprintln!(
                    "[jit] evicting block {:#x}: cache size {} exceeds max {}",
                    evict_addr,
                    self.block_cache.len(),
                    self.max_blocks
                );
                self.invalidate_block(evict_addr);
                break; // invalidate_block removed the entry, re-check on next insert
            }
            // Stale entry (block was already removed via invalidation) —
            // continue popping until we find a live entry or the queue is empty.
        }
    }

    /// Recompute the `code_pages` set from all currently cached blocks.
    /// This is O(n) in the number of compiled blocks, so it should only be
    /// called when blocks are added or removed (not on every write check).
    pub(super) fn rebuild_code_pages(&mut self) {
        self.code_pages.clear();
        for block in self.block_cache.values() {
            let start_page = block.guest_address & !0xfff;
            let end_page = (block.guest_address + block_guest_span(block) - 1) & !0xfff;
            let mut page = start_page;
            while page <= end_page {
                self.code_pages.insert(page);
                page += 0x1000;
            }
        }
    }

    /// Check if a guest memory write at `address` of `length` bytes overlaps
    /// any compiled code pages. If it does, invalidate all affected blocks
    /// and return `true` (indicating self-modifying code was detected).
    ///
    /// This is the primary entry point for self-modifying code detection.
    /// It should be called before every guest memory write that could
    /// potentially overlap compiled code pages.
    ///
    /// Returns the list of guest addresses of invalidated blocks, or an empty
    /// vec if no blocks were affected.
    pub fn invalidate_blocks_writing_to(&mut self, address: u64, length: usize) -> Vec<u64> {
        if length == 0 || self.block_cache.is_empty() {
            return Vec::new();
        }

        // Compute the set of 4K pages touched by this write.
        let start_page = address & !0xfff;
        let end_page = (address + length as u64 - 1) & !0xfff;

        // Fast path: if none of the touched pages have compiled code, skip.
        let mut page = start_page;
        let mut any_overlap = false;
        while page <= end_page {
            if self.code_pages.contains(&page) {
                any_overlap = true;
                break;
            }
            page += 0x1000;
        }
        if !any_overlap {
            return Vec::new();
        }

        // Slow path: check each compiled block for overlap with the write range.
        let write_end = address.saturating_add(length as u64);
        let affected: Vec<u64> = self
            .block_cache
            .keys()
            .copied()
            .filter(|&block_addr| {
                let block = match self.block_cache.get(&block_addr) {
                    Some(b) => b,
                    None => return false,
                };
                let block_end = block.guest_address.saturating_add(block_guest_span(block));
                // Overlap if: write_start < block_end AND write_end > block_start
                address < block_end && write_end > block.guest_address
            })
            .collect();

        if affected.is_empty() {
            return Vec::new();
        }

        let count = affected.len();
        for &block_addr in &affected {
            self.invalidate_block(block_addr);
        }
        // Invalidate synced pages in the write range so they get re-synced
        // with the updated code on the next block execution.
        let mut page = start_page;
        while page <= end_page {
            self.synced_pages.remove(&page);
            page += 0x1000;
        }
        eprintln!(
            "[jit] self-modifying code detected: write at {:#x}+{} invalidated {} block(s)",
            address, length, count
        );
        affected
    }

    /// Invalidate all compiled blocks whose `touched_pages` intersect with
    /// `dirty_pages`. This is a page-granularity invalidation method used
    /// for bulk operations (e.g., when a full page is written to).
    ///
    /// Returns the list of invalidated guest addresses.
    pub fn invalidate_blocks_on_pages(
        &mut self,
        dirty_pages: &std::collections::BTreeSet<u64>,
    ) -> Vec<u64> {
        if dirty_pages.is_empty()
            || (self.block_cache.is_empty() && self.slice_block_cache.is_empty())
        {
            return Vec::new();
        }

        // Fast check: are any of the dirty pages in our code_pages set?
        let mut any_overlap = false;
        for page in dirty_pages {
            if self.code_pages.contains(page) {
                any_overlap = true;
                break;
            }
        }
        if !any_overlap {
            return Vec::new();
        }
        // Worker slice blocks compile from the same source pages; a code
        // write invalidates them just like dispatcher blocks and clears every
        // native link so no stale entry can be observed.
        self.clear_slice_blocks();

        let affected: Vec<u64> = self
            .block_cache
            .keys()
            .copied()
            .filter(|&block_addr| {
                let block = match self.block_cache.get(&block_addr) {
                    Some(b) => b,
                    None => return false,
                };
                let start_page = block.guest_address & !0xfff;
                let end_page = (block.guest_address + block_guest_span(block) - 1) & !0xfff;
                let mut page = start_page;
                while page <= end_page {
                    if dirty_pages.contains(&page) {
                        return true; // Block overlaps a dirty page — needs invalidation
                    }
                    page += 0x1000;
                }
                false
            })
            .collect();

        if affected.is_empty() {
            return Vec::new();
        }

        for &block_addr in &affected {
            self.invalidate_block(block_addr);
        }
        // Invalidate synced pages for dirty pages so they get re-synced.
        for page in dirty_pages {
            self.synced_pages.remove(page);
        }
        eprintln!(
            "[jit] page-granularity invalidation: removed {} block(s)",
            affected.len()
        );
        affected
    }

    /// Returns `true` if the unwind table has been modified since the last
    /// `register_with_seh()` call, meaning the SEH subsystem needs to be
    /// updated.
    pub fn is_unwind_dirty(&self) -> bool {
        self.unwind_table.is_dirty()
    }

    /// Check whether a block at `guest_address` has been compiled.
    pub fn is_compiled(&self, guest_address: u64) -> bool {
        self.block_cache.contains_key(&guest_address)
    }

    /// Unchain all blocks that chain *to* `target_address`.
    ///
    /// Called when a block is invalidated or recompiled so that stale
    /// chains don't redirect execution to freed/reused memory.
    pub fn unchain_target(&mut self, target_address: u64) -> AppResult<()> {
        let sources: Vec<u64> = self
            .block_chains
            .keys()
            .filter(|(_, to)| *to == target_address)
            .map(|(from, _)| *from)
            .collect();
        for from in sources {
            self.unchain_block(from)?;
        }
        Ok(())
    }

    /// Break **all** existing block chains by restoring the RET instruction
    /// at the end of every chained block.
    ///
    /// After calling this method, every previously-chained block will return
    /// to the dispatcher (the main loop in [`pe_runtime`](crate::pe_runtime))
    /// after execution, allowing the CPU yield check and GDI frame
    /// re-publication to fire.
    ///
    /// Blocks are **not** invalidated — they remain compiled and will be
    /// re-chained automatically on subsequent executions (either via the
    /// auto-chaining logic in [`get_or_compile`](JitRuntime::get_or_compile)
    /// or via the explicit chain check in the PE runtime's main loop).
    pub fn break_all_chains(&mut self) {
        // Acquire the write lock on JIT_EXEC_LOCK to prevent the MAP_JIT
        // permission race. If the worker is inside entry_fn() (holding the
        // read lock), try_write() fails and we return early — chain-breaking
        // will be retried on the next 50 ms tick.
        let _lock = match JIT_EXEC_LOCK.try_write() {
            Ok(guard) => guard,
            Err(_) => {
                eprintln!("[jit] break_all_chains: worker holds read lock — deferring chain break");
                return;
            }
        };

        let keys: Vec<(u64, u64)> = self.block_chains.keys().copied().collect();
        let count = keys.len();
        if count == 0 {
            return;
        }
        for (from_addr, _) in keys {
            if let Err(e) = self.unchain_block(from_addr) {
                eprintln!(
                    "[jit] break_all_chains: failed to unchain {:#x}: {}",
                    from_addr, e
                );
            }
        }
        eprintln!("[jit] break_all_chains: broke {count} chain(s)");
    }

    /// Emit a host safepoint check at the start of a compiled block.
    ///
    /// When the JIT is re-enabled, every compiled block must begin with a
    /// check of the host safepoint flag so that guest code executing
    /// inside long chained blocks can still be interrupted — the host-side
    /// 2 ms block-dispatch safepoint in `pe_runtime.rs` only fires between
    /// dispatches, and a fully-chained loop never returns to the
    /// dispatcher.
    ///
    /// The intended emission (ARM64):
    ///
    /// ```text
    /// mov_imm64 xT, &JIT_SAFEPOINT_REQUESTED   // address of the flag
    /// ldr  wT,  [xT]                            // load the flag
    /// cbnz xT,  safepoint_stub                  // branch when set
    /// ...
    /// safepoint_stub:
    ///   emit_store_guest_registers(arch)
    ///   movz x0, EXIT_SAFEPOINT
    ///   emit_epilogue()                          // return EXIT_SAFEPOINT
    /// ```
    ///
    /// The dispatcher maps `EXIT_SAFEPOINT` to
    /// [`JitExitReason::Safepoint`], runs the host safepoint body (pump
    /// pending guest threads, drain timers/APCs, advance the guest clock),
    /// then re-dispatches the block.
    /// Execute a JIT-compiled block.
    ///
    /// # Safety
    /// The caller must ensure the block was correctly compiled and memory is valid.
    /// `block.entry()` must point to valid ARM64 machine code, `state` must be a
    /// valid CpuState, and `memory` must be a valid MemoryImage.
    pub unsafe fn execute_block(
        &mut self,
        block: &JitCompiledBlock,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> JitExitReason {
        self.blocks_executed += 1;

        #[cfg(test)]
        {
            let call = JIT_TEST_EXEC_CALLS.with(|calls| {
                let call = calls.get() + 1;
                calls.set(call);
                call
            });
            if JIT_TEST_IGNORE_SAFEPOINT_AT.with(|at| at.get()) == call {
                JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
            }
            if JIT_TEST_FORCE_SAFEPOINT_AT.with(|at| at.get()) == call {
                JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Relaxed);
            }
        }

        // ── Fault-equivalent fallback ────────────────────────────────────
        // An invalid installation (null/unpublished entry) or a block that
        // previously faulted must never be jumped into: hand this block to
        // the interpreter instead of aborting the process.
        let entry_ptr = block.published_entry();
        if entry_ptr.is_null() || self.faulted_blocks.contains(&block.guest_address) {
            self.report_block_fault(block.guest_address);
            return JitExitReason::Safepoint;
        }

        // ── Self-modifying code, entry check ────────────────────────────
        // The interpreter may have written guest code pages between JIT
        // executions.  Drain those writes before running a stale block; if
        // this very block was invalidated, return the safepoint fallback so
        // the dispatcher executes the block through the interpreter.
        let _smc_dirty = self.drain_smc_invalidations();
        // The caller resolved `block` before this call; it may have been
        // invalidated by the drain above or by an earlier block's exit
        // drain (SMC).  Never execute a stale clone: hand it to the
        // interpreter instead.
        let still_current = self
            .block_cache
            .get(&block.guest_address)
            .is_some_and(|cached| cached.published_entry() == entry_ptr);
        if !still_current {
            self.interpreter_fallbacks += 1;
            return JitExitReason::Safepoint;
        }

        // Both views must alias the same canonical pages before any native
        // load/store executes.  This is O(1) (Arc identity), not a page copy.
        self.attach_guest_memory(memory);

        // The JIT entry point expects:
        // x0 = pointer to CpuState
        // x1 = flat memory base
        // x2 = pointer to MemoryImage
        // x3 = pointer to exit_reason (output)
        // The x3 argument is a legacy exit-reason slot: every emission arm
        // returns its exit code in x0 (`movz x0, EXIT_*`) and no arm writes
        // [x3].  Decoding the slot therefore saw only zero (`EXIT_NORMAL`) and
        // collapsed safepoint/ret/jump exits into Normal.  Keep the slot in
        // the ABI, but decode the real x0 return value below.
        // The legacy x3 "exit reason" slot is repurposed as a per-thread
        // two-word cell: [0] is the block that most recently entered native
        // code (written by every prologue), [1] is this runtime's flat-mirror
        // base (read by chained jump exits to restore x1).  Both values are
        // thread-local because the cell lives on this stack.
        let mut chain = ChainState::new(self.flat_memory.base(), block.guest_address, LINK_BUDGET);
        let state_ptr = state as *mut CpuState;
        let mem_base = chain.flat_base;
        let mem_image_ptr = memory as *mut MemoryImage;
        let exit_ptr = &mut chain as *mut ChainState;

        // SAFETY: block.entry() points to JIT-compiled ARM64 code that was
        // written by this compiler and finalized (icache flushed, executable
        // permissions set). The JIT code respects the ARM64 ABI and only
        // accesses memory through the provided base pointer and validated
        // offsets.
        //
        // The transmute converts a raw code pointer (usize) to a function
        // pointer with the JIT block ABI:
        //   (cpu_state_ptr, mem_base_u64, memory_image_ptr, exit_reason_ptr) -> u64
        // This is valid because:
        // 1. block.entry() was produced by JitMemoryManager during compilation
        //    of this specific IR block. The manager allocates MAP_JIT pages
        //    and sets executable permissions after writing.
        // 2. The JIT compiler emits ARM64 machine code conforming to this
        //    exact calling convention (x0-x3 for args, x0 for return).
        // 3. The function pointer signature matches the JIT-emitted
        //    prologue/epilogue and register usage.
        // 4. No guest-controlled data influences the function pointer — it
        //    is determined at JIT compile time from the trusted block cache.
        // Publish this runtime's SMC state for the store helper.  The guard
        // is thread-local and only refers to the boxed atomics, never to the
        // mutably borrowed runtime itself.
        let _smc_guard = ActiveSmcGuard::install(&self.smc);

        // SAFETY: the write-protect toggle only affects this thread's view of
        // MAP_JIT pages; enabling execute state is required before jumping
        // into a block compiled on possibly another thread.
        let reason = unsafe {
            self.compiler.memory_manager.prepare_execution();
            let entry_fn: unsafe extern "C" fn(
                *mut CpuState,
                u64,
                *mut MemoryImage,
                *mut ChainState,
            ) -> u64 = std::mem::transmute(entry_ptr);

            let result = entry_fn(state_ptr, mem_base, mem_image_ptr, exit_ptr);

            // A linked jump enters the target block directly, so the block
            // that produced this exit may differ from the dispatched one.
            // Decode jump-family exits with the FINAL block's metadata (its
            // prologue wrote the address into the per-thread cell) — using
            // the source's target here would re-dispatch (double-execute) the
            // chained target.
            let final_address = (*exit_ptr).current_block;
            let exit_info = if final_address == block.guest_address {
                block.last_exit_info
            } else {
                self.block_cache
                    .get(&final_address)
                    .map(|final_block| final_block.last_exit_info)
                    .unwrap_or(block.last_exit_info)
            };

            // x0 carries the exit code for every native exit arm; the optional
            // dynamic payload (indirect target / target pointer) is written by
            // the compiled block into exec_slot[2].
            map_exit_reason(result, state, result, exit_info, (*exit_ptr).payload)
        };
        // A budget/epoch guard stops BEFORE the block body runs.  Re-dispatch
        // exactly that block; never re-run the chain's already-executed
        // prefix.
        if matches!(
            reason,
            JitExitReason::LinkBudget { .. } | JitExitReason::CodeEpoch { .. }
        ) {
            state.rip = chain.current_block;
        }
        // Self-modifying code, exit check: the block just executed may have
        // written another block's code page (or its own).  Invalidate before
        // the dispatcher looks the next block up, so the stale block can
        // never run.
        self.drain_smc_invalidations();
        reason
    }

    /// Attach the flat view to the live image's canonical store.
    ///
    /// O(1): an `Arc` identity check.  Both views then address the same
    /// direct-window mapping, so no page copy is needed before or after
    /// execution.
    pub(crate) fn attach_guest_memory(&mut self, memory: &MemoryImage) {
        self.flat_memory.attach_store(memory.canonical_store());
    }

    /// Mark a committed page as visible to the flat view.
    ///
    /// The bytes are already shared (the page lives in the canonical store);
    /// this only updates the diagnostic bitmap and `synced_pages`.
    pub fn sync_page_to_flat(&mut self, memory: &MemoryImage, page_addr: u64) {
        let aligned = page_addr & !0xfff;
        self.attach_guest_memory(memory);
        self.flat_memory.materialise_pages(memory, &[aligned]);
        self.synced_pages.insert(aligned);
    }

    /// Establish the baseline flat view for all committed guest pages.
    ///
    /// No bytes are copied: committed pages already live in the canonical
    /// store the flat view aliases.  This pass only records which fully
    /// mapped pages are visible to direct JIT addressing and updates the
    /// compatibility telemetry consumed by the sync-path benchmark.
    pub fn sync_all_pages_to_flat(&mut self, memory: &MemoryImage) {
        self.attach_guest_memory(memory);
        let pages = memory.committed_page_addresses();
        self.flat_memory.materialise_pages(memory, &pages);
        self.synced_pages = pages.into_iter().collect();
    }

    /// Incremental bookkeeping: only new pages are noted since the last pass.
    pub fn sync_new_pages_to_flat(&mut self, memory: &MemoryImage) {
        self.attach_guest_memory(memory);
        let current_pages: BTreeSet<u64> = memory.committed_page_addresses().into_iter().collect();
        let new_pages: Vec<u64> = current_pages
            .difference(&self.synced_pages)
            .copied()
            .collect();
        if !new_pages.is_empty() {
            self.flat_memory.materialise_pages(memory, &new_pages);
        }
        self.synced_pages = current_pages;
    }

    /// Coherence is immediate through the shared canonical store, so there is
    /// nothing to copy back.  Retained for source compatibility.
    pub fn sync_flat_to_memory(&self, _guest_addr: u64, _memory: &mut MemoryImage, _size: usize) {}

    /// No-op: JIT stores already land in the canonical pages the interpreter
    /// reads.  Retained for source compatibility.
    pub fn sync_all_flat_to_memory(&self, _memory: &mut MemoryImage) {}

    /// No-op: see [`Self::sync_all_flat_to_memory`].
    pub fn sync_synced_flat_to_memory(&self, _memory: &mut MemoryImage) {}

    /// Install the SIGBUS handler that syncs guest pages on demand during JIT
    /// execution. Stores `self` and `memory` as raw pointers for the signal
    /// handler (which must be async-signal-safe).
    ///
    /// Must be paired with a matching call to `remove_sigbus_handler` after
    /// JIT execution completes.
    pub fn install_sigbus_handler(&self, memory: &MemoryImage) {
        // Reset loop detection state
        SIGBUS_LAST_FAULT_ADDR.store(0, Ordering::Relaxed);
        SIGBUS_CONSECUTIVE_COUNT.store(0, Ordering::Relaxed);

        SIGBUS_JIT_RUNTIME.store(
            self as *const JitRuntime as *mut JitRuntime,
            Ordering::Release,
        );
        SIGBUS_JIT_MEMORY.store(
            memory as *const MemoryImage as *mut MemoryImage,
            Ordering::Release,
        );

        // SAFETY: sigaction is a POSIX function that installs a signal handler.
        // We zero-initialize the struct, set flags and handler, then call
        // sigaction. The old handler is not needed (null oact). SA_NODEFER
        // allows recursive SIGBUS detection (see handler docs above).
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            // sa_sigaction is a union with sa_handler on Apple platforms;
            // libc exposes it as usize. Store our SA_SIGINFO handler.
            // SA_NODEFER allows the handler to be re-entered if the sync
            // itself touches an unmapped flat-memory page, preventing an
            // infinite SIGBUS loop that would crash the process.
            action.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
            action.sa_sigaction = sigbus_sa_handler as *const () as usize;
            libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut());
        }
    }

    /// Ensure the SIGBUS handler is installed for this JIT session.
    /// If already installed (`sigbus_installed` flag), this is a no-op,
    /// eliminating the per-block sigaction syscall overhead.
    /// Only updates the memory pointer (in case it changed).
    pub fn ensure_sigbus_handler(&mut self, memory: &MemoryImage) {
        // The fallback services faulting pages of the store the flat view
        // addresses, so pin the view to this image before publishing pointers.
        self.attach_guest_memory(memory);
        if !self.sigbus_installed {
            self.install_sigbus_handler(memory);
            self.sigbus_installed = true;
        } else {
            // Handler already installed, just update the memory pointer
            // (the memory reference may change between blocks if the host
            // runtime modifies the MemoryImage).
            SIGBUS_JIT_MEMORY.store(
                memory as *const MemoryImage as *mut MemoryImage,
                Ordering::Release,
            );
            // Reset loop detection for new block
            SIGBUS_LAST_FAULT_ADDR.store(0, Ordering::Relaxed);
            SIGBUS_CONSECUTIVE_COUNT.store(0, Ordering::Relaxed);
        }
    }

    /// Remove the SIGBUS handler installed by `install_sigbus_handler` and
    /// restore the default SIGBUS disposition. Clears the static pointers.
    ///
    /// On Apple platforms, `libc::sigaction` exposes the `sa_sigaction`/`sa_handler`
    /// union as a single `sa_sigaction: usize` field. Setting it to `SIG_DFL` (0)
    /// restores the default disposition.
    pub fn remove_sigbus_handler(&self) {
        SIGBUS_JIT_RUNTIME.store(std::ptr::null_mut(), Ordering::Release);
        SIGBUS_JIT_MEMORY.store(std::ptr::null_mut(), Ordering::Release);

        // SAFETY: Restoring the default SIGBUS disposition. zeroed()
        // produces a valid sigaction struct with sa_flags=0 and
        // sa_sigaction=SIG_DFL (0), which is the default handler.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut());
        }
    }

    /// Remove the SIGBUS handler at the end of a JIT session.
    /// Only performs the sigaction syscall if the handler was actually installed.
    pub fn remove_sigbus_handler_session(&mut self) {
        if self.sigbus_installed {
            self.remove_sigbus_handler();
            self.sigbus_installed = false;
        }
    }

    /// Invalidate the synced pages set. Should be called when memory is
    /// invalidated (e.g., self-modifying code detection, module unloading)
    /// to force a full re-sync on the next block execution.
    pub fn invalidate_synced_pages(&mut self) {
        self.synced_pages.clear();
    }

    /// Returns the total number of SIGBUS events since the process started.
    /// Useful for diagnostics and performance monitoring.
    pub fn sigbus_event_count() -> u64 {
        SIGBUS_TOTAL_EVENTS.load(Ordering::Relaxed)
    }

    /// Returns the number of pages currently in the synced set.
    pub fn synced_page_count(&self) -> usize {
        self.synced_pages.len()
    }
}

/// Map the raw JIT exit code (returned by a compiled block in x0) to a
/// [`JitExitReason`].
///
/// The jump-family exit codes (`EXIT_JUMP`, `EXIT_COND_BRANCH`,
/// `EXIT_INDIRECT_CALL`) must NOT collapse into `Normal`: the compiled
/// code never writes `state.rip` for these (see the emission comments in
/// `compile_instruction`), so the dispatcher must reconstruct RIP from
/// the reason.  `block_exit_info` carries the block's final control-flow
/// metadata captured at compile time.
///
/// `result` is the block's X0 return value (for `EXIT_THUNK`/`EXIT_RET`
/// it carries the guest return RIP; the dormant jump-family arms use it
/// as a best-effort carrier — a re-enabled JIT must either populate it or
/// have the dispatcher re-derive the target from `state`).
pub(super) fn map_exit_reason(
    exit_reason: u64,
    state: &CpuState,
    result: u64,
    block_exit_info: Option<BlockExitInfo>,
    payload: u64,
) -> JitExitReason {
    // Indirect call sites need the static return address (never written by the
    // compiled block); the dynamic callee target arrives in `payload`.
    let call_return_address = match block_exit_info {
        Some(BlockExitInfo::CallIndirect { return_address }) => return_address,
        Some(BlockExitInfo::Call { return_address, .. }) => return_address,
        _ => 0,
    };
    let direct_call_target = match block_exit_info {
        Some(BlockExitInfo::Call { target, .. }) => target,
        _ => payload,
    };
    match exit_reason {
        EXIT_NORMAL => JitExitReason::Normal { new_rip: state.rip },
        EXIT_THUNK => JitExitReason::ThunkDispatch {
            target_rip: state.rip,
            return_rip: result,
        },
        EXIT_UNIMPL => JitExitReason::UnimplementedInstruction {
            rip: state.rip,
            opcode: result as u8,
        },
        EXIT_COND_BRANCH => {
            let taken = match block_exit_info {
                Some(BlockExitInfo::JumpIf { condition, .. }) => {
                    crate::cpu::evaluate_condition(condition, &state.flags)
                }
                _ => result != 0,
            };
            JitExitReason::ConditionalBranch {
                rip: state.rip,
                taken,
            }
        }
        EXIT_INDIRECT_CALL => JitExitReason::IndirectCall {
            target: result,
            return_address: state.rip,
            target_is_pointer: false,
        },
        EXIT_INDIRECT_JUMP_REG => JitExitReason::IndirectJump {
            target: payload,
            target_is_pointer: false,
        },
        EXIT_INDIRECT_CALL_REG => JitExitReason::IndirectCall {
            target: payload,
            return_address: call_return_address,
            target_is_pointer: false,
        },
        EXIT_INDIRECT_JUMP_MEM => JitExitReason::IndirectJump {
            target: payload,
            target_is_pointer: true,
        },
        EXIT_INDIRECT_CALL_MEM => JitExitReason::IndirectCall {
            target: payload,
            return_address: call_return_address,
            target_is_pointer: true,
        },
        EXIT_CALL_DIRECT => JitExitReason::DirectCall {
            target: direct_call_target,
            return_address: call_return_address,
        },
        EXIT_CALL_PUSHED => JitExitReason::DirectCallPushed {
            target: direct_call_target,
            return_address: call_return_address,
        },
        EXIT_RET_RESOLVED => JitExitReason::ReturnResolved { target: payload },
        EXIT_LINK_BUDGET => JitExitReason::LinkBudget { rip: state.rip },
        EXIT_CODE_EPOCH => JitExitReason::CodeEpoch { rip: state.rip },
        EXIT_COND_TAKEN => JitExitReason::ConditionalTaken { rip: state.rip },
        EXIT_COND_NOT_TAKEN => JitExitReason::ConditionalNotTaken { rip: state.rip },
        EXIT_RET => JitExitReason::Return { return_rip: result },
        EXIT_MEM_ACCESS => JitExitReason::MemoryAccess {
            address: result,
            is_write: false,
            width: 0,
        },
        EXIT_CPUID => JitExitReason::Cpuid,
        EXIT_EXCEPTION => JitExitReason::Exception {
            code: result as u32,
            address: state.rip,
        },
        EXIT_JUMP => {
            let target = match block_exit_info {
                Some(BlockExitInfo::Jump { target }) => target,
                _ => state.rip,
            };
            JitExitReason::Jump { target }
        }
        EXIT_SAFEPOINT => JitExitReason::Safepoint,
        EXIT_GUEST_FAULT => JitExitReason::GuestFault,
        _ => JitExitReason::Normal { new_rip: state.rip },
    }
}

impl Drop for JitRuntime {
    fn drop(&mut self) {
        // Clean up the persistent SIGBUS handler if still installed.
        // This ensures the signal handler doesn't reference freed memory.
        self.remove_sigbus_handler_session();
    }
}

impl JitRuntime {
    /// Chain two compiled blocks so that the exit jump of `from_address` is
    /// patched to go directly to the entry of `to_address`, bypassing the
    /// dispatcher.
    ///
    /// # Performance Impact
    /// Eliminates dispatcher overhead (indirect call, block lookup, register
    /// restore/save) for hot block-to-block transitions, reducing branch
    /// misprediction penalty and improving instruction-cache locality.
    ///
    /// # Thread Safety
    /// This method never writes instruction memory: it publishes the target
    /// entry into the source block's atomic link slot with Release ordering.
    /// The compiled jump reads that slot with an acquire load (LDAR), so a
    /// concurrent executor sees either the old link (including zero, which
    /// exits to the dispatcher) or the new one — never a torn code sequence.
    pub fn chain_blocks(&mut self, from_address: u64, to_address: u64) -> AppResult<()> {
        #[cfg(test)]
        if JIT_TEST_FORCE_CHAIN_ERROR.with(|force| force.replace(false)) {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "injected chain failure",
            ));
        }
        let Some(from_block) = self.block_cache.get(&from_address) else {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("cannot chain missing source block {from_address:#x}"),
            ));
        };
        if !matches!(from_block.last_exit_info, Some(BlockExitInfo::Jump { .. })) {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("block {from_address:#x} does not end in an unconditional jump"),
            ));
        }
        let Some(to_block) = self.block_cache.get(&to_address) else {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("cannot chain to missing target block {to_address:#x}"),
            ));
        };
        // Only Jump/JumpIf targets are chainable.  Their exit is fully
        // described by `last_exit_info`, which `execute_block` looks up for
        // the final chained block.  Straight-line targets would leave RIP
        // wrong, and Return/Call targets need the dispatcher to re-run the
        // terminator IR of the *dispatched* (source) block — double-executing
        // the chained target.
        if !matches!(
            to_block.last_exit_info,
            Some(BlockExitInfo::Jump { .. } | BlockExitInfo::JumpIf { .. })
        ) {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("block {to_address:#x} does not end in a chainable jump"),
            ));
        }
        let target_entry = to_block.published_entry() as u64;
        if target_entry == 0 {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                format!("block {to_address:#x} has no published entry"),
            ));
        }
        let slot = Arc::clone(&from_block.link_target);
        let patch_location = Arc::as_ptr(&slot) as u64;
        #[cfg(test)]
        if JIT_TEST_PREPUBLISH_CHAIN.with(|prepublish| prepublish.replace(false)) {
            from_block
                .link_target
                .store(target_entry, Ordering::Release);
        }
        let previous = slot.swap(target_entry, Ordering::AcqRel);
        self.block_chains.insert(
            (from_address, to_address),
            BlockChainEntry {
                from_address,
                to_address,
                chain_patch_location: patch_location,
                chained: true,
            },
        );
        if previous != target_entry {
            self.chain_links_formed += 1;
            JIT_CHAIN_LINKS_FORMED.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Remove a block chain originating from `from_address`.
    ///
    /// Used when a block is invalidated (e.g., self-modifying code) so that
    /// stale chains don't redirect execution to freed/reused memory.
    pub fn unchain_block(&mut self, from_address: u64) -> AppResult<()> {
        let keys_to_remove: Vec<(u64, u64)> = self
            .block_chains
            .keys()
            .filter(|(from, _)| *from == from_address)
            .copied()
            .collect();

        for key in keys_to_remove {
            if self.block_chains.remove(&key).is_some() {
                // Links are atomic pointer slots, never patched instructions:
                // clearing the slot is a single Release store, safe while
                // another thread is executing the block.
                if let Some(from_block) = self.block_cache.get(&from_address)
                    && from_block.link_target.swap(0, Ordering::AcqRel) != 0
                {
                    self.chain_links_broken += 1;
                    JIT_CHAIN_LINKS_BROKEN.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }

    /// Returns `true` if `start` can reach `target` by following existing
    /// block chains (`block_chains`), i.e. if there is already a patched
    /// native path `start → ... → target`.
    ///
    /// Used by [`chain_blocks`](Self::chain_blocks) to refuse creating a
    /// chain that would close a cycle (which would loop forever in native
    /// code without returning to the dispatcher).  Because each compiled
    /// block has at most one outgoing chain, the chain graph is a set of
    /// disjoint paths, so this DFS is linear in the number of chained
    /// blocks visited.  The hop cap bounds the worst case.
    #[allow(dead_code)] // block-chaining reachability query; not yet used by the chaining policy
    pub(super) fn chain_reaches(&self, start: u64, target: u64) -> bool {
        const MAX_HOPS: usize = 4096;
        let mut current = start;
        for _ in 0..MAX_HOPS {
            if current == target {
                return true;
            }
            // Each block has at most one outgoing chain, so find the single
            // chain whose `from_address == current`.
            match self
                .block_chains
                .iter()
                .find(|(_, entry)| entry.from_address == current && entry.chained)
            {
                Some((_, entry)) => current = entry.to_address,
                None => return false,
            }
        }
        // Exhausted the hop budget without reaching `target` or a dead end —
        // treat as not-reaching to stay safe (a genuine cycle longer than
        // MAX_HOPS would be broken by the watchdog's force_break_all_chains).
        false
    }

    /// Register a host function pointer as a fast thunk, returning the thunk
    /// index that can be used by JIT-compiled code to call the host function
    /// directly (bypassing the full guest→host dispatch loop).
    pub fn register_host_thunk(&mut self, host_fn: usize) -> Option<usize> {
        self.fast_thunk_table.register(host_fn).ok()
    }

    /// Register a host function as the resolved target for a guest thunk
    /// address.  Subsequent compilations of `Call { target: guest_addr }`
    /// emit a direct trampoline call instead of an EXIT_THUNK dispatcher
    /// round-trip.
    pub fn register_host_thunk_for_guest(
        &mut self,
        host_fn: usize,
        guest_addr: u64,
    ) -> Option<usize> {
        self.fast_thunk_table
            .register_with_guest_addr(host_fn, guest_addr)
            .ok()
    }

    /// Guest thunk addresses with a resolved trampoline.
    pub fn guest_thunk_addrs(&self) -> std::collections::HashSet<u64> {
        self.fast_thunk_table.guest_addrs()
    }

    /// Look up the executable thunk address for a previously registered
    /// fast-thunk index. Returns `None` if the index is out of range.
    pub fn lookup_thunk_address(&self, idx: usize) -> Option<usize> {
        self.fast_thunk_table.thunk_address(idx)
    }
}
