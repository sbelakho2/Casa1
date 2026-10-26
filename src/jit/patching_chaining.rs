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

/// Global mapping from guest thunk address (u64) to ARM64 trampoline executable
/// address (usize).  Populated by [`FastThunkTable::register_with_guest_addr`] and
/// consumed by [`JitCompiler::compile_instruction`] when emitting a direct `bl`
/// to a fast-thunk trampoline.
pub(super) static FAST_THUNK_MAP: LazyLock<Mutex<HashMap<u64, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// ── Executable-code write tracking (self-modifying code) ────────────────────
//
// Guest stores execute inside JIT-compiled code through `jit_helper_store`.
// That helper runs while the owning thread is inside `execute_block`, so it
// cannot form a `&JitRuntime` (the runtime is mutably borrowed there).
// Instead the executing thread publishes a pointer to the runtime's
// `SmcState` in a thread-local, and the helper records writes into that
// state's atomics:
//
//   * `watched`  — lock-free open-addressing set of guest pages that host a
//                  compiled block (key = page + 1, 0 = empty);
//   * `dirty`    — bounded lock-free ring of pages written since the last
//                  drain (overflow sets a flag: the drain then invalidates
//                  every block, which is always safe).
//
// Tracking is per runtime, not global: two runtimes in one process (tests,
// live sessions) never invalidate each other's blocks.  When no runtime is
// executing on this thread the helper's fast path is a thread-local load.
pub(super) const SMC_WATCH_SLOTS: usize = 8192;
pub(super) const SMC_WATCH_MASK: usize = SMC_WATCH_SLOTS - 1;
pub(super) const SMC_DIRTY_SLOTS: usize = 4096;

pub(super) struct SmcState {
    pub(super) watched: Box<[AtomicU64]>,
    pub(super) watched_count: AtomicUsize,
    pub(super) watch_overflow: AtomicBool,
    pub(super) dirty: Box<[AtomicU64]>,
    pub(super) dirty_count: AtomicUsize,
    pub(super) dirty_overflow: AtomicBool,
}

impl SmcState {
    pub(super) fn new() -> Self {
        Self {
            watched: (0..SMC_WATCH_SLOTS)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            watched_count: AtomicUsize::new(0),
            watch_overflow: AtomicBool::new(false),
            dirty: (0..SMC_DIRTY_SLOTS)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            dirty_count: AtomicUsize::new(0),
            dirty_overflow: AtomicBool::new(false),
        }
    }

    pub(super) fn slot(page: u64) -> usize {
        let x = (page >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (x >> (64 - 13)) as usize & SMC_WATCH_MASK
    }

    /// Rebuild the watched-page set from the runtime's current `code_pages`.
    /// Called only when blocks are added/removed (never during execution).
    pub(super) fn rebuild_watch<'a>(&self, pages: impl Iterator<Item = &'a u64>) {
        for slot in self.watched.iter() {
            slot.store(0, Ordering::Relaxed);
        }
        let mut count = 0usize;
        let mut overflow = false;
        for &page in pages {
            let key = page + 1;
            let mut idx = Self::slot(page);
            let mut placed = false;
            for _ in 0..SMC_WATCH_SLOTS {
                if self.watched[idx].load(Ordering::Relaxed) == 0 {
                    self.watched[idx].store(key, Ordering::Release);
                    placed = true;
                    break;
                }
                idx = (idx + 1) & SMC_WATCH_MASK;
            }
            if placed {
                count += 1;
            } else {
                // Hash table full: treat every page as watched (conservative).
                overflow = true;
                break;
            }
        }
        self.watched_count.store(count, Ordering::Release);
        self.watch_overflow.store(overflow, Ordering::Release);
    }

    pub(super) fn is_watched(&self, page: u64) -> bool {
        if self.watch_overflow.load(Ordering::Acquire) {
            return true;
        }
        let key = page + 1;
        let mut idx = Self::slot(page);
        for _ in 0..SMC_WATCH_SLOTS {
            let value = self.watched[idx].load(Ordering::Acquire);
            if value == 0 {
                return false;
            }
            if value == key {
                return true;
            }
            idx = (idx + 1) & SMC_WATCH_MASK;
        }
        false
    }

    pub(super) fn mark_dirty(&self, page: u64) {
        let pos = self.dirty_count.fetch_add(1, Ordering::Relaxed);
        if pos < SMC_DIRTY_SLOTS {
            self.dirty[pos].store(page + 1, Ordering::Release);
        } else {
            self.dirty_overflow.store(true, Ordering::Release);
        }
    }

    /// Take the dirty pages (4K-aligned) and the overflow flag, clearing both.
    pub(super) fn take_dirty(&self) -> (Vec<u64>, bool) {
        let count = self
            .dirty_count
            .swap(0, Ordering::AcqRel)
            .min(SMC_DIRTY_SLOTS);
        let mut pages = Vec::with_capacity(count);
        for slot in self.dirty.iter().take(count) {
            let value = slot.swap(0, Ordering::AcqRel);
            if value != 0 {
                pages.push((value - 1) & !0xfff);
            }
        }
        let overflow = self.dirty_overflow.swap(false, Ordering::AcqRel);
        (pages, overflow)
    }
}

/// Guest stores observed at a watched code page (diagnostic counter).
pub static SMC_WRITES_OBSERVED: AtomicU64 = AtomicU64::new(0);
/// Code pages marked dirty by such stores (diagnostic counter).
pub static SMC_PAGES_MARKED_DIRTY: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// `SmcState` of the runtime executing on this thread, or null.
    static ACTIVE_SMC: std::cell::Cell<*const SmcState> =
        const { std::cell::Cell::new(std::ptr::null()) };
}

/// RAII publication of the executing runtime's SMC state to the helper.
pub(super) struct ActiveSmcGuard(*const SmcState);

impl ActiveSmcGuard {
    pub(super) fn install(state: &SmcState) -> Self {
        let previous = ACTIVE_SMC.with(|cell| {
            let previous = cell.get();
            cell.set(state as *const SmcState);
            previous
        });
        Self(previous)
    }
}

impl Drop for ActiveSmcGuard {
    fn drop(&mut self) {
        ACTIVE_SMC.with(|cell| cell.set(self.0));
    }
}

/// Serializes writes to executable code pages across every host thread.
/// `pthread_jit_write_protect_np` is per-thread, so this lock only prevents
/// two installers from writing the same code zone concurrently; executing
/// threads keep their own execute view and never take this lock.
pub(super) static JIT_CODE_INSTALL_LOCK: Mutex<()> = Mutex::new(());

/// Number of block-to-block links published (atomic link-slot stores).
pub static JIT_CHAIN_LINKS_FORMED: AtomicU64 = AtomicU64::new(0);
/// Number of block-to-block links cleared (invalidation / chain break).
pub static JIT_CHAIN_LINKS_BROKEN: AtomicU64 = AtomicU64::new(0);
/// Number of guest Call sites compiled to a direct resolved-thunk call.
pub static JIT_THUNK_DIRECT_CALLS: AtomicU64 = AtomicU64::new(0);

/// Monotonic epoch of guest code writes.
///
/// Every compiled block's prologue compares this value with the epoch captured
/// by its execution chain.  A write to a compiled-code page bumps the epoch, so
/// the next block entry in an otherwise native chain exits to its dispatcher
/// before the stale block can run.  Combined with [`LINK_BUDGET`] this makes
/// per-block SMC checks and safepoint polling non-skippable even when blocks
/// branch directly into one another.
pub static JIT_CODE_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Maximum number of native block entries between two returns to the worker
/// loop (or the cooperative dispatcher).  The counter lives in the per-chain
/// [`ChainState`] and is decremented by every block prologue; reaching zero
/// forces a dispatch boundary where the safepoint and SMC checks are
/// re-evaluated by the host.
pub(crate) const LINK_BUDGET: u64 = 256;

/// Byte offsets into the `#[repr(C)]` [`ChainState`] that are embedded in
/// compiled code.  Keeping them as named constants makes the ABI auditable and
/// keeps the emitter, the executor and the relocation writer in sync.
pub(crate) mod chain_offsets {
    pub(crate) const CURRENT_BLOCK: u32 = 0;
    pub(crate) const FLAT_BASE: u32 = 8;
    pub(crate) const PAYLOAD: u32 = 16;
    pub(crate) const LINK_BUDGET: u32 = 24;
    pub(crate) const BLOCKS: u32 = 32;
    pub(crate) const INSTRUCTIONS: u32 = 40;
    pub(crate) const SMC_EPOCH: u32 = 48;
    pub(crate) const RETURN_DEPTH: u32 = 56;
    pub(crate) const NATIVE_CALLS: u32 = 64;
    pub(crate) const NATIVE_RETURN_HITS: u32 = 72;
    pub(crate) const NATIVE_RETURN_MISSES: u32 = 80;
    pub(crate) const NATIVE_RETURN_MISPREDICTS: u32 = 88;
    pub(crate) const RETURN_STACK: u32 = 96;
}

/// Maximum depth of the native direct-call return stack carried by one chain.
pub(crate) const CHAIN_RETURN_DEPTH: usize = 16;

/// Per-execution state shared with compiled code through `x3`/`x23`.
///
/// This replaces the legacy four-word exit cell.  It is a plain (non-atomic)
/// stack object owned exclusively by the thread executing the chain, so the
/// emitted loads/stores never race: a worker owns its state for the duration
/// of a slice, and the cooperative dispatcher owns it for one block chain.
#[repr(C)]
pub(crate) struct ChainState {
    pub(crate) current_block: u64,
    pub(crate) flat_base: u64,
    pub(crate) payload: u64,
    pub(crate) link_budget: u64,
    pub(crate) blocks: u64,
    pub(crate) instructions: u64,
    pub(crate) smc_epoch: u64,
    pub(crate) return_depth: u64,
    pub(crate) native_calls: u64,
    pub(crate) native_return_hits: u64,
    pub(crate) native_return_misses: u64,
    pub(crate) native_return_mispredicts: u64,
    /// `(guest return address, compiled entry)` pairs, newest at
    /// `return_depth - 1`.  A caller pushes the statically known return
    /// address; a native `ret` pops it only when the guest stack agrees.
    pub(crate) return_stack: [[u64; 2]; CHAIN_RETURN_DEPTH],
}

impl ChainState {
    pub(crate) fn new(flat_base: u64, block_address: u64, link_budget: u64) -> Self {
        Self {
            current_block: block_address,
            flat_base,
            payload: 0,
            link_budget,
            blocks: 0,
            instructions: 0,
            smc_epoch: JIT_CODE_EPOCH.load(Ordering::Acquire),
            return_depth: 0,
            native_calls: 0,
            native_return_hits: 0,
            native_return_misses: 0,
            native_return_mispredicts: 0,
            return_stack: [[0; 2]; CHAIN_RETURN_DEPTH],
        }
    }

    pub(crate) fn push_return(&mut self, target: u64, entry: u64) {
        if self.return_depth as usize >= CHAIN_RETURN_DEPTH {
            return;
        }
        self.return_stack[self.return_depth as usize] = [target, entry];
        self.return_depth += 1;
    }

    #[allow(dead_code)] // used by native/AOT diagnostics
    pub(crate) fn return_entry(&self, target: u64) -> Option<u64> {
        if self.return_depth == 0 {
            return None;
        }
        let top = self.return_stack[self.return_depth as usize - 1];
        (top[0] == target && top[1] != 0).then_some(top[1])
    }
}

/// Record a guest write to `[address, address + length)`.
///
/// Called from `jit_helper_store` for every native guest store.  The fast path
/// is a thread-local load when this thread is not executing JIT code.
pub fn note_guest_code_write(address: u64, length: usize) {
    if length == 0 {
        return;
    }
    let state_ptr = ACTIVE_SMC.with(|cell| cell.get());
    if state_ptr.is_null() {
        return;
    }
    // SAFETY: the pointer is published by `ActiveSmcGuard` for the duration
    // of `execute_block` on this same thread; the referenced boxed state
    // outlives the guard, and all accesses are atomics (no Rust references
    // to the mutably borrowed runtime are formed).
    let state = unsafe { &*state_ptr };
    if state.watched_count.load(Ordering::Acquire) == 0
        && !state.watch_overflow.load(Ordering::Acquire)
    {
        return;
    }
    let end = address.saturating_add(length as u64);
    let mut page = address & !0xfff;
    let last = end.saturating_sub(1) & !0xfff;
    let mut observed = false;
    while page <= last {
        if state.is_watched(page) {
            state.mark_dirty(page);
            SMC_PAGES_MARKED_DIRTY.fetch_add(1, Ordering::Relaxed);
            observed = true;
        }
        page = match page.checked_add(0x1000) {
            Some(next) => next,
            None => return,
        };
    }
    if observed {
        SMC_WRITES_OBSERVED.fetch_add(1, Ordering::Relaxed);
        JIT_CODE_EPOCH.fetch_add(1, Ordering::AcqRel);
    }
}

/// `(writes_observed, pages_marked_dirty)` since process start.
pub fn smc_telemetry() -> (u64, u64) {
    (
        SMC_WRITES_OBSERVED.load(Ordering::Relaxed),
        SMC_PAGES_MARKED_DIRTY.load(Ordering::Relaxed),
    )
}

/// Reset the SMC diagnostic counters (test helper).
pub fn reset_smc_telemetry() {
    SMC_WRITES_OBSERVED.store(0, Ordering::Relaxed);
    SMC_PAGES_MARKED_DIRTY.store(0, Ordering::Relaxed);
}

// Helper: write JIT diagnostic info to a temp file for post-crash analysis.
// The runner process captures stderr via pipes that are lost if the runner
// crashes, so we write to a file as a fallback.  Not called from signal
// handlers — only from the JIT worker thread diagnostic path.
// ---------------------------------------------------------------------------
// JIT Block Chaining Entry
// ---------------------------------------------------------------------------

/// Represents a single block chain link between two compiled blocks.
///
/// When a block at `from_address` exits by branching to `to_address`, the
/// exit jump in the JIT code is patched to go directly to the target block's
/// entry point, skipping the dispatcher loop entirely.
#[derive(Debug, Clone)]
pub struct BlockChainEntry {
    /// Guest address of the source block.
    pub from_address: u64,
    /// Guest address of the target block.
    pub to_address: u64,
    /// Address in JIT code where the branch instruction was patched.
    pub chain_patch_location: u64,
    /// Whether the chain is currently active.
    pub chained: bool,
}

// ---------------------------------------------------------------------------
// Inline Cache
// ---------------------------------------------------------------------------

/// A single inline cache entry for indirect call sites.
///
/// Caches the last resolved target address for an indirect call or virtual
/// dispatch. On subsequent calls, the cached target is tried first (fast path)
/// before falling back to full resolution (slow path).
#[derive(Debug, Clone)]
pub struct InlineCacheEntry {
    /// Guest address of the call site.
    pub call_site: u64,
    /// Last resolved target guest address.
    pub last_target: u64,
    /// Number of cache hits (target matched).
    pub hit_count: u32,
    /// Number of cache misses (target changed).
    pub miss_count: u32,
}

/// Inline cache for indirect calls and virtual dispatches.
///
/// # Performance Impact
/// Indirect calls (e.g., virtual function tables, function pointers) require
/// expensive lookups each time. By caching the last target, the common
/// monomorphic case (same target every time) is reduced to a single comparison
/// and direct branch, avoiding the full dispatch overhead.
#[derive(Debug)]
pub struct InlineCache {
    /// Cache entries keyed by call-site guest address.
    pub entries: HashMap<u64, InlineCacheEntry>,
    /// FIFO eviction queue tracking insertion order.
    /// Front = oldest entry (next to evict), Back = newest entry.
    pub(super) eviction_queue: VecDeque<u64>,
    /// Maximum number of cache entries before eviction.
    pub max_entries: usize,
}

impl InlineCache {
    /// Create a new inline cache with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            eviction_queue: VecDeque::new(),
            max_entries,
        }
    }

    /// Look up a call site in the cache with the expected target.
    ///
    /// Returns `true` if the target matches the cached value (cache hit),
    /// `false` if it doesn't match or wasn't cached (cache miss). On a miss,
    /// the cache is updated with the new target.
    pub fn lookup(&mut self, call_site: u64, target: u64) -> bool {
        if let Some(entry) = self.entries.get_mut(&call_site) {
            if entry.last_target == target {
                entry.hit_count += 1;
                return true; // Cache hit — matching target found
            } else {
                entry.last_target = target;
                entry.miss_count += 1;
                return false;
            }
        }

        // New entry — evict oldest (FIFO) if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        self.eviction_queue.push_back(call_site);
        self.entries.insert(
            call_site,
            InlineCacheEntry {
                call_site,
                last_target: target,
                hit_count: 0,
                miss_count: 1,
            },
        );

        false
    }

    /// Evict the oldest entry from the cache (FIFO policy).
    /// Skips any stale eviction queue entries that were already removed
    /// (e.g., via `invalidate()`).
    pub(super) fn evict_oldest(&mut self) {
        while let Some(evict_key) = self.eviction_queue.pop_front() {
            if self.entries.remove(&evict_key).is_some() {
                break;
            }
        }
    }

    /// Invalidate a single cache entry.
    pub fn invalidate(&mut self, call_site: u64) {
        self.entries.remove(&call_site);
        // Note: the eviction queue entry becomes stale and will be
        // skipped on the next eviction via `evict_oldest()`.
        // This avoids an O(n) scan of the queue to find the entry.
    }

    /// Invalidate all cache entries.
    pub fn invalidate_all(&mut self) {
        self.entries.clear();
        self.eviction_queue.clear();
    }

    /// Get the hit rate as a value between 0.0 and 1.0.
    pub fn hit_rate(&self) -> f64 {
        let total_hits: u32 = self.entries.values().map(|e| e.hit_count).sum();
        let total_misses: u32 = self.entries.values().map(|e| e.miss_count).sum();
        let total = total_hits + total_misses;
        if total == 0 {
            0.0
        } else {
            total_hits as f64 / total as f64
        }
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// G5: FastThunk — ARM64 thunk codegen for direct host-call dispatch
// ---------------------------------------------------------------------------

/// A registered fast-thunk entry: maps a host function pointer to a small
/// ARM64 trampoline that calls it directly from JIT-compiled guest code.
#[allow(dead_code)] // fast-thunk machine-code cache (kept for the disabled fast-thunk path)
pub(super) struct FastThunkEntry {
    /// The host function to call.
    pub(super) host_fn: usize,
    /// ARM64 trampoline machine code ("thunk") that jumps to `host_fn`.
    pub(super) thunk_code: Vec<u8>,
    /// Virtual address where the thunk is mapped for execution.
    pub(super) thunk_addr: usize,
    /// Guest (x86) virtual address of the thunk call target, if known.
    /// Set by [`FastThunkTable::register_with_guest_addr`] so the JIT can
    /// look up the trampoline address when compiling a `Call` instruction.
    pub(super) guest_addr: Option<u64>,
}

/// Manages all registered fast-thunks, providing executable ARM64 trampolines
/// that allow JIT-compiled guest code to call host functions without going
/// through the full guest→host dispatch loop.
pub struct FastThunkTable {
    pub(super) entries: Vec<FastThunkEntry>,
    /// Resolved-target cache: guest (x86) address → trampoline address.
    /// Maintained at registration time so repeat resolutions bypass both the
    /// linear entry scan and the global-map mutex.
    pub(super) guest_index: HashMap<u64, usize>,
    /// mmap'd executable code zone for thunks.
    pub(super) code_zone: Option<*mut u8>,
    pub(super) code_zone_size: usize,
    pub(super) code_zone_used: usize,
}

// SAFETY: FastThunkTable contains raw mmap'd pointers for the code zone.
// It is safe to send across threads because the code zone is only accessed
// through &mut methods (register). The entries vector is also only modified
// under &mut self.
unsafe impl Send for FastThunkTable {}
// SAFETY: All shared methods take &self and only read data. Mutable
// operations (register) require &mut self, preventing data races.
unsafe impl Sync for FastThunkTable {}

impl Default for FastThunkTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FastThunkTable {
    /// Create a new, empty fast-thunk table.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            guest_index: HashMap::new(),
            code_zone: None,
            code_zone_size: 0,
            code_zone_used: 0,
        }
    }

    /// Ensure we have an executable code zone, allocating one if needed.
    pub(super) fn ensure_code_zone(&mut self) -> AppResult<()> {
        if self.code_zone.is_some() {
            return Ok(());
        }
        #[cfg(test)]
        if JIT_TEST_DENY_THUNK_ZONE.with(|deny| deny.replace(false)) {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "failed to mmap fast-thunk code zone",
            ));
        }
        // Allocate 64 KB (one JIT page) of executable memory for thunks
        let size = 64 * 1024;
        // SAFETY: mmap allocates a 64KB anonymous private mapping with
        // RWX permissions (or MAP_JIT on aarch64). null_mut() lets the
        // kernel choose the address. fd=-1 is valid for MAP_ANONYMOUS.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "failed to mmap fast-thunk code zone",
            ));
        }
        self.code_zone = Some(ptr as *mut u8);
        self.code_zone_size = size;
        self.code_zone_used = 0;
        Ok(())
    }

    /// Register a fast-thunk for a host function.
    ///
    /// Returns the entry index, which can be used by the JIT to emit a call
    /// to this thunk instead of going through the full dispatch loop.
    pub fn register(&mut self, host_fn: usize) -> AppResult<usize> {
        self.ensure_code_zone()?;

        let zone = self.code_zone.unwrap();
        let offset = self.code_zone_used;
        // SAFETY: zone is a valid mmap'd pointer from ensure_code_zone.
        // offset tracks the number of bytes already used in the zone,
        // and the caller ensures offset + thunk.len() <= code_zone_size.
        let addr = unsafe { zone.add(offset) } as usize;

        // Emit ARM64 trampoline with proper frame save/restore:
        //
        //   stp   x29, x30, [sp, #-16]!   // Save frame pointer and link register
        //   mov   x29, sp                  // Set up frame pointer
        //   ldr   x17, [pc, #16]           // Load host_fn address from literal pool
        //   blr   x17                      // Call host function (return value in x0)
        //   ldp   x29, x30, [sp], #16      // Restore frame pointer and link register
        //   ret                             // Return to caller
        //   .quad host_fn                  // Literal pool entry (8 bytes)
        //
        // This provides:
        //   - Proper x29/x30 frame chain for stack unwinding and debugging
        //   - BLR-based calling convention (sets x30 for unwinders)
        //   - Correct return via x0 after host function completes
        //
        // Encodings:
        //   stp x29, x30, [sp, #-16]! = 0xA9BF7BFD
        //   mov x29, sp                = 0x910003FD
        //   ldr x17, [pc, #16]         = 0x58000091
        //   blr x17                    = 0xD63F0220
        //   ldp x29, x30, [sp], #16   = 0xA8C17BFD
        //   ret                        = 0xD65F03C0
        let thunk: Vec<u8> = vec![
            0xFD,
            0x7B,
            0xBF,
            0xA9, // stp x29, x30, [sp, #-16]!
            0xFD,
            0x03,
            0x00,
            0x91, // mov x29, sp
            0x91,
            0x00,
            0x00,
            0x58, // ldr x17, [pc, #16]
            0x20,
            0x02,
            0x3F,
            0xD6, // blr x17
            0xFD,
            0x7B,
            0xC1,
            0xA8, // ldp x29, x30, [sp], #16
            0xC0,
            0x03,
            0x5F,
            0xD6, // ret
            // literal pool: host_fn (8 bytes, little-endian)
            (host_fn & 0xFF) as u8,
            ((host_fn >> 8) & 0xFF) as u8,
            ((host_fn >> 16) & 0xFF) as u8,
            ((host_fn >> 24) & 0xFF) as u8,
            ((host_fn >> 32) & 0xFF) as u8,
            ((host_fn >> 40) & 0xFF) as u8,
            ((host_fn >> 48) & 0xFF) as u8,
            ((host_fn >> 56) & 0xFF) as u8,
        ];

        // Toggle MAP_JIT region to writable (and non-executable).  On Apple
        // Silicon, MAP_JIT memory can only be either writable or executable
        // at any given time — never both.
        // SAFETY: pthread_jit_write_protect_np(0) switches MAP_JIT pages
        // from executable to writable. No concurrent execution of thunk
        // code occurs because registration happens before execution.
        let _install = JIT_CODE_INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            libc::pthread_jit_write_protect_np(0);
        }

        // Write thunk into the code zone
        // SAFETY: addr is within the mmap'd code zone (offset + thunk.len()
        // <= code_zone_size ensured by ensure_code_zone). thunk.as_ptr() is
        // valid for thunk.len() bytes. Regions are non-overlapping.
        // After writing, we switch back to executable with write_protect(1).
        unsafe {
            std::ptr::copy_nonoverlapping(thunk.as_ptr(), addr as *mut u8, thunk.len());
            // ARM64 requires an explicit instruction-cache flush after writing
            // code, exactly like block installation.
            JitMemoryManager::flush_icache(addr as *mut u8, thunk.len());
            // Re-enable execute (and disable write) on the MAP_JIT region.
            // On Apple Silicon, MAP_JIT memory can only be either writable or
            // executable at any given time — never both.  After writing the
            // trampoline we must switch back to executable so the CPU can
            // run it without faulting (SIGBUS).
            libc::pthread_jit_write_protect_np(1);
        }
        self.code_zone_used += thunk.len();

        let entry = FastThunkEntry {
            host_fn,
            thunk_code: thunk,
            thunk_addr: addr,
            guest_addr: None,
        };
        let idx = self.entries.len();
        self.entries.push(entry);
        Ok(idx)
    }

    /// Register a fast-thunk for a host function, associating it with a guest
    /// virtual address so the JIT compiler can look up the trampoline when it
    /// encounters a `Call` to `guest_addr`.
    ///
    /// Returns the entry index.
    pub fn register_with_guest_addr(
        &mut self,
        host_fn: usize,
        guest_addr: u64,
    ) -> AppResult<usize> {
        let idx = self.register(host_fn)?;
        if let Some(entry) = self.entries.get_mut(idx) {
            entry.guest_addr = Some(guest_addr);
        }
        if let Some(thunk_addr) = self.thunk_address(idx) {
            // Populate the in-table resolved-target cache so repeat
            // resolutions are an O(1) hash lookup with no lock.
            self.guest_index.insert(guest_addr, thunk_addr);
        }
        {
            // Propagate lock poisoning as an explicit error — the caller
            // needs to know that the thunk registration may not have
            // completed, which could cause JIT-compiled calls to fall
            // back to the slow dispatch path.
            let mut map = FAST_THUNK_MAP.lock().map_err(|e| {
                AppError::new(
                    ReasonCode::RcLockPoisoned,
                    format!("FAST_THUNK_MAP lock poisoned during register_with_guest_addr: {e}"),
                )
            })?;
            if let Some(thunk_addr) = self.thunk_address(idx) {
                map.insert(guest_addr, thunk_addr);
            }
        }
        Ok(idx)
    }

    /// Look up the ARM64 trampoline address for a given guest thunk address.
    ///
    /// The resolved-target index populated by
    /// [`FastThunkTable::register_with_guest_addr`] is consulted first: a
    /// repeat resolution is a single hash lookup that bypasses both the
    /// linear entry scan and the global-map mutex.  The entry scan / global
    /// map remain as the fallback for tables that were not populated through
    /// `register_with_guest_addr`.
    pub fn find_thunk_by_guest(&self, guest_addr: u64) -> Option<usize> {
        // Fast path: resolved-target cache (no scan, no lock).
        if let Some(thunk_addr) = self.guest_index.get(&guest_addr) {
            THUNK_RESOLVE_HITS.fetch_add(1, Ordering::Relaxed);
            return Some(*thunk_addr);
        }
        THUNK_RESOLVE_MISSES.fetch_add(1, Ordering::Relaxed);
        // Fallback 1: in-memory entries (may have been populated by a table
        // instance that did not go through `register_with_guest_addr`).
        for entry in &self.entries {
            if entry.guest_addr == Some(guest_addr) {
                return Some(entry.thunk_addr);
            }
        }
        // Fallback 2: the global map (may have been populated by another
        // table instance). This method returns Option, so we recover from
        // a poisoned lock (returning None) rather than propagating an error,
        // since the caller already handles the "not found" case.
        let map = match FAST_THUNK_MAP.lock() {
            Ok(guard) => guard,
            Err(e) => {
                eprintln!(
                    "FAST_THUNK_MAP lock poisoned during find_thunk_by_guest: {e}, returning None"
                );
                return None;
            }
        };
        map.get(&guest_addr).copied()
    }

    /// Get the thunk address for a registered entry.
    pub fn thunk_address(&self, idx: usize) -> Option<usize> {
        self.entries.get(idx).map(|e| e.thunk_addr)
    }

    /// Get the host function pointer for a registered entry.
    pub fn host_fn(&self, idx: usize) -> Option<usize> {
        self.entries.get(idx).map(|e| e.host_fn)
    }

    /// Number of registered thunks.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no thunks are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns true if the given guest address has a registered fast-thunk.
    pub fn contains_guest_addr(&self, guest_addr: u64) -> bool {
        self.guest_index.contains_key(&guest_addr)
            || self
                .entries
                .iter()
                .any(|e| e.guest_addr == Some(guest_addr))
    }

    /// Snapshot of every guest address with a resolved trampoline.  Passed to
    /// `JitCompiler::compile_instruction` so `Call` sites to stable resolved
    /// thunks are emitted as direct trampoline calls instead of dispatcher
    /// exits.
    pub fn guest_addrs(&self) -> std::collections::HashSet<u64> {
        let mut addrs: std::collections::HashSet<u64> = self.guest_index.keys().copied().collect();
        for entry in &self.entries {
            if let Some(guest_addr) = entry.guest_addr {
                addrs.insert(guest_addr);
            }
        }
        addrs
    }
}

impl Drop for FastThunkTable {
    fn drop(&mut self) {
        if let Some(zone) = self.code_zone.take() {
            // SAFETY: zone was returned by a successful mmap in
            // ensure_code_zone, and code_zone_size matches the original
            // allocation. munmap releases the mapping.
            unsafe {
                libc::munmap(zone as *mut libc::c_void, self.code_zone_size);
            }
        }
    }
}
