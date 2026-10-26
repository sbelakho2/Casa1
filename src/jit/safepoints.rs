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

/// When set to `true`, the JIT chaining mechanism will refuse to create
/// *new* block chains.  Existing chains are unaffected — they must be
/// broken explicitly via [`JitRuntime::break_all_chains()`].
///
/// # Protocol
/// - **Watchdog / live-session thread** sets this flag periodically to
///   force the PE runtime to stop forming new chains, eventually causing
///   execution to return to the main loop where the CPU yield check fires.
/// - **PE runtime main loop** checks this flag before auto-chaining in
///   [`get_or_compile`](JitRuntime::get_or_compile) and
///   [`chain_blocks`](JitRuntime::chain_blocks).  After breaking chains
///   and yielding, it clears the flag.
pub static JIT_CHAIN_BREAK_REQUESTED: AtomicBool = AtomicBool::new(false);

/// When set to `true`, the host-side scheduler has requested that the
/// next JIT-compiled block exit to the dispatcher so the safepoint body
/// can run (pump pending guest threads, drain timers/APCs, advance the
/// guest clock).
///
/// # Protocol
/// - **Host scheduler (PE runtime main loop / live watchdog)** sets this
///   flag when the block-dispatch safepoint has been overdue.
/// - **JIT-compiled blocks** check the flag at their prologue (see
///   [`JitCompiler::emit_safepoint_check`]) and exit with `EXIT_SAFEPOINT`
///   when set; the dispatcher maps that to
///   [`JitExitReason::Safepoint`], runs the safepoint body, then
///   re-dispatches the block.
///
/// Active whenever the capability probe selected an executable-memory
/// mechanism: every compiled block reads this flag in its prologue, so a
/// long-running native chain can still reach the host safepoint.
pub static JIT_SAFEPOINT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Global pointer to the active [`JitRuntime`] instance, used by the live
/// session's watchdog thread to force chain-breaking when the worker thread
/// is stuck inside JIT-compiled chains that never return to the dispatcher.
///
/// # Safety
/// - Set by [`register_jit_runtime()`] before the main execution loop starts
///   and cleared by [`unregister_jit_runtime()`] after it finishes.
/// - The pointer is only dereferenced while the PE runtime's main loop is
///   running — at that point `JitRuntime` is guaranteed to be alive on the
///   worker thread's stack (inside `PeHostRuntime`).
/// - `AtomicPtr` is used instead of `Mutex<Option<NonNull>>` because
///   `NonNull` is not `Send`, making it ineligible for use in a static.
pub(super) static JIT_RUNTIME_PTR: AtomicPtr<JitRuntime> = AtomicPtr::new(std::ptr::null_mut());

/// Global lock that prevents the MAP_JIT permission race between JIT code
/// execution and chain-breaking operations.
///
/// On Apple Silicon, `pthread_jit_write_protect_np(0)` (called inside
/// `make_writable()`) makes ALL MAP_JIT pages non-executable for ALL threads.
/// If the worker thread is executing JIT code via `entry_fn()` at that moment,
/// it gets `EXC_BAD_ACCESS` (prefetch abort, code=2).
///
/// # Locking protocol
///
/// * **Read lock** — acquired by `execute_with_jit()` around `entry_fn()`
///   (JIT code execution). Multiple read locks can be held concurrently
///   (though there is currently only one worker thread).
/// * **Write lock (try)** — acquired by `chain_blocks()`, `break_all_chains()`,
///   and `force_break_all_chains()` via `try_write()`. If the worker holds
///   the read lock (inside `entry_fn()`), the chain operation silently skips.
///   The `JIT_CHAIN_BREAK_REQUESTED` flag ensures that the worker will skip
///   JIT execution on its next iteration, allowing the chain operation to
///   succeed then.
///
/// # Why `try_write()` instead of `write()`
///
/// Using a blocking `write()` would cause a deadlock: the watchdog thread
/// would block waiting for the worker to release the read lock, but the
/// worker cannot release the read lock until it exits `entry_fn()`, which
/// requires the watchdog to break chains first. `try_write()` breaks this
/// circular dependency by making chain-breaking best-effort rather than
/// mandatory.
pub static JIT_EXEC_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// Register the active [`JitRuntime`] so the live-session watchdog can
/// force chain-breaking across threads.
///
/// Must be paired with a matching call to [`unregister_jit_runtime()`].
pub fn register_jit_runtime(runtime: &mut JitRuntime) {
    JIT_RUNTIME_PTR.store(runtime as *mut JitRuntime, Ordering::Release);
}

/// Unregister the active [`JitRuntime`] — called after the main execution loop
/// finishes so the watchdog no longer holds a reference.
pub fn unregister_jit_runtime() {
    JIT_RUNTIME_PTR.store(std::ptr::null_mut(), Ordering::Release);
}

/// Forcefully break all JIT block chains on the worker thread, regardless of
/// which thread calls this function.
///
/// This is safe to call from any thread as long as [`register_jit_runtime()`]
/// was called and the runtime is still alive (i.e., the worker thread has not
/// yet called [`unregister_jit_runtime()`]).
///
/// # MAP_JIT permission race
///
/// On Apple Silicon, `pthread_jit_write_protect_np(0)` (called inside
/// `break_all_chains()` → `unchain_block()` → `make_writable()`) makes ALL
/// MAP_JIT pages non-executable for ALL threads.  If the worker thread is
/// executing JIT code (via `entry_fn()` in `execute_with_jit`) at that moment,
/// it gets `EXC_BAD_ACCESS` (prefetch abort, code=2).
///
/// To mitigate this, `force_break_all_chains()` sleeps for 50 ms before
/// calling `break_all_chains()`.  During this sleep, the worker thread has
/// time to exit `entry_fn()` naturally (between block iterations).  Before
/// entering `entry_fn()`, `execute_with_jit()` checks
/// [`JIT_CHAIN_BREAK_REQUESTED`] and skips JIT execution if the flag is set,
/// avoiding the race entirely for the common case.
///
/// For the rare case where the worker is already inside an already-formed
/// chain (a loop of ARM64 B instructions that never returns to the
/// dispatcher), the 50 ms sleep does not help — the worker never exits
/// `entry_fn()`.  In this case, `break_all_chains()` is called without
/// protection, exposing the same microsecond race window as the original
/// code (which worked for 85,000+ blocks before hitting the race).
///
/// Callers MUST set [`JIT_CHAIN_BREAK_REQUESTED`] to `true` BEFORE calling
/// this function.  The worker checks that flag in `chain_blocks()` and in
/// `execute_with_jit()` before `entry_fn()`, stopping new chains from forming.
pub fn force_break_all_chains() {
    // Sleep to give the worker thread a chance to exit entry_fn() between
    // iterations so chain_blocks() can later acquire the write lock.
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Try to acquire the write lock on JIT_EXEC_LOCK to prevent the MAP_JIT
    // permission race. If the worker is inside entry_fn() (holding the read
    // lock), try_write() fails and we return early — chain-breaking will be
    // retried on the next 50 ms tick.
    let _lock = match JIT_EXEC_LOCK.try_write() {
        Ok(guard) => guard,
        Err(_) => {
            eprintln!(
                "[jit] force_break_all_chains: worker holds read lock — deferring chain break"
            );
            return;
        }
    };

    let ptr = JIT_RUNTIME_PTR.load(Ordering::Acquire);
    if !ptr.is_null() {
        // SAFETY: The worker is not inside entry_fn() (we acquired the write
        // lock), so there is no MAP_JIT permission race.
        unsafe {
            (*ptr).break_all_chains();
        }
    }
}
