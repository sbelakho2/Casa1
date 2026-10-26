//! JIT execution engine for Casa1.
//!
//! Compiles translated IR blocks into native ARM64 machine code and executes them
//! directly on the host CPU. Uses MAP_JIT for W^X-compliant executable memory
//! allocation on Apple Silicon.

#![allow(unused_imports)]
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

mod aot;
mod arm64_emitter;
mod code_cache;
mod frontend;
mod optimizer;
mod patching_chaining;
mod profiling;
mod register_allocator;
mod safepoints;
mod unwind;

pub use aot::*;
pub use arm64_emitter::*;
pub use code_cache::*;
pub use frontend::*;
pub use optimizer::*;
pub use patching_chaining::*;
pub use profiling::*;
use register_allocator::*;
pub use safepoints::*;
pub use unwind::*;

// ---------------------------------------------------------------------------
// JIT memory management
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Executable memory manager
// ---------------------------------------------------------------------------

// Test-only fault-injection seams.  Each counter records how many times the
// corresponding operation was entered; when the matching `*_AT` slot equals
// that 1-based call index the operation fails.  `0` disables the seam.
#[cfg(test)]
thread_local! {
    static JIT_TEST_ALLOC_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_FAIL_ALLOC_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_WRITE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_DENY_WRITE_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_FINALIZE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_DENY_FINALIZE_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_DENY_THUNK_ZONE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Force the next `chain_blocks` call to fail (self-test error-path probe).
    static JIT_TEST_FORCE_CHAIN_ERROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Force the next resolved-thunk map lookup to miss.
    static JIT_TEST_THUNK_MAP_MISS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Make the self-test host thunk write the wrong sentinel.
    static JIT_TEST_SELF_TEST_THUNK_BAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Drive the parent self-test's executable-resolution paths: 1 = make
    /// `current_exe` fail, 2 = spawn a nonexistent child, 3 = spawn `/bin/true`
    /// (exits 0 without a report).
    static JIT_TEST_SELF_TEST_EXE_MODE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    /// Compile the self-test's first block with a wrong immediate.
    static JIT_TEST_SELF_TEST_WRONG_ORIGINAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Skip writing the self-test's re-patched instruction (finalize still runs).
    static JIT_TEST_SKIP_REPATCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Count `execute_block` entries per thread and suppress the safepoint
    /// flag on the configured 1-based call.
    static JIT_TEST_EXEC_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_IGNORE_SAFEPOINT_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Force the host safepoint flag on the configured 1-based execute call.
    static JIT_TEST_FORCE_SAFEPOINT_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Corrupt the next non-empty SMC drain: 1 = drop the invalidation
    /// (stale block stays cached), 2 = evict the cache without an
    /// invalidation event (stale clone detected, counter stays zero).
    static JIT_TEST_SMC_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    /// Ignore the faulted-block bar once (simulates a lost quarantine).
    static JIT_TEST_IGNORE_FAULTED_BLOCKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Pre-publish the source link before `chain_blocks` (simulates an
    /// already-linked slot whose publication is not re-counted).
    static JIT_TEST_PREPUBLISH_CHAIN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn test_seam_fails(
    calls: &'static std::thread::LocalKey<std::cell::Cell<usize>>,
    fail_at: &'static std::thread::LocalKey<std::cell::Cell<usize>>,
) -> bool {
    calls.with(|calls| {
        let call = calls.get() + 1;
        calls.set(call);
        fail_at.with(|fail_at| fail_at.get() == call)
    })
}

#[cfg(test)]
mod coverage_adversarial_tests;
#[cfg(test)]
mod jit_helper_semantics;
#[cfg(test)]
mod production_safety_tests;
#[cfg(test)]
mod sigbus_diagnostic_tests;
#[cfg(test)]
mod tests;
