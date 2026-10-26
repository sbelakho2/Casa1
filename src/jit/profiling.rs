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

// ── Guest-page materialisation instrumentation ──────────────────────────────
//
// The flat guest mirror is populated strictly on demand: only guest pages
// that are actually committed (or faulted on) are copied into it.  These
// monotonic counters make that work observable so tests can assert that the
// former whole-4-GiB prefault is gone.

/// Number of 4 KiB guest pages copied into (materialised in) the flat mirror.
pub static GUEST_PAGES_MATERIALISED: AtomicU64 = AtomicU64::new(0);
/// Number of batched sync operations performed (one per contiguous run of
/// materialised pages, plus one per page in the signal-handler fast path).
pub static GUEST_SYNC_OPERATIONS: AtomicU64 = AtomicU64::new(0);
/// Total bytes copied from `MemoryImage` into the flat mirror.
pub static GUEST_SYNC_BYTES_COPIED: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the guest-page materialisation counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuestMemoryTelemetry {
    pub pages_materialised: u64,
    pub sync_operations: u64,
    pub bytes_copied: u64,
}

/// Read the current guest-page materialisation counters.
pub fn guest_memory_telemetry() -> GuestMemoryTelemetry {
    GuestMemoryTelemetry {
        pages_materialised: GUEST_PAGES_MATERIALISED.load(Ordering::Relaxed),
        sync_operations: GUEST_SYNC_OPERATIONS.load(Ordering::Relaxed),
        bytes_copied: GUEST_SYNC_BYTES_COPIED.load(Ordering::Relaxed),
    }
}

/// Reset the guest-page materialisation counters (test/diagnostic helper).
pub fn reset_guest_memory_telemetry() {
    GUEST_PAGES_MATERIALISED.store(0, Ordering::Relaxed);
    GUEST_SYNC_OPERATIONS.store(0, Ordering::Relaxed);
    GUEST_SYNC_BYTES_COPIED.store(0, Ordering::Relaxed);
}

// ── Resolved host-thunk target instrumentation ─────────────────────────────

/// Number of guest→host thunk resolutions served from the resolved-target
/// index (the fast path that bypasses the entry scan and global-map lock).
pub static THUNK_RESOLVE_HITS: AtomicU64 = AtomicU64::new(0);
/// Number of guest→host thunk resolutions that missed the fast index and
/// fell back to the global map (or returned "not registered").
pub static THUNK_RESOLVE_MISSES: AtomicU64 = AtomicU64::new(0);

/// Reset the thunk-resolution counters (test/diagnostic helper).
pub fn reset_thunk_resolve_telemetry() {
    THUNK_RESOLVE_HITS.store(0, Ordering::Relaxed);
    THUNK_RESOLVE_MISSES.store(0, Ordering::Relaxed);
}

/// `(hits, misses)` since the last reset.
pub fn thunk_resolve_telemetry() -> (u64, u64) {
    (
        THUNK_RESOLVE_HITS.load(Ordering::Relaxed),
        THUNK_RESOLVE_MISSES.load(Ordering::Relaxed),
    )
}

/// Benchmark-only AOT cache probe: compile once, then load the persisted
/// block through `rounds` fresh runtime instances.  Returns the accumulated
/// `(hits, misses, rejected)` counters.
#[doc(hidden)]
pub fn bench_aot_hits(rounds: u64) -> (u64, u64, u64) {
    let directory = std::env::temp_dir().join(format!(
        "casa1-aot-bench-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let ir = [IrInstruction::Nop];
    let address = 0x1000;
    let mut totals = (0_u64, 0_u64, 0_u64);
    {
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.set_aot_cache_dir(Some(directory.clone()));
        let _ = runtime.get_or_compile_slice_block(&ir, address, GuestArch::X64);
        let metrics = runtime.aot_metrics();
        totals = (
            totals.0 + metrics.0,
            totals.1 + metrics.1,
            totals.2 + metrics.2,
        );
    }
    for _ in 0..rounds {
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.set_aot_cache_dir(Some(directory.clone()));
        let _ = runtime.get_or_compile_slice_block(&ir, address, GuestArch::X64);
        let metrics = runtime.aot_metrics();
        totals = (
            totals.0 + metrics.0,
            totals.1 + metrics.1,
            totals.2 + metrics.2,
        );
    }
    let _ = std::fs::remove_dir_all(&directory);
    totals
}

/// Benchmark-only harness for production worker slices.  It keeps the
/// `JitRuntime` alive because the compiled entry addresses live in its
/// executable mappings.
#[doc(hidden)]
pub struct WorkerSliceBenchmark {
    pub(super) _runtime: JitRuntime,
    pub(super) program: GuestSliceProgram,
    pub(super) state: CpuState,
    pub(super) thread: SliceThreadState,
    pub(super) shutdown: AtomicBool,
    pub(super) entry: u64,
    pub(super) rsp: u64,
}

#[doc(hidden)]
impl WorkerSliceBenchmark {
    pub fn new(
        arch: GuestArch,
        memory: &MemoryImage,
        blocks: &[(u64, Vec<IrInstruction>)],
        entry: u64,
        rsp: u64,
    ) -> Self {
        let mut runtime = JitRuntime::new(arch);
        runtime.set_aot_cache_dir(None);
        for (address, ir) in blocks {
            runtime
                .get_or_compile_slice_block(ir, *address, arch)
                .expect("compile benchmark worker block");
        }
        let program = runtime.build_slice_program(memory);
        let mut state = CpuState::new(arch);
        state.set(Register::Rsp, rsp);
        Self {
            _runtime: runtime,
            program,
            state,
            thread: SliceThreadState::default(),
            shutdown: AtomicBool::new(false),
            entry,
            rsp,
        }
    }

    pub fn reset(&mut self) {
        self.state.rip = self.entry;
        self.state.set(Register::Rsp, self.rsp);
        self.state.set(Register::Rcx, 0);
        self.thread = SliceThreadState::default();
    }

    pub fn set_rax(&mut self, value: u64) {
        self.state.set(Register::Rax, value);
    }

    /// Seed the guest loop counter (RCX) for benchmark workloads.
    pub fn set_rcx(&mut self, value: u64) {
        self.state.set(Register::Rcx, value);
    }

    /// Enable or disable native block linking for this benchmark harness.
    ///
    /// Disabling clears every worker link slot; execution still produces the
    /// same guest state but dispatches each block separately.  This is the
    /// measurement control for the linked-loop benchmark.
    pub fn set_linking(&mut self, enabled: bool) {
        if enabled {
            self._runtime.publish_slice_links();
        } else {
            for block in self.program.blocks.values() {
                block.link_target.store(0, Ordering::Release);
                block.taken_link.store(0, Ordering::Release);
                block.fallthrough_link.store(0, Ordering::Release);
                block.call_link.store(0, Ordering::Release);
                block.return_entry_link.store(0, Ordering::Release);
            }
        }
    }

    /// Borrow the guest state (benchmark inspection).
    pub fn state(&self) -> &CpuState {
        &self.state
    }

    pub fn run(&mut self, budget: u64) -> (u64, u64, SliceMetrics) {
        // SAFETY: the harness owns the runtime, the program was built from it,
        // and `state` is exclusively borrowed for the call.
        let report = unsafe {
            run_slice(
                &self.program,
                &mut self.state,
                &mut self.thread,
                budget,
                &self.shutdown,
            )
        };
        (
            report.blocks_executed,
            report.metrics.instructions_executed,
            report.metrics,
        )
    }
}

/// Benchmark-only indirect-cache workload: returns the accumulated hit count.
#[doc(hidden)]
pub fn bench_indirect_cache(iterations: u64) -> u64 {
    let mut cache = IndirectInlineCache::default();
    let mut hits = 0_u64;
    for index in 0..iterations {
        let target = 0x2000 + (index % 6) * 0x1000;
        if let Some(entry) = cache.lookup(0x1000, target) {
            hits = hits.wrapping_add(entry as u64);
        } else {
            cache.insert(0x1000, target, target as usize);
        }
    }
    hits.wrapping_add(cache.hits())
}

/// Benchmark-only return-predictor workload: returns the accumulated hit count.
#[doc(hidden)]
pub fn bench_return_predictor(iterations: u64) -> u64 {
    let mut predictor = ReturnPredictor::default();
    let mut hits = 0_u64;
    for index in 0..iterations {
        let return_address = 0x1000 + (index % 64) * 0x10;
        predictor.on_call(return_address);
        if predictor.on_return(return_address) {
            hits = hits.wrapping_add(1);
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// JIT self-test (--jit-self-test)
// ---------------------------------------------------------------------------

/// Machine-readable report of the `--jit-self-test` run.
///
/// `active` is true only when code was actually ALLOCATED through the
/// capability-probed mechanism, compiled, executed and re-patched in a child
/// process — a self-test that cannot execute reports `active: false` with the
/// reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JitSelfTestReport {
    /// True when the full self-test (compile → execute → safepoint →
    /// re-patch → re-execute) completed in a real process.
    pub active: bool,
    /// Number of blocks compiled during the self-test.
    pub compiled_blocks: u64,
    /// Number of block executions during the self-test.
    pub executed_blocks: u64,
    /// True when the host safepoint flag was observed to produce
    /// EXIT_SAFEPOINT from compiled code.
    pub safepoint_observed: bool,
    /// Block links published during the self-test (backedge linking).
    #[serde(default)]
    pub chain_links: u64,
    /// `Call` sites compiled to a direct resolved-thunk call.
    #[serde(default)]
    pub thunk_direct_calls: u64,
    /// Compiled blocks invalidated by the self-modifying-code test.
    #[serde(default)]
    pub smc_invalidations: u64,
    /// Blocks handed to the interpreter by the fault-equivalent fallback.
    #[serde(default)]
    pub fault_fallbacks: u64,
    /// Why the self-test is not active, when it is not.
    pub fallback_reason: Option<String>,
}

impl Default for JitSelfTestReport {
    fn default() -> Self {
        Self {
            active: false,
            compiled_blocks: 0,
            executed_blocks: 0,
            safepoint_observed: false,
            chain_links: 0,
            thunk_direct_calls: 0,
            smc_invalidations: 0,
            fault_fallbacks: 0,
            fallback_reason: None,
        }
    }
}

/// The guest value the self-test block writes into RAX before any patching.
pub(super) const JIT_SELF_TEST_ORIGINAL_VALUE: u64 = 42;
/// The value written by the RE-PATCHED instruction (the patch must be
/// observable: executing the changed code must yield this value).
pub(super) const JIT_SELF_TEST_PATCHED_VALUE: u64 = 43;

/// ARM64 `movz x4, #imm16` encodings for the two self-test immediates (RAX is
/// guest GPR 0, mapped to ARM64 x4).  `movz x4, #imm` = `0xd2800000 |
/// (imm << 5) | 4`.
pub(super) fn movz_x4(imm: u16) -> u32 {
    0xd2800000u32 | ((imm as u32) << 5) | 4
}

/// Run the FULL self-test inside this process.  Verifies:
///
/// 1. MAP_JIT memory is allocated and flipped W→X
///    ([`JitCompiler::compile_block`] + [`JitMemoryManager::finalize_code`]);
/// 2. a tiny translated block executes and produces the guest result;
/// 3. the host safepoint flag produces `EXIT_SAFEPOINT` from compiled code;
/// 4. the code page is re-patched (W) and the changed code executes (X),
///    yielding the patched value.
///
/// Any verification failure returns an error.  If the recorded capability is
/// wrong and execution faults, the caller runs this in a child process and
/// turns the fault into `active: false`.
pub fn run_jit_self_test_child() -> AppResult<JitSelfTestReport> {
    let mut runtime = JitRuntime::new(GuestArch::X64);
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    // A tiny translated block: `mov rax, 42` at guest 0x1000.  The block has
    // no control flow, so it exits EXIT_NORMAL and the compiled prefix is
    // exactly what we verify.
    let guest_address = 0x1000u64;
    #[cfg(test)]
    let original_value = if JIT_TEST_SELF_TEST_WRONG_ORIGINAL.with(|wrong| wrong.replace(false)) {
        JIT_SELF_TEST_ORIGINAL_VALUE.wrapping_sub(1)
    } else {
        JIT_SELF_TEST_ORIGINAL_VALUE
    };
    #[cfg(not(test))]
    let original_value = JIT_SELF_TEST_ORIGINAL_VALUE;
    let ir = vec![IrInstruction::MovImm {
        dst: Register::Rax,
        value: original_value,
    }];
    state.rip = guest_address;

    // Copy the compiled block's identity out immediately: the reference into
    // `runtime` must not outlive the mutable borrows below.
    let (block_entry, block_code_size, compiled) = {
        let block = runtime
            .get_or_compile(&ir, guest_address, GuestArch::X64, None)
            .map_err(|error| {
                AppError::new(
                    ReasonCode::RcJitCompilationError,
                    format!("JIT self-test: compile_block failed: {}", error.message),
                )
            })?;
        (block.entry(), block.code_size, runtime.blocks_compiled)
    };
    let code_words: Vec<u32> = unsafe {
        std::slice::from_raw_parts(block_entry as *const u32, block_code_size / 4).to_vec()
    };
    let original_insn = movz_x4(original_value as u16);
    let patched_insn = movz_x4(JIT_SELF_TEST_PATCHED_VALUE as u16);
    let patch_offset = code_words
        .iter()
        .position(|word| *word == original_insn)
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                "JIT self-test: compiled block does not contain the movz x4 immediate \
                 (block layout changed?)",
            )
        })?;

    // Sync guest memory and install the SIGBUS page-sync handler, exactly as
    // the live runtime does before native execution.
    runtime.sync_all_pages_to_flat(&memory);
    runtime.ensure_sigbus_handler(&memory);

    let mut execute = |runtime: &mut JitRuntime, state: &mut CpuState| -> JitExitReason {
        let block = runtime
            .block_cache
            .get(&guest_address)
            .cloned()
            .expect("self-test block remains compiled");
        // SAFETY: single-threaded self-test; block points into this runtime's
        // MAP_JIT pages; state/memory are live for the duration of the call.
        // The read lock prevents a concurrent chain-break from racing the
        // W/X flip.
        let _guard = JIT_EXEC_LOCK
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe { runtime.execute_block(&block, state, &mut memory) }
    };

    // 1. Execute the original code: guest result must be visible.
    let reason = execute(&mut runtime, &mut state);
    if reason != (JitExitReason::Normal { new_rip: state.rip }) {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!("JIT self-test: first execution exited with {reason:?}, expected Normal"),
        ));
    }
    if state.get(Register::Rax) != JIT_SELF_TEST_ORIGINAL_VALUE {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: guest result mismatch: rax={} expected {}",
                state.get(Register::Rax),
                JIT_SELF_TEST_ORIGINAL_VALUE
            ),
        ));
    }

    // 2. Safepoint: set the host flag; the compiled prologue must exit with
    // EXIT_SAFEPOINT without running the body.
    state.set(Register::Rax, 0);
    JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Relaxed);
    let reason = execute(&mut runtime, &mut state);
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
    if reason != JitExitReason::Safepoint {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: safepoint flag did not produce EXIT_SAFEPOINT (got {reason:?})"
            ),
        ));
    }
    let safepoint_observed = true;

    // 3. Re-patch the code page (W) and execute the changed code (X): the
    // patched immediate must be visible to execution.
    // SAFETY: single-threaded; no code is executing while the page is
    // writable (we are between execute_block calls).
    unsafe {
        if !runtime
            .compiler
            .memory_manager
            .make_writable(block_entry as *mut u8, block_code_size)
        {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "JIT self-test: compiled code page is not writable",
            ));
        }
        let words = std::slice::from_raw_parts_mut(block_entry as *mut u32, block_code_size / 4);
        #[cfg(test)]
        let skip_repatch = JIT_TEST_SKIP_REPATCH.with(|skip| skip.replace(false));
        #[cfg(not(test))]
        let skip_repatch = false;
        if !skip_repatch {
            words[patch_offset] = patched_insn;
        }
        if !runtime
            .compiler
            .memory_manager
            .finalize_code(block_entry as *mut u8, block_code_size)
        {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "JIT self-test: re-patched code page is not executable",
            ));
        }
    }
    state.set(Register::Rax, 0);
    let reason = execute(&mut runtime, &mut state);
    if reason != (JitExitReason::Normal { new_rip: state.rip }) {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!("JIT self-test: re-patched execution exited with {reason:?}"),
        ));
    }
    if state.get(Register::Rax) != JIT_SELF_TEST_PATCHED_VALUE {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: re-patched execution did not observe the patch: rax={} expected {}",
                state.get(Register::Rax),
                JIT_SELF_TEST_PATCHED_VALUE
            ),
        ));
    }

    // 4. Backedge/forward linking: publish a link from a jump block to a
    //    control-flow target and execute it.  The source must branch into
    //    the target entry (no dispatcher return), the target must exit with
    //    its own EXIT_JUMP, and the host frame must stay balanced.
    let chain_source = 0x2000u64;
    let chain_target = 0x3000u64;
    let chain_exit = 0x4000u64;
    let source_ir = vec![
        IrInstruction::Nop,
        IrInstruction::Jump {
            target: chain_target,
        },
    ];
    let target_ir = vec![
        IrInstruction::Nop,
        IrInstruction::Jump { target: chain_exit },
    ];
    runtime
        .get_or_compile(&source_ir, chain_source, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: chain source compile failed: {}",
                    error.message
                ),
            )
        })?;
    runtime
        .get_or_compile(&target_ir, chain_target, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: chain target compile failed: {}",
                    error.message
                ),
            )
        })?;
    runtime
        .chain_blocks(chain_source, chain_target)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("JIT self-test: chain_blocks failed: {}", error.message),
            )
        })?;
    let chain_links = runtime.chain_links_formed;
    if chain_links == 0 {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: no block link was published",
        ));
    }
    let source_block = runtime
        .block_cache
        .get(&chain_source)
        .cloned()
        .expect("chain source block remains compiled");
    state.rip = chain_source;
    let reason = unsafe { runtime.execute_block(&source_block, &mut state, &mut memory) };
    if reason != (JitExitReason::Jump { target: chain_exit }) {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!("JIT self-test: linked execution exited with {reason:?}, expected Jump"),
        ));
    }

    // 5. Direct resolved-thunk call: a registered guest thunk must compile to
    //    a direct trampoline call (no EXIT_THUNK) and update guest state.
    const SELF_TEST_THUNK_GUEST: u64 = 0x5000;
    let thunk_registered = runtime
        .register_host_thunk_for_guest(
            jit_self_test_host_thunk as *const () as usize,
            SELF_TEST_THUNK_GUEST,
        )
        .is_some();
    if !thunk_registered {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: failed to register the direct-call host thunk",
        ));
    }
    let thunk_ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 7,
        },
        IrInstruction::Call {
            target: SELF_TEST_THUNK_GUEST,
            return_address: 0x6004,
        },
    ];
    let thunk_before = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed);
    runtime
        .get_or_compile(&thunk_ir, 0x6000, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: thunk block compile failed: {}",
                    error.message
                ),
            )
        })?;
    let thunk_direct_calls = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed) - thunk_before;
    if thunk_direct_calls == 0 {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: Call to a resolved thunk did not compile to a direct call",
        ));
    }
    let thunk_block = runtime
        .block_cache
        .get(&0x6000u64)
        .cloned()
        .expect("thunk block remains compiled");
    state.set(Register::Rax, 0);
    state.set(Register::Rsp, 0x2000);
    state.rip = 0x6000;
    let reason = unsafe { runtime.execute_block(&thunk_block, &mut state, &mut memory) };
    if reason != (JitExitReason::Normal { new_rip: state.rip }) || state.get(Register::Rax) != 0x99
    {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: direct thunk call failed: reason={reason:?} rax={:#x}",
                state.get(Register::Rax)
            ),
        ));
    }

    // 6. Self-modifying code: a compiled block that stores over its own code
    //    page must invalidate the stale block; the next execution falls back
    //    to the interpreter and recompilation observes the new IR.
    let smc_address = 0x7000u64;
    let smc_writer = 0x7100u64;
    // The guest store must target mapped guest memory (an unmapped write
    // takes the fault path instead of reaching the SMC hook).
    memory.map_zeroed_if_unmapped(smc_address, 0x1000);
    let smc_ir = vec![IrInstruction::MovImm {
        dst: Register::Rax,
        value: 42,
    }];
    runtime
        .get_or_compile(&smc_ir, smc_address, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("JIT self-test: SMC block compile failed: {}", error.message),
            )
        })?;
    let smc_block = runtime
        .block_cache
        .get(&smc_address)
        .cloned()
        .expect("SMC block remains compiled");
    state.rip = smc_address;
    let _ = unsafe { runtime.execute_block(&smc_block, &mut state, &mut memory) };
    let writer_ir = vec![
        IrInstruction::StoreImmediate {
            address: crate::cpu::MemoryOperand {
                base: None,
                index: None,
                scale: 1,
                displacement: 0,
                rip_relative: false,
                rip_base: 0,
                segment: None,
                address_size_32: false,
                absolute_address: Some(smc_address),
            },
            value: 0x9090_9090,
            width: 4,
        },
        IrInstruction::Nop,
    ];
    runtime
        .get_or_compile(&writer_ir, smc_writer, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: SMC writer compile failed: {}",
                    error.message
                ),
            )
        })?;
    let writer_block = runtime
        .block_cache
        .get(&smc_writer)
        .cloned()
        .expect("SMC writer remains compiled");
    state.rip = smc_writer;
    let _ = unsafe { runtime.execute_block(&writer_block, &mut state, &mut memory) };
    // The stale block must NOT run: the entry drain invalidates it and the
    // dispatcher receives the interpreter fallback.
    state.rip = smc_address;
    let reason = unsafe { runtime.execute_block(&smc_block, &mut state, &mut memory) };
    if reason != JitExitReason::Safepoint {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!("JIT self-test: stale SMC block ran instead of falling back: {reason:?}"),
        ));
    }
    let smc_invalidations = runtime.code_invalidations;
    if smc_invalidations == 0 {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: self-modifying code did not invalidate a block",
        ));
    }
    let smc_new_ir = vec![IrInstruction::MovImm {
        dst: Register::Rax,
        value: 43,
    }];
    runtime
        .get_or_compile(&smc_new_ir, smc_address, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("JIT self-test: SMC recompile failed: {}", error.message),
            )
        })?;
    let recompiled = runtime
        .block_cache
        .get(&smc_address)
        .cloned()
        .expect("recompiled SMC block");
    state.set(Register::Rax, 0);
    state.rip = smc_address;
    let _ = unsafe { runtime.execute_block(&recompiled, &mut state, &mut memory) };
    if state.get(Register::Rax) != 43 {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: recompiled SMC block observed stale code: rax={}",
                state.get(Register::Rax)
            ),
        ));
    }

    // 7. Fault-equivalent fallback: an invalid block installation must hand
    //    the block to the interpreter (counter + permanent bar), never abort.
    let fault_address = 0x8000u64;
    runtime
        .get_or_compile(
            &[IrInstruction::MovImm {
                dst: Register::Rax,
                value: 7,
            }],
            fault_address,
            GuestArch::X64,
            None,
        )
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: fault block compile failed: {}",
                    error.message
                ),
            )
        })?;
    runtime.report_block_fault(fault_address);
    let fault_fallbacks = runtime.fault_fallbacks;
    if fault_fallbacks == 0
        || runtime
            .get_or_compile(
                &[IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 7,
                }],
                fault_address,
                GuestArch::X64,
                None,
            )
            .is_ok()
    {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: faulted block was not barred from native compilation",
        ));
    }

    Ok(JitSelfTestReport {
        active: true,
        compiled_blocks: compiled,
        executed_blocks: runtime.blocks_executed,
        safepoint_observed,
        chain_links,
        thunk_direct_calls,
        smc_invalidations,
        fault_fallbacks,
        fallback_reason: None,
    })
}

/// Host thunk used by the self-test direct-call step: the trampoline calls
/// this with (runtime, state, memory, guest_thunk).  It records a sentinel in
/// RAX and asks the bridge to continue (-1).
pub(super) extern "C" fn jit_self_test_host_thunk(
    _runtime: *mut c_void,
    state: *mut CpuState,
    _memory: *mut MemoryImage,
    _thunk_address: u64,
) -> i32 {
    #[cfg(test)]
    let sentinel = if JIT_TEST_SELF_TEST_THUNK_BAD.with(|bad| bad.replace(false)) {
        0x98
    } else {
        0x99
    };
    #[cfg(not(test))]
    let sentinel = 0x99;
    if !state.is_null() {
        // SAFETY: state is the live CpuState passed by the self-test block.
        unsafe {
            (*state).gpr[0] = sentinel;
        }
    }
    -1
}

/// Run the self-test with crash isolation: the actual test executes in a
/// CHILD process so an executable-memory fault is observed as a child
/// failure instead of killing the caller.  `active` is true only when the
/// child ran the full test and reported success.
pub fn run_jit_self_test() -> JitSelfTestReport {
    #[cfg(test)]
    let exec_mode = JIT_TEST_SELF_TEST_EXE_MODE.with(|mode| mode.replace(0));
    #[cfg(not(test))]
    let exec_mode = 0u8;
    let current_exe = match if exec_mode == 1 {
        Err(std::io::Error::from_raw_os_error(libc::ENOENT))
    } else if exec_mode == 2 {
        Ok(std::path::PathBuf::from("/casa1/self-test-missing-binary"))
    } else if exec_mode == 3 {
        Ok(std::path::PathBuf::from("/usr/bin/true"))
    } else {
        std::env::current_exe()
    } {
        Ok(path) => path,
        Err(error) => {
            return JitSelfTestReport {
                active: false,
                compiled_blocks: 0,
                executed_blocks: 0,
                safepoint_observed: false,
                fallback_reason: Some(format!(
                    "cannot resolve current executable for the self-test child: {error}"
                )),
                ..JitSelfTestReport::default()
            };
        }
    };
    let output = match std::process::Command::new(&current_exe)
        .arg("--jit-self-test-child")
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return JitSelfTestReport {
                active: false,
                compiled_blocks: 0,
                executed_blocks: 0,
                safepoint_observed: false,
                fallback_reason: Some(format!("failed to spawn self-test child: {error}")),
                ..JitSelfTestReport::default()
            };
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        match serde_json::from_str::<JitSelfTestReport>(stdout.trim()) {
            Ok(mut report) => {
                // The child only reports active=true on full success; keep
                // its counters but never let a child claim activity it did
                // not prove.
                report.active &= report.safepoint_observed;
                report
            }
            Err(error) => JitSelfTestReport {
                active: false,
                compiled_blocks: 0,
                executed_blocks: 0,
                safepoint_observed: false,
                fallback_reason: Some(format!(
                    "self-test child exited 0 without a valid JitSelfTestReport JSON: {error}"
                )),
                ..JitSelfTestReport::default()
            },
        }
    } else {
        let signal_note = status_signal_description(&output.status);
        JitSelfTestReport {
            active: false,
            compiled_blocks: 0,
            executed_blocks: 0,
            safepoint_observed: false,
            fallback_reason: Some(format!(
                "JIT self-test child did not complete: exit={:?}{}; stdout={} stderr={}",
                output.status.code(),
                signal_note,
                stdout.trim(),
                String::from_utf8_lossy(&output.stderr).trim(),
            )),
            ..JitSelfTestReport::default()
        }
    }
}

#[cfg(unix)]
pub(super) fn status_signal_description(status: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match status.signal() {
        Some(signal) => format!(
            " signal={signal} (fault while executing JIT code — the \
            capability probe's mechanism failed in the child; no entitlement shortcut is assumed)"
        ),
        None => String::new(),
    }
}

#[cfg(not(unix))]
pub(super) fn status_signal_description(_status: &std::process::ExitStatus) -> String {
    String::new()
}
