// ---------------------------------------------------------------------------
// Adversarial coverage: probe failure protocol, executable-memory refusals,
// SMC watch/dirty edge cases, chaining/tier errors, and fault fallbacks.
// ---------------------------------------------------------------------------

use super::*;
use crate::cpu::{GUEST_FLAT_ALIGN, GUEST_FLAT_MIN_SIZE, GUEST_FLAT_SIZE};
use std::sync::atomic::Ordering;

fn probe_matrix(selected: JitExecMechanism) -> JitExecProbeMatrix {
    JitExecProbeMatrix {
        mprotect_rx: JitExecProbeOutcome::NotProbed,
        map_jit_wx_write_protect: JitExecProbeOutcome::NotProbed,
        map_jit_rw_write_protect: JitExecProbeOutcome::NotProbed,
        map_jit_wx_no_write_protect: JitExecProbeOutcome::NotProbed,
        selected,
    }
}

fn capable_runtime() -> JitRuntime {
    assert!(
        jit_execution_available(),
        "this test requires a working executable-memory mechanism"
    );
    JitRuntime::new(GuestArch::X64)
}

fn execute_cached(
    runtime: &mut JitRuntime,
    address: u64,
    state: &mut CpuState,
    memory: &mut MemoryImage,
) -> JitExitReason {
    let block = runtime
        .block_cache
        .get(&address)
        .cloned()
        .expect("block must be compiled");
    state.rip = address;
    // SAFETY: test-only single-threaded execution of a block compiled by
    // this runtime; state/memory outlive the call.
    unsafe { runtime.execute_block(&block, state, memory) }
}

fn smc_slot(page: u64) -> usize {
    let x = (page >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (x >> (64 - 13)) as usize & SMC_WATCH_MASK
}

// ── Capability probe reporting ──────────────────────────────────────────

#[test]
fn jit_exec_mechanism_display_rejects_ambiguous_text() {
    assert_eq!(
        JitExecMechanism::MapJitWx.to_string(),
        "MAP_JIT RWX + pthread_jit_write_protect_np"
    );
    assert_eq!(
        JitExecMechanism::MprotectRx.to_string(),
        "mmap RW + mprotect RX"
    );
    assert_eq!(JitExecMechanism::RwxMmap.to_string(), "mmap RWX");
    assert_eq!(JitExecMechanism::Unavailable.to_string(), "unavailable");
}

#[test]
fn jit_exec_probe_outcome_display_reports_exact_failures() {
    assert_eq!(
        JitExecProbeOutcome::Executed(42).to_string(),
        "executed, returned 42"
    );
    assert_eq!(
        JitExecProbeOutcome::MmapFailed(libc::EINVAL).to_string(),
        "mmap failed: errno 22 (Invalid argument (os error 22))"
    );
    assert_eq!(
        JitExecProbeOutcome::MprotectFailed(libc::EINVAL).to_string(),
        "mprotect(PROT_EXEC) failed: errno 22 (Invalid argument (os error 22))"
    );
    assert_eq!(
        JitExecProbeOutcome::WriteFaulted(libc::SIGBUS).to_string(),
        "write faulted: signal 10"
    );
    assert_eq!(
        JitExecProbeOutcome::ExecuteFaulted(libc::SIGSEGV).to_string(),
        "execution faulted: signal 11"
    );
    assert_eq!(
        JitExecProbeOutcome::ForkFailed(libc::EAGAIN).to_string(),
        "fork failed: errno 35 (Resource temporarily unavailable (os error 35))"
    );
    assert_eq!(
        JitExecProbeOutcome::ChildFailed(7).to_string(),
        "probe child exited without a result: 7"
    );
    assert_eq!(
        JitExecProbeOutcome::NotProbed.to_string(),
        "not probed on this target"
    );
}

#[test]
fn jit_exec_probe_select_rejects_non_executing_mechanisms() {
    // A mechanism that "runs" but returns the wrong value must not win.
    let wrong = JitExecProbeMatrix::select(
        JitExecProbeOutcome::Executed(42),
        JitExecProbeOutcome::Executed(41),
        JitExecProbeOutcome::WriteFaulted(libc::SIGBUS),
        JitExecProbeOutcome::ExecuteFaulted(libc::SIGBUS),
    );
    assert_eq!(wrong.selected, JitExecMechanism::MprotectRx);
    // When neither mechanism executes the stub, native execution is off.
    let none = JitExecProbeMatrix::select(
        JitExecProbeOutcome::MmapFailed(libc::EINVAL),
        JitExecProbeOutcome::MmapFailed(libc::EINVAL),
        JitExecProbeOutcome::MmapFailed(libc::EINVAL),
        JitExecProbeOutcome::MmapFailed(libc::EINVAL),
    );
    assert_eq!(none.selected, JitExecMechanism::Unavailable);
    // The W^X MAP_JIT mechanism is preferred when it executes.
    let preferred = JitExecProbeMatrix::select(
        JitExecProbeOutcome::Executed(42),
        JitExecProbeOutcome::Executed(42),
        JitExecProbeOutcome::Executed(42),
        JitExecProbeOutcome::Executed(42),
    );
    assert_eq!(preferred.selected, JitExecMechanism::MapJitWx);
}

// ── Executable-memory manager refusals ──────────────────────────────────

#[test]
fn jit_memory_manager_mprotect_rejects_foreign_mappings() {
    let mut manager = JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::MprotectRx));
    let code = [0x1f, 0x20, 0x03, 0xd5];
    let ptr = manager.allocate_code_space(code.len());
    assert_eq!(manager.mechanism(), JitExecMechanism::MprotectRx);
    assert!(!ptr.is_null());
    assert_eq!(manager.total_allocated(), JIT_PAGE_SIZE);
    assert_eq!(manager.total_used(), 64);
    // SAFETY: ptr was allocated by this manager for at least code.len().
    unsafe {
        assert_eq!(manager.make_writable(ptr, code.len()), true);
        ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len());
        assert_eq!(manager.finalize_code(ptr, code.len()), true);
    }
    // A pointer outside every managed mmap must be refused, not blindly
    // mprotect'ed (which would corrupt an unrelated host mapping).
    let mut foreign = [0u32; 2];
    let foreign_ptr = foreign.as_mut_ptr() as *mut u8;
    unsafe {
        assert_eq!(manager.make_writable(foreign_ptr, 4), false);
        assert_eq!(manager.finalize_code(foreign_ptr, 4), false);
    }
}

#[test]
fn jit_memory_manager_rwx_rejects_zero_size_finalize() {
    // Plain RWX anon mmap is refused on this host (no MAP_JIT); the arm
    // must still be exercised and must fail allocation rather than lie.
    let mut plain = JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::RwxMmap));
    let _ = plain.allocate_code_space(4);

    // Exercise the direct-RWX permission arms with a live mapping so the
    // mechanism's "already writable/executable" contract is pinned.
    let mut backing = JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::MapJitWx));
    let ptr = backing.allocate_code_space(64);
    assert!(!ptr.is_null());
    let mut manager = JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::RwxMmap));
    manager.pages.push((ptr, JIT_PAGE_SIZE));
    assert_eq!(manager.mechanism(), JitExecMechanism::RwxMmap);
    // SAFETY: ptr is a live mapping owned by this test.
    unsafe {
        assert_eq!(manager.make_writable(ptr, 4), true);
        assert_eq!(manager.finalize_code(ptr, 4), true);
        assert_eq!(manager.finalize_code(ptr, 0), false);
        assert_eq!(manager.finalize_code(std::ptr::null_mut(), 4), false);
    }
}

#[test]
fn jit_install_code_rejects_foreign_writable_page() {
    let mut compiler = JitCompiler::new();
    compiler.memory_manager =
        JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::MprotectRx));
    compiler.emitter.nop();
    let mut foreign = [0u32; 2];
    let error = compiler
        .install_code(foreign.as_mut_ptr() as *mut u8, 4)
        .unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
    assert_eq!(error.message, "JIT: executable code page is not writable");
}

#[test]
fn jit_install_code_rejects_zero_size_finalize() {
    let mut compiler = JitCompiler::new();
    let ptr = compiler.memory_manager.allocate_code_space(64);
    assert!(!ptr.is_null());
    let error = compiler.install_code(ptr, 0).unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
    assert_eq!(
        error.message,
        "JIT: failed to make compiled block executable"
    );
}

#[test]
fn jit_compile_block_rejects_unavailable_executable_memory() {
    let mut compiler = JitCompiler::new();
    compiler.memory_manager =
        JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::Unavailable));
    let error = compiler
        .compile_block(&[IrInstruction::Nop], 0x1000, GuestArch::X64, None)
        .err()
        .expect("unavailable memory must fail compilation");
    assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
    assert_eq!(error.message, "JIT: failed to allocate executable memory");
}

// ── SMC watch/dirty edge cases ──────────────────────────────────────────

#[test]
fn smc_watch_overflow_marks_every_page_watched() {
    let state = SmcState::new();
    let pages: Vec<u64> = (0..=SMC_WATCH_SLOTS as u64)
        .map(|i| (i + 1) * 0x1000)
        .collect();
    state.rebuild_watch(pages.iter());
    assert_eq!(state.watched_count.load(Ordering::Acquire), SMC_WATCH_SLOTS);
    assert_eq!(state.watch_overflow.load(Ordering::Acquire), true);
    assert_eq!(
        state.is_watched(0xFFFF_FFFF_FFFF_F000),
        true,
        "overflow must conservatively watch unknown pages"
    );
}

#[test]
fn smc_watch_full_table_rejects_absent_page() {
    let state = SmcState::new();
    let pages: Vec<u64> = (0..SMC_WATCH_SLOTS as u64)
        .map(|i| (i + 1) * 0x1000)
        .collect();
    state.rebuild_watch(pages.iter());
    assert_eq!(state.watched_count.load(Ordering::Acquire), SMC_WATCH_SLOTS);
    assert_eq!(state.watch_overflow.load(Ordering::Acquire), false);
    // Every probe slot is occupied by another key; the scan must exhaust
    // the bounded probe sequence and report "not watched".
    assert_eq!(state.is_watched(0xFFFF_FFFF_FFFF_8000), false);
}

#[test]
fn smc_watch_invalid_lookup_after_collision_probes_next_slot() {
    let state = SmcState::new();
    // Two distinct pages that hash to the same initial slot force the
    // linear-probe advance before the second key is found.
    let first = 0x1000u64;
    let mut second = 0x2000u64;
    while smc_slot(second) != smc_slot(first) {
        second += 0x1000;
    }
    state.rebuild_watch([first, second].iter());
    assert_eq!(state.is_watched(first), true);
    assert_eq!(state.is_watched(second), true);
    // A fresh table must reject a page whose probe finds an empty slot.
    let empty = SmcState::new();
    empty.rebuild_watch([first].iter());
    assert_eq!(empty.is_watched(second), false);
}

#[test]
fn smc_dirty_overflow_marks_overflow_and_keeps_bounded_ring() {
    let state = SmcState::new();
    for i in 0..=SMC_DIRTY_SLOTS as u64 {
        state.mark_dirty((i + 1) * 0x1000);
    }
    let (pages, overflow) = state.take_dirty();
    assert_eq!(pages.len(), SMC_DIRTY_SLOTS);
    assert_eq!(overflow, true);
    assert_eq!(pages[0], 0x1000);
    assert_eq!(pages[SMC_DIRTY_SLOTS - 1], SMC_DIRTY_SLOTS as u64 * 0x1000);
    // take_dirty clears the ring and the overflow flag.
    let (empty, cleared) = state.take_dirty();
    assert_eq!(empty.len(), 0);
    assert_eq!(cleared, false);
}

#[test]
fn note_guest_code_write_rejects_zero_length_and_unwatched_state() {
    reset_smc_telemetry();
    note_guest_code_write(0x1000, 0);
    assert_eq!(smc_telemetry(), (0, 0));

    // No watched pages: the helper must take the early-return fast path.
    let state = SmcState::new();
    {
        let _guard = ActiveSmcGuard::install(&state);
        note_guest_code_write(0x1000, 8);
    }
    assert_eq!(smc_telemetry(), (0, 0));
}

#[test]
fn note_guest_code_write_overflowing_page_range_returns_without_marking() {
    reset_smc_telemetry();
    let state = SmcState::new();
    state.rebuild_watch([0x2000u64].iter());
    {
        let _guard = ActiveSmcGuard::install(&state);
        // The page walk saturates at u64::MAX; checked_add must stop it.
        note_guest_code_write(u64::MAX & !0xfff, 1);
    }
    assert_eq!(smc_telemetry(), (0, 0));
}

#[test]
fn note_guest_code_write_counts_exactly_one_dirty_page_at_boundary() {
    reset_smc_telemetry();
    let state = SmcState::new();
    state.rebuild_watch([0x3000u64].iter());
    {
        let _guard = ActiveSmcGuard::install(&state);
        note_guest_code_write(0x3000, 8);
    }
    assert_eq!(smc_telemetry(), (1, 1));
    let (pages, overflow) = state.take_dirty();
    assert_eq!(pages, vec![0x3000]);
    assert_eq!(overflow, false);
    reset_smc_telemetry();
    assert_eq!(smc_telemetry(), (0, 0));
}

// ── Tier compilation, promotion, and constant folding ───────────────────

#[test]
fn jit_tier1_and_tier2_compile_pin_tier_edges() {
    let mut compiler = JitCompiler::new();
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 40,
        },
        IrInstruction::AddImm {
            dst: Register::Rax,
            value: 2,
            width: 8,
        },
        IrInstruction::Nop,
    ];
    let tier1 = compiler
        .compile_tier1(&ir, 0x1000, GuestArch::X64, None)
        .expect("tier1 compile");
    assert_eq!(tier1.compile_tier, CompilationTier::Tier1);
    assert_eq!(tier1.guest_address, 0x1000);
    assert_eq!(tier1.instruction_count, 3);
    assert_ne!(tier1.source_hash, 0);
    assert_ne!(tier1.entry() as usize, 0);
    let tier2 = compiler
        .compile_tier2(&ir, 0x2000, GuestArch::X64, None)
        .expect("tier2 compile");
    assert_eq!(tier2.compile_tier, CompilationTier::Tier2);
    assert_eq!(tier2.guest_address, 0x2000);
    assert_eq!(tier2.instruction_count, 3);
}

#[test]
fn jit_tier1_and_tier2_reject_failed_allocations() {
    let mut compiler = JitCompiler::new();
    let ir = vec![IrInstruction::Nop];
    JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
    JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(1));
    let error = compiler
        .compile_tier1(&ir, 0x1000, GuestArch::X64, None)
        .err()
        .expect("tier1 allocation failure");
    assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
    assert_eq!(
        error.message,
        "JIT Tier1: failed to allocate executable memory"
    );

    let mut compiler = JitCompiler::new();
    JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
    JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(1));
    let error = compiler
        .compile_tier2(&ir, 0x2000, GuestArch::X64, None)
        .err()
        .expect("tier2 allocation failure");
    assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
    assert_eq!(
        error.message,
        "JIT Tier2: failed to allocate executable memory"
    );
    JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(0));
}

#[test]
fn jit_constant_fold_pins_every_fold_and_noop_edge() {
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 5,
        },
        IrInstruction::AddImm {
            dst: Register::Rax,
            value: 3,
            width: 8,
        },
        IrInstruction::SubImm {
            dst: Register::Rax,
            value: 2,
            width: 8,
        },
        IrInstruction::ShlImm {
            dst: Register::Rax,
            count: 1,
            width: 8,
        },
        IrInstruction::AndImm {
            dst: Register::Rax,
            value: 0x0F,
            width: 1,
        },
        IrInstruction::OrImm {
            dst: Register::Rax,
            value: 1,
            width: 8,
        },
        IrInstruction::XorImm {
            dst: Register::Rax,
            value: 5,
            width: 8,
        },
        IrInstruction::AddImm {
            dst: Register::Rbx,
            value: 0,
            width: 8,
        },
        IrInstruction::SubImm {
            dst: Register::Rbx,
            value: 0,
            width: 8,
        },
        IrInstruction::ShlImm {
            dst: Register::Rbx,
            count: 0,
            width: 8,
        },
        IrInstruction::AndImm {
            dst: Register::Rbx,
            value: 0xFFFF,
            width: 2,
        },
        IrInstruction::MovImm {
            dst: Register::Rbx,
            value: 7,
        },
        IrInstruction::MovReg {
            dst: Register::Rax,
            src: Register::Rbx,
            width: 8,
        },
        IrInstruction::MovReg {
            dst: Register::Rcx,
            src: Register::Rdx,
            width: 8,
        },
    ];
    let folded = JitCompiler::constant_fold(&ir);
    assert_eq!(
        folded,
        vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 8,
            },
            IrInstruction::MovImm {
                dst: Register::Rbx,
                value: 7,
            },
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 7,
            },
            IrInstruction::MovReg {
                dst: Register::Rcx,
                src: Register::Rdx,
                width: 8,
            },
        ],
        "constant folding must coalesce and propagate exactly"
    );
}

#[test]
fn jit_runtime_tier_promotion_replaces_stale_block() {
    let _serial = jit_test_serial();
    let mut runtime = capable_runtime();
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 40,
        },
        IrInstruction::AddImm {
            dst: Register::Rax,
            value: 2,
            width: 8,
        },
    ];
    let entry0 = {
        let block = runtime
            .get_or_compile(&ir, 0x00C1_0000, GuestArch::X64, None)
            .expect("tier0 compile");
        block.published_entry() as usize
    };
    assert_eq!(runtime.tier0_compiles, 1);
    let tier1_entry = {
        let block = runtime
            .get_or_compile_at_tier(
                &ir,
                0x00C1_0000,
                GuestArch::X64,
                CompilationTier::Tier1,
                None,
            )
            .expect("tier1 promotion");
        assert_eq!(block.compile_tier, CompilationTier::Tier1);
        block.published_entry() as usize
    };
    assert_eq!(runtime.tier1_compiles, 1);
    assert_ne!(tier1_entry, entry0, "promotion must install new code");
    let tier2_entry = {
        let block = runtime
            .get_or_compile_at_tier(
                &ir,
                0x00C1_0000,
                GuestArch::X64,
                CompilationTier::Tier2,
                None,
            )
            .expect("tier2 promotion");
        assert_eq!(block.compile_tier, CompilationTier::Tier2);
        block.published_entry() as usize
    };
    assert_eq!(runtime.tier2_compiles, 1);
    assert_ne!(tier2_entry, tier1_entry);
    assert_eq!(runtime.blocks_compiled, 3);
    assert_eq!(runtime.code_invalidations, 2);

    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    let reason = execute_cached(&mut runtime, 0x00C1_0000, &mut state, &mut memory);
    assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
    assert_eq!(state.get(Register::Rax), 42);
}

#[test]
fn jit_get_or_compile_rejects_uncompilable_block() {
    let mut runtime = capable_runtime();
    let error = runtime
        .get_or_compile(&[IrInstruction::Cpuid], 0x00C2_0000, GuestArch::X64, None)
        .err()
        .expect("uncompilable block must be rejected");
    assert_eq!(error.code, ReasonCode::RcUnimplInsn);
    assert_eq!(
        error.message,
        "block contains an instruction the JIT cannot compile"
    );
    assert_eq!(runtime.interpreter_fallbacks, 1);
    assert_eq!(runtime.is_compiled(0x00C2_0000), false);
}

#[test]
fn jit_hash_mismatch_recompiles_stale_cached_block() {
    let _serial = jit_test_serial();
    let mut runtime = capable_runtime();
    let address = 0x00C3_0000u64;
    runtime
        .get_or_compile(
            &[IrInstruction::MovImm {
                dst: Register::Rax,
                value: 42,
            }],
            address,
            GuestArch::X64,
            None,
        )
        .expect("original compile");
    runtime
        .get_or_compile(
            &[IrInstruction::MovImm {
                dst: Register::Rax,
                value: 43,
            }],
            address,
            GuestArch::X64,
            None,
        )
        .expect("recompile after IR change");
    assert_eq!(runtime.code_invalidations, 1);
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    let reason = execute_cached(&mut runtime, address, &mut state, &mut memory);
    assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
    assert_eq!(
        state.get(Register::Rax),
        43,
        "the stale block must not run after the hash mismatch"
    );
}

// ── Chaining refusals and counters ──────────────────────────────────────

#[test]
fn jit_chain_blocks_rejects_missing_and_nonjump_endpoints() {
    let mut runtime = capable_runtime();

    let error = runtime.chain_blocks(0xDEAD, 0x1000).unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(error.message, "cannot chain missing source block 0xdead");

    runtime
        .get_or_compile(&[IrInstruction::Nop], 0x1000, GuestArch::X64, None)
        .expect("straight-line block");
    runtime
        .get_or_compile(
            &[IrInstruction::Nop, IrInstruction::Jump { target: 0x3000 }],
            0x2000,
            GuestArch::X64,
            None,
        )
        .expect("jump block");
    let error = runtime.chain_blocks(0x1000, 0x2000).unwrap_err();
    assert_eq!(
        error.message,
        "block 0x1000 does not end in an unconditional jump"
    );
    let error = runtime.chain_blocks(0x2000, 0xDEAD).unwrap_err();
    assert_eq!(error.message, "cannot chain to missing target block 0xdead");
    assert_eq!(runtime.chain_links_formed, 0);
}

#[test]
fn jit_chain_blocks_rejects_non_chainable_target() {
    let mut runtime = capable_runtime();
    runtime
        .get_or_compile(
            &[IrInstruction::Nop, IrInstruction::Jump { target: 0x4000 }],
            0x3000,
            GuestArch::X64,
            None,
        )
        .expect("source");
    runtime
        .get_or_compile(
            &[
                IrInstruction::Nop,
                IrInstruction::Return { stack_adjust: 0 },
            ],
            0x4000,
            GuestArch::X64,
            None,
        )
        .expect("return target");
    let error = runtime.chain_blocks(0x3000, 0x4000).unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "block 0x4000 does not end in a chainable jump"
    );
    assert_eq!(runtime.chain_links_formed, 0);
}

#[test]
fn jit_chain_blocks_rejects_unpublished_target_entry() {
    let mut runtime = capable_runtime();
    runtime
        .get_or_compile(
            &[IrInstruction::Nop, IrInstruction::Jump { target: 0x5000 }],
            0x5000 - 0x1000,
            GuestArch::X64,
            None,
        )
        .expect("source");
    runtime
        .get_or_compile(
            &[IrInstruction::Nop, IrInstruction::Jump { target: 0x6000 }],
            0x5000,
            GuestArch::X64,
            None,
        )
        .expect("target");
    runtime
        .block_cache
        .get_mut(&0x5000)
        .expect("cached target")
        .entry_atomic
        .store(std::ptr::null_mut(), Ordering::Release);
    let error = runtime.chain_blocks(0x4000, 0x5000).unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
    assert_eq!(error.message, "block 0x5000 has no published entry");
}

#[test]
fn jit_autochain_failure_on_non_chainable_target_is_silent() {
    let mut runtime = capable_runtime();
    runtime
        .get_or_compile(
            &[
                IrInstruction::Nop,
                IrInstruction::Return { stack_adjust: 0 },
            ],
            0x7000,
            GuestArch::X64,
            None,
        )
        .expect("return target");
    runtime
        .get_or_compile(
            &[IrInstruction::Nop, IrInstruction::Jump { target: 0x7000 }],
            0x6000,
            GuestArch::X64,
            None,
        )
        .expect("source with rejected auto-chain");
    assert_eq!(runtime.block_chains.len(), 0);
    assert_eq!(runtime.chain_links_formed, 0);
    assert_eq!(
        runtime
            .block_cache
            .get(&0x6000)
            .expect("source cached")
            .link_target
            .load(Ordering::Acquire),
        0,
        "a rejected chain must not publish a target"
    );
}

#[test]
fn jit_drain_smc_overflow_invalidates_every_cached_block() {
    let mut runtime = capable_runtime();
    runtime
        .get_or_compile(
            &[IrInstruction::MovImm {
                dst: Register::Rax,
                value: 1,
            }],
            0x8000,
            GuestArch::X64,
            None,
        )
        .expect("first block");
    runtime
        .get_or_compile(
            &[IrInstruction::MovImm {
                dst: Register::Rax,
                value: 2,
            }],
            0x9000,
            GuestArch::X64,
            None,
        )
        .expect("second block");
    for i in 0..=SMC_DIRTY_SLOTS as u64 {
        runtime.smc.mark_dirty((i + 1) * 0x1000);
    }
    let affected = runtime.drain_smc_invalidations();
    assert_eq!(affected.len(), 2);
    assert_eq!(runtime.code_invalidations, 2);
    assert_eq!(runtime.smc_invalidation_events, 1);
    assert_eq!(runtime.block_cache.len(), 0);
}

#[test]
fn jit_invalidate_block_rejects_stale_chain_target() {
    let mut runtime = capable_runtime();
    runtime
        .get_or_compile(
            &[
                IrInstruction::Nop,
                IrInstruction::Jump {
                    target: 0x00C5_1000,
                },
            ],
            0x00C5_0000,
            GuestArch::X64,
            None,
        )
        .expect("source");
    runtime
        .get_or_compile(
            &[
                IrInstruction::Nop,
                IrInstruction::Jump {
                    target: 0x00C5_2000,
                },
            ],
            0x00C5_1000,
            GuestArch::X64,
            None,
        )
        .expect("target");
    runtime
        .chain_blocks(0x00C5_0000, 0x00C5_1000)
        .expect("publish chain");
    assert_eq!(runtime.chain_links_formed, 1);
    runtime.invalidate_block(0x00C5_0000);
    assert_eq!(runtime.chain_links_broken, 1);
    // The outgoing chain record remains until the target is invalidated,
    // but the source block itself and its link slot are gone.
    assert_eq!(runtime.block_chains.len(), 1);
    assert_eq!(runtime.block_cache.get(&0x00C5_0000).is_none(), true);
}

#[test]
fn jit_thunk_registration_rejects_unknown_indices_and_pins_guest_addrs() {
    use std::collections::HashSet;
    let mut runtime = capable_runtime();
    let guest = 0x00C6_5000u64;
    assert_eq!(
        runtime
            .register_host_thunk_for_guest(jit_self_test_host_thunk as *const () as usize, guest),
        Some(0)
    );
    assert_eq!(
        runtime.guest_thunk_addrs(),
        HashSet::from([guest]),
        "guest_addrs must include registered guest targets"
    );
    assert_eq!(
        runtime.register_host_thunk(jit_self_test_host_thunk as *const () as usize),
        Some(1)
    );
    assert_eq!(
        runtime.guest_thunk_addrs(),
        HashSet::from([guest]),
        "an entry without a guest address must not appear"
    );
    assert_ne!(runtime.lookup_thunk_address(0), None);
    assert_eq!(runtime.lookup_thunk_address(2), None);
}

#[test]
fn jit_direct_thunk_unregistered_call_fallback_does_not_count() {
    let _serial = jit_test_serial();
    use std::collections::HashSet;
    let mut runtime = capable_runtime();
    let guest = 0x00C7_5000u64;
    runtime
        .register_host_thunk_for_guest(jit_self_test_host_thunk as *const () as usize, guest)
        .expect("register resolved thunk");
    let resolved: HashSet<u64> = HashSet::from([guest]);
    let before = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed);
    runtime
        .get_or_compile(
            &[
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 7,
                },
                IrInstruction::Call {
                    target: guest,
                    return_address: 0x00C7_6004,
                },
            ],
            0x00C7_6000,
            GuestArch::X64,
            Some(&resolved),
        )
        .expect("direct thunk compile");
    assert_eq!(
        JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed) - before,
        1,
        "a resolved thunk must be emitted as exactly one direct call"
    );

    let before = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed);
    runtime
        .get_or_compile(
            &[IrInstruction::Call {
                target: 0xDEAD,
                return_address: 0x00C7_7004,
            }],
            0x00C7_7000,
            GuestArch::X64,
            Some(&HashSet::new()),
        )
        .expect("unregistered call falls back to EXIT_THUNK");
    assert_eq!(
        JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed),
        before,
        "an unregistered target must not count as a direct call"
    );
}

#[test]
fn jit_jump_missing_link_slot_pins_exit_encoding() {
    let mut compiler = JitCompiler::new();
    compiler.link_slots = None;
    compiler
        .compile_instruction(
            &IrInstruction::Jump { target: 0x2000 },
            GuestArch::X64,
            None,
            true,
        )
        .expect("jump emission");
    let code = &compiler.emitter.code;
    let movz_exit_jump = (0xd280_0000u32 | ((EXIT_JUMP as u32) << 5)).to_le_bytes();
    assert_eq!(
        code.windows(4)
            .filter(|word| *word == movz_exit_jump)
            .count(),
        1,
        "an unlinked jump must return EXIT_JUMP exactly once"
    );
    assert_eq!(
        &code[code.len() - 4..],
        &0xd65f_03c0u32.to_le_bytes(),
        "the unlinked jump arm must end in RET"
    );
}

#[test]
fn jit_self_test_report_default_rejects_fabricated_activity() {
    let report = JitSelfTestReport::default();
    assert_eq!(report.active, false);
    assert_eq!(report.compiled_blocks, 0);
    assert_eq!(report.executed_blocks, 0);
    assert_eq!(report.safepoint_observed, false);
    assert_eq!(report.chain_links, 0);
    assert_eq!(report.thunk_direct_calls, 0);
    assert_eq!(report.smc_invalidations, 0);
    assert_eq!(report.fault_fallbacks, 0);
    assert_eq!(report.fallback_reason, None);
}

// ── In-process self-test: success path and injected failures ────────────

#[test]
fn jit_self_test_pins_exact_counters_without_fallback() {
    let _serial = jit_test_serial();
    let report = run_jit_self_test_child().expect("self-test must complete");
    assert_eq!(report.active, true);
    assert_eq!(report.safepoint_observed, true);
    assert_eq!(report.compiled_blocks, 1);
    assert_eq!(report.executed_blocks, 9);
    assert_eq!(report.chain_links, 1);
    assert_eq!(report.thunk_direct_calls, 1);
    assert_eq!(report.smc_invalidations, 2);
    assert_eq!(report.fault_fallbacks, 1);
    assert_eq!(report.fallback_reason, None);
}

#[test]
fn jit_self_test_pending_safepoint_rejects_first_execution() {
    let _serial = jit_test_serial();
    JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Relaxed);
    let error = run_jit_self_test_child().unwrap_err();
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: first execution exited with Safepoint, expected Normal"
    );
}

#[test]
fn jit_self_test_unwritable_repatch_page_rejects_repatch() {
    let _serial = jit_test_serial();
    // The first make_writable call installs the initial block; the second
    // is the self-test's deliberate re-patch of the code page.
    JIT_TEST_WRITE_CALLS.with(|calls| calls.set(0));
    JIT_TEST_DENY_WRITE_AT.with(|at| at.set(2));
    let error = run_jit_self_test_child().unwrap_err();
    JIT_TEST_DENY_WRITE_AT.with(|at| at.set(0));
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: compiled code page is not writable"
    );
}

#[test]
fn jit_self_test_unextendable_repatch_page_rejects_repatch() {
    let _serial = jit_test_serial();
    JIT_TEST_FINALIZE_CALLS.with(|calls| calls.set(0));
    JIT_TEST_DENY_FINALIZE_AT.with(|at| at.set(2));
    let error = run_jit_self_test_child().unwrap_err();
    JIT_TEST_DENY_FINALIZE_AT.with(|at| at.set(0));
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: re-patched code page is not executable"
    );
}

#[test]
fn jit_self_test_unavailable_thunk_zone_rejects_registration() {
    let _serial = jit_test_serial();
    JIT_TEST_DENY_THUNK_ZONE.with(|deny| deny.set(true));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: failed to register the direct-call host thunk"
    );
}

#[test]
fn jit_self_test_missed_smc_invalidation_rejects_stale_execution() {
    let _serial = jit_test_serial();
    JIT_TEST_SMC_FAULT.with(|fault| fault.set(1));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: stale SMC block ran instead of falling back: Normal { new_rip: 28672 }"
    );
}

fn self_test_with_safepoint_at(call: usize) -> AppError {
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
    JIT_TEST_EXEC_CALLS.with(|calls| calls.set(0));
    JIT_TEST_FORCE_SAFEPOINT_AT.with(|at| at.set(call));
    let error = run_jit_self_test_child().unwrap_err();
    JIT_TEST_FORCE_SAFEPOINT_AT.with(|at| at.set(0));
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
    error
}

#[test]
fn jit_self_test_safepoint_interrupts_reject_later_steps() {
    let _serial = jit_test_serial();
    let error = self_test_with_safepoint_at(3);
    assert_eq!(
        error.message,
        "JIT self-test: re-patched execution exited with Safepoint"
    );
    let error = self_test_with_safepoint_at(4);
    assert_eq!(
        error.message,
        "JIT self-test: linked execution exited with Safepoint, expected Jump"
    );
    let error = self_test_with_safepoint_at(9);
    assert_eq!(
        error.message,
        "JIT self-test: recompiled SMC block observed stale code: rax=0"
    );
}

#[test]
fn jit_self_test_already_linked_chain_rejects_missing_publication() {
    let _serial = jit_test_serial();
    JIT_TEST_PREPUBLISH_CHAIN.with(|prepublish| prepublish.set(true));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(error.message, "JIT self-test: no block link was published");
}

#[test]
fn jit_self_test_uncounted_eviction_rejects_missing_invalidation() {
    let _serial = jit_test_serial();
    JIT_TEST_SMC_FAULT.with(|fault| fault.set(2));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: self-modifying code did not invalidate a block"
    );
}

#[test]
fn jit_self_test_lost_fault_bar_rejects_native_compilation() {
    let _serial = jit_test_serial();
    JIT_TEST_IGNORE_FAULTED_BLOCKS.with(|ignore| ignore.set(true));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: faulted block was not barred from native compilation"
    );
}

#[test]
fn jit_self_test_wrong_original_rejects_guest_result() {
    let _serial = jit_test_serial();
    JIT_TEST_SELF_TEST_WRONG_ORIGINAL.with(|wrong| wrong.set(true));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: guest result mismatch: rax=41 expected 42"
    );
}

#[test]
fn jit_self_test_ignored_safepoint_rejects_missing_exit() {
    let _serial = jit_test_serial();
    JIT_TEST_IGNORE_SAFEPOINT_AT.with(|at| at.set(2));
    let error = run_jit_self_test_child().unwrap_err();
    JIT_TEST_IGNORE_SAFEPOINT_AT.with(|at| at.set(0));
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: safepoint flag did not produce EXIT_SAFEPOINT (got Normal { new_rip: 4096 })"
    );
}

#[test]
fn jit_self_test_unapplied_repatch_rejects_stale_value() {
    let _serial = jit_test_serial();
    JIT_TEST_SKIP_REPATCH.with(|skip| skip.set(true));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: re-patched execution did not observe the patch: rax=42 expected 43"
    );
}

fn assert_self_test_allocation_failure(fail_at: usize, expected: &str) {
    JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
    JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(fail_at));
    let error = run_jit_self_test_child().unwrap_err();
    JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(0));
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(error.message, expected);
}

#[test]
fn jit_self_test_allocation_failures_reject_each_later_step() {
    let _serial = jit_test_serial();
    assert_self_test_allocation_failure(
        2,
        "JIT self-test: chain source compile failed: JIT: failed to allocate executable memory",
    );
    assert_self_test_allocation_failure(
        3,
        "JIT self-test: chain target compile failed: JIT: failed to allocate executable memory",
    );
    assert_self_test_allocation_failure(
        4,
        "JIT self-test: thunk block compile failed: JIT: failed to allocate executable memory",
    );
    assert_self_test_allocation_failure(
        5,
        "JIT self-test: SMC block compile failed: JIT: failed to allocate executable memory",
    );
    assert_self_test_allocation_failure(
        6,
        "JIT self-test: SMC writer compile failed: JIT: failed to allocate executable memory",
    );
    assert_self_test_allocation_failure(
        7,
        "JIT self-test: SMC recompile failed: JIT: failed to allocate executable memory",
    );
    assert_self_test_allocation_failure(
        8,
        "JIT self-test: fault block compile failed: JIT: failed to allocate executable memory",
    );
    assert_eq!(JIT_TEST_FAIL_ALLOC_AT.with(|at| at.get()), 0);
}

#[test]
fn jit_self_test_chain_failure_rejects_chain_step() {
    let _serial = jit_test_serial();
    JIT_TEST_FORCE_CHAIN_ERROR.with(|force| force.set(true));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: chain_blocks failed: injected chain failure"
    );
}

#[test]
fn jit_self_test_lost_thunk_resolution_rejects_direct_call() {
    let _serial = jit_test_serial();
    JIT_TEST_THUNK_MAP_MISS.with(|miss| miss.set(true));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: Call to a resolved thunk did not compile to a direct call"
    );
}

#[test]
fn jit_self_test_wrong_thunk_result_rejects_execution() {
    let _serial = jit_test_serial();
    JIT_TEST_SELF_TEST_THUNK_BAD.with(|bad| bad.set(true));
    let error = run_jit_self_test_child().unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message,
        "JIT self-test: direct thunk call failed: reason=Normal { new_rip: 24576 } rax=0x98"
    );
}

#[test]
fn jit_self_test_exec_resolution_failures_reject_fabricated_success() {
    let _serial = jit_test_serial();
    JIT_TEST_SELF_TEST_EXE_MODE.with(|mode| mode.set(1));
    let report = run_jit_self_test();
    assert_eq!(report.active, false);
    assert_eq!(
        report.fallback_reason.as_deref(),
        Some(
            "cannot resolve current executable for the self-test child: \
                 No such file or directory (os error 2)"
        )
    );

    JIT_TEST_SELF_TEST_EXE_MODE.with(|mode| mode.set(2));
    let report = run_jit_self_test();
    assert_eq!(report.active, false);
    assert_eq!(
        report.fallback_reason.as_deref(),
        Some("failed to spawn self-test child: No such file or directory (os error 2)")
    );

    JIT_TEST_SELF_TEST_EXE_MODE.with(|mode| mode.set(3));
    let report = run_jit_self_test();
    assert_eq!(report.active, false);
    assert_eq!(report.compiled_blocks, 0);
    assert_eq!(
        report
            .fallback_reason
            .as_deref()
            .is_some_and(|reason| reason
                .starts_with("self-test child exited 0 without a valid JitSelfTestReport JSON:")),
        true
    );
}

#[test]
fn jit_self_test_missing_child_flag_reports_inactive() {
    let _serial = jit_test_serial();
    // In the lib test binary `--jit-self-test-child` is not a real child
    // mode: the parent must report inactive with the child's diagnostics
    // instead of trusting a non-existent report.
    let report = run_jit_self_test();
    assert_eq!(report.active, false);
    assert_eq!(report.compiled_blocks, 0);
    assert_eq!(report.fallback_reason.is_some(), true);
}

#[test]
fn jit_runtime_tier_recompilation_rejects_allocation_failure() {
    let mut runtime = capable_runtime();
    let ir = vec![IrInstruction::Nop];
    JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
    JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(1));
    let tier1 = runtime
        .get_or_compile_at_tier(
            &ir,
            0x00C5_0000,
            GuestArch::X64,
            CompilationTier::Tier1,
            None,
        )
        .err()
        .expect("tier1 runtime allocation failure");
    assert_eq!(tier1.code, ReasonCode::RcJitCodeAllocFailed);
    assert_eq!(
        tier1.message,
        "JIT Tier1: failed to allocate executable memory"
    );

    JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
    JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(1));
    let tier2 = runtime
        .get_or_compile_at_tier(
            &ir,
            0x00C6_0000,
            GuestArch::X64,
            CompilationTier::Tier2,
            None,
        )
        .err()
        .expect("tier2 runtime allocation failure");
    assert_eq!(tier2.code, ReasonCode::RcJitCodeAllocFailed);
    assert_eq!(
        tier2.message,
        "JIT Tier2: failed to allocate executable memory"
    );
    JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(0));
}

#[test]
fn jit_self_test_host_thunk_bad_sentinel_overwrites_gpr0() {
    JIT_TEST_SELF_TEST_THUNK_BAD.with(|bad| bad.set(true));
    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rax, 0x1234);
    let result = jit_self_test_host_thunk(
        std::ptr::null_mut(),
        &mut state as *mut CpuState,
        std::ptr::null_mut(),
        0,
    );
    assert_eq!(result, -1);
    assert_eq!(state.get(Register::Rax), 0x98);
}

#[test]
fn jit_diag_file_append_recovers_from_truncated_fault_line() {
    let path = "/tmp/casa1_jit_diag.txt";
    std::fs::write(path, b"torn fault").expect("seed truncated diagnostic line");
    write_diag_file("fault-chain: first");
    write_diag_file("fault-chain: second");
    let after = std::fs::read_to_string(path).expect("diagnostic file must be readable");
    assert_eq!(after, "torn faultfault-chain: first\nfault-chain: second\n");
}

#[test]
fn constant_fold_drops_overwritten_mov_imm_but_keeps_read_values() {
    use crate::cpu::{IrInstruction, Register};
    // A long chain of overwritten MOV immediates collapses to the last
    // write: every earlier value is unread and must be dropped.
    let chain: Vec<IrInstruction> = (1..=128u64)
        .map(|value| IrInstruction::MovImm {
            dst: Register::Rax,
            value,
        })
        .collect();
    let folded = JitCompiler::constant_fold(&chain);
    assert_eq!(
        folded,
        vec![IrInstruction::MovImm {
            dst: Register::Rax,
            value: 128
        }],
        "an unread MOV chain must collapse to its final write"
    );
    // A value read between writes is not dropped: the first write folds
    // into the reader, and the later overwrite remains.
    let interleaved = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 7,
        },
        IrInstruction::MovReg {
            dst: Register::Rcx,
            src: Register::Rax,
            width: 8,
        },
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 9,
        },
    ];
    let folded = JitCompiler::constant_fold(&interleaved);
    assert_eq!(
        folded,
        vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 7
            },
            IrInstruction::MovImm {
                dst: Register::Rcx,
                value: 7
            },
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 9
            },
        ],
        "a read value must be preserved even when the register is overwritten"
    );
}
#[test]
fn guest_slice_memory_false_sharing_race_merges_and_publishes() {
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x1000, &[0_u8; 0x1000]);
    let view = GuestSliceMemory::new(&memory, BTreeSet::new());
    let base = 0x1000_u64;
    std::thread::scope(|scope| {
        for index in 0..4_u8 {
            let view = &view;
            scope.spawn(move || {
                let pattern = [index.wrapping_add(1), 0xF0_u8.wrapping_add(index)];
                for _ in 0..1_000 {
                    view.store(base + u64::from(index) * 2, &pattern)
                        .expect("the page is fully mapped");
                }
            });
        }
    });
    let word = view.load(base, 8).expect("mapped");
    assert_eq!(
        word.to_le_bytes(),
        [1, 0xF0, 2, 0xF1, 3, 0xF2, 4, 0xF3],
        "coincident sub-word stores must preserve every neighbour"
    );

    let published = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let view = &view;
        let published = &published;
        scope.spawn(move || {
            view.store(base + 8, &0xA5A5_5A5A_DEAD_BEEF_u64.to_le_bytes())
                .expect("mapped");
            published.store(true, std::sync::atomic::Ordering::Release);
        });
        while !published.load(std::sync::atomic::Ordering::Acquire) {
            std::hint::spin_loop();
        }
        assert_eq!(
            view.load(base + 8, 8).expect("mapped"),
            0xA5A5_5A5A_DEAD_BEEF,
            "a published store must be visible to another worker"
        );
    });

    assert_eq!(
        view.load(0x9000, 8)
            .expect_err("an unmapped page must fault")
            .address,
        0x9000
    );
    let store_fault = view
        .store(0x9000, &[0x11, 0x22])
        .expect_err("an unmapped store must fault");
    assert_eq!((store_fault.address, store_fault.write), (0x9000, true));

    let code_view = GuestSliceMemory::new(&memory, BTreeSet::from([0x1000]));
    assert_eq!(code_view.store(base, &[0x33]).expect("mapped"), true);
    assert_eq!(code_view.take_code_writes(), vec![(base, 1)]);
}

#[test]
fn jit_compare_jump_stale_flag_race_is_exact_for_slice_loops() {
    let _serial = jit_test_serial();
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    let mut runtime = JitRuntime::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    runtime.attach_guest_memory(&mut memory);
    let ir = vec![
        IrInstruction::SubImm {
            dst: Register::Rcx,
            value: 1,
            width: 4,
        },
        IrInstruction::Compare {
            lhs: crate::cpu::CompareOperand::Register(Register::Rcx),
            rhs: crate::cpu::CompareOperand::ImmediateU64(0),
            width: 4,
        },
        IrInstruction::JumpIf {
            condition: ConditionCode::NotEqual,
            target: 0x1000,
            fallthrough: 0x1006,
        },
    ];
    let block = runtime
        .get_or_compile_slice_block(&ir, 0x1000, GuestArch::X86)
        .expect("compile slice loop")
        .clone();
    let view = Arc::new(GuestSliceMemory::new(&memory, BTreeSet::new()));
    let program = GuestSliceProgram {
        blocks: HashMap::from([(0x1000, block)]),
        flat_base: view.flat_base(),
        memory: view,
        mechanism: runtime.compiler.memory_manager.mechanism(),
        epoch: 0,
    };
    let mut state = CpuState::new(GuestArch::X86);
    state.set(Register::Rcx, 3);
    let mut taken = Vec::new();
    for _ in 0..4 {
        let mut chain = ChainState::new(program.flat_base, 0x1000, LINK_BUDGET);
        let outcome = unsafe {
            execute_slice_block(&program, &program.blocks[&0x1000], &mut state, &mut chain)
        };
        let branch_taken = match outcome.reason {
            JitExitReason::ConditionalBranch { taken, .. } => taken,
            JitExitReason::ConditionalTaken { .. } => true,
            JitExitReason::ConditionalNotTaken { .. } => false,
            other => panic!("expected conditional branch, got {other:?}"),
        };
        taken.push(branch_taken);
    }
    assert_eq!(taken, vec![true, true, false, true]);
    assert_eq!(state.get(Register::Rcx), 0xFFFF_FFFF);
}

#[test]
fn jit_worker_slice_store_flag_and_unmapped_fault_are_exact() {
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x1000, &[0u8; 0x1000]);
    memory.map_bytes(0x2000, &[0u8; 0x1000]);
    let view = GuestSliceMemory::new(&memory, BTreeSet::from([0x1000]));
    let mut state = CpuState::new(GuestArch::X64);

    {
        let guard = WorkerSliceGuard::install(&view);
        // SAFETY: `state` and `view` outlive the call; the canonical store
        // is alive for the guard's lifetime and the address is mapped.
        unsafe {
            jit_helper_store(&mut state, ptr::null_mut(), 0x2000, 0x11, 1);
        }
        assert_eq!(guard.code_written(), false);
        unsafe {
            jit_helper_store(&mut state, ptr::null_mut(), 0x1000, 0xAB, 1);
        }
        assert_eq!(guard.code_written(), true);
        assert_eq!(state.jit_pending_fault, None);
    }
    assert_eq!(view.take_code_writes(), vec![(0x1000, 1)]);

    {
        let guard = WorkerSliceGuard::install(&view);
        // SAFETY: same contract as above; 0x9000 is deliberately unmapped
        // so the helper must report the exact write fault through state.
        unsafe {
            jit_helper_store(&mut state, ptr::null_mut(), 0x9000, 0xCD, 2);
        }
        assert_eq!(state.jit_pending_fault, Some(0x9000));
        assert_eq!(state.jit_pending_fault_write, true);
        assert_eq!(guard.code_written(), false);
    }
}

#[test]
fn jit_worker_slice_load_success_and_fault_are_exact() {
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x1000, &[0u8; 0x1000]);
    let view = GuestSliceMemory::new(&memory, BTreeSet::new());
    let mut state = CpuState::new(GuestArch::X64);
    {
        let guard = WorkerSliceGuard::install(&view);
        // SAFETY: `state` and `view` outlive the call and the address is
        // mapped in the canonical store.
        let value = unsafe { jit_helper_load(&mut state, ptr::null_mut(), 0x1000, 8) };
        assert_eq!(value, 0);
        assert_eq!(state.jit_pending_fault, None);
        // SAFETY: same contract; 0x9000 is unmapped so the helper must
        // report a read fault instead of fabricating a zero.
        let faulted = unsafe { jit_helper_load(&mut state, ptr::null_mut(), 0x9000, 4) };
        assert_eq!(faulted, 0);
        assert_eq!(state.jit_pending_fault, Some(0x9000));
        assert_eq!(state.jit_pending_fault_write, false);
        assert_eq!(guard.code_written(), false);
    }
}

#[test]
fn jit_worker_slice_null_memory_store_without_guard_is_dropped() {
    let mut state = CpuState::new(GuestArch::X64);
    assert_eq!(worker_slice_memory().is_none(), true);
    // SAFETY: both pointers are null and no worker slice is installed; the
    // helper must return without dereferencing either pointer.
    unsafe {
        jit_helper_store(&mut state, ptr::null_mut(), 0x1000, 0x55, 8);
    }
    assert_eq!(state.jit_pending_fault, None);
    assert_eq!(state.jit_pending_fault_write, false);
}

#[test]
fn guest_slice_memory_boundary_overflow_and_empty_range_faults_are_exact() {
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x1000, &[0u8; 0x1000]);
    let view = GuestSliceMemory::new(&memory, BTreeSet::new());

    assert_eq!(view.range_available(0x1000, 0), false);
    assert_eq!(view.load(0x1000, 8).expect("one mapped page"), 0);
    assert_eq!(view.load(0x1004, 4).expect("unaligned mapped load"), 0);
    assert_eq!(view.load(0x1002, 4).expect("word-crossing mapped load"), 0);
    assert_eq!(
        view.load(0x1000, 0)
            .expect_err("zero-length load must fault"),
        GuestMemoryFault {
            address: 0x1000,
            write: false,
            read_len: 0,
        }
    );
    assert_eq!(
        view.store(0x1000, &[])
            .expect_err("zero-length store must fault"),
        GuestMemoryFault {
            address: 0x1000,
            write: true,
            read_len: 0,
        }
    );
    assert_eq!(
        view.load(u64::MAX - 3, 8)
            .expect_err("overflowing address range must fault"),
        GuestMemoryFault {
            address: u64::MAX - 3,
            write: false,
            read_len: 8,
        }
    );
    assert_eq!(
        view.load(view.flat_size(), 8)
            .expect_err("range beyond the flat window must fault"),
        GuestMemoryFault {
            address: view.flat_size(),
            write: false,
            read_len: 8,
        }
    );
    assert_eq!(
        view.load(0x1FFC, 8)
            .expect_err("range crossing into an unmapped page must fault"),
        GuestMemoryFault {
            address: 0x2000,
            write: false,
            read_len: 8,
        }
    );
}

#[test]
fn invalid_small_flat_view_bitmap_is_grown_on_attach() {
    let mut flat = FlatGuestMemory {
        store: Arc::new(GuestMemoryStore::invalid_for_test()),
        materialised: vec![AtomicU64::new(0)].into_boxed_slice(),
    };
    assert_eq!(flat.materialised.len(), 1);
    assert_eq!(flat.is_page_materialised(0), false);
    let memory = MemoryImage::default();
    flat.attach_store(memory.canonical_store());
    let required_words = flat.size().div_ceil(4096 * 64);
    assert_eq!(flat.materialised.len(), required_words);
    assert_eq!(
        required_words >= GUEST_FLAT_MIN_SIZE.div_ceil(4096 * 64),
        true,
        "the attached bitmap must cover at least the 128 GiB minimum"
    );
    assert_eq!(flat.is_page_materialised(0), false);
}

#[test]
fn guest_slice_memory_above_four_gib_is_direct_and_window_end_faults_exactly() {
    let address = 0x2_0000_0000_u64;
    let mut memory = MemoryImage::default();
    let window_size = memory.canonical_store().flat_size() as u64;
    let last_window_page = window_size - 0x1000;
    let window_end = window_size;
    memory.map_bytes(address, &[0u8; 4096]);
    memory.map_bytes(last_window_page, &[0u8; 4096]);
    let view = GuestSliceMemory::new(&memory, BTreeSet::from([address]));
    assert_eq!(view.flat_size(), window_size);
    assert_eq!(view.flat_size() / 4096, window_size / 4096);
    assert_eq!(
        view.flat_base() % GUEST_FLAT_ALIGN as u64,
        0,
        "the JIT base must be aligned for direct guest addressing"
    );

    assert_eq!(view.load(address, 8).expect("direct load"), 0);
    assert_eq!(
        view.store(address, &0x1122_3344_5566_7788_u64.to_le_bytes())
            .expect("direct store"),
        true,
        "a store to a >4 GiB code page must report the SMC write"
    );
    assert_eq!(
        view.load(address, 8).expect("direct reload"),
        0x1122_3344_5566_7788
    );
    assert_eq!(memory.read_u64(address).unwrap(), 0x1122_3344_5566_7788);
    assert_eq!(
        view.load(last_window_page, 8)
            .expect("the last window page is direct"),
        0
    );
    assert_eq!(view.take_code_writes(), vec![(address, 8)]);

    let fault = view
        .load(window_end, 8)
        .expect_err("an address at the window end must fault");
    assert_eq!(
        fault,
        GuestMemoryFault {
            address: window_end,
            write: false,
            read_len: 8,
        }
    );
    let store_fault = view
        .store(window_end, &[0x11, 0x22])
        .expect_err("an address beyond the window must fault");
    assert_eq!((store_fault.address, store_fault.write), (window_end, true));
    assert_eq!(memory.canonical_store().materialisation_count(), 2);
    assert_eq!(memory.canonical_store().high_page_count(), 0);
}

#[test]
fn jit_loop_with_heap_above_four_gib_executes_without_fault_or_overflow() {
    let _serial = jit_test_serial();
    let mut runtime = capable_runtime();
    let heap = 0x2_0000_0000_u64;
    let site = 0x2_0000_1000_u64;
    let operand = crate::cpu::MemoryOperand {
        base: None,
        index: None,
        scale: 1,
        displacement: 0,
        rip_relative: false,
        rip_base: 0,
        segment: None,
        address_size_32: false,
        absolute_address: Some(heap),
    };
    let ir = vec![
        IrInstruction::LoadMemory {
            dst: Register::Rax,
            address: operand,
            width: 8,
        },
        IrInstruction::AddImm {
            dst: Register::Rax,
            value: 1,
            width: 8,
        },
        IrInstruction::StoreMemory {
            src: Register::Rax,
            address: operand,
            width: 8,
        },
        IrInstruction::SubImm {
            dst: Register::Rcx,
            value: 1,
            width: 8,
        },
        IrInstruction::Compare {
            lhs: crate::cpu::CompareOperand::Register(Register::Rcx),
            rhs: crate::cpu::CompareOperand::ImmediateU64(0),
            width: 8,
        },
        IrInstruction::JumpIf {
            condition: ConditionCode::NotEqual,
            target: site,
            fallthrough: site + 0x100,
        },
    ];
    let block = runtime
        .get_or_compile_slice_block(&ir, site, GuestArch::X64)
        .expect("compile >4 GiB slice loop")
        .clone();
    assert_eq!(block.worker_safe, true);
    let mut memory = MemoryImage::default();
    memory.map_bytes(heap, &[0u8; 4096]);
    let view = Arc::new(GuestSliceMemory::new(
        &memory,
        BTreeSet::from([site & !0xfff]),
    ));
    let program = GuestSliceProgram {
        blocks: HashMap::from([(site, block)]),
        flat_base: view.flat_base(),
        memory: view,
        mechanism: runtime.compiler.memory_manager.mechanism(),
        epoch: 0,
    };
    let _guard = WorkerSliceGuard::install(&program.memory);
    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rcx, 3);
    let mut branches = Vec::new();
    for _ in 0..4 {
        let mut chain = ChainState::new(program.flat_base, site, LINK_BUDGET);
        let outcome = unsafe {
            execute_slice_block(&program, &program.blocks[&site], &mut state, &mut chain)
        };
        let taken = match outcome.reason {
            JitExitReason::ConditionalBranch { taken, .. } => taken,
            JitExitReason::ConditionalTaken { .. } => true,
            JitExitReason::ConditionalNotTaken { .. } => false,
            other => panic!("expected conditional branch, got {other:?}"),
        };
        branches.push(taken);
        if !taken {
            break;
        }
    }
    assert_eq!(branches, vec![true, true, false]);
    assert_eq!(state.get(Register::Rcx), 0);
    assert_eq!(
        memory.read_u64(heap).unwrap(),
        3,
        "each dispatched loop iteration must increment the >4 GiB heap word"
    );
    assert_eq!(memory.canonical_store().materialisation_count(), 1);
}

#[test]
fn jit_memory_helpers_above_four_gib_and_high_frame_fallback_are_exact() {
    let _serial = jit_test_serial();
    let mut runtime = capable_runtime();
    let flat_address = 0x2_0000_0000_u64;
    let upper_flat_address = 0x10_0000_0000_u64;
    let high_address = 0x1800_0000_0000_u64;
    let site = 0x2_0000_5000_u64;
    let mut memory = MemoryImage::default();
    memory.map_bytes(flat_address, &[0u8; 4096]);
    memory.write_u64(flat_address, 0x0102_0304_0506_0708);
    memory.map_bytes(upper_flat_address, &[0u8; 4096]);
    memory.write_u64(upper_flat_address, 0x2122_2324_2526_2728);
    memory.map_bytes(high_address, &[0u8; 4096]);
    memory.write_u64(high_address, 0x1112_1314_1516_1718);
    runtime.attach_guest_memory(&memory);

    let flat_operand = crate::cpu::MemoryOperand {
        base: None,
        index: None,
        scale: 1,
        displacement: 0,
        rip_relative: false,
        rip_base: 0,
        segment: None,
        address_size_32: false,
        absolute_address: Some(flat_address),
    };
    let upper_flat_operand = crate::cpu::MemoryOperand {
        absolute_address: Some(upper_flat_address),
        ..flat_operand
    };
    let high_operand = crate::cpu::MemoryOperand {
        absolute_address: Some(high_address),
        ..flat_operand
    };
    runtime
        .get_or_compile(
            &[IrInstruction::LoadMemory {
                dst: Register::Rax,
                address: flat_operand,
                width: 8,
            }],
            site,
            GuestArch::X64,
            None,
        )
        .expect("compile >4 GiB load");
    let mut state = CpuState::new(GuestArch::X64);
    let reason = execute_cached(&mut runtime, site, &mut state, &mut memory);
    assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
    assert_eq!(state.get(Register::Rax), 0x0102_0304_0506_0708);

    runtime
        .get_or_compile(
            &[IrInstruction::LoadMemory {
                dst: Register::Rax,
                address: upper_flat_operand,
                width: 8,
            }],
            site + 0x200,
            GuestArch::X64,
            None,
        )
        .expect("compile 64 GiB load");
    let reason = execute_cached(&mut runtime, site + 0x200, &mut state, &mut memory);
    assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
    assert_eq!(
        state.get(Register::Rax),
        0x2122_2324_2526_2728,
        "a 64 GiB address must be served directly by the window"
    );

    runtime
        .get_or_compile(
            &[IrInstruction::LoadMemory {
                dst: Register::Rax,
                address: high_operand,
                width: 8,
            }],
            site + 0x100,
            GuestArch::X64,
            None,
        )
        .expect("compile high-frame load");
    let reason = execute_cached(&mut runtime, site + 0x100, &mut state, &mut memory);
    assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
    assert_eq!(
        state.get(Register::Rax),
        0x1112_1314_1516_1718,
        "addresses beyond the window must keep using MemoryImage frames"
    );
    assert_eq!(memory.canonical_store().materialisation_count(), 3);
    assert_eq!(memory.canonical_store().high_page_count(), 1);
    assert_eq!(
        memory.canonical_store().resident_flat_page_count(),
        2,
        "the high-address frame must not consume flat residency"
    );
}

#[test]
fn sigbus_fallback_above_four_gib_uses_the_direct_window() {
    let mut memory = MemoryImage::default();
    let page = 0x2_0000_0000_u64;
    memory.map_bytes(page, &[0x5A; 4096]);
    let mut runtime = JitRuntime::new(GuestArch::X64);
    runtime.attach_guest_memory(&memory);
    let base = runtime.flat_memory.base() as *mut u8;
    let size = runtime.flat_memory.size();
    let before = SIGBUS_PAGE_FOUND.load(Ordering::Relaxed);
    service_faulting_page(&runtime, &memory, page, base, size);
    assert_eq!(SIGBUS_PAGE_FOUND.load(Ordering::Relaxed), before + 1);
    assert_eq!(runtime.flat_memory.is_page_materialised(page), true);
    // SAFETY: the >4 GiB page is inside the canonical flat mapping.
    let byte = unsafe { std::ptr::read_volatile(base.add(page as usize)) };
    assert_eq!(byte, 0x5A);
    assert_eq!(memory.read_u8(page).unwrap(), 0x5A);
    assert_eq!(memory.canonical_store().materialisation_count(), 1);
}

#[test]
fn sigbus_partial_page_tail_mapping_fallback_is_exact() {
    let runtime = JitRuntime::new(GuestArch::X64);
    let mut tail = MemoryImage::default();
    tail.map_bytes(0x1FFF, &[0x5A]);
    assert_eq!(tail.page_is_fully_mapped(0x1000), false);
    assert_eq!(tail.page_exists(0x1000), true);
    assert_eq!(tail.page_byte_is_mapped(0x1000, 0), false);
    assert_eq!(tail.page_byte_is_mapped(0x1000, 4095), true);
    let mut interior = MemoryImage::default();
    interior.map_bytes(0x1001, &[0x00]);
    assert_eq!(interior.page_exists(0x1000), true);
    assert_eq!(interior.page_byte_is_mapped(0x1000, 0), false);
    assert_eq!(interior.page_byte_is_mapped(0x1000, 4095), false);
    let mut flat = vec![0u8; 0x2000];
    let before = SIGBUS_PAGE_NOT_FOUND.load(Ordering::Relaxed);
    service_faulting_page(&runtime, &tail, 0x1000, flat.as_mut_ptr(), flat.len());
    service_faulting_page(&runtime, &interior, 0x1000, flat.as_mut_ptr(), flat.len());
    assert_eq!(SIGBUS_PAGE_NOT_FOUND.load(Ordering::Relaxed), before + 2);
}

#[test]
fn execute_slice_block_stale_null_entry_falls_back_to_safepoint() {
    let _serial = jit_test_serial();
    let mut runtime = capable_runtime();
    let block = runtime
        .get_or_compile_slice_block(&[IrInstruction::Nop], 0x7000, GuestArch::X64)
        .expect("compile slice block")
        .clone();
    assert_eq!(block.published_entry().is_null(), false);
    block.entry_atomic.store(ptr::null_mut(), Ordering::Release);
    assert_eq!(block.published_entry().is_null(), true);

    let mut memory = MemoryImage::default();
    memory.map_bytes(0x7000, &[0u8; 0x1000]);
    let view = Arc::new(GuestSliceMemory::new(&memory, BTreeSet::new()));
    let program = GuestSliceProgram {
        blocks: HashMap::from([(0x7000, block)]),
        flat_base: view.flat_base(),
        memory: view,
        mechanism: runtime.compiler.memory_manager.mechanism(),
        epoch: 0,
    };
    let mut state = CpuState::new(GuestArch::X64);
    let mut chain = ChainState::new(program.flat_base, 0x7000, LINK_BUDGET);
    assert_eq!(program.block(0x7000).is_some(), true);
    assert_eq!(program.block(0x7001).is_none(), true);
    let outcome =
        unsafe { execute_slice_block(&program, &program.blocks[&0x7000], &mut state, &mut chain) };
    assert_eq!(outcome.reason, JitExitReason::Safepoint);
    assert_eq!(outcome.final_block, 0x7000);
    assert_eq!(state.jit_pending_fault, None);
}

#[test]
fn jit_slice_block_cache_clear_drops_worker_blocks() {
    let mut runtime = capable_runtime();
    let block = runtime
        .get_or_compile_slice_block(&[IrInstruction::Nop], 0x7100, GuestArch::X64)
        .expect("compile slice block");
    assert_eq!(block.worker_safe, true);
    assert_eq!(runtime.slice_block(0x7100).is_some(), true);
    runtime.clear_slice_blocks();
    assert_eq!(runtime.slice_block(0x7100).is_none(), true);
    assert_eq!(runtime.slice_block_cache.is_empty(), true);
    let memory = MemoryImage::default();
    let program = runtime.build_slice_program(&memory);
    assert_eq!(program.flat_base, program.memory.flat_base());
    assert_eq!(program.flat_base == 0, false);
    assert_eq!(program.blocks.is_empty(), true);
}

#[test]
fn worker_safe_classification_accepts_native_control_transfer_rejects_mid_block_exits() {
    // An interpreter-helper fallback still needs a live `MemoryImage`, so
    // it can never run on a production worker.
    assert_eq!(block_is_worker_safe(&[IrInstruction::Nop], true), false);
    // Mid-block-exit instructions re-run the whole block on the
    // interpreter, so they must stay host barriers.
    assert_eq!(block_is_worker_safe(&[IrInstruction::Cpuid], false), false);
    assert_eq!(block_is_worker_safe(&[IrInstruction::Xgetbv], false), false);
    assert_eq!(
        block_is_worker_safe(
            &[IrInstruction::Fxsave {
                address: crate::cpu::MemoryOperand {
                    base: None,
                    index: None,
                    scale: 1,
                    displacement: 0,
                    rip_relative: false,
                    rip_base: 0,
                    segment: None,
                    address_size_32: false,
                    absolute_address: None,
                }
            }],
            false
        ),
        false
    );
    // Guest call / ret / indirect control transfer now lowers to a native
    // worker exit (target published in the exit cell), so the block is
    // worker-safe even though the target block may take the owner path.
    assert_eq!(
        block_is_worker_safe(
            &[IrInstruction::Call {
                target: 0x1000,
                return_address: 0x1005,
            }],
            false,
        ),
        true
    );
    assert_eq!(
        block_is_worker_safe(
            &[IrInstruction::CallRegister {
                src: Register::Rax,
                return_address: 0x1005,
            }],
            false,
        ),
        true
    );
    assert_eq!(
        block_is_worker_safe(&[IrInstruction::JumpRegister { src: Register::Rax }], false),
        true
    );
    assert_eq!(
        block_is_worker_safe(&[IrInstruction::Return { stack_adjust: 0 }], false),
        true
    );
    assert_eq!(
        block_is_worker_safe(
            &[
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 1,
                },
                IrInstruction::Nop,
            ],
            false,
        ),
        true
    );
    assert_eq!(
        block_is_worker_safe(
            &[IrInstruction::JumpIf {
                condition: ConditionCode::Equal,
                target: 0x1000,
                fallthrough: 0x1006,
            }],
            false,
        ),
        true
    );
}
// ── Production worker control flow (return predictor / inline caches) ──

fn worker_program(
    runtime: &mut JitRuntime,
    memory: &MemoryImage,
    arch: GuestArch,
    blocks: &[(u64, Vec<IrInstruction>)],
) -> GuestSliceProgram {
    for (address, ir) in blocks {
        runtime
            .get_or_compile_slice_block(ir, *address, arch)
            .expect("compile worker block");
    }
    runtime.build_slice_program(memory)
}

fn worker_memory(stack: u64) -> MemoryImage {
    let mut memory = MemoryImage::default();
    memory.map_bytes(stack & !0xfff, &vec![0_u8; 0x1000]);
    memory
}

#[test]
fn indirect_inline_cache_polymorphic_boundary_and_megamorphic_counts_are_exact() {
    let site = 0x1_000_u64;
    let mut cache = IndirectInlineCache::default();
    assert_eq!(cache.lookup(site, 0xA), None);
    cache.insert(site, 0xA, 0xAA);
    assert_eq!(cache.lookup(site, 0xA), Some(0xAA));
    assert_eq!(cache.lookup(site, 0xB), None);
    cache.insert(site, 0xB, 0xBB);
    assert_eq!(cache.lookup(site, 0xA), Some(0xAA));
    assert_eq!(cache.lookup(site, 0xB), Some(0xBB));
    assert_eq!(
        (
            cache.hits(),
            cache.misses(),
            cache.megamorphic_sites(),
            cache.megamorphic_hits(),
            cache.is_megamorphic(site),
        ),
        (3, 2, 0, 0, false),
        "a 2-way code path must stay polymorphic (monomorphic first)"
    );

    assert_eq!(cache.lookup(site, 0xC), None);
    cache.insert(site, 0xC, 0xCC);
    assert_eq!(cache.lookup(site, 0xD), None);
    cache.insert(site, 0xD, 0xDD);
    for (target, entry) in [(0xA, 0xAA), (0xB, 0xBB), (0xC, 0xCC), (0xD, 0xDD)] {
        assert_eq!(cache.lookup(site, target), Some(entry));
    }
    assert_eq!(
        (
            cache.hits(),
            cache.misses(),
            cache.megamorphic_sites(),
            cache.megamorphic_hits(),
        ),
        (7, 4, 0, 0),
        "four distinct targets are exactly the 4-way polymorphic limit"
    );

    assert_eq!(cache.lookup(site, 0xE), None);
    cache.insert(site, 0xE, 0xEE);
    assert_eq!(
        (cache.megamorphic_sites(), cache.is_megamorphic(site)),
        (1, true),
        "a fifth distinct target must promote the site to megamorphic"
    );
    for (target, entry) in [
        (0xA, 0xAA),
        (0xB, 0xBB),
        (0xC, 0xCC),
        (0xD, 0xDD),
        (0xE, 0xEE),
    ] {
        assert_eq!(cache.lookup(site, target), Some(entry));
    }
    assert_eq!(cache.lookup(site, 0xF), None);
    assert_eq!(
        (
            cache.hits(),
            cache.misses(),
            cache.megamorphic_sites(),
            cache.megamorphic_hits(),
        ),
        (7, 6, 1, 5),
        "megamorphic lookups must be counted separately from hits/misses"
    );
}

#[test]
fn return_predictor_misprediction_edge_boundary_is_exact() {
    let mut predictor = ReturnPredictor::new(4);
    assert_eq!(predictor.on_return(0x10), false);
    assert_eq!(
        (
            predictor.hits(),
            predictor.misses(),
            predictor.mispredictions()
        ),
        (0, 1, 0),
        "a return without a call is a miss, not a misprediction"
    );
    predictor.on_call(0x10);
    assert_eq!(predictor.on_return(0x10), true);
    predictor.on_call(0x20);
    predictor.on_call(0x30);
    assert_eq!(predictor.on_return(0x30), true);
    assert_eq!(predictor.on_return(0x99), false);
    assert_eq!(
        (
            predictor.hits(),
            predictor.misses(),
            predictor.mispredictions()
        ),
        (2, 2, 1),
        "the real guest return address must be authoritative"
    );
    assert_eq!(predictor.on_return(0x77), false);
    assert_eq!(
        (
            predictor.hits(),
            predictor.misses(),
            predictor.mispredictions()
        ),
        (2, 3, 1)
    );

    // A non-local return resynchronises to the real frame when possible.
    predictor.reset();
    predictor.on_call(0x1);
    predictor.on_call(0x2);
    predictor.on_call(0x3);
    assert_eq!(predictor.on_return(0x2), false);
    assert_eq!(
        (
            predictor.hits(),
            predictor.misses(),
            predictor.mispredictions()
        ),
        (0, 1, 1)
    );
    assert_eq!(
        predictor.on_return(0x2),
        true,
        "the predictor must resynchronise after a misprediction"
    );
    assert_eq!(
        (
            predictor.hits(),
            predictor.misses(),
            predictor.mispredictions()
        ),
        (1, 1, 1)
    );
}

#[test]
fn worker_recursion_uses_native_call_ret_chain_and_exact_predictor_counters() {
    let _serial = jit_test_serial();
    let arch = GuestArch::X64;
    let stack = 0x11_000_u64;
    let mut memory = worker_memory(stack);
    memory.write_u64(stack + 0x800, 0xDEAD);
    let mut runtime = JitRuntime::new(arch);
    let blocks = vec![
        (
            0x1000,
            vec![IrInstruction::Call {
                target: 0x2000,
                return_address: 0x1010,
            }],
        ),
        (0x1010, vec![IrInstruction::Return { stack_adjust: 0 }]),
        (
            0x2000,
            vec![
                IrInstruction::SubImm {
                    dst: Register::Rcx,
                    value: 1,
                    width: 8,
                },
                IrInstruction::Compare {
                    lhs: crate::cpu::CompareOperand::Register(Register::Rcx),
                    rhs: crate::cpu::CompareOperand::ImmediateU64(0),
                    width: 8,
                },
                IrInstruction::JumpIf {
                    condition: ConditionCode::NotEqual,
                    target: 0x2010,
                    fallthrough: 0x2020,
                },
            ],
        ),
        (
            0x2010,
            vec![IrInstruction::Call {
                target: 0x2000,
                return_address: 0x2018,
            }],
        ),
        (0x2018, vec![IrInstruction::Return { stack_adjust: 0 }]),
        (0x2020, vec![IrInstruction::Return { stack_adjust: 0 }]),
    ];
    let program = worker_program(&mut runtime, &memory, arch, &blocks);
    let mut state = CpuState::new(arch);
    state.rip = 0x1000;
    state.set(Register::Rsp, stack + 0x800);
    state.set(Register::Rcx, 3);
    let mut thread = SliceThreadState::default();
    let shutdown = AtomicBool::new(false);
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 64, &shutdown) };
    assert_eq!(
        report.stop,
        SliceStop::HostBarrier { rip: 0xDEAD },
        "the balanced recursion must unwind to the caller's sentinel"
    );
    assert_eq!(state.get(Register::Rcx), 0);
    assert_eq!(report.blocks_executed, 10);
    assert_eq!(
        (
            report.metrics.return_predictions,
            report.metrics.return_hits,
            report.metrics.return_misses,
            report.metrics.return_mispredictions,
            report.metrics.native_chains,
        ),
        (4, 3, 1, 0, 9),
        "three calls and four returns must be predicted exactly"
    );
    assert_eq!(report.metrics.blocks_executed, 10);
    assert_eq!(
        report.metrics.dispatcher_exits, 1,
        "the balanced recursion is one native chain"
    );
    assert_eq!(report.metrics.instructions_executed, 16);
}

#[test]
fn worker_mispredicted_return_follows_the_real_guest_address() {
    let _serial = jit_test_serial();
    let arch = GuestArch::X64;
    let stack = 0x12_000_u64;
    let top = stack + 0x800;
    let memory = worker_memory(stack);
    let mut runtime = JitRuntime::new(arch);
    let address = crate::cpu::MemoryOperand {
        base: None,
        index: None,
        scale: 1,
        displacement: 0,
        rip_relative: false,
        rip_base: 0,
        segment: None,
        address_size_32: false,
        absolute_address: Some(top - 8),
    };
    let blocks = vec![
        (
            0x1000,
            vec![IrInstruction::Call {
                target: 0x2000,
                return_address: 0x1010,
            }],
        ),
        (
            0x2000,
            vec![
                IrInstruction::StoreMemory {
                    src: Register::Rcx,
                    address,
                    width: 8,
                },
                IrInstruction::Return { stack_adjust: 0 },
            ],
        ),
        (0x2020, vec![IrInstruction::Jump { target: 0x2020 }]),
    ];
    let program = worker_program(&mut runtime, &memory, arch, &blocks);
    let mut state = CpuState::new(arch);
    state.rip = 0x1000;
    state.set(Register::Rsp, top);
    state.set(Register::Rcx, 0x2020);
    let mut thread = SliceThreadState::default();
    let shutdown = AtomicBool::new(false);
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 4, &shutdown) };
    assert_eq!(
        report.stop,
        SliceStop::Budget,
        "execution must continue at the real return address, not the prediction"
    );
    assert_eq!(state.rip, 0x2020);
    assert_eq!(
        (
            report.metrics.return_hits,
            report.metrics.return_misses,
            report.metrics.return_mispredictions,
        ),
        (0, 1, 1),
        "the overwritten return address must be a counted misprediction"
    );
    assert_eq!(report.metrics.native_chains, 2);
}

#[test]
fn worker_indirect_calls_use_monomorphic_polymorphic_and_megamorphic_caches() {
    let _serial = jit_test_serial();
    let arch = GuestArch::X64;
    let stack = 0x13_000_u64;
    let memory = worker_memory(stack);
    let mut runtime = JitRuntime::new(arch);
    let mut blocks = vec![(
        0x1000,
        vec![IrInstruction::CallRegister {
            src: Register::Rax,
            return_address: 0x1010,
        }],
    )];
    for target in [0x2000_u64, 0x3000, 0x4000, 0x5000, 0x6000] {
        blocks.push((target, vec![IrInstruction::Return { stack_adjust: 0 }]));
    }
    let program = worker_program(&mut runtime, &memory, arch, &blocks);
    let mut state = CpuState::new(arch);
    state.set(Register::Rsp, stack + 0x800);
    let mut thread = SliceThreadState::default();
    let shutdown = AtomicBool::new(false);
    let sequence = [
        0x2000, 0x3000, 0x2000, 0x4000, 0x5000, 0x2000, 0x3000, 0x4000, 0x5000,
    ];
    for target in sequence {
        state.rip = 0x1000;
        state.set(Register::Rsp, stack + 0x800);
        state.set(Register::Rax, target);
        // SAFETY: program/state are live for the call; budget 1 executes
        // only the indirect call block.
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
        assert_eq!(report.stop, SliceStop::Budget);
        assert_eq!(state.rip, target);
        assert_eq!(report.metrics.indirect_megamorphic_sites, 0);
    }
    assert_eq!(
        (
            thread.metrics.indirect_ic_hits,
            thread.metrics.indirect_ic_misses,
            thread.metrics.indirect_megamorphic_sites,
            thread.metrics.indirect_megamorphic_hits,
        ),
        (5, 4, 0, 0),
        "four distinct call targets stay inside the 4-way polymorphic cache"
    );
    state.rip = 0x1000;
    state.set(Register::Rsp, stack + 0x800);
    state.set(Register::Rax, 0x6000);
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
    assert_eq!(report.metrics.indirect_megamorphic_sites, 1);
    assert_eq!(report.metrics.indirect_ic_misses, 1);
    for target in [0x2000_u64, 0x3000, 0x4000, 0x5000, 0x6000] {
        state.rip = 0x1000;
        state.set(Register::Rsp, stack + 0x800);
        state.set(Register::Rax, target);
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
        assert_eq!(report.metrics.indirect_megamorphic_hits, 1);
    }
    assert_eq!(thread.metrics.indirect_megamorphic_hits, 5);
    assert_eq!(thread.metrics.indirect_ic_hits, 5);
    state.rip = 0x1000;
    state.set(Register::Rsp, stack + 0x800);
    state.set(Register::Rax, 0x2000);
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
    assert_eq!(
        (
            report.metrics.indirect_ic_hits,
            report.metrics.indirect_megamorphic_hits,
            thread.metrics.indirect_megamorphic_sites,
        ),
        (0, 1, 1),
        "a megamorphic hit must not be reported as an ordinary hit"
    );
}

#[test]
fn worker_chained_code_safepoint_and_smc_stop_before_the_next_block() {
    let _serial = jit_test_serial();
    let arch = GuestArch::X64;
    let stack = 0x14_000_u64;
    let mut memory = worker_memory(stack);
    memory.map_bytes(0x5000, &vec![0_u8; 0x1000]);
    let mut runtime = JitRuntime::new(arch);
    runtime.code_pages.insert(0x5000);
    let call_blocks = vec![
        (
            0x1000,
            vec![IrInstruction::Call {
                target: 0x2000,
                return_address: 0x1010,
            }],
        ),
        (0x2000, vec![IrInstruction::Return { stack_adjust: 0 }]),
        (0x1010, vec![IrInstruction::Jump { target: 0x1010 }]),
    ];
    let call_program = worker_program(&mut runtime, &memory, arch, &call_blocks);
    let mut state = CpuState::new(arch);
    state.rip = 0x1000;
    state.set(Register::Rsp, stack + 0x800);
    let mut thread = SliceThreadState::default();
    let shutdown = AtomicBool::new(false);
    let report = unsafe { run_slice(&call_program, &mut state, &mut thread, 1, &shutdown) };
    assert_eq!(report.stop, SliceStop::Budget);
    assert_eq!(state.rip, 0x2000);
    crate::jit::JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Release);
    let report = unsafe { run_slice(&call_program, &mut state, &mut thread, 8, &shutdown) };
    crate::jit::JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    assert_eq!(
        report.stop,
        SliceStop::Safepoint,
        "a chained callee must poll the safepoint at its block entry"
    );
    assert_eq!(state.rip, 0x2000);
    assert_eq!(
        report.blocks_executed, 0,
        "the callee's entry safepoint poll must stop before its body runs"
    );

    let write = crate::cpu::MemoryOperand {
        base: None,
        index: None,
        scale: 1,
        displacement: 0,
        rip_relative: false,
        rip_base: 0,
        segment: None,
        address_size_32: false,
        absolute_address: Some(0x5010),
    };
    let smc_blocks = vec![
        (0x5000, vec![IrInstruction::Jump { target: 0x5010 }]),
        (
            0x5010,
            vec![
                IrInstruction::StoreMemory {
                    src: Register::Rcx,
                    address: write,
                    width: 8,
                },
                IrInstruction::Jump { target: 0x5020 },
            ],
        ),
        (
            0x5020,
            vec![IrInstruction::AddImm {
                dst: Register::Rdx,
                value: 1,
                width: 8,
            }],
        ),
    ];
    let smc_program = worker_program(&mut runtime, &memory, arch, &smc_blocks);
    let mut state = CpuState::new(arch);
    state.rip = 0x5000;
    state.set(Register::Rcx, 0x1122_3344_5566_7788);
    let mut thread = SliceThreadState::default();
    let report = unsafe { run_slice(&smc_program, &mut state, &mut thread, 8, &shutdown) };
    assert_eq!(report.stop, SliceStop::CodeWrite);
    assert_eq!(report.blocks_executed, 2);
    assert_eq!(report.code_writes, vec![(0x5010, 8)]);
    assert_eq!(
        state.get(Register::Rdx),
        0,
        "the block after a chained code write must not execute"
    );
    assert_eq!(state.rip, 0x5020);
}

// ── Native linking / in-block branches / persistent AOT cache ──────────

fn worker_runtime(arch: GuestArch) -> JitRuntime {
    assert!(
        jit_execution_available(),
        "this test requires a working executable-memory mechanism"
    );
    let mut runtime = JitRuntime::new(arch);
    runtime.set_aot_cache_dir(None);
    runtime
}

fn unlink_program(program: &GuestSliceProgram) {
    for block in program.blocks.values() {
        block.link_target.store(0, Ordering::Release);
        block.taken_link.store(0, Ordering::Release);
        block.fallthrough_link.store(0, Ordering::Release);
        block.call_link.store(0, Ordering::Release);
        block.return_entry_link.store(0, Ordering::Release);
    }
}

fn loop_blocks(site: u64, exit: u64) -> Vec<(u64, Vec<IrInstruction>)> {
    vec![
        (
            site,
            vec![
                IrInstruction::SubImm {
                    dst: Register::Rcx,
                    value: 1,
                    width: 4,
                },
                IrInstruction::Compare {
                    lhs: crate::cpu::CompareOperand::Register(Register::Rcx),
                    rhs: crate::cpu::CompareOperand::ImmediateU64(0),
                    width: 4,
                },
                IrInstruction::JumpIf {
                    condition: ConditionCode::NotEqual,
                    target: site,
                    fallthrough: exit,
                },
            ],
        ),
        (exit, vec![IrInstruction::Nop]),
    ]
}

#[test]
fn jit_worker_linked_loop_and_call_return_match_unlinked_exactly() {
    let _serial = jit_test_serial();
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    let mut runtime = worker_runtime(GuestArch::X64);
    let memory = worker_memory(0x7000);
    runtime.attach_guest_memory(&memory);
    let mut blocks = loop_blocks(0x1000, 0x1010);
    blocks.push((
        0x2000,
        vec![IrInstruction::Call {
            target: 0x2100,
            return_address: 0x2010,
        }],
    ));
    blocks.push((0x2010, vec![IrInstruction::Jump { target: 0x9000 }]));
    blocks.push((0x2100, vec![IrInstruction::Return { stack_adjust: 0 }]));
    let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
    let shutdown = std::sync::atomic::AtomicBool::new(false);

    let run_loop = |program: &GuestSliceProgram, budget: u64| {
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x1000;
        state.set(Register::Rcx, 100);
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(program, &mut state, &mut thread, budget, &shutdown) };
        (report, state.get(Register::Rcx))
    };
    let (linked_report, linked_rcx) = run_loop(&program, 8);
    unlink_program(&program);
    let (unlinked_report, unlinked_rcx) = run_loop(&program, 8);
    assert_eq!(
        (linked_report.blocks_executed, linked_rcx),
        (8, 100 - 8),
        "linked loop must execute exactly the slice budget"
    );
    assert_eq!(
        (unlinked_report.blocks_executed, unlinked_rcx),
        (8, 100 - 8),
        "unlinked execution must reach the identical guest state"
    );
    assert_eq!(linked_report.metrics.native_chains, 7);
    assert_eq!(unlinked_report.metrics.native_chains, 0);
    assert_eq!(linked_report.metrics.instructions_executed, 24);
    assert_eq!(unlinked_report.metrics.instructions_executed, 24);
    assert_eq!(linked_report.stop, SliceStop::Budget);
    assert_eq!(unlinked_report.stop, SliceStop::Budget);

    let run_call = |program: &GuestSliceProgram| {
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x2000;
        state.set(Register::Rsp, 0x7800);
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(program, &mut state, &mut thread, 4, &shutdown) };
        (
            report.blocks_executed,
            report.stop,
            state.get(Register::Rsp),
        )
    };
    // Re-publish links for the call/ret measurement.
    runtime.build_slice_program(&memory);
    let linked_call = run_call(&program);
    unlink_program(&program);
    let unlinked_call = run_call(&program);
    assert_eq!(
        linked_call,
        (3, SliceStop::HostBarrier { rip: 0x9000 }, 0x7800)
    );
    assert_eq!(
        unlinked_call,
        (3, SliceStop::HostBarrier { rip: 0x9000 }, 0x7800)
    );
    // Call + return must be linked; the final uncompiled jump is not.
    assert_eq!(
        unsafe {
            let mut state = CpuState::new(GuestArch::X64);
            state.rip = 0x2000;
            state.set(Register::Rsp, 0x7800);
            let mut thread = SliceThreadState::default();
            runtime.build_slice_program(&memory);
            run_slice(&program, &mut state, &mut thread, 4, &shutdown)
                .metrics
                .native_chains
        },
        2
    );
}

#[test]
fn jit_worker_safepoint_stop_is_observed_within_the_link_budget() {
    let _serial = jit_test_serial();
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    let mut runtime = worker_runtime(GuestArch::X64);
    let memory = worker_memory(0x7000);
    runtime.attach_guest_memory(&memory);
    let program = worker_program(
        &mut runtime,
        &memory,
        GuestArch::X64,
        &loop_blocks(0x1100, 0x1110),
    );
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Release);
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x1100;
    state.set(Register::Rcx, 10);
    let mut thread = SliceThreadState::default();
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 8, &shutdown) };
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    assert_eq!(report.stop, SliceStop::Safepoint);
    assert_eq!(report.blocks_executed, 0);
    assert_eq!(state.rip, 0x1100);
    assert_eq!(state.get(Register::Rcx), 10);

    // A running chain must observe a safepoint set by another host thread
    // before the slice budget is exhausted, and never exceed LINK_BUDGET
    // block entries between dispatch boundaries.
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let setter = std::sync::Arc::clone(&flag);
    let watcher = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(2));
        setter.store(true, Ordering::Release);
        JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Release);
    });
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x1100;
    state.set(Register::Rcx, 100_000_000);
    let mut thread = SliceThreadState::default();
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 50_000_000, &shutdown) };
    watcher.join().expect("safepoint setter");
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    assert_eq!(flag.load(Ordering::Acquire), true);
    assert_eq!(report.stop, SliceStop::Safepoint);
    assert_eq!(report.blocks_executed > 0, true);
    assert_eq!(report.blocks_executed <= 50_000_000, true);
}

#[test]
fn jit_worker_smc_write_invalidates_native_links_exactly() {
    let _serial = jit_test_serial();
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    let mut runtime = worker_runtime(GuestArch::X64);
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x3000, &[0_u8; 0x1000]);
    runtime.attach_guest_memory(&memory);
    let operand = crate::cpu::MemoryOperand {
        base: None,
        index: None,
        scale: 1,
        displacement: 0,
        rip_relative: false,
        rip_base: 0,
        segment: None,
        address_size_32: false,
        absolute_address: Some(0x3000),
    };
    let blocks = vec![(
        0x3000,
        vec![
            IrInstruction::StoreImmediate {
                address: operand,
                value: 0x90,
                width: 1,
            },
            IrInstruction::Jump { target: 0x3000 },
        ],
    )];
    let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
    let link = Arc::clone(&program.blocks[&0x3000].link_target);
    assert_eq!(link.load(Ordering::Acquire) != 0, true);
    let epoch_before = JIT_CODE_EPOCH.load(Ordering::Acquire);
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x3000;
    let mut thread = SliceThreadState::default();
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 4, &shutdown) };
    assert_eq!(report.stop, SliceStop::CodeWrite);
    assert_eq!(report.blocks_executed, 1);
    assert_eq!(report.code_writes, vec![(0x3000, 1)]);
    assert_eq!(state.rip, 0x3000);
    assert_eq!(JIT_CODE_EPOCH.load(Ordering::Acquire) > epoch_before, true);

    let pages = BTreeSet::from([0x3000]);
    let affected = runtime.invalidate_blocks_on_pages(&pages);
    assert_eq!(affected, Vec::<u64>::new());
    assert_eq!(link.load(Ordering::Acquire), 0);
    assert_eq!(runtime.slice_block(0x3000).is_none(), true);
    assert_eq!(runtime.slice_epoch, 1);

    // Recompilation after invalidation must use the new guest code.
    let replacement = vec![(
        0x3000,
        vec![IrInstruction::AddImm {
            dst: Register::Rcx,
            value: 7,
            width: 8,
        }],
    )];
    let program = worker_program(&mut runtime, &memory, GuestArch::X64, &replacement);
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x3000;
    let mut thread = SliceThreadState::default();
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
    assert_eq!(report.blocks_executed, 1);
    assert_eq!(state.get(Register::Rcx), 7);
}

#[test]
fn jit_worker_host_call_barrier_pushes_return_exactly_once() {
    let _serial = jit_test_serial();
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    let mut runtime = worker_runtime(GuestArch::X64);
    let memory = worker_memory(0x7000);
    runtime.attach_guest_memory(&memory);
    let blocks = vec![(
        0x4000,
        vec![IrInstruction::Call {
            target: 0x9000,
            return_address: 0x4010,
        }],
    )];
    let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x4000;
    state.set(Register::Rsp, 0x7800);
    let mut thread = SliceThreadState::default();
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 4, &shutdown) };
    assert_eq!(report.stop, SliceStop::HostBarrier { rip: 0x9000 });
    assert_eq!(report.blocks_executed, 1);
    assert_eq!(state.get(Register::Rsp), 0x77f8);
    assert_eq!(memory.read_u64(0x77f8).expect("mapped stack"), 0x4010);
    assert_eq!(
        thread.return_predictor.hits() + thread.return_predictor.misses(),
        0
    );
}

#[test]
fn jit_worker_conditional_flags_equivalence_all_conditions_is_exact() {
    let _serial = jit_test_serial();
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    let mut runtime = worker_runtime(GuestArch::X64);
    let memory = worker_memory(0x7000);
    runtime.attach_guest_memory(&memory);
    let conditions = [
        ConditionCode::Equal,
        ConditionCode::NotEqual,
        ConditionCode::Overflow,
        ConditionCode::NotOverflow,
        ConditionCode::Below,
        ConditionCode::NotBelow,
        ConditionCode::Above,
        ConditionCode::NotAbove,
        ConditionCode::Sign,
        ConditionCode::NotSign,
        ConditionCode::Less,
        ConditionCode::GreaterEqual,
        ConditionCode::LessEqual,
        ConditionCode::Greater,
        ConditionCode::Parity,
        ConditionCode::NotParity,
    ];
    let mut blocks = Vec::new();
    let mut addresses = Vec::new();
    for (index, condition) in conditions.iter().enumerate() {
        let address = 0x5000 + (index as u64) * 0x20;
        addresses.push(address);
        blocks.push((
            address,
            vec![IrInstruction::JumpIf {
                condition: *condition,
                target: 0x9000,
                fallthrough: 0x9008,
            }],
        ));
    }
    let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
    let mut checks = 0_u64;
    for (index, condition) in conditions.iter().enumerate() {
        for bits in 0..32_u8 {
            let mut state = CpuState::new(GuestArch::X64);
            state.flags = crate::cpu::Flags {
                cf: bits & 1 != 0,
                pf: bits & 2 != 0,
                zf: bits & 4 != 0,
                sf: bits & 8 != 0,
                of: bits & 16 != 0,
                af: false,
            };
            let mut chain = ChainState::new(program.flat_base, addresses[index], LINK_BUDGET);
            let outcome = unsafe {
                execute_slice_block(
                    &program,
                    &program.blocks[&addresses[index]],
                    &mut state,
                    &mut chain,
                )
            };
            let actual = match outcome.reason {
                JitExitReason::ConditionalTaken { .. } => true,
                JitExitReason::ConditionalNotTaken { .. } => false,
                other => panic!("expected native conditional exit, got {other:?}"),
            };
            assert_eq!(
                actual,
                crate::cpu::evaluate_condition(*condition, &state.flags),
                "condition {condition:?} with flags {bits:#07b}"
            );
            checks += 1;
        }
    }
    assert_eq!(checks, 16 * 32);
}

#[test]
fn jit_worker_lazy_flags_materialize_before_native_jcc_exactly() {
    let _serial = jit_test_serial();
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    let mut runtime = worker_runtime(GuestArch::X64);
    let memory = worker_memory(0x7000);
    runtime.attach_guest_memory(&memory);
    let cases = [
        (ConditionCode::Equal, true, true),
        (ConditionCode::Overflow, true, true),
        (ConditionCode::Sign, true, true),
    ];
    let mut blocks = Vec::new();
    for (index, _) in cases.iter().enumerate() {
        blocks.push((
            0x5300 + (index as u64) * 0x20,
            vec![IrInstruction::JumpIf {
                condition: cases[index].0,
                target: 0x9000,
                fallthrough: 0x9008,
            }],
        ));
    }
    let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
    let materialised_before = crate::cpu::lazy_flag_telemetry().materialised;
    let mut stats = crate::cpu::LazyFlagStats::default();
    for (index, (condition, _, _)) in cases.iter().enumerate() {
        let address = 0x5300 + (index as u64) * 0x20;
        let mut state = CpuState::new(GuestArch::X64);
        match index {
            0 => state.defer_sub_flags(5, 5, 0, 32, &mut stats),
            1 => state.defer_add_flags(i64::MAX as u64, 1, i64::MIN as u64, 64, &mut stats),
            _ => state.defer_sub_flags(1, 2, u64::MAX, 64, &mut stats),
        }
        assert_eq!(state.pending_flags.is_some(), true);
        let mut chain = ChainState::new(program.flat_base, address, LINK_BUDGET);
        let outcome = unsafe {
            execute_slice_block(&program, &program.blocks[&address], &mut state, &mut chain)
        };
        assert_eq!(state.pending_flags.is_none(), true);
        assert_eq!(
            outcome.reason,
            JitExitReason::ConditionalTaken { rip: address },
            "lazy flags must be materialised before the native branch"
        );
        assert_eq!(
            cases[index].1,
            crate::cpu::evaluate_condition(*condition, &state.flags)
        );
    }
    assert_eq!(
        crate::cpu::lazy_flag_telemetry().materialised,
        materialised_before + 3
    );
}

fn decode_fixed_mov_imm64(bytes: &[u8]) -> u64 {
    let mut value = 0_u64;
    for index in 0..4 {
        let word = u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
        let hw = (word >> 21) & 3;
        let imm = ((word >> 5) & 0xffff) as u64;
        value |= imm << (hw * 16);
    }
    value
}

fn aot_probe_ir() -> Vec<IrInstruction> {
    vec![IrInstruction::AddImm {
        dst: Register::Rcx,
        value: 1,
        width: 8,
    }]
}

fn run_aot_probe(runtime: &mut JitRuntime, memory: &MemoryImage) -> (u64, u64) {
    let ir = aot_probe_ir();
    runtime
        .get_or_compile_slice_block(&ir, 0x6000, GuestArch::X64)
        .expect("compile or load AOT probe");
    let program = runtime.build_slice_program(memory);
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x6000;
    state.set(Register::Rcx, 41);
    let mut thread = SliceThreadState::default();
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 4, &shutdown) };
    (report.blocks_executed, state.get(Register::Rcx))
}

#[test]
fn jit_worker_aot_cache_round_trip_across_process_boundaries_loads_exact_code() {
    let _serial = jit_test_serial();
    if let Ok(directory) = std::env::var("CASA1_AOT_CHILD_DIR") {
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.set_aot_cache_dir(Some(std::path::PathBuf::from(directory)));
        let memory = worker_memory(0x7000);
        runtime.attach_guest_memory(&memory);
        assert_eq!(run_aot_probe(&mut runtime, &memory), (1, 42));
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    let executable = std::env::current_exe().expect("test executable");
    let name = format!(
        "{}::jit_worker_aot_cache_round_trip_across_process_boundaries_loads_exact_code",
        module_path!()
    )
    .replace("casa1::", "");
    let status = std::process::Command::new(executable)
        .args(["--exact", &name, "--nocapture", "--test-threads=1"])
        .env("CASA1_AOT_CHILD_DIR", directory.path())
        .status()
        .expect("spawn AOT child process");
    assert_eq!(status.success(), true);

    let mut runtime = JitRuntime::new(GuestArch::X64);
    runtime.set_aot_cache_dir(Some(directory.path().to_path_buf()));
    let memory = worker_memory(0x7000);
    runtime.attach_guest_memory(&memory);
    assert_eq!(run_aot_probe(&mut runtime, &memory), (1, 42));
    assert_eq!(runtime.aot_metrics(), (1, 0, 0));
}

#[test]
fn jit_worker_aot_corrupt_and_wrong_version_cache_are_rejected_with_counters() {
    let directory = tempfile::tempdir().expect("tempdir");
    let ir = aot_probe_ir();
    let source_hash = compute_ir_hash(&ir, 0x6100);
    let mut writer = JitRuntime::new(GuestArch::X64);
    writer.set_aot_cache_dir(Some(directory.path().to_path_buf()));
    writer
        .get_or_compile_slice_block(&ir, 0x6100, GuestArch::X64)
        .expect("initial compile");
    let path = writer.aot_path(source_hash, 0x6100).expect("cache path");
    assert_eq!(path.is_file(), true);

    std::fs::write(&path, b"corrupt").expect("corrupt cache write");
    let mut corrupt = JitRuntime::new(GuestArch::X64);
    corrupt.set_aot_cache_dir(Some(directory.path().to_path_buf()));
    corrupt
        .get_or_compile_slice_block(&ir, 0x6100, GuestArch::X64)
        .expect("fallback compile after corruption");
    assert_eq!(corrupt.aot_metrics(), (0, 0, 1));

    let bytes = std::fs::read(&path).expect("rewritten cache");
    let mut record = AotRecord::decode(&bytes).expect("valid rewritten record");
    record.translator = record.translator.wrapping_add(1);
    std::fs::write(&path, record.encode()).expect("wrong-version cache write");
    let mut wrong = JitRuntime::new(GuestArch::X64);
    wrong.set_aot_cache_dir(Some(directory.path().to_path_buf()));
    wrong
        .get_or_compile_slice_block(&ir, 0x6100, GuestArch::X64)
        .expect("fallback compile after version mismatch");
    assert_eq!(wrong.aot_metrics(), (0, 0, 1));
}

#[test]
fn jit_worker_aot_relocations_rebind_link_slots_exactly() {
    let _serial = jit_test_serial();
    let directory = tempfile::tempdir().expect("tempdir");
    let mut writer = JitRuntime::new(GuestArch::X64);
    writer.set_aot_cache_dir(Some(directory.path().to_path_buf()));
    let memory = worker_memory(0x7000);
    writer.attach_guest_memory(&memory);
    let ir = vec![IrInstruction::Jump { target: 0x6210 }];
    let source_hash = compute_ir_hash(&ir, 0x6200);
    writer
        .get_or_compile_slice_block(&ir, 0x6200, GuestArch::X64)
        .expect("compile jump");
    writer
        .get_or_compile_slice_block(
            &[IrInstruction::Jump { target: 0x9000 }],
            0x6210,
            GuestArch::X64,
        )
        .expect("compile target");
    let path = writer.aot_path(source_hash, 0x6200).expect("cache path");
    let bytes = std::fs::read(&path).expect("cache record");
    let record = AotRecord::decode(&bytes).expect("decode cache record");
    let relocation = record
        .relocations
        .iter()
        .find(|relocation| relocation.kind == AotRelocKind::JumpLink)
        .expect("jump link relocation");
    let offset = relocation.offset as usize;
    let on_disk = decode_fixed_mov_imm64(&record.code[offset..offset + 16]);
    assert_eq!(on_disk != 0, true);

    let mut reader = JitRuntime::new(GuestArch::X64);
    reader.set_aot_cache_dir(Some(directory.path().to_path_buf()));
    reader.attach_guest_memory(&memory);
    let _ = reader
        .get_or_compile_slice_block(
            &[IrInstruction::Jump { target: 0x9000 }],
            0x6210,
            GuestArch::X64,
        )
        .expect("load target jump");
    let loaded = reader
        .get_or_compile_slice_block(&ir, 0x6200, GuestArch::X64)
        .expect("load jump")
        .clone();
    // Both jump blocks came from the persistent cache.
    assert_eq!(reader.aot_metrics(), (2, 0, 0));
    // SAFETY: the loaded entry is finalized executable code; reading its
    // bytes is side-effect free.
    let loaded_code =
        unsafe { std::slice::from_raw_parts(loaded.entry() as *const u8, loaded.code_size) };
    let relocated = decode_fixed_mov_imm64(&loaded_code[offset..offset + 16]);
    assert_eq!(relocated, Arc::as_ptr(&loaded.link_target) as u64);
    assert_eq!(relocated != on_disk, true);
    let mut in_reloc = vec![false; loaded.code_size];
    for relocation in &record.relocations {
        let start = relocation.offset as usize;
        for byte in &mut in_reloc[start..start + 16] {
            *byte = true;
        }
    }
    for (index, (a, b)) in record.code.iter().zip(loaded_code.iter()).enumerate() {
        if !in_reloc[index] {
            assert_eq!(a, b, "non-relocated byte {index:#x} changed");
        }
    }
    for relocation in &record.relocations {
        let start = relocation.offset as usize;
        let original_rd =
            u32::from_le_bytes(record.code[start..start + 4].try_into().unwrap()) & 0x1f;
        let relocated_rd =
            u32::from_le_bytes(loaded_code[start..start + 4].try_into().unwrap()) & 0x1f;
        assert_eq!(
            original_rd, relocated_rd,
            "relocation must preserve its destination register"
        );
        let value = decode_fixed_mov_imm64(&loaded_code[start..start + 16]);
        let expected = match relocation.kind {
            AotRelocKind::SafepointFlag => &JIT_SAFEPOINT_REQUESTED as *const _ as u64,
            AotRelocKind::CodeEpoch => &JIT_CODE_EPOCH as *const _ as u64,
            AotRelocKind::JumpLink => Arc::as_ptr(&loaded.link_target) as u64,
            other => panic!("unexpected relocation {other:?}"),
        };
        assert_eq!(value, expected, "relocation {relocation:?}");
    }

    let program = reader.build_slice_program(&memory);
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x6200;
    let mut thread = SliceThreadState::default();
    let report = unsafe { run_slice(&program, &mut state, &mut thread, 8, &shutdown) };
    assert_eq!(report.blocks_executed, 2);
    assert_eq!(report.metrics.native_chains, 1);
    assert_eq!(report.stop, SliceStop::HostBarrier { rip: 0x9000 });
}

#[test]
fn jit_worker_concurrent_in_flight_linked_blocks_are_exact() {
    let _serial = jit_test_serial();
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
    let mut runtime = worker_runtime(GuestArch::X64);
    let memory = worker_memory(0x7000);
    runtime.attach_guest_memory(&memory);
    let program = std::sync::Arc::new(worker_program(
        &mut runtime,
        &memory,
        GuestArch::X64,
        &loop_blocks(0x1200, 0x1210),
    ));
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    let entry = program.blocks[&0x1200].entry() as u64;
    let slot = Arc::clone(&program.blocks[&0x1200].taken_link);
    let results = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let program = std::sync::Arc::clone(&program);
            let results = &results;
            let shutdown = &shutdown;
            scope.spawn(move || {
                let mut state = CpuState::new(GuestArch::X64);
                state.rip = 0x1200;
                state.set(Register::Rcx, 100);
                let mut thread = SliceThreadState::default();
                let report = unsafe { run_slice(&program, &mut state, &mut thread, 50, shutdown) };
                results
                    .lock()
                    .expect("results lock")
                    .push((report.blocks_executed, state.get(Register::Rcx)));
            });
        }
        let slot = &slot;
        scope.spawn(move || {
            for index in 0..2_000_u64 {
                slot.store(if index % 2 == 0 { 0 } else { entry }, Ordering::Release);
            }
        });
    });
    let mut results = results.into_inner().expect("results");
    results.sort_unstable();
    assert_eq!(results, vec![(50, 50), (50, 50), (50, 50), (50, 50)]);
}

#[test]
fn hot_path_loads_persisted_aot_record_without_recompiling() {
    let directory = tempfile::tempdir().expect("tempdir");
    let ir = vec![
        IrInstruction::Nop,
        IrInstruction::Return { stack_adjust: 0 },
    ];
    let mut writer = JitRuntime::new(GuestArch::X64);
    writer.set_aot_cache_dir(Some(directory.path().to_path_buf()));
    writer
        .get_or_compile_slice_block(&ir, 0x9100, GuestArch::X64)
        .expect("persist worker block");

    let mut reader = JitRuntime::new(GuestArch::X64);
    reader.set_aot_cache_dir(Some(directory.path().to_path_buf()));
    reader
        .get_or_compile_at_tier(&ir, 0x9100, GuestArch::X64, CompilationTier::Tier0, None)
        .expect("hot path load");
    assert_eq!(reader.aot_metrics().0, 1, "one persistent hit");
    assert_eq!(reader.blocks_compiled, 0, "an AOT hit does not recompile");
    assert_eq!(reader.tier0_compiles, 0);
}
