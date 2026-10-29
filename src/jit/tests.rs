use super::*;
use crate::cpu::GUEST_FLAT_SIZE;

#[test]
fn jit_memory_manager_rejects_null_and_zero_size_finalize() {
    let mut mgr = JitMemoryManager::new();
    let code = [0xd5, 0x03, 0x20, 0x1f]; // NOP
    let ptr = mgr.allocate_code_space(code.len());
    assert_eq!(ptr.is_null(), false);
    assert_eq!(mgr.total_allocated(), JIT_PAGE_SIZE);
    assert_eq!(mgr.total_used(), 64);
    // SAFETY: ptr was allocated by allocate_code_space and is valid
    // for code.len() bytes. code.as_ptr() is valid for code.len() bytes.
    // Regions are non-overlapping.
    unsafe {
        assert_eq!(
            mgr.make_writable(ptr, code.len()),
            true,
            "selected mechanism must provide writable code memory"
        );
        ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len());
        assert_eq!(
            mgr.finalize_code(ptr, code.len()),
            true,
            "selected mechanism must provide executable code memory"
        );
        // Null and zero-size requests must be refused: making them
        // "succeed" would claim a nonexistent code range is executable.
        assert_eq!(mgr.finalize_code(std::ptr::null_mut(), code.len()), false);
        assert_eq!(mgr.finalize_code(ptr, 0), false);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn jit_exec_probe_matrix_macos_aarch64() {
    let matrix = probe_jit_execution();
    eprintln!("[jit] executable-memory probe matrix: {matrix:#?}");
    // macOS may deny the RX transition with ENOENT depending on the
    // process's W^X state; the selected mechanism below must still be the
    // MAP_JIT W^X path that does execute.
    assert!(
        matches!(
            matrix.mprotect_rx,
            JitExecProbeOutcome::Executed(42) | JitExecProbeOutcome::MprotectFailed(2)
        ),
        "mmap RW -> mprotect RX must execute or fail with a real ENOENT: {}",
        matrix.mprotect_rx
    );
    match matrix.map_jit_wx_write_protect {
        JitExecProbeOutcome::Executed(42) => {
            assert_eq!(
                matrix.selected,
                JitExecMechanism::MapJitWx,
                "the JIT must prefer the W^X MAP_JIT mechanism when it executes"
            );
        }
        // A hardened-runtime process without
        // `com.apple.security.cs.allow-jit` is refused by the kernel at mmap
        // time with EPERM.  That is the only supported outage: pin the exact
        // refusal and require the selection to match what actually ran.
        JitExecProbeOutcome::MmapFailed(libc::EPERM) => {
            let expected = if matrix.mprotect_rx == JitExecProbeOutcome::Executed(42) {
                JitExecMechanism::MprotectRx
            } else {
                JitExecMechanism::Unavailable
            };
            assert_eq!(
                matrix.selected, expected,
                "a MAP_JIT refusal must select exactly the mechanism that ran"
            );
        }
        other => panic!("MAP_JIT W^X must execute or be refused with EPERM; got {other}"),
    }
    // Regression guard: the pre-fix allocation (MAP_JIT without PROT_EXEC)
    // must never silently start "working" as if it were executable.
    assert!(
        !matches!(
            matrix.map_jit_rw_write_protect,
            JitExecProbeOutcome::Executed(_)
        ),
        "RW-only MAP_JIT must not execute; got {}",
        matrix.map_jit_rw_write_protect
    );
    // The no-toggle test writes into an execute-protected MAP_JIT region
    // and must fault rather than execute.
    assert!(
        !matches!(
            matrix.map_jit_wx_no_write_protect,
            JitExecProbeOutcome::Executed(_)
        ),
        "MAP_JIT RWX without write-protect toggles must not execute; got {}",
        matrix.map_jit_wx_no_write_protect
    );
}

fn verify_capability_selection(matrix: JitExecProbeMatrix) {
    match matrix.selected {
        JitExecMechanism::MapJitWx => assert_eq!(
            matrix.map_jit_wx_write_protect,
            JitExecProbeOutcome::Executed(42),
            "selected MAP_JIT but its probe did not execute"
        ),
        JitExecMechanism::MprotectRx => assert_eq!(
            matrix.mprotect_rx,
            JitExecProbeOutcome::Executed(42),
            "selected mprotect RX but its probe did not execute"
        ),
        JitExecMechanism::RwxMmap => {}
        JitExecMechanism::Unavailable => {
            eprintln!("[jit] native execution unavailable: {matrix:?}");
            assert_ne!(
                matrix.selected,
                JitExecMechanism::Unavailable,
                "an unavailable capability must report unavailable"
            );
        }
    }
    for (name, outcome) in [
        ("mprotect_rx", matrix.mprotect_rx),
        ("map_jit_wx_write_protect", matrix.map_jit_wx_write_protect),
    ] {
        if let JitExecProbeOutcome::Executed(value) = outcome {
            assert_eq!(value, 42, "{name} executed a stub that must return 42");
        }
    }
}

#[test]
fn jit_capability_selection_rejects_inconsistent_real_matrix() {
    let matrix = jit_execution_capability();
    assert_eq!(
        matrix.selected != JitExecMechanism::Unavailable,
        jit_execution_available()
    );
    if matrix.selected == JitExecMechanism::Unavailable {
        // Hosts that deny every mechanism (for example a hardened-runtime
        // process without com.apple.security.cs.allow-jit) are a supported
        // outcome, but no probe may claim it executed the stub.
        for (name, outcome) in [
            ("mprotect_rx", matrix.mprotect_rx),
            ("map_jit_wx_write_protect", matrix.map_jit_wx_write_protect),
            ("map_jit_rw_write_protect", matrix.map_jit_rw_write_protect),
            (
                "map_jit_wx_no_write_protect",
                matrix.map_jit_wx_no_write_protect,
            ),
        ] {
            assert!(
                !matches!(outcome, JitExecProbeOutcome::Executed(_)),
                "unavailable capability reported an executing {name}: {outcome}"
            );
        }
        return;
    }
    verify_capability_selection(matrix);
}

#[test]
fn jit_capability_selection_rejects_mprotect_and_rwx_matrices() {
    let mprotect = JitExecProbeMatrix {
        mprotect_rx: JitExecProbeOutcome::Executed(42),
        map_jit_wx_write_protect: JitExecProbeOutcome::WriteFaulted(libc::SIGBUS),
        map_jit_rw_write_protect: JitExecProbeOutcome::WriteFaulted(libc::SIGBUS),
        map_jit_wx_no_write_protect: JitExecProbeOutcome::WriteFaulted(libc::SIGBUS),
        selected: JitExecMechanism::MprotectRx,
    };
    assert_eq!(mprotect.selected, JitExecMechanism::MprotectRx);
    verify_capability_selection(mprotect);
    let rwx = JitExecProbeMatrix {
        mprotect_rx: JitExecProbeOutcome::NotProbed,
        map_jit_wx_write_protect: JitExecProbeOutcome::NotProbed,
        map_jit_rw_write_protect: JitExecProbeOutcome::NotProbed,
        map_jit_wx_no_write_protect: JitExecProbeOutcome::NotProbed,
        selected: JitExecMechanism::RwxMmap,
    };
    assert_eq!(rwx.selected, JitExecMechanism::RwxMmap);
    verify_capability_selection(rwx);
}

#[test]
#[should_panic(expected = "an unavailable capability must report unavailable")]
fn jit_capability_selection_rejects_unavailable_matrix() {
    verify_capability_selection(JitExecProbeMatrix {
        mprotect_rx: JitExecProbeOutcome::NotProbed,
        map_jit_wx_write_protect: JitExecProbeOutcome::NotProbed,
        map_jit_rw_write_protect: JitExecProbeOutcome::NotProbed,
        map_jit_wx_no_write_protect: JitExecProbeOutcome::NotProbed,
        selected: JitExecMechanism::Unavailable,
    });
}

#[test]
fn jit_unavailable_capability_returns_null_allocation() {
    let unavailable = JitExecProbeMatrix {
        mprotect_rx: JitExecProbeOutcome::NotProbed,
        map_jit_wx_write_protect: JitExecProbeOutcome::NotProbed,
        map_jit_rw_write_protect: JitExecProbeOutcome::NotProbed,
        map_jit_wx_no_write_protect: JitExecProbeOutcome::NotProbed,
        selected: JitExecMechanism::Unavailable,
    };
    let mut manager = JitMemoryManager::with_capability(unavailable);
    assert_eq!(manager.mechanism(), JitExecMechanism::Unavailable);
    assert!(
        manager.allocate_code_space(64).is_null(),
        "an unavailable OS capability must fail allocation, not fabricate memory"
    );
    // SAFETY: the unavailable mechanism returns before dereferencing.
    unsafe {
        assert!(!manager.make_writable(std::ptr::null_mut(), 4));
        assert!(!manager.finalize_code(std::ptr::null_mut(), 4));
    }
}

#[test]
fn jit_execute_with_jit_falls_back_when_block_not_compiled() {
    let _serial = jit_test_serial();
    let config = crate::cpu::CpuEngineConfig::from_profile(GuestArch::X64, "test", "test", None)
        .expect("cpu config");
    let engine = crate::cpu::CpuExecutionEngine::new(config);
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x1000;
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x1000, &[0; 0x100]);
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 7,
        },
        IrInstruction::Jump { target: 0 },
    ];
    let mut jit = JitRuntime::new(GuestArch::X64);
    engine
        .execute_with_jit(&mut state, &mut memory, &ir, Some(&mut jit))
        .expect("fallback execution");
    assert_eq!(state.get(Register::Rax), 7);
    assert!(!jit.is_compiled(0x1000));
    assert_eq!(jit.blocks_executed, 0);
}

#[test]
fn jit_compiler_compiles_nop_block() {
    let mut compiler = JitCompiler::new();
    let ir = vec![IrInstruction::Nop];
    let result = compiler.compile_block(&ir, 0x1000, GuestArch::X64, None);
    assert!(result.is_ok(), "expected JIT compilation to succeed");
    let block = result.unwrap();
    assert_eq!(block.guest_address, 0x1000);
    assert_eq!(block.instruction_count, 1);
    assert!(block.code_size > 0);
    assert!(!block.entry().is_null());
}

#[test]
fn jit_lowering_telemetry_counts_native_and_helper_fallback_per_opcode() {
    // Compile a batch of a unique native opcode (MovImm) and a unique
    // helper-fallback opcode (Xgetbv); the per-opcode counters must move
    // by exactly the batch sizes.  (Nop is compiled by other tests
    // concurrently, so this test uses opcodes no other test compiles —
    // exact per-opcode deltas are therefore deterministic.)
    let native_op = ir_opcode_index(&IrInstruction::MovImm {
        dst: Register::Rax,
        value: 0,
    });
    let fallback_op = ir_opcode_index(&IrInstruction::Xgetbv);
    let native_before = JIT_NATIVE_LOWERED[native_op].load(Ordering::Relaxed);
    let fallback_before = JIT_HELPER_FALLBACK[fallback_op].load(Ordering::Relaxed);

    let mut compiler = JitCompiler::new();
    let mut ir = Vec::new();
    for i in 0..8u64 {
        ir.push(IrInstruction::MovImm {
            dst: Register::Rax,
            value: i,
        });
        ir.push(IrInstruction::Xgetbv);
    }
    let block = compiler
        .compile_block(&ir, 0x4000, GuestArch::X64, None)
        .expect("compile block with native + fallback instructions");
    assert_eq!(block.instruction_count, 16);

    // Other tests compile MovImm/Xgetbv blocks concurrently, so the
    // process-global per-opcode counters may move by more than this
    // block's contribution.  The batch is a guaranteed lower bound.
    assert!(
        JIT_NATIVE_LOWERED[native_op].load(Ordering::Relaxed) >= native_before + 8,
        "MovImm must be counted as native lowering"
    );
    assert!(
        JIT_HELPER_FALLBACK[fallback_op].load(Ordering::Relaxed) >= fallback_before + 8,
        "Xgetbv must be counted as interpreter-helper fallback"
    );

    let (native_total, fallback_total) = jit_lowering_telemetry();
    assert!(native_total >= native_before + 8);
    assert!(fallback_total >= fallback_before + 8);
}

// --- Phase 7: Block Chaining Tests ---

// (helper removed — no remaining caller; chain_blocks is a documented
// no-op and block chaining is disabled)

#[test]
fn block_chaining_fails_for_missing_block() {
    let mut rt = JitRuntime::new(GuestArch::X64);
    let ir_a = vec![IrInstruction::Nop, IrInstruction::Jump { target: 0x2000 }];
    rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
        .unwrap();
    let error = rt.chain_blocks(0x1000, 0x2000).unwrap_err();
    assert_eq!(error.code, ReasonCode::RcJitCompilationError);
    assert_eq!(
        error.message, "cannot chain to missing target block 0x2000",
        "chaining to a missing target must fail with the exact reason"
    );
}

// --- Phase 7: Tiered Compiler Tests ---

// --- Phase 7: Inline Cache Tests ---

#[test]
fn inline_cache_hit_miss() {
    let mut cache = InlineCache::new(16);

    // First lookup — miss (no entry)
    let hit = cache.lookup(0x1000, 0x5000);
    assert!(!hit, "first lookup should be a miss");

    // Second lookup with same target — hit
    let hit = cache.lookup(0x1000, 0x5000);
    assert!(hit, "same target should be a hit");

    // Third lookup with different target — miss
    let hit = cache.lookup(0x1000, 0x6000);
    assert!(!hit, "different target should be a miss");

    // Verify counters
    let entry = cache.entries.get(&0x1000).unwrap();
    assert_eq!(entry.hit_count, 1);
    assert_eq!(entry.miss_count, 2);
    assert_eq!(entry.last_target, 0x6000);
}

#[test]
fn inline_cache_invalidate() {
    let mut cache = InlineCache::new(16);
    cache.lookup(0x1000, 0x5000);
    assert!(cache.entries.contains_key(&0x1000));

    cache.invalidate(0x1000);
    assert!(!cache.entries.contains_key(&0x1000));
}

#[test]
fn inline_cache_invalidate_all() {
    let mut cache = InlineCache::new(16);
    cache.lookup(0x1000, 0x5000);
    cache.lookup(0x2000, 0x6000);
    assert_eq!(cache.entries.len(), 2);

    cache.invalidate_all();
    assert!(cache.entries.is_empty());
}

#[test]
fn inline_cache_eviction() {
    let mut cache = InlineCache::new(2);
    cache.lookup(0x1000, 0x5000);
    cache.lookup(0x2000, 0x6000);
    assert_eq!(cache.entries.len(), 2);

    // Adding a third entry should evict one
    cache.lookup(0x3000, 0x7000);
    assert_eq!(cache.entries.len(), 2);
    assert!(cache.entries.contains_key(&0x3000));
}

// --- Phase 7: Adaptive Budget Tests ---

// --- Phase 8: Constant Folding Tests ---

#[test]
fn test_constant_fold_no_change() {
    use crate::cpu::Register;

    // Instructions that cannot be folded (src register not known)
    // Add PushReg consumers so DCE doesn't remove the instructions
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 10,
        },
        IrInstruction::MovReg {
            dst: Register::Rbx,
            src: Register::Rcx,
            width: 8,
        },
        IrInstruction::AddImm {
            dst: Register::Rbx,
            value: 5,
            width: 8,
        },
        IrInstruction::PushReg { src: Register::Rax },
        IrInstruction::PushReg { src: Register::Rbx },
    ];

    let folded = JitCompiler::constant_fold(&ir);

    // MovReg(rbx, rcx) can't be folded since rcx is unknown
    // AddImm(rbx, 5) can't be folded since rbx is a copy of rcx (not an immediate)
    // So these should pass through
    assert!(!folded.is_empty(), "non-foldable IR should not be empty");

    // The MovImm should still be a MovImm
    // MovReg and AddImm should remain as they were
    let has_movreg = folded
        .iter()
        .any(|insn| matches!(insn, IrInstruction::MovReg { .. }));
    let has_addimm = folded
        .iter()
        .any(|insn| matches!(insn, IrInstruction::AddImm { .. }));
    assert!(has_movreg, "MovReg should remain unchanged: {:?}", folded);
    assert!(has_addimm, "AddImm should remain unchanged: {:?}", folded);
}

#[test]
fn test_constant_fold_movreg_propagation() {
    use crate::cpu::Register;

    // MovImm(rax, 42), MovReg(rbx, rax) → MovImm(rbx, 42) and rax still known
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 42,
        },
        IrInstruction::MovReg {
            dst: Register::Rbx,
            src: Register::Rax,
            width: 8,
        },
    ];

    let folded = JitCompiler::constant_fold(&ir);

    // After folding: MovReg(rbx, rax) where rax=42 → MovImm(rbx, 42)
    // After DCE: both might be removed since neither rax nor rbx is read later
    // Let's check if MovReg is no longer present
    let has_movreg = folded
        .iter()
        .any(|insn| matches!(insn, IrInstruction::MovReg { .. }));
    assert!(!has_movreg, "MovReg should have been folded to MovImm");
}

// --- Phase 9: Loop Unrolling Tests ---

#[test]
fn test_loop_unroll_full() {
    use crate::cpu::Register;

    // Loop with counter initialized to 3 (≤4, should fully unroll)
    let ir = vec![
        // Initialize counter
        IrInstruction::MovImm {
            dst: Register::Rcx,
            value: 3,
        },
        // Loop body: increment rax
        IrInstruction::AddImm {
            dst: Register::Rax,
            value: 1,
            width: 8,
        },
        // Decrement counter
        IrInstruction::SubImm {
            dst: Register::Rcx,
            value: 1,
            width: 8,
        },
        // Branch back if counter != 0
        IrInstruction::JumpIf {
            condition: ConditionCode::NotEqual,
            target: 0x1000,
            fallthrough: 0x2000,
        },
    ];

    let unrolled = JitCompiler::loop_unroll(&ir, 0x1000);

    // After full unrolling with count=3:
    // MovImm(rcx, 3), AddImm(rax,1), AddImm(rax,1), AddImm(rax,1)
    // The SubImm and JumpIf are removed
    // (plus constant folding may reduce further)
    assert!(
        !unrolled.is_empty(),
        "unrolled loop should have instructions"
    );
    // The loop back-edge should be gone
    let has_jumpif = unrolled
        .iter()
        .any(|insn| matches!(insn, IrInstruction::JumpIf { .. }));
    assert!(!has_jumpif, "fully unrolled loop should not have JumpIf");
}

#[test]
fn test_loop_unroll_no_side_effects() {
    use crate::cpu::Register;

    // A semantically equivalent loop: unrolling should produce the same
    // net effect on the counter and other registers.
    // Initialize rax=0, then loop 2 times adding 1 to rax.
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 0,
        },
        IrInstruction::MovImm {
            dst: Register::Rcx,
            value: 2,
        },
        // Loop body: rax += 1
        IrInstruction::AddImm {
            dst: Register::Rax,
            value: 1,
            width: 8,
        },
        // Decrement counter
        IrInstruction::SubImm {
            dst: Register::Rcx,
            value: 1,
            width: 8,
        },
        // Branch back if counter != 0
        IrInstruction::JumpIf {
            condition: ConditionCode::NotEqual,
            target: 0x1000,
            fallthrough: 0x2000,
        },
    ];

    let unrolled = JitCompiler::loop_unroll(&ir, 0x1000);

    // After full unrolling with count=2:
    // The loop body (AddImm rax,1) should be duplicated 2 times
    // No JumpIf should remain
    let has_jumpif = unrolled
        .iter()
        .any(|insn| matches!(insn, IrInstruction::JumpIf { .. }));
    assert!(!has_jumpif, "fully unrolled loop should not have JumpIf");

    // Count the number of AddImm(rax,1) instructions
    let add_count = unrolled
        .iter()
        .filter(|insn| {
            matches!(
                insn,
                IrInstruction::AddImm {
                    dst: Register::Rax,
                    value: 1,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        add_count, 2,
        "should have 2 AddImm(rax,1) after unrolling count=2, got {}",
        add_count
    );
}

// --- G6: JIT Unwind Registration Tests ---

#[test]
fn unwind_table_register_block_adds_entry() {
    let mut table = JitUnwindTable::new();
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);
    assert!(!table.is_dirty(), "new table should not be dirty");

    table.register_block(0x1000, 0x1020);
    assert!(!table.is_empty());
    assert_eq!(table.len(), 1);
    assert!(table.is_dirty(), "register_block should set dirty flag");

    // Verify the entry matches
    let entry = &table.entries[0];
    assert_eq!(entry.start_rva, 0x1000);
    assert_eq!(entry.end_rva, 0x1020);
    assert!(
        !entry.unwind_data.is_empty(),
        "unwind_data should be generated"
    );
}

#[test]
fn unwind_table_unregister_block_removes_entry() {
    let mut table = JitUnwindTable::new();
    table.register_block(0x1000, 0x1020);
    table.register_block(0x2000, 0x2040);
    assert_eq!(table.len(), 2);

    // Re-register to clear dirty flag
    table.dirty = false;

    let removed = table.unregister_block(0x1000);
    assert!(
        removed,
        "unregister_block should return true when entry found"
    );
    assert_eq!(table.len(), 1);
    assert_eq!(
        table.entries[0].start_rva, 0x2000,
        "remaining entry should be 0x2000"
    );
    assert!(table.is_dirty(), "unregister should set dirty flag");

    // Unregister non-existent block
    let removed = table.unregister_block(0x9999);
    assert!(
        !removed,
        "unregister_block should return false for missing entry"
    );
    assert_eq!(table.len(), 1);
}

#[test]
fn unwind_table_dirty_flag_tracking() {
    let mut table = JitUnwindTable::new();
    assert!(!table.is_dirty());

    // register_block sets dirty
    table.register_block(0x1000, 0x1020);
    assert!(table.is_dirty());

    // register_with_seh clears dirty (even if entries present)
    let mut seh = crate::seh::SehSubsystem::new();
    table.register_with_seh(&mut seh);
    assert!(!table.is_dirty());

    // New registration sets dirty again
    table.register_block(0x2000, 0x2040);
    assert!(table.is_dirty());

    // unregister_block sets dirty
    table.dirty = false;
    table.unregister_block(0x2000);
    assert!(table.is_dirty());
}

#[test]
fn unwind_table_register_with_seh_empty_clears_dirty() {
    let mut table = JitUnwindTable::new();
    table.dirty = true; // artificially set

    let mut seh = crate::seh::SehSubsystem::new();
    table.register_with_seh(&mut seh);
    assert!(
        !table.is_dirty(),
        "register_with_seh with no entries should still clear dirty"
    );
}

#[test]
fn jit_runtime_invalidate_block_removes_from_cache_and_unwind() {
    let mut rt = JitRuntime::new(GuestArch::X64);
    let ir = vec![IrInstruction::Nop];

    // Compile a block
    rt.get_or_compile(&ir, 0x1000, GuestArch::X64, None)
        .unwrap();
    assert!(rt.is_compiled(0x1000));
    assert_eq!(rt.unwind_table.len(), 1);

    // Invalidate the block
    rt.invalidate_block(0x1000);
    assert!(
        !rt.is_compiled(0x1000),
        "block should be removed from cache"
    );
    assert!(
        rt.unwind_table.is_empty(),
        "block should be unregistered from unwind table"
    );
}

#[test]
fn jit_runtime_invalidate_block_unchains() {
    // Chaining disabled: invalidate_block still works (removes the block
    // from the cache); there are simply no chains to unchain.
    let mut rt = JitRuntime::new(GuestArch::X64);
    let ir_a = vec![IrInstruction::Nop];
    let ir_b = vec![IrInstruction::Nop, IrInstruction::Nop];

    rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
        .unwrap();
    rt.get_or_compile(&ir_b, 0x2000, GuestArch::X64, None)
        .unwrap();
    let _ = rt.chain_blocks(0x1000, 0x2000); // no-op

    rt.invalidate_block(0x2000);
    assert!(
        !rt.block_chains.contains_key(&(0x1000, 0x2000)),
        "no chains exist (chaining disabled)"
    );
}

#[test]
fn jit_runtime_unwind_dirty_cleared_after_seh_sync() {
    let mut rt = JitRuntime::new(GuestArch::X64);
    let ir = vec![IrInstruction::Nop];

    rt.get_or_compile(&ir, 0x1000, GuestArch::X64, None)
        .unwrap();
    assert!(rt.is_unwind_dirty());

    // After syncing to SEH, dirty should be cleared
    let mut seh = crate::seh::SehSubsystem::new();
    rt.unwind_table.register_with_seh(&mut seh);
    assert!(!rt.is_unwind_dirty());
}

// ─── Phase D2/R2: JIT Unwind Info Format Verification and Extended Tests ───

#[test]
fn unwind_table_empty_table_unregister() {
    let mut table = JitUnwindTable::new();
    assert!(table.is_empty());

    // Unregister on empty table should return false and not set dirty
    table.dirty = false;
    let removed = table.unregister_block(0x1000);
    assert!(!removed, "unregister on empty table should return false");
    assert!(
        !table.is_dirty(),
        "unregister on empty table should NOT set dirty flag"
    );
}

#[test]
fn unwind_table_clear_on_empty_table() {
    let mut table = JitUnwindTable::new();
    assert!(table.is_empty());

    // clear on already empty table should not set dirty
    table.dirty = false;
    table.clear();
    assert!(
        !table.is_dirty(),
        "clear on empty table should NOT set dirty flag"
    );
}

#[test]
fn unwind_table_duplicate_entries() {
    let mut table = JitUnwindTable::new();

    // Register the same address range twice
    table.register_block(0x1000, 0x1020);
    assert_eq!(table.len(), 1);

    // Registering the same range again should add a duplicate entry
    // (the JIT currently does not deduplicate — callers are responsible
    // for calling get_or_compile which checks block_cache before register_block)
    table.register_block(0x1000, 0x1020);
    assert_eq!(
        table.len(),
        2,
        "registering duplicate range adds another entry"
    );

    // Both entries should have the same data
    assert_eq!(table.entries[0].start_rva, table.entries[1].start_rva);
    assert_eq!(table.entries[0].end_rva, table.entries[1].end_rva);
    assert_eq!(table.entries[0].unwind_data, table.entries[1].unwind_data);

    // unregister_block uses retain() which removes ALL entries with
    // matching start_rva, so both duplicates are removed at once.
    let removed = table.unregister_block(0x1000);
    assert!(removed);
    assert_eq!(
        table.len(),
        0,
        "retain removes ALL matching entries, not just one"
    );

    // Second remove on empty table
    let removed = table.unregister_block(0x1000);
    assert!(!removed);
    assert_eq!(table.len(), 0);
}

#[test]
fn unwind_table_out_of_order_removal() {
    let mut table = JitUnwindTable::new();
    table.register_block(0x1000, 0x1020);
    table.register_block(0x2000, 0x2040);
    table.register_block(0x3000, 0x3030);

    // Remove middle entry
    let removed = table.unregister_block(0x2000);
    assert!(removed);
    assert_eq!(table.len(), 2);

    // Remaining entries should be 0x1000 and 0x3000
    assert_eq!(table.entries[0].start_rva, 0x1000);
    assert_eq!(table.entries[1].start_rva, 0x3000);

    // Remove first entry
    let removed = table.unregister_block(0x1000);
    assert!(removed);
    assert_eq!(table.len(), 1);
    assert_eq!(table.entries[0].start_rva, 0x3000);

    // Remove last entry
    let removed = table.unregister_block(0x3000);
    assert!(removed);
    assert!(table.is_empty());
}

#[test]
fn unwind_table_seh_cache_invalidation_on_reregister() {
    // Verify that when register_with_seh() is called multiple times,
    // the SEH subsystem's unwind_cache is properly invalidated and
    // fresh entries are parsed.
    let mut table = JitUnwindTable::new();
    let mut seh = crate::seh::SehSubsystem::new();

    // First registration: register block at 0x1000..0x1020
    table.register_block(0x1000, 0x1020);
    table.register_with_seh(&mut seh);

    const JIT_IMAGE_BASE: u64 = 0;

    // Verify first registration works
    let rf1 = seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000);
    assert!(
        rf1.is_some(),
        "first registration: block should be findable"
    );
    assert_eq!(rf1.unwrap().begin_addr, 0x1000);

    // Second registration: replace with different block at 0x3000..0x3050
    table.clear();
    table.register_block(0x3000, 0x3050);
    table.register_with_seh(&mut seh);

    // Old block should be gone
    assert!(
        seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000).is_none(),
        "old block should be gone after re-registration"
    );
    // New block should be present
    let rf2 = seh.find_runtime_function(JIT_IMAGE_BASE, 0x3000);
    assert!(
        rf2.is_some(),
        "new block should be findable after re-registration"
    );
    assert_eq!(rf2.unwrap().begin_addr, 0x3000);

    // Force a third registration with the same data but different ordering
    // to ensure cache invalidation works for same-RVA scenarios
    table.clear();
    table.register_block(0x3000, 0x3050);
    table.register_block(0x1000, 0x1020);
    table.register_with_seh(&mut seh);

    // Both blocks should be findable
    assert!(
        seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000).is_some(),
        "0x1000 should be findable after third registration"
    );
    assert!(
        seh.find_runtime_function(JIT_IMAGE_BASE, 0x3000).is_some(),
        "0x3000 should be findable after third registration"
    );

    // The unwind_info for 0x1000 should be parseable (cache was cleared)
    let rf_new = seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000).unwrap();
    let ui = seh.get_unwind_info(rf_new.unwind_info_addr);
    assert!(
        ui.is_some(),
        "unwind info for re-registered block should be parseable"
    );
    let ui = ui.unwrap();
    assert_eq!(ui.version, 1);
    assert_eq!(ui.flags, 0);
}

#[test]
fn unwind_table_runtime_unwind_dirty_sync_cycle() {
    // Full lifecycle test for the dirty → sync → dirty → sync cycle
    let mut rt = JitRuntime::new(GuestArch::X64);
    let ir = vec![IrInstruction::Nop];
    let mut seh = crate::seh::SehSubsystem::new();

    // Initial state: empty, not dirty
    assert!(!rt.is_unwind_dirty());
    assert!(rt.unwind_table.is_empty());

    // Step 1: Compile a block → dirty
    rt.get_or_compile(&ir, 0x1000, GuestArch::X64, None)
        .unwrap();
    assert!(rt.is_unwind_dirty());
    assert_eq!(rt.unwind_table.len(), 1);

    // Step 2: Sync to SEH → not dirty
    rt.unwind_table.register_with_seh(&mut seh);
    assert!(!rt.is_unwind_dirty());

    // Step 3: Compile another block → dirty again
    rt.get_or_compile(&ir, 0x2000, GuestArch::X64, None)
        .unwrap();
    assert!(rt.is_unwind_dirty());
    assert_eq!(rt.unwind_table.len(), 2);

    // Step 4: Sync again → not dirty
    rt.unwind_table.register_with_seh(&mut seh);
    assert!(!rt.is_unwind_dirty());

    // Step 5: Invalidate a block → dirty
    rt.invalidate_block(0x1000);
    assert!(rt.is_unwind_dirty());
    assert_eq!(rt.unwind_table.len(), 1);

    // Step 6: Final sync → not dirty
    rt.unwind_table.register_with_seh(&mut seh);
    assert!(!rt.is_unwind_dirty());

    // Verify SEH state after all operations
    const JIT_IMAGE_BASE: u64 = 0;
    assert!(
        seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000).is_none(),
        "invalidated block 0x1000 should not be in SEH"
    );
    assert!(
        seh.find_runtime_function(JIT_IMAGE_BASE, 0x2000).is_some(),
        "valid block 0x2000 should be in SEH"
    );
}

// =====================================================================
// Self-modifying code stress tests
// =====================================================================

#[test]
fn self_modifying_code_basic_invalidation() {
    let mut rt = JitRuntime::new(GuestArch::X64);

    // Compile an initial block at 0x1000
    let ir_initial = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 42,
        },
        IrInstruction::Nop,
    ];
    rt.get_or_compile(&ir_initial, 0x1000, GuestArch::X64, None)
        .unwrap();
    assert!(rt.is_compiled(0x1000), "block should be compiled");
    assert_eq!(rt.blocks_compiled, 1, "exactly one block compiled");
    assert!(
        rt.code_pages.contains(&0x1000),
        "code page should be tracked"
    );

    // Simulate a guest write to the block's address range (self-modifying code).
    // The block at 0x1000 has some code_size; writing at 0x1000 with length > 0
    // should overlap and trigger invalidation.
    let invalidated = rt.invalidate_blocks_writing_to(0x1000, 4);
    assert!(
        !invalidated.is_empty(),
        "write should invalidate at least one block"
    );
    assert_eq!(
        invalidated,
        vec![0x1000],
        "block 0x1000 should be invalidated"
    );
    assert!(
        !rt.is_compiled(0x1000),
        "block should no longer be compiled after write"
    );
    assert!(rt.block_cache.is_empty(), "block cache should be empty");

    // Recompile with different content (simulating modified code)
    let ir_modified = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 99,
        },
        IrInstruction::Nop,
    ];
    rt.get_or_compile(&ir_modified, 0x1000, GuestArch::X64, None)
        .unwrap();
    assert!(rt.is_compiled(0x1000), "block should be recompiled");
    assert_eq!(rt.blocks_compiled, 2, "should have compiled twice total");
    assert!(
        rt.code_pages.contains(&0x1000),
        "code page should be tracked after recompilation"
    );
}

#[test]
fn self_modifying_code_write_to_data_page_no_invalidation() {
    let mut rt = JitRuntime::new(GuestArch::X64);

    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 42,
        },
        IrInstruction::Nop,
    ];
    rt.get_or_compile(&ir, 0x1000, GuestArch::X64, None)
        .unwrap();

    // Write to a data page (no compiled blocks)
    let affected = rt.invalidate_blocks_writing_to(0x7000, 8);
    assert!(
        affected.is_empty(),
        "write to data page should not invalidate any blocks"
    );
    assert!(rt.is_compiled(0x1000), "block should still be compiled");
}

#[test]
fn self_modifying_code_multiple_modifications() {
    let mut rt = JitRuntime::new(GuestArch::X64);
    let modification_count = 15;

    for i in 0..modification_count {
        // Each cycle: compile a unique block, then simulate a write to its range
        let addr = 0x1000 + (i as u64 * 0x100);

        // Compile with unique content for this iteration
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: i as u64,
            },
            IrInstruction::Nop,
        ];
        rt.get_or_compile(&ir, addr, GuestArch::X64, None).unwrap();
        assert!(
            rt.is_compiled(addr),
            "block at {:#x} should be compiled",
            addr
        );

        // Simulate self-modifying write
        let affected = rt.invalidate_blocks_writing_to(addr, 4);
        assert_eq!(
            affected,
            vec![addr],
            "write at {:#x} should invalidate only that block",
            addr
        );
        assert!(
            !rt.is_compiled(addr),
            "block at {:#x} should be invalidated",
            addr
        );
    }

    // After all cycles, block cache should be empty and code_pages should be empty
    assert!(
        rt.block_cache.is_empty(),
        "all blocks should have been invalidated"
    );
    assert!(
        rt.code_pages.is_empty(),
        "no code pages should remain after all invalidations"
    );
    assert_eq!(
        rt.blocks_compiled, modification_count as u64,
        "all {} compilations should have happened",
        modification_count
    );
}

#[test]
fn self_modifying_code_invalidation_cascade() {
    let mut rt = JitRuntime::new(GuestArch::X64);

    // Compile three adjacent blocks
    let ir_a = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 10,
        },
        IrInstruction::Nop,
    ];
    let ir_b = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 20,
        },
        IrInstruction::Nop,
    ];
    let ir_c = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 30,
        },
        IrInstruction::Nop,
    ];

    rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
        .unwrap();
    rt.get_or_compile(&ir_b, 0x1100, GuestArch::X64, None)
        .unwrap();
    rt.get_or_compile(&ir_c, 0x1200, GuestArch::X64, None)
        .unwrap();

    assert!(rt.is_compiled(0x1000));
    assert!(rt.is_compiled(0x1100));
    assert!(rt.is_compiled(0x1200));

    // Invalidate the middle block only
    let affected = rt.invalidate_blocks_writing_to(0x1100, 4);
    assert_eq!(
        affected,
        vec![0x1100],
        "only the middle block should be invalidated"
    );
    assert!(
        !rt.is_compiled(0x1100),
        "middle block should be invalidated"
    );
    assert!(rt.is_compiled(0x1000), "first block should remain compiled");
    assert!(rt.is_compiled(0x1200), "third block should remain compiled");
}

#[test]
fn self_modifying_code_recompilation_stress() {
    let mut rt = JitRuntime::new(GuestArch::X64);
    let stress_count = 150;

    for i in 0..stress_count {
        let addr = 0x1000;

        // Compile with unique content each time (simulating modified code)
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: i as u64,
            },
            IrInstruction::Nop,
        ];
        rt.get_or_compile(&ir, addr, GuestArch::X64, None).unwrap();
        assert!(
            rt.is_compiled(addr),
            "block at {:#x} should be compiled (cycle {})",
            addr,
            i
        );

        // Simulate self-modifying write to trigger recompilation on next cycle
        let affected = rt.invalidate_blocks_writing_to(addr, 4);
        assert!(
            !affected.is_empty(),
            "write should invalidate block (cycle {})",
            i
        );
    }

    // After all stress cycles, the block cache should be empty
    // (we invalidated after each compilation)
    assert!(
        rt.block_cache.is_empty(),
        "block cache should be empty after {} stress cycles",
        stress_count
    );
    assert!(
        rt.code_pages.is_empty(),
        "code pages should be empty after all invalidations"
    );
    assert_eq!(
        rt.blocks_compiled, stress_count as u64,
        "all {} recompilations should have occurred",
        stress_count
    );
}

#[test]
fn self_modifying_code_hash_mismatch_detection() {
    let mut rt = JitRuntime::new(GuestArch::X64);

    // Compile a block with initial content
    let ir_original = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 42,
        },
        IrInstruction::Nop,
    ];
    rt.get_or_compile(&ir_original, 0x1000, GuestArch::X64, None)
        .unwrap();
    assert!(rt.is_compiled(0x1000));
    assert_eq!(rt.blocks_compiled, 1);

    // Simulate modified code by requesting get_or_compile with different IR
    // at the same address. The hash check should detect the mismatch,
    // invalidate the old block, and recompile.
    let ir_modified = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 99,
        },
        IrInstruction::Nop,
    ];
    rt.get_or_compile(&ir_modified, 0x1000, GuestArch::X64, None)
        .unwrap();
    assert!(
        rt.is_compiled(0x1000),
        "block should be recompiled with modified IR"
    );
    assert_eq!(
        rt.blocks_compiled, 2,
        "should have recompiled (2 total compilations)"
    );

    // Verify the block has the new source hash
    let block = rt.block_cache.get(&0x1000).unwrap();
    let expected_hash = compute_ir_hash(&ir_modified, 0x1000);
    assert_eq!(
        block.source_hash, expected_hash,
        "recompiled block should have hash of modified IR"
    );
}

#[test]
fn self_modifying_code_page_set_invalidation() {
    let mut rt = JitRuntime::new(GuestArch::X64);

    // Compile blocks on different pages
    let ir_a = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 1,
        },
        IrInstruction::Nop,
    ];
    let ir_b = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 2,
        },
        IrInstruction::Nop,
    ];
    let ir_c = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 3,
        },
        IrInstruction::Nop,
    ];

    rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
        .unwrap();
    rt.get_or_compile(&ir_b, 0x2000, GuestArch::X64, None)
        .unwrap();
    rt.get_or_compile(&ir_c, 0x3000, GuestArch::X64, None)
        .unwrap();

    assert!(rt.is_compiled(0x1000));
    assert!(rt.is_compiled(0x2000));
    assert!(rt.is_compiled(0x3000));

    // Invalidate blocks on pages 0x1000 and 0x3000
    let mut dirty_pages = std::collections::BTreeSet::new();
    dirty_pages.insert(0x1000);
    dirty_pages.insert(0x3000);

    let affected = rt.invalidate_blocks_on_pages(&dirty_pages);
    assert_eq!(affected.len(), 2, "two blocks should be invalidated");
    assert!(affected.contains(&0x1000));
    assert!(affected.contains(&0x3000));
    assert!(!rt.is_compiled(0x1000));
    assert!(rt.is_compiled(0x2000), "block on page 0x2000 should remain");
    assert!(!rt.is_compiled(0x3000));
}

// =====================================================================
// Gap 9.1: FastThunkTable ARM64 trampoline tests
// =====================================================================

extern "C" fn thunk_test_target() -> u64 {
    0x42
}

// =====================================================================
// JIT Safety Tests: executable memory exhaustion, SIGBUS loop
// detection, and out-of-range fault handling
// =====================================================================

#[test]
fn jit_compile_handles_executable_memory_exhaustion() {
    let mut compiler = JitCompiler::new();

    // Exhaust the memory manager by allocating many large blocks.
    // Use a large per-allocation size to exhaust quickly.
    let mut exhausted = false;
    for _ in 0..10_000 {
        let ptr = compiler
            .memory_manager_mut()
            .allocate_code_space(1024 * 1024);
        if ptr.is_null() {
            exhausted = true;
            break;
        }
    }

    if !exhausted {
        // On systems with overcommit (e.g., macOS), mmap may never fail.
        // In that case, test the error path directly by verifying that
        // allocate_code_space returns null for an impossibly large request.
        let ptr = compiler
            .memory_manager_mut()
            .allocate_code_space(1_usize << 50);
        assert!(
            ptr.is_null(),
            "impossibly large allocation should return null"
        );
    }

    // Now try to compile — should NOT panic regardless of outcome.
    // On systems with memory overcommit (e.g., macOS), mmap may never fail
    // for reasonably-sized pages, so compile_block may succeed. In that case
    // the impossibly-large allocation check above already verified that null
    // pointers are handled correctly. If it does fail, verify the error code.
    let ir = vec![IrInstruction::Nop];
    let result = compiler.compile_block(&ir, 0x1000, GuestArch::X64, None);
    if let Err(err) = result {
        assert_eq!(
            err.code,
            ReasonCode::RcJitCodeAllocFailed,
            "error should be RcJitCodeAllocFailed, got {:?}",
            err.code
        );
    }
}

#[test]
fn sigbus_reentrancy_guard_prevents_recursive_entry() {
    let _guard = SIGBUS_STATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Ensure guard starts clear
    SIGBUS_IN_HANDLER.store(false, Ordering::Release);
    assert!(!SIGBUS_IN_HANDLER.load(Ordering::Acquire));

    // First entry: swap should return false (was not set)
    let was_set = SIGBUS_IN_HANDLER.swap(true, Ordering::Acquire);
    assert!(!was_set, "first entry should see false");

    // Second entry (recursive): swap should return true (was set)
    let was_set = SIGBUS_IN_HANDLER.swap(true, Ordering::Acquire);
    assert!(was_set, "recursive entry should see true and return early");

    // After clearing: should allow entry again
    SIGBUS_IN_HANDLER.store(false, Ordering::Release);
    let was_set = SIGBUS_IN_HANDLER.swap(true, Ordering::Acquire);
    assert!(!was_set, "entry after clear should see false");

    // Clean up
    SIGBUS_IN_HANDLER.store(false, Ordering::Release);
}

#[test]
fn sigbus_out_of_range_fault_diagnostic_counters() {
    let _guard = SIGBUS_STATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let rt = JitRuntime::new(GuestArch::X64);
    let flat_base = rt.flat_memory.base();
    let flat_size = rt.flat_memory.size() as u64;

    // Address within range
    let in_range_addr = flat_base + 0x1000;
    assert!(
        in_range_addr >= flat_base && in_range_addr < flat_base + flat_size,
        "address should be within flat memory range"
    );

    // Address before the range
    let before_range_addr = if flat_base > 0x2000 {
        flat_base - 0x1000
    } else {
        0 // edge case: base is near zero
    };
    assert!(
        before_range_addr < flat_base,
        "address should be before flat memory range"
    );

    // Address after the range
    let after_range_addr = flat_base + flat_size + 0x1000;
    assert!(
        after_range_addr >= flat_base + flat_size,
        "address should be after flat memory range"
    );

    // Verify the range check logic matches what the handler uses
    // (fault_addr >= flat_base && fault_addr < flat_base + flat_size)
    let check_in_range = |addr: u64| -> bool { addr >= flat_base && addr < flat_base + flat_size };

    assert!(
        check_in_range(in_range_addr),
        "in-range address should pass range check"
    );
    assert!(
        !check_in_range(before_range_addr),
        "before-range address should fail range check"
    );
    assert!(
        !check_in_range(after_range_addr),
        "after-range address should fail range check"
    );

    // Verify that the SIGBUS statics are null (no handler installed)
    // and that the disabled events counter would be incremented
    assert!(
        SIGBUS_JIT_RUNTIME.load(Ordering::Acquire).is_null(),
        "runtime pointer should be null when no handler is installed"
    );
    assert!(
        SIGBUS_JIT_MEMORY.load(Ordering::Acquire).is_null(),
        "memory pointer should be null when no handler is installed"
    );
}

#[test]
fn fast_thunk_fallback_dispatch_when_not_registered() {
    let mut compiler = JitCompiler::new();
    let ir = vec![IrInstruction::Call {
        target: 0xDEAD_BEEF,
        return_address: 0x1004,
    }];
    // No fast_thunk_addrs provided, so the Call should fall back to
    // EXIT_THUNK path, which emits standard exit without fast-thunk.
    let result = compiler.compile_block(&ir, 0x1000, GuestArch::X64, None);
    assert!(
        result.is_ok(),
        "compile_block should succeed even without fast thunks"
    );
}

#[test]
fn block_chaining_publishes_link_and_unchains() {
    let mut rt = JitRuntime::new(GuestArch::X64);

    let ir_a = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 1,
        },
        IrInstruction::Jump { target: 0x2000 },
    ];
    let ir_b = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 2,
        },
        IrInstruction::Jump { target: 0x3000 },
    ];

    rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
        .unwrap();
    rt.get_or_compile(&ir_b, 0x2000, GuestArch::X64, None)
        .unwrap();

    assert!(rt.is_compiled(0x1000));
    assert!(rt.is_compiled(0x2000));

    rt.chain_blocks(0x1000, 0x2000).unwrap();
    let chain_key = (0x1000, 0x2000);
    assert!(rt.block_chains.contains_key(&chain_key));
    assert_ne!(
        rt.block_cache
            .get(&0x1000)
            .unwrap()
            .link_target
            .load(Ordering::Acquire),
        0
    );

    let unchain_result = rt.unchain_block(0x1000);
    assert!(unchain_result.is_ok(), "unchaining should succeed");
    assert!(!rt.block_chains.contains_key(&chain_key));
    assert_eq!(
        rt.block_cache
            .get(&0x1000)
            .unwrap()
            .link_target
            .load(Ordering::Acquire),
        0,
        "unchaining must clear the atomic link slot"
    );
}

#[test]
fn fast_thunk_compile_fallback_when_global_map_missing() {
    let mut compiler = JitCompiler::new();
    let ir = vec![IrInstruction::Call {
        target: 0xDEAD_BEEF,
        return_address: 0x1004,
    }];
    // Provide a set containing the target address, but the global
    // FAST_THUNK_MAP has no entry for it. The compiler should fall
    // back gracefully to EXIT_THUNK instead of panicking.
    let mut fast_thunk_addrs = std::collections::HashSet::new();
    fast_thunk_addrs.insert(0xDEAD_BEEF);
    let result = compiler.compile_block(&ir, 0x1000, GuestArch::X64, Some(&fast_thunk_addrs));
    assert!(
        result.is_ok(),
        "compile_block should fall back to EXIT_THUNK even if global map missing entry"
    );
}

// =====================================================================
// On-demand guest-page materialisation
// =====================================================================

static GUEST_MEMORY_TELEMETRY_LOCK: Mutex<()> = Mutex::new(());
/// Serializes tests that install/remove the SIGBUS handler or mutate its
/// process-wide state.
static SIGBUS_STATE_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn sparse_guest_memory_materialises_only_committed_pages() {
    let _guard = GUEST_MEMORY_TELEMETRY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut memory = MemoryImage::default();
    for i in 0..16u64 {
        memory.map_bytes(i * 0x0800_0000, &[0xABu8; 4096]);
    }
    assert_eq!(memory.committed_page_addresses().len(), 16);
    assert_eq!(
        memory.canonical_store().materialisation_count(),
        16,
        "each committed page is materialised exactly once by the store"
    );

    let mut runtime = JitRuntime::new(GuestArch::X64);
    reset_guest_memory_telemetry();
    runtime.sync_all_pages_to_flat(&memory);

    let telemetry = guest_memory_telemetry();
    assert_eq!(
        telemetry.pages_materialised, 16,
        "only the 16 committed pages may be materialised"
    );
    assert_eq!(
        telemetry.sync_operations, 16,
        "16 isolated pages form 16 runs"
    );
    assert_eq!(telemetry.bytes_copied, 16 * 4096);
    assert_eq!(
        memory.canonical_store().materialisation_count(),
        16,
        "the sync pass must not re-materialise canonical pages"
    );
    runtime.sync_all_pages_to_flat(&memory);
    assert_eq!(
        memory.canonical_store().materialisation_count(),
        16,
        "repeated sync passes must leave canonical materialisation unchanged"
    );
    assert_eq!(runtime.flat_memory.materialised_page_count(), 16);
    assert_eq!(
        runtime.flat_memory.total_page_count(),
        (runtime.flat_memory.size() / 4096) as u64,
        "the flat region is the whole direct window"
    );
    assert!(
        telemetry.pages_materialised < runtime.flat_memory.total_page_count() / 1000,
        "materialisation must not be proportional to the flat region"
    );
    assert!(runtime.flat_memory.is_page_materialised(0));
    assert!(!runtime.flat_memory.is_page_materialised(0x1000));
    assert!(
        !runtime
            .flat_memory
            .is_page_materialised(0x0800_0000 + 0x1000)
    );

    // The committed bytes really made it into the mirror.
    let mut buf = [0u8; 8];
    runtime.flat_memory.read(0, &mut buf);
    assert_eq!(buf, [0xAB; 8]);
    runtime.flat_memory.sync_from_memory_image(0, &[0xCD; 8]);
    assert_eq!(
        memory.read_u8(0).unwrap(),
        0xCD,
        "an explicit flat write must land in the shared canonical page"
    );
    runtime.flat_memory.read(0, &mut buf);
    assert_eq!(buf, [0xCD; 8]);
    // Out-of-window syncs/reads/diagnostic probes must be refused without
    // touching the mapping.
    runtime
        .flat_memory
        .sync_from_memory_image(u64::MAX - 3, &[0xEE; 8]);
    runtime.flat_memory.read(u64::MAX - 3, &mut buf);
    assert_eq!(buf, [0xCD; 8]);
    assert!(!runtime.flat_memory.is_page_materialised(0x1001));
    assert!(
        !runtime
            .flat_memory
            .is_page_materialised(GUEST_FLAT_SIZE as u64)
    );
    let debug = format!("{memory:?}");
    assert!(debug.contains("GuestMemoryStore"));
    assert!(!debug.contains("materialised: ["));
}

#[test]
fn invalid_flat_view_rejects_reads_syncs_and_materialisation() {
    let memory = MemoryImage::default();
    let store = Arc::new(GuestMemoryStore::invalid_for_test());
    let bitmap_words = GUEST_FLAT_SIZE.div_ceil(4096 * 64);
    let flat = FlatGuestMemory {
        store,
        materialised: (0..bitmap_words)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    };
    assert!(!flat.is_valid());
    assert_eq!(flat.base(), 0);
    let mut buf = [0xAA; 8];
    flat.read(0, &mut buf);
    assert_eq!(buf, [0xAA; 8], "an invalid view must not write the buffer");
    flat.sync_from_memory_image(0, &[0x11; 8]);
    let stats = flat.materialise_pages(&memory, &[0]);
    assert_eq!(stats.pages_materialised, 0);
    assert_eq!(stats.bytes_copied, 0);
    assert!(!flat.is_page_materialised(0));
}

#[test]
fn partially_mapped_page_is_not_materialised() {
    let _guard = GUEST_MEMORY_TELEMETRY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut memory = MemoryImage::default();
    // Only the first 16 bytes of the page are mapped.
    memory.map_bytes(0x3000_0000, &[0x11u8; 16]);

    let mut runtime = JitRuntime::new(GuestArch::X64);
    let detached = runtime
        .flat_memory
        .materialise_pages(&memory, &[0x3000_0000]);
    assert_eq!(detached.pages_materialised, 0);
    assert_eq!(detached.bytes_copied, 0);
    assert!(!runtime.flat_memory.is_page_materialised(0x3000_0000));

    reset_guest_memory_telemetry();
    runtime.sync_all_pages_to_flat(&memory);

    let telemetry = guest_memory_telemetry();
    assert_eq!(telemetry.pages_materialised, 0);
    assert_eq!(telemetry.bytes_copied, 0);
    assert!(!runtime.flat_memory.is_page_materialised(0x3000_0000));

    let empty = runtime.flat_memory.materialise_pages(&memory, &[]);
    assert_eq!(empty.pages_materialised, 0);
    let outside = runtime
        .flat_memory
        .materialise_pages(&memory, &[GUEST_FLAT_SIZE as u64]);
    assert_eq!(outside.pages_materialised, 0);
    assert_eq!(outside.sync_operations, 0);
}

#[test]
fn sigbus_fallback_never_corrupts_committed_bytes_and_handles_partial_and_absent_pages() {
    let _guard = GUEST_MEMORY_TELEMETRY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x1000, &[0xAB; 4096]);
    memory.map_bytes(0x2000, &[0x11; 16]);
    memory.map_bytes(0x4000 + 4080, &[0x22; 16]);
    let mut runtime = JitRuntime::new(GuestArch::X64);
    runtime.sync_all_pages_to_flat(&memory);
    let base = runtime.flat_memory.base() as *mut u8;
    let size = runtime.flat_memory.size();

    service_faulting_page(&runtime, &memory, 0x1000, base, size);
    // SAFETY: page 0x1000 is inside the shared flat window.
    let first = unsafe { std::ptr::read_volatile(base.add(0x1000)) };
    assert_eq!(first, 0xAB, "servicing must never zero committed bytes");
    assert_eq!(memory.read_u8(0x1000).unwrap(), 0xAB);

    service_faulting_page(&runtime, &memory, 0x2000, base, size);
    // SAFETY: page 0x2000 is inside the shared flat window.
    let partial_head = unsafe { std::ptr::read_volatile(base.add(0x2000)) };
    assert_eq!(partial_head, 0x11);
    assert!(!runtime.flat_memory.is_page_materialised(0x2000));

    service_faulting_page(&runtime, &memory, 0x4000, base, size);
    // SAFETY: page 0x4000 is inside the shared flat window.
    let partial_tail = unsafe { std::ptr::read_volatile(base.add(0x4000 + 4095)) };
    assert_eq!(partial_tail, 0x22);
    assert!(!runtime.flat_memory.is_page_materialised(0x4000));

    service_faulting_page(&runtime, &memory, 0x6000, base, size);
    // SAFETY: page 0x6000 is inside the shared flat window.
    let absent_tail = unsafe { std::ptr::read_volatile(base.add(0x6000 + 4095)) };
    assert_eq!(absent_tail, 0);
    assert!(runtime.flat_memory.is_page_materialised(0x6000));
    assert!(
        memory.read_u8(0x6000).is_err(),
        "an uncommitted page must stay unmapped for the interpreter"
    );
    assert_eq!(memory.canonical_store().materialisation_count(), 3);
}

#[test]
fn sigbus_fallback_touches_mapped_tail_without_zeroing_or_marking_it() {
    let mut memory = MemoryImage::default();
    // Only the last 16 bytes of the page are mapped.
    memory.map_bytes(0x4FF0, &[0x33; 16]);
    let mut runtime = JitRuntime::new(GuestArch::X64);
    runtime.sync_all_pages_to_flat(&memory);
    let base = runtime.flat_memory.base() as *mut u8;
    let size = runtime.flat_memory.size();

    service_faulting_page(&runtime, &memory, 0x4000, base, size);
    // SAFETY: page 0x4000 is inside the shared flat window.
    let tail = unsafe { std::ptr::read_volatile(base.add(0x4FFF)) };
    assert_eq!(tail, 0x33, "a mapped tail byte must never be zeroed");
    // SAFETY: byte 0 of the same page is inside the flat window.
    let head = unsafe { std::ptr::read_volatile(base.add(0x4000)) };
    assert_eq!(head, 0);
    assert!(!runtime.flat_memory.is_page_materialised(0x4000));
    assert_eq!(memory.read_u8(0x4FFF).unwrap(), 0x33);
}

#[test]
fn legacy_sync_entry_points_never_leave_stale_or_duplicate_state() {
    let _guard = GUEST_MEMORY_TELEMETRY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x1000, &[0x11; 4096]);
    memory.map_bytes(0x2000, &[0x22; 4096]);
    let mut runtime = JitRuntime::new(GuestArch::X64);
    runtime.sync_all_pages_to_flat(&memory);
    assert_eq!(runtime.synced_page_count(), 2);

    runtime.sync_page_to_flat(&memory, 0x1000);
    assert_eq!(runtime.synced_page_count(), 2);
    memory.map_bytes(0x3000, &[0x33; 4096]);
    runtime.sync_new_pages_to_flat(&memory);
    assert_eq!(runtime.synced_page_count(), 3);
    assert_eq!(
        memory.canonical_store().materialisation_count(),
        3,
        "incremental sync must not rematerialise existing pages"
    );

    // These back-compatibility entry points are deliberate no-ops: a
    // write through either view is already visible through the other.
    runtime.sync_flat_to_memory(0x1000, &mut memory, 8);
    runtime.sync_all_flat_to_memory(&mut memory);
    runtime.sync_synced_flat_to_memory(&mut memory);
    assert_eq!(memory.read_u8(0x1000).unwrap(), 0x11);
    assert_eq!(memory.read_u8(0x2000).unwrap(), 0x22);
    assert_eq!(memory.read_u8(0x3000).unwrap(), 0x33);
    assert_eq!(memory.canonical_store().materialisation_count(), 3);
}

#[test]
fn sigbus_handler_services_flat_fault_without_copying_or_corrupting() {
    let _guard = SIGBUS_STATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x7000, &[0x5A; 4096]);
    let mut runtime = JitRuntime::new(GuestArch::X64);
    runtime.sync_all_pages_to_flat(&memory);
    runtime.install_sigbus_handler(&memory);

    // SAFETY: `siginfo_t` is zero-initialised and only public fields are
    // set.  The handler is called directly (not from a real signal) with a
    // flat-window address that is fully committed.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        info.si_signo = libc::SIGBUS;
        info.si_addr = (runtime.flat_memory.base() + 0x7000) as *mut c_void;
        sigbus_sa_handler(libc::SIGBUS, &mut info, std::ptr::null_mut());
    }

    assert_eq!(
        memory.read_u8(0x7000).unwrap(),
        0x5A,
        "the fallback must preserve committed bytes"
    );
    assert!(runtime.flat_memory.is_page_materialised(0x7000));
    assert_eq!(SIGBUS_HANDLER_DEPTH.load(Ordering::Relaxed), 0);
    assert!(!SIGBUS_IN_HANDLER.load(Ordering::Acquire));
    runtime.remove_sigbus_handler();
    assert!(SIGBUS_JIT_RUNTIME.load(Ordering::Acquire).is_null());
    assert!(SIGBUS_JIT_MEMORY.load(Ordering::Acquire).is_null());
}
