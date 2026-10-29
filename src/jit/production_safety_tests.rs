use super::*;

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

fn skip_without_capability(test: &str) -> bool {
    skip_without_capability_for(test, jit_execution_available())
}

fn skip_without_capability_for(test: &str, available: bool) -> bool {
    if available {
        return false;
    }
    eprintln!("[jit] skipping {test}: executable-memory probe unavailable");
    true
}

#[test]
fn jit_capability_gate_reports_unavailable_host_without_running_native_code() {
    let _serial = jit_test_serial();
    assert_eq!(skip_without_capability_for("fixture", true), false);
    assert_eq!(skip_without_capability_for("fixture", false), true);
    assert_eq!(
        skip_without_capability("fixture"),
        !jit_execution_available()
    );
}

#[test]
fn jit_construction_gate_rejects_deterministic_and_unavailable_hosts() {
    let _serial = jit_test_serial();
    use crate::runner::JitMode;
    // Auto selects native execution only on a capable, non-deterministic
    // host.
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Auto, false, true),
        true
    );
    // Auto is interpreter-only when the probe failed...
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Auto, false, false),
        false
    );
    // ...and in deterministic/replay mode even on a capable host.
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Auto, true, true),
        false
    );
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Auto, true, false),
        false
    );
    // Disabled never constructs; Enabled is an explicit override.
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Disabled, false, true),
        false
    );
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Enabled, false, false),
        true
    );
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Enabled, true, true),
        true
    );
}

#[test]
fn auto_unavailable_host_and_deterministic_modes_fall_back() {
    let _serial = jit_test_serial();
    use crate::runner::JitMode;
    // Incapable host: Auto never constructs the JIT runtime.
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Auto, false, false),
        false
    );
    // Deterministic host under Auto: interpreter-only, same behaviour.
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Auto, true, true),
        false
    );
    // Explicit Enabled still constructs (documented override), and a
    // disabled mode never does.
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Enabled, true, true),
        true
    );
    assert_eq!(
        crate::runtime::jit_construction_selected(&JitMode::Disabled, false, true),
        false
    );
}

fn run_self_modifying_code_case(available: bool) -> Option<()> {
    if !available {
        return None;
    }
    let code = 0x00A1_0000u64;
    let writer = 0x00A1_1000u64;
    let mut runtime = JitRuntime::new(GuestArch::X64);
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let original = vec![IrInstruction::MovImm {
        dst: Register::Rax,
        value: 42,
    }];
    runtime
        .get_or_compile(&original, code, GuestArch::X64, None)
        .expect("compile original block");
    let stale = runtime.block_cache.get(&code).cloned().expect("cached");
    let _ = execute_cached(&mut runtime, code, &mut state, &mut memory);
    assert_eq!(state.get(Register::Rax), 42);

    // Guest code itself overwrites the block's first four bytes.  The
    // page must be mapped so the store reaches the SMC hook (an unmapped
    // store takes the guest-fault path instead).
    memory.map_zeroed_if_unmapped(code, 0x1000);
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
                absolute_address: Some(code),
            },
            value: 0x9090_9090,
            width: 4,
        },
        IrInstruction::Nop,
    ];
    runtime
        .get_or_compile(&writer_ir, writer, GuestArch::X64, None)
        .expect("compile writer block");
    let _ = execute_cached(&mut runtime, writer, &mut state, &mut memory);
    assert!(
        runtime.code_invalidations >= 1,
        "guest store to a code page must invalidate the compiled block"
    );
    assert!(runtime.smc_invalidation_events >= 1);

    // The stale block must not execute its old bytes: the entry check
    // returns the interpreter fallback.
    state.set(Register::Rax, 0);
    state.rip = code;
    let reason = unsafe { runtime.execute_block(&stale, &mut state, &mut memory) };
    assert_eq!(
        reason,
        JitExitReason::Safepoint,
        "a stale SMC block must fall back to the interpreter, not run"
    );

    // Recompiling from the new code observes the new behaviour.
    let updated = vec![IrInstruction::MovImm {
        dst: Register::Rax,
        value: 43,
    }];
    runtime
        .get_or_compile(&updated, code, GuestArch::X64, None)
        .expect("recompile modified block");
    state.set(Register::Rax, 0);
    let _ = execute_cached(&mut runtime, code, &mut state, &mut memory);
    assert_eq!(
        state.get(Register::Rax),
        43,
        "recompilation must not execute stale code"
    );
    Some(())
}

#[test]
fn self_modifying_code_guest_store_invalidates_and_recompiles() {
    let _serial = jit_test_serial();
    assert_eq!(
        run_self_modifying_code_case(false),
        None,
        "an unavailable probe must skip native SMC invalidation"
    );
    assert_eq!(
        run_self_modifying_code_case(jit_execution_available()).is_some(),
        jit_execution_available()
    );
}

fn run_backedge_link_case(available: bool) -> Option<()> {
    if !available {
        return None;
    }
    let source = 0x00A2_0000u64;
    let target = 0x00A2_1000u64;
    let exit = 0x00A2_2000u64;
    let mut runtime = JitRuntime::new(GuestArch::X64);
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let source_ir = vec![IrInstruction::Nop, IrInstruction::Jump { target }];
    let target_ir = vec![IrInstruction::Nop, IrInstruction::Jump { target: exit }];
    runtime
        .get_or_compile(&source_ir, source, GuestArch::X64, None)
        .expect("compile source");
    runtime
        .get_or_compile(&target_ir, target, GuestArch::X64, None)
        .expect("compile target");
    runtime.chain_blocks(source, target).expect("publish link");
    assert_eq!(runtime.chain_links_formed, 1);
    assert!(
        runtime
            .block_cache
            .get(&source)
            .expect("source cached")
            .link_target
            .load(Ordering::Acquire)
            != 0,
        "link slot must publish the target entry"
    );

    // Linked execution reaches the target's EXIT_JUMP (target semantics),
    // proving the dispatcher was bypassed.
    let reason = execute_cached(&mut runtime, source, &mut state, &mut memory);
    assert_eq!(reason, JitExitReason::Jump { target: exit });

    // Safepoint semantics survive chaining: the target prologue (and the
    // source prologue) still poll the host flag.
    JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Relaxed);
    let reason = execute_cached(&mut runtime, source, &mut state, &mut memory);
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
    assert_eq!(reason, JitExitReason::Safepoint);
    Some(())
}

#[test]
fn backedge_link_falls_back_to_safepoint_when_requested() {
    let _serial = jit_test_serial();
    assert_eq!(
        run_backedge_link_case(false),
        None,
        "an unavailable probe must skip native chain execution"
    );
    assert_eq!(
        run_backedge_link_case(jit_execution_available()).is_some(),
        jit_execution_available()
    );
}

extern "C" fn direct_thunk_target(
    _runtime: *mut c_void,
    state: *mut CpuState,
    _memory: *mut MemoryImage,
    _thunk: u64,
) -> i32 {
    if !state.is_null() {
        unsafe {
            (*state).gpr[0] = 0x77;
        }
    }
    -1
}

#[test]
fn direct_thunk_target_invalid_state_is_safe_and_pins_sentinel() {
    let _serial = jit_test_serial();
    assert_eq!(
        direct_thunk_target(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0
        ),
        -1,
        "a null state must not be dereferenced and must still request continuation"
    );
    let mut state = CpuState::new(GuestArch::X64);
    assert_eq!(
        direct_thunk_target(
            std::ptr::null_mut(),
            &mut state,
            std::ptr::null_mut(),
            0xDEAD
        ),
        -1
    );
    assert_eq!(state.get(Register::Rax), 0x77);
}

#[test]
fn direct_resolved_thunk_call_bypasses_dispatcher() {
    let _serial = jit_test_serial();
    if skip_without_capability("direct_resolved_thunk_call_bypasses_dispatcher") {
        return;
    }
    const GUEST_THUNK: u64 = 0x00A3_5000;
    let mut runtime = JitRuntime::new(GuestArch::X64);
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rsp, 0x2000);
    runtime
        .register_host_thunk_for_guest(direct_thunk_target as *const () as usize, GUEST_THUNK)
        .expect("register resolved thunk");
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 7,
        },
        IrInstruction::Call {
            target: GUEST_THUNK,
            return_address: 0x00A3_6004,
        },
    ];
    let before = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed);
    runtime
        .get_or_compile(&ir, 0x00A3_6000, GuestArch::X64, None)
        .expect("compile direct-call block");
    assert!(
        JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed) > before,
        "resolved thunk must be emitted as a direct call"
    );
    let reason = execute_cached(&mut runtime, 0x00A3_6000, &mut state, &mut memory);
    assert!(matches!(reason, JitExitReason::Normal { .. }));
    assert_eq!(
        state.get(Register::Rax),
        0x77,
        "the host thunk must run without an EXIT_THUNK dispatcher trip"
    );
}

fn run_invalid_block_installation_case(available: bool) -> Option<()> {
    if !available {
        return None;
    }
    let address = 0x00A4_0000u64;
    let mut runtime = JitRuntime::new(GuestArch::X64);
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    let ir = vec![IrInstruction::MovImm {
        dst: Register::Rax,
        value: 42,
    }];
    runtime
        .get_or_compile(&ir, address, GuestArch::X64, None)
        .expect("compile");
    let stale = runtime.block_cache.get(&address).cloned().expect("cached");

    // Simulate a crash-equivalent signal at block installation/unwind:
    // the block is quarantined and handed to the interpreter.
    runtime.report_block_fault(address);
    assert_eq!(runtime.fault_fallbacks, 1);
    assert!(runtime.faulted_blocks.contains(&address));
    assert!(!runtime.is_compiled(address));
    assert!(
        runtime
            .get_or_compile(&ir, address, GuestArch::X64, None)
            .is_err(),
        "a faulted block must stay on the interpreter"
    );

    state.rip = address;
    let reason = unsafe { runtime.execute_block(&stale, &mut state, &mut memory) };
    assert_eq!(reason, JitExitReason::Safepoint);
    assert!(runtime.fault_fallbacks >= 1);
    Some(())
}

#[test]
fn invalid_block_installation_falls_back_to_interpreter() {
    let _serial = jit_test_serial();
    assert_eq!(
        run_invalid_block_installation_case(false),
        None,
        "an unavailable probe must skip the native fault fallback"
    );
    assert_eq!(
        run_invalid_block_installation_case(jit_execution_available()).is_some(),
        jit_execution_available()
    );
}

#[test]
fn jit_block_and_interpreter_store_never_observe_a_stale_canonical_page() {
    let _serial = jit_test_serial();
    if skip_without_capability(
        "jit_block_and_interpreter_store_never_observe_a_stale_canonical_page",
    ) {
        return;
    }
    let address = 0x2_0000_u64;
    let load_site = 0x3_0000_u64;
    let store_site = 0x4_0000_u64;
    let mut memory = MemoryImage::default();
    memory.map_bytes(address, &[0_u8; 16]);
    let mut runtime = JitRuntime::new(GuestArch::X64);
    runtime.sync_all_pages_to_flat(&memory);

    assert!(
        Arc::ptr_eq(runtime.flat_memory.store(), memory.canonical_store()),
        "the JIT flat view must alias the image's canonical store"
    );
    assert_eq!(
        runtime.flat_memory.base(),
        memory.canonical_store().flat_base(),
        "both views must share the same direct-window mapping"
    );
    assert_eq!(memory.canonical_store().materialisation_count(), 1);

    // Direct JIT-view store → interpreter read, with no sync call.
    // SAFETY: the page is committed, aligned and inside the shared map.
    unsafe {
        ptr::write_volatile(
            (runtime.flat_memory.base() as *mut u64).add((address / 8) as usize),
            0x1111_2222_3333_4444,
        );
    }
    assert_eq!(memory.read_u64(address).unwrap(), 0x1111_2222_3333_4444);

    // Interpreter store → direct JIT-view read, with no sync call.
    memory.write_u64(address, 0x5555_6666_7777_8888);
    // SAFETY: same canonical page as above.
    let flat_value = unsafe {
        ptr::read_volatile((runtime.flat_memory.base() as *const u64).add((address / 8) as usize))
    };
    assert_eq!(flat_value, 0x5555_6666_7777_8888);

    let operand = crate::cpu::MemoryOperand {
        base: None,
        index: None,
        scale: 1,
        displacement: 0,
        rip_relative: false,
        rip_base: 0,
        segment: None,
        address_size_32: false,
        absolute_address: Some(address),
    };
    let load_ir = vec![IrInstruction::LoadMemory {
        dst: Register::Rax,
        address: operand.clone(),
        width: 8,
    }];
    runtime
        .get_or_compile(&load_ir, load_site, GuestArch::X64, None)
        .expect("compile canonical load block");
    let mut state = CpuState::new(GuestArch::X64);
    let reason = execute_cached(&mut runtime, load_site, &mut state, &mut memory);
    assert!(matches!(reason, JitExitReason::Normal { .. }));
    assert_eq!(
        state.get(Register::Rax),
        0x5555_6666_7777_8888,
        "the compiled block must see the interpreter's store immediately"
    );

    // A later interpreter store is visible to the next block execution
    // without an explicit sync.
    memory.write_u64(address, 0x9999_AAAA_BBBB_CCCC);
    state.set(Register::Rax, 0);
    let reason = execute_cached(&mut runtime, load_site, &mut state, &mut memory);
    assert!(matches!(reason, JitExitReason::Normal { .. }));
    assert_eq!(state.get(Register::Rax), 0x9999_AAAA_BBBB_CCCC);

    // Compiled store → interpreter read, with no write-back pass.
    let store_ir = vec![IrInstruction::StoreMemory {
        src: Register::Rcx,
        address: operand,
        width: 8,
    }];
    runtime
        .get_or_compile(&store_ir, store_site, GuestArch::X64, None)
        .expect("compile canonical store block");
    state.set(Register::Rcx, 0xDDDD_EEEE_FFFF_0001);
    let reason = execute_cached(&mut runtime, store_site, &mut state, &mut memory);
    assert!(matches!(reason, JitExitReason::Normal { .. }));
    assert_eq!(
        memory.read_u64(address).unwrap(),
        0xDDDD_EEEE_FFFF_0001,
        "the interpreter must see the compiled block's store immediately"
    );

    assert_eq!(
        memory.canonical_store().materialisation_count(),
        1,
        "JIT execution must never materialise an already-committed page"
    );
}
