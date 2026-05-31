//! Section 35 — System and state-management instructions (execution_plan gaps G1-G4).
//!
//! Rigorous coverage for the four CPU gaps closed in this work:
//!   * G1 — FXSAVE / FXRSTOR / XSAVE / XRSTOR state serialization
//!   * G2 — CMPS / SCAS string instructions with REP/REPE/REPNE
//!   * G3 — HLT / CLI / STI / STD / IN / OUT system instructions
//!   * G4 — Debug-register moves (MOV DRn, r / MOV r, DRn)

use casa1::cpu::{
    CpuEngineConfig, CpuExecutionEngine, CpuState, GuestArch, MemoryImage, Register, XmmValue,
};

fn engine() -> CpuExecutionEngine {
    let config = CpuEngineConfig::from_profile(GuestArch::X64, "22631", "0.1.0", None)
        .expect("build CPU config");
    CpuExecutionEngine::new(config)
}

fn run(engine: &CpuExecutionEngine, bytes: &[u8], state: &mut CpuState, memory: &mut MemoryImage) {
    let decoded = engine.decode_block(bytes, 0x1400_000000).expect("decode block");
    let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower to IR");
    engine
        .execute_ir(state, memory, &ir)
        .expect("execute IR block");
}

// ──────────────────────────────────────────────────────────────────────────
// G1: FXSAVE / FXRSTOR round-trip
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn fxsave_fxrstor_round_trip_preserves_xmm_mxcsr_and_x87() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let base = 0x20_0000u64;
    memory.map_bytes(base, &[0u8; 1024]);
    state.set(Register::Rax, base);
    state.set_xmm(0, XmmValue { low: 0xAABB_CCDD_1122_3344, high: 0x5566_7788_99AA_BBCC });
    state.set_xmm(7, XmmValue { low: 0x0102_0304_0506_0708, high: 0x1112_1314_1516_1718 });
    state.mxcsr = 0x0000_1F80;
    // 1.5 and 2.5 are exactly representable as f64 → f80 → f64.
    state.x87.stack = vec![1.5, 2.5, -3.25];

    // FXSAVE [rax]  (0F AE /0, modrm 0x00 → [rax])
    run(&engine, &[0x0F, 0xAE, 0x00], &mut state, &mut memory);

    // MXCSR lives at base+24.
    assert_eq!(memory.read_u32(base + 24).expect("mxcsr"), 0x0000_1F80);
    // MXCSR_MASK at base+28.
    assert_eq!(memory.read_u32(base + 28).expect("mxcsr mask"), 0x0000_FFFF);
    // XMM0 at base+160.
    assert_eq!(memory.read_u64(base + 160).expect("xmm0 low"), 0xAABB_CCDD_1122_3344);
    assert_eq!(memory.read_u64(base + 168).expect("xmm0 high"), 0x5566_7788_99AA_BBCC);

    // Clobber all the saved state.
    state.set_xmm(0, XmmValue::default());
    state.set_xmm(7, XmmValue::default());
    state.mxcsr = 0;
    state.x87.stack.clear();

    // FXRSTOR [rax]  (0F AE /1, modrm 0x08 → [rax])
    run(&engine, &[0x0F, 0xAE, 0x08], &mut state, &mut memory);

    assert_eq!(state.xmm[0].low, 0xAABB_CCDD_1122_3344);
    assert_eq!(state.xmm[0].high, 0x5566_7788_99AA_BBCC);
    assert_eq!(state.xmm[7].low, 0x0102_0304_0506_0708);
    assert_eq!(state.mxcsr, 0x0000_1F80);
    assert_eq!(state.x87.stack, vec![1.5, 2.5, -3.25]);
}

#[test]
fn xsave_xrstor_round_trip_preserves_ymm_upper() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let base = 0x30_0000u64;
    memory.map_bytes(base, &[0u8; 1024]);
    state.set(Register::Rax, base);
    state.set_xmm(1, XmmValue { low: 0xDEAD_BEEF_0000_0001, high: 0x0000_0000_CAFE_BABE });
    state.ymm_upper[1] = XmmValue { low: 0x1111_2222_3333_4444, high: 0x5555_6666_7777_8888 };
    state.mxcsr = 0x0000_9FC0;

    // XSAVE [rax]  (0F AE /4, modrm 0x20 → [rax])
    run(&engine, &[0x0F, 0xAE, 0x20], &mut state, &mut memory);

    // XSTATE_BV header at base+512 announces x87 | SSE | AVX.
    assert_eq!(memory.read_u64(base + 512).expect("xstate_bv"), 0b111);
    // YMM1 upper half at base+576+16.
    assert_eq!(memory.read_u64(base + 592).expect("ymm1 upper low"), 0x1111_2222_3333_4444);
    assert_eq!(memory.read_u64(base + 600).expect("ymm1 upper high"), 0x5555_6666_7777_8888);

    // Clobber.
    state.set_xmm(1, XmmValue::default());
    state.ymm_upper[1] = XmmValue::default();
    state.mxcsr = 0;

    // XRSTOR [rax]  (0F AE /5, modrm 0x28 → [rax])
    run(&engine, &[0x0F, 0xAE, 0x28], &mut state, &mut memory);

    assert_eq!(state.xmm[1].low, 0xDEAD_BEEF_0000_0001);
    assert_eq!(state.xmm[1].high, 0x0000_0000_CAFE_BABE);
    assert_eq!(state.ymm_upper[1].low, 0x1111_2222_3333_4444);
    assert_eq!(state.ymm_upper[1].high, 0x5555_6666_7777_8888);
    assert_eq!(state.mxcsr, 0x0000_9FC0);
}

// ──────────────────────────────────────────────────────────────────────────
// G2: CMPS / SCAS string instructions
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn repe_cmpsb_matches_equal_strings_to_completion() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let lhs = 0x10_0000u64;
    let rhs = 0x10_1000u64;
    memory.map_bytes(lhs, b"abc");
    memory.map_bytes(rhs, b"abc");
    state.set(Register::Rsi, lhs);
    state.set(Register::Rdi, rhs);
    state.set(Register::Rcx, 3);

    // REPE CMPSB  (F3 A6)
    run(&engine, &[0xF3, 0xA6], &mut state, &mut memory);

    // All three bytes equal → RCX drained to 0, last compare ZF=1.
    assert_eq!(state.get(Register::Rcx), 0);
    assert!(state.flags.zf);
    assert_eq!(state.get(Register::Rsi), lhs + 3);
    assert_eq!(state.get(Register::Rdi), rhs + 3);
}

#[test]
fn repe_cmpsb_stops_at_first_mismatch() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let lhs = 0x10_0000u64;
    let rhs = 0x10_1000u64;
    memory.map_bytes(lhs, b"abXd");
    memory.map_bytes(rhs, b"abYd");
    state.set(Register::Rsi, lhs);
    state.set(Register::Rdi, rhs);
    state.set(Register::Rcx, 4);

    // REPE CMPSB  (F3 A6)
    run(&engine, &[0xF3, 0xA6], &mut state, &mut memory);

    // Mismatch at index 2 ('X' vs 'Y') → stops with ZF=0, RCX=1 remaining.
    assert!(!state.flags.zf);
    assert_eq!(state.get(Register::Rcx), 1);
    assert_eq!(state.get(Register::Rsi), lhs + 3);
    assert_eq!(state.get(Register::Rdi), rhs + 3);
}

#[test]
fn repne_scasb_finds_null_terminator() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let buf = 0x12_0000u64;
    memory.map_bytes(buf, b"hello\0");
    state.set(Register::Rdi, buf);
    state.set(Register::Rax, 0); // scan for the NUL byte in AL
    state.set(Register::Rcx, 32);

    // REPNE SCASB  (F2 AE)
    run(&engine, &[0xF2, 0xAE], &mut state, &mut memory);

    // 6 bytes scanned ("hello" + NUL); RDI lands one past the terminator.
    assert!(state.flags.zf);
    assert_eq!(state.get(Register::Rdi), buf + 6);
    assert_eq!(state.get(Register::Rcx), 32 - 6);
}

#[test]
fn scasb_honors_direction_flag() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let buf = 0x13_0000u64;
    memory.write_u8(buf, 0x41);
    state.set(Register::Rdi, buf);
    state.set(Register::Rax, 0x41);
    // DF=1 (decrement): set bit 10 of eflags_extra via STD first.
    run(&engine, &[0xFD], &mut state, &mut memory); // STD

    // Single (non-REP) SCASB  (AE)
    run(&engine, &[0xAE], &mut state, &mut memory);

    assert!(state.flags.zf); // 0x41 == 0x41
    assert_eq!(state.get(Register::Rdi), buf.wrapping_sub(1));
}

// ──────────────────────────────────────────────────────────────────────────
// G3: HLT / CLI / STI / STD / IN / OUT
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn hlt_terminates_with_halted_reason() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let decoded = engine.decode_block(&[0xF4], 0x1400_000000).expect("decode HLT");
    let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower HLT");
    let err = engine
        .execute_ir(&mut state, &mut memory, &ir)
        .expect_err("HLT must terminate execution");
    assert_eq!(err.code.name(), "HALTED");
}

#[test]
fn cli_sti_toggle_interrupt_flag() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    run(&engine, &[0xFB], &mut state, &mut memory); // STI
    assert_eq!(state.eflags_extra & (1 << 9), 1 << 9);
    run(&engine, &[0xFA], &mut state, &mut memory); // CLI
    assert_eq!(state.eflags_extra & (1 << 9), 0);
}

#[test]
fn std_sets_direction_flag() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    run(&engine, &[0xFD], &mut state, &mut memory); // STD
    assert_eq!(state.eflags_extra & (1 << 10), 1 << 10);
}

#[test]
fn in_reads_zero_into_accumulator() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0xFFFF_FFFF_FFFF_FFFF);
    // IN AL, 0x60  (E4 60)
    run(&engine, &[0xE4, 0x60], &mut state, &mut memory);
    // Only AL is cleared; upper bytes preserved.
    assert_eq!(state.get(Register::Rax), 0xFFFF_FFFF_FFFF_FF00);
}

#[test]
fn out_is_a_silent_drop() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x1234);
    // OUT 0x60, AL  (E6 60) — must not error and must not change RAX.
    run(&engine, &[0xE6, 0x60], &mut state, &mut memory);
    assert_eq!(state.get(Register::Rax), 0x1234);
}

// ──────────────────────────────────────────────────────────────────────────
// G4: Debug-register moves
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn mov_to_and_from_debug_register_round_trips() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x1234_5678_9ABC_DEF0);
    // MOV DR0, RAX  (0F 23 C0)
    run(&engine, &[0x0F, 0x23, 0xC0], &mut state, &mut memory);
    assert_eq!(state.dr[0], 0x1234_5678_9ABC_DEF0);

    // MOV RCX, DR0  (0F 21 C1)
    run(&engine, &[0x0F, 0x21, 0xC1], &mut state, &mut memory);
    assert_eq!(state.get(Register::Rcx), 0x1234_5678_9ABC_DEF0);
}
