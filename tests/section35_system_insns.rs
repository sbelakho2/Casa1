//! Section 35 — System and state-management instructions (execution_plan gaps G1-G4).
//!
//! Rigorous coverage for the four CPU gaps closed in this work:
//!   * G1 — FXSAVE / FXRSTOR / XSAVE / XRSTOR state serialization
//!   * G2 — CMPS / SCAS string instructions with REP/REPE/REPNE
//!   * G3 — HLT / CLI / STI / STD / IN / OUT system instructions
//!   * G4 — Debug-register moves (MOV DRn, r / MOV r, DRn)

use casa1::cpu::{
    CpuEngineConfig, CpuExecutionEngine, CpuState, GuestArch, IoPortBus, MemoryImage, Register,
    XmmValue,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Test port-I/O bus: unmapped-port reads return 0 and every write is
/// recorded by port, so tests can assert that OUT reached the bus.
#[derive(Default)]
struct TestPortBus {
    written: BTreeMap<u16, u32>,
}

impl IoPortBus for TestPortBus {
    fn read_u8(&self, _port: u16) -> u8 {
        0
    }
    fn read_u16(&self, _port: u16) -> u16 {
        0
    }
    fn read_u32(&self, _port: u16) -> u32 {
        0
    }
    fn write_u8(&mut self, port: u16, value: u8) {
        self.written.insert(port, value as u32);
    }
    fn write_u16(&mut self, port: u16, value: u16) {
        self.written.insert(port, value as u32);
    }
    fn write_u32(&mut self, port: u16, value: u32) {
        self.written.insert(port, value);
    }
}

fn engine() -> CpuExecutionEngine {
    let config = CpuEngineConfig::from_profile(GuestArch::X64, "22631", "0.1.0", None)
        .expect("build CPU config");
    CpuExecutionEngine::new(config)
}

fn engine_with_bus() -> (CpuExecutionEngine, Arc<Mutex<TestPortBus>>) {
    let config = CpuEngineConfig::from_profile(GuestArch::X64, "22631", "0.1.0", None)
        .expect("build CPU config");
    let bus = Arc::new(Mutex::new(TestPortBus::default()));
    (
        CpuExecutionEngine::new(config).with_port_bus(bus.clone()),
        bus,
    )
}

fn run(engine: &CpuExecutionEngine, bytes: &[u8], state: &mut CpuState, memory: &mut MemoryImage) {
    let decoded = engine
        .decode_block(bytes, 0x1400_000000)
        .expect("decode block");
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
    state.set_xmm(
        0,
        XmmValue {
            low: 0xAABB_CCDD_1122_3344,
            high: 0x5566_7788_99AA_BBCC,
        },
    );
    state.set_xmm(
        7,
        XmmValue {
            low: 0x0102_0304_0506_0708,
            high: 0x1112_1314_1516_1718,
        },
    );
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
    assert_eq!(
        memory.read_u64(base + 160).expect("xmm0 low"),
        0xAABB_CCDD_1122_3344
    );
    assert_eq!(
        memory.read_u64(base + 168).expect("xmm0 high"),
        0x5566_7788_99AA_BBCC
    );

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

// XSAVE announces exactly the state it stores — x87 | SSE | AVX
// (XSTATE_BV = 0b111) — because the XSAVE area serializes exactly those
// components. The requested-component mask comes from EDX:EAX, the
// destination must be 64-byte aligned, and after XRSTOR the restored state
// matches the saved state.
#[test]
fn xsave_xrstor_round_trip_preserves_ymm_upper() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let base = 0x30_0000u64;
    memory.map_bytes(base, &[0u8; 1024]);
    // The memory operand addresses the XSAVE area via RDI; EDX:EAX holds the
    // requested component mask (x87 | SSE | AVX).
    state.set(Register::Rdi, base);
    state.set(Register::Rax, 0b111);
    state.set(Register::Rdx, 0);
    state.set_xmm(
        1,
        XmmValue {
            low: 0xDEAD_BEEF_0000_0001,
            high: 0x0000_0000_CAFE_BABE,
        },
    );
    state.ymm_upper[1] = XmmValue {
        low: 0x1111_2222_3333_4444,
        high: 0x5555_6666_7777_8888,
    };
    state.mxcsr = 0x0000_9FC0;

    // XSAVE [rdi]  (0F AE /4, modrm 0x27 → [rdi])
    run(&engine, &[0x0F, 0xAE, 0x27], &mut state, &mut memory);

    // XSTATE_BV header at base+512 announces exactly the written components.
    assert_eq!(
        memory.read_u64(base + 512).expect("xstate_bv"),
        0b111,
        "XSTATE_BV must equal the written-state mask"
    );
    // XCOMP_BV: standard (non-compacted) format.
    assert_eq!(memory.read_u64(base + 520).expect("xcomp_bv"), 0);
    // YMM1 upper half at base+576+16.
    assert_eq!(
        memory.read_u64(base + 592).expect("ymm1 upper low"),
        0x1111_2222_3333_4444
    );
    assert_eq!(
        memory.read_u64(base + 600).expect("ymm1 upper high"),
        0x5555_6666_7777_8888
    );
    // MXCSR at base+24, MXCSR_MASK at base+28.
    assert_eq!(memory.read_u32(base + 24).expect("mxcsr"), 0x0000_9FC0);
    assert_eq!(memory.read_u32(base + 28).expect("mxcsr mask"), 0x0000_FFFF);

    // Clobber.
    state.set_xmm(1, XmmValue::default());
    state.ymm_upper[1] = XmmValue::default();
    state.mxcsr = 0;

    // XRSTOR [rdi]  (0F AE /5, modrm 0x2F → [rdi])
    run(&engine, &[0x0F, 0xAE, 0x2F], &mut state, &mut memory);

    assert_eq!(state.xmm[1].low, 0xDEAD_BEEF_0000_0001);
    assert_eq!(state.xmm[1].high, 0x0000_0000_CAFE_BABE);
    assert_eq!(state.ymm_upper[1].low, 0x1111_2222_3333_4444);
    assert_eq!(state.ymm_upper[1].high, 0x5555_6666_7777_8888);
    assert_eq!(state.mxcsr, 0x0000_9FC0);
}

// XSAVEOPT (0F AE /6) uses the same EDX:EAX mask contract and must produce
// the same XSTATE_BV; the emulator always saves every requested component.
#[test]
fn xsaveopt_writes_the_same_honest_xstate_bv() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    let base = 0x31_0000u64;
    memory.map_bytes(base, &[0u8; 1024]);
    state.set(Register::Rsi, base);
    state.set(Register::Rax, 0b111);
    state.set(Register::Rdx, 0);
    state.ymm_upper[0] = XmmValue {
        low: 0x0102_0304_0506_0708,
        high: 0x090A_0B0C_0D0E_0F10,
    };

    // XSAVEOPT [rsi]  (0F AE /6, modrm 0x26 → [rsi])
    run(&engine, &[0x0F, 0xAE, 0x26], &mut state, &mut memory);

    assert_eq!(
        memory.read_u64(base + 512).expect("xstate_bv"),
        0b111,
        "XSAVEOPT XSTATE_BV must equal the written-state mask"
    );
    assert_eq!(
        memory.read_u64(base + 576).expect("ymm0 upper low"),
        0x0102_0304_0506_0708
    );

    // An unsupported requested component (#GP on real hardware) surfaces as
    // an execution error and must not write the area.
    let mut state2 = CpuState::new(GuestArch::X64);
    let mut memory2 = MemoryImage::default();
    state2.set(Register::Rsi, base);
    state2.set(Register::Rax, 1 << 9); // PKRU — not serialized
    state2.set(Register::Rdx, 0);
    let decoded = engine
        .decode_block(&[0x0F, 0xAE, 0x26], 0x1400_000000)
        .expect("decode XSAVEOPT");
    let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower XSAVEOPT");
    let result = engine.execute_ir(&mut state2, &mut memory2, &ir);
    assert!(result.is_err(), "unsupported component mask must error");

    // A misaligned destination (not 64-byte aligned) is rejected.
    state.set(Register::Rsi, base + 32);
    state.set(Register::Rax, 0b111);
    let decoded = engine
        .decode_block(&[0x0F, 0xAE, 0x26], 0x1400_000000)
        .expect("decode XSAVEOPT");
    let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower XSAVEOPT");
    let result = engine.execute_ir(&mut state, &mut memory, &ir);
    assert!(result.is_err(), "misaligned XSAVEOPT must error");
}

// CPUID leaf 0xD reports the serialized XSAVE layout: XCR0 = 0b111, total
// area size 832, XSAVEOPT advertised, and per-component size/offset for AVX.
#[test]
fn cpuid_leaf_d_reports_serialized_xsave_layout() {
    let engine = engine();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    // Sub-leaf 0: XCR0 + area size.
    state.set(Register::Rax, 0xD);
    state.set(Register::Rcx, 0);
    run(&engine, &[0x0F, 0xA2], &mut state, &mut memory); // CPUID
    assert_eq!(state.get(Register::Rax), 0b111, "XCR0 = x87|SSE|AVX");
    assert_eq!(state.get(Register::Rdx), 0, "no high XCR0 bits");
    assert_eq!(state.get(Register::Rbx), 832, "XSAVE area size");

    // Sub-leaf 1: XSAVEOPT (bit 0) advertised, nothing else.
    state.set(Register::Rax, 0xD);
    state.set(Register::Rcx, 1);
    run(&engine, &[0x0F, 0xA2], &mut state, &mut memory); // CPUID
    assert_eq!(state.get(Register::Rax), 0b001, "only XSAVEOPT advertised");

    // Sub-leaf 2: AVX YMM component = 256 bytes at offset 576.
    state.set(Register::Rax, 0xD);
    state.set(Register::Rcx, 2);
    run(&engine, &[0x0F, 0xA2], &mut state, &mut memory); // CPUID
    assert_eq!(state.get(Register::Rax), 256, "AVX component size");
    assert_eq!(state.get(Register::Rbx), 576, "AVX component offset");

    // Sub-leaf 3+ beyond the serialized layout: all zeros.
    state.set(Register::Rax, 0xD);
    state.set(Register::Rcx, 3);
    run(&engine, &[0x0F, 0xA2], &mut state, &mut memory); // CPUID
    assert_eq!(state.get(Register::Rax), 0, "sub-leaf 3 is empty");
    assert_eq!(state.get(Register::Rbx), 0);
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

    let decoded = engine
        .decode_block(&[0xF4], 0x1400_000000)
        .expect("decode HLT");
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

// IN AL/AX/EAX with imm8 or DX addresses read from the configured port-I/O
// bus into the accumulator; the unmapped-port default of the test bus is 0.
#[test]
fn in_reads_zero_into_accumulator() {
    let (engine, _bus) = engine_with_bus();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    // IN AL, 0x60  (E4 60): only AL is cleared; upper bytes preserved.
    state.set(Register::Rax, 0xFFFF_FFFF_FFFF_FFFF);
    run(&engine, &[0xE4, 0x60], &mut state, &mut memory);
    assert_eq!(state.get(Register::Rax), 0xFFFF_FFFF_FFFF_FF00);

    // IN AX, 0x61  (66 E5 61): AX cleared, upper bytes preserved.
    state.set(Register::Rax, 0xFFFF_FFFF_FFFF_FFFF);
    run(&engine, &[0x66, 0xE5, 0x61], &mut state, &mut memory);
    assert_eq!(state.get(Register::Rax), 0xFFFF_FFFF_FFFF_0000);

    // IN EAX, 0x62  (E5 62): EAX zeroed (64-bit zero extension).
    state.set(Register::Rax, 0xFFFF_FFFF_FFFF_FFFF);
    run(&engine, &[0xE5, 0x62], &mut state, &mut memory);
    assert_eq!(state.get(Register::Rax), 0);

    // IN AL, DX  (EC): port from DX.
    state.set(Register::Rax, 0xFFFF_FFFF_FFFF_FFFF);
    state.set(Register::Rdx, 0x63);
    run(&engine, &[0xEC], &mut state, &mut memory);
    assert_eq!(state.get(Register::Rax), 0xFFFF_FFFF_FFFF_FF00);

    // IN AX, DX  (66 ED): port from DX.
    state.set(Register::Rax, 0xFFFF_FFFF_FFFF_FFFF);
    state.set(Register::Rdx, 0x64);
    run(&engine, &[0x66, 0xED], &mut state, &mut memory);
    assert_eq!(state.get(Register::Rax), 0xFFFF_FFFF_FFFF_0000);

    // IN EAX, DX  (ED): port from DX.
    state.set(Register::Rax, 0xFFFF_FFFF_FFFF_FFFF);
    state.set(Register::Rdx, 0x65);
    run(&engine, &[0xED], &mut state, &mut memory);
    assert_eq!(state.get(Register::Rax), 0);
}

// OUT imm8/DX, AL/AX/EAX writes the accumulator to the configured port-I/O
// bus without changing any register.
#[test]
fn out_writes_reach_the_bus() {
    let (engine, bus) = engine_with_bus();
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    // OUT 0x60, AL  (E6 60)
    state.set(Register::Rax, 0x1234);
    run(&engine, &[0xE6, 0x60], &mut state, &mut memory);
    assert_eq!(bus.lock().unwrap().written.get(&0x60), Some(&0x34));
    assert_eq!(state.get(Register::Rax), 0x1234, "OUT must not change RAX");

    // OUT 0x61, AX  (66 E7 61)
    state.set(Register::Rax, 0x1234_5678);
    run(&engine, &[0x66, 0xE7, 0x61], &mut state, &mut memory);
    assert_eq!(bus.lock().unwrap().written.get(&0x61), Some(&0x5678));

    // OUT 0x62, EAX  (E7 62)
    state.set(Register::Rax, 0x89AB_CDEF);
    run(&engine, &[0xE7, 0x62], &mut state, &mut memory);
    assert_eq!(bus.lock().unwrap().written.get(&0x62), Some(&0x89AB_CDEF));

    // OUT DX, AL  (EE)
    state.set(Register::Rax, 0x4321);
    state.set(Register::Rdx, 0x70);
    run(&engine, &[0xEE], &mut state, &mut memory);
    assert_eq!(bus.lock().unwrap().written.get(&0x70), Some(&0x21));

    // OUT DX, AX  (66 EF)
    state.set(Register::Rax, 0x8765_4321);
    state.set(Register::Rdx, 0x71);
    run(&engine, &[0x66, 0xEF], &mut state, &mut memory);
    assert_eq!(bus.lock().unwrap().written.get(&0x71), Some(&0x4321));

    // OUT DX, EAX  (EF)
    state.set(Register::Rax, 0xFEED_FACE);
    state.set(Register::Rdx, 0x72);
    run(&engine, &[0xEF], &mut state, &mut memory);
    assert_eq!(bus.lock().unwrap().written.get(&0x72), Some(&0xFEED_FACE));
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
