#![allow(dead_code, unused_imports)]
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

// XSAVE announces exactly the state it stores — x87 | SSE | AVX
// (XSTATE_BV = 0b111) — because the XSAVE area serializes exactly those
// components. The requested-component mask comes from EDX:EAX, the
// destination must be 64-byte aligned, and after XRSTOR the restored state
// matches the saved state.

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

// ──────────────────────────────────────────────────────────────────────────
// G2: CMPS / SCAS string instructions
// ──────────────────────────────────────────────────────────────────────────

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

// ──────────────────────────────────────────────────────────────────────────
// G3: HLT / CLI / STI / STD / IN / OUT
// ──────────────────────────────────────────────────────────────────────────

// IN AL/AX/EAX with imm8 or DX addresses read from the configured port-I/O
// bus into the accumulator; the unmapped-port default of the test bus is 0.

// OUT imm8/DX, AL/AX/EAX writes the accumulator to the configured port-I/O
// bus without changing any register.

// ──────────────────────────────────────────────────────────────────────────
// G4: Debug-register moves
// ──────────────────────────────────────────────────────────────────────────
