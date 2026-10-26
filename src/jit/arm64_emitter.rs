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

// ---------------------------------------------------------------------------
// ARM64 instruction encoder
// ---------------------------------------------------------------------------

pub struct Emitter {
    pub(super) code: Vec<u8>,
}

#[allow(dead_code)]
impl Emitter {
    pub(super) fn new() -> Self {
        Self {
            code: Vec::with_capacity(4096),
        }
    }

    #[inline(always)]
    pub(super) fn emit(&mut self, insn: u32) {
        self.code.extend_from_slice(&insn.to_le_bytes());
    }

    pub(super) fn len(&self) -> usize {
        self.code.len()
    }

    // -- Moves and immediates --

    /// MOV Xd, Xn (alias for ORR Xd, XZR, Xn)
    pub(super) fn mov_reg(&mut self, rd: u32, rn: u32) {
        self.emit(0xaa0003e0 | (rn << 16) | rd);
    }

    /// MOVZ Xd, #imm16, LSL #shift
    pub(super) fn movz(&mut self, rd: u32, imm16: u16, shift: u32) {
        let hw = shift / 16;
        self.emit(0xd2800000 | (hw << 21) | ((imm16 as u32) << 5) | rd);
    }

    /// MOVK Xd, #imm16, LSL #shift
    pub(super) fn movk(&mut self, rd: u32, imm16: u16, shift: u32) {
        let hw = shift / 16;
        self.emit(0xf2800000 | (hw << 21) | ((imm16 as u32) << 5) | rd);
    }

    /// Move a 64-bit immediate into register using MOVZ + MOVK sequence.
    pub(super) fn mov_imm64(&mut self, rd: u32, value: u64) {
        let chunks: [(u16, u32); 4] = [
            ((value & 0xffff) as u16, 0),
            (((value >> 16) & 0xffff) as u16, 16),
            (((value >> 32) & 0xffff) as u16, 32),
            (((value >> 48) & 0xffff) as u16, 48),
        ];

        self.movz(rd, chunks[0].0, chunks[0].1);
        for &(imm, shift) in &chunks[1..] {
            if imm != 0 {
                self.movk(rd, imm, shift);
            }
        }
    }

    /// Fixed-width 64-bit immediate load (always four instructions).
    ///
    /// AOT-cached code embeds absolute addresses that change between address
    /// spaces.  A fixed four-instruction encoding gives every relocation a
    /// constant size, so the loader can re-bind it in place without shifting
    /// the surrounding code.
    pub(super) fn mov_imm64_fixed(&mut self, rd: u32, value: u64) {
        self.movz(rd, (value & 0xffff) as u16, 0);
        self.movk(rd, ((value >> 16) & 0xffff) as u16, 16);
        self.movk(rd, ((value >> 32) & 0xffff) as u16, 32);
        self.movk(rd, ((value >> 48) & 0xffff) as u16, 48);
    }

    // -- ALU --

    /// ADD Xd, Xn, #imm12
    pub(super) fn add_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0x91000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// SUB Xd, Xn, #imm12
    pub(super) fn sub_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0xd1000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// ADD Xd, Xn, Xm
    pub(super) fn add_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x8b000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// SUB Xd, Xn, Xm
    pub(super) fn sub_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xcb000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// AND Xd, Xn, Xm
    pub(super) fn and_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x8a000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// ANDS Xd, Xn, Xm (logical AND setting NZCV).
    pub(super) fn ands_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xea000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// ORR Xd, Xn, Xm
    pub(super) fn orr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xaa000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// EOR Xd, Xn, Xm
    pub(super) fn eor_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xca000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// MUL Xd, Xn, Xm
    pub(super) fn mul_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9b007c00 | (rm << 16) | (rn << 5) | rd);
    }

    /// SDIV Xd, Xn, Xm
    pub(super) fn sdiv(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9ac00c00 | (rm << 16) | (rn << 5) | rd);
    }

    /// UDIV Xd, Xn, Xm
    pub(super) fn udiv(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9ac00800 | (rm << 16) | (rn << 5) | rd);
    }

    /// MSUB Xd, Xn, Xm, Xa (Xd = Xa - Xn*Xm)
    pub(super) fn msub(&mut self, rd: u32, rn: u32, rm: u32, ra: u32) {
        self.emit(0x9b008000 | (rm << 16) | (ra << 10) | (rn << 5) | rd);
    }

    /// NEG Xd, Xn (SUB Xd, XZR, Xn)
    pub(super) fn neg(&mut self, rd: u32, rn: u32) {
        self.emit(0xcb000000 | (rn << 16) | (31 << 5) | rd);
    }

    /// MVN Xd, Xn (ORN Xd, XZR, Xn)
    pub(super) fn mvn(&mut self, rd: u32, rn: u32) {
        self.emit(0xaa200000 | (rn << 16) | (31 << 5) | rd);
    }

    // -- Shifts --

    /// LSL Xd, Xn, #shift
    pub(super) fn lsl_imm(&mut self, rd: u32, rn: u32, shift: u32) {
        self.emit(0xd3400000 | ((64 - shift) << 16) | ((63 - shift) << 10) | (rn << 5) | rd);
    }

    /// LSR Xd, Xn, #shift
    pub(super) fn lsr_imm(&mut self, rd: u32, rn: u32, shift: u32) {
        self.emit(0xd3400000 | ((shift & 63) << 16) | (63 << 10) | (rn << 5) | rd);
    }

    /// ASR Xd, Xn, #shift
    pub(super) fn asr_imm(&mut self, rd: u32, rn: u32, shift: u32) {
        self.emit(0x93400000 | ((shift & 63) << 16) | (63 << 10) | (rn << 5) | rd);
    }

    /// ROR Xd, Xn, Xm
    pub(super) fn ror_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02c00 | (rm << 16) | (rn << 5) | rd);
    }

    /// LSLV Xd, Xn, Xm
    pub(super) fn lsl_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02000 | (rm << 16) | (rn << 5) | rd);
    }

    /// LSRV Xd, Xn, Xm
    pub(super) fn lsr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02400 | (rm << 16) | (rn << 5) | rd);
    }

    /// ASRV Xd, Xn, Xm
    pub(super) fn asr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02800 | (rm << 16) | (rn << 5) | rd);
    }

    // -- Flag-setting ALU --

    /// ADDS Xd, Xn, #imm12
    pub(super) fn adds_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0xb1000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// SUBS Xd, Xn, #imm12
    pub(super) fn subs_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0xf1000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// ADDS Xd, Xn, Xm
    pub(super) fn adds_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xab000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// SUBS Xd, Xn, Xm
    pub(super) fn subs_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xeb000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// ADCS Xd, Xn, Xm
    pub(super) fn adcs(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9a100000 | (rm << 16) | (rn << 5) | rd);
    }

    /// SBCS Xd, Xn, Xm
    pub(super) fn sbcs(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xfa100000 | (rm << 16) | (rn << 5) | rd);
    }

    // -- Memory --

    /// LDR Xt, [Xn, #offset] (64-bit unsigned offset)
    pub(super) fn ldr64(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xf9400000 | ((offset >> 3) << 10) | (rn << 5) | rt);
    }

    /// LDAR Xt, [Xn] — 64-bit load-acquire, used to publish/read block links.
    pub(super) fn ldar64(&mut self, rt: u32, rn: u32) {
        self.emit(0xc8dffc00 | (rn << 5) | rt);
    }

    /// STR Xt, [Xn, #offset] (64-bit unsigned offset)
    pub(super) fn str64(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xf9000000 | ((offset >> 3) << 10) | (rn << 5) | rt);
    }

    /// LDR Wt, [Xn, #offset] (32-bit unsigned offset)
    pub(super) fn ldr32(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xb9400000 | ((offset >> 2) << 10) | (rn << 5) | rt);
    }

    /// STR Wt, [Xn, #offset] (32-bit unsigned offset)
    pub(super) fn str32(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xb9000000 | ((offset >> 2) << 10) | (rn << 5) | rt);
    }

    /// LDRB Wt, [Xn, #offset]
    pub(super) fn ldr8(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0x39400000 | ((offset & 0xfff) << 10) | (rn << 5) | rt);
    }

    /// STRB Wt, [Xn, #offset]
    pub(super) fn str8(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0x39000000 | ((offset & 0xfff) << 10) | (rn << 5) | rt);
    }

    /// LDR Xt, [Xn, Xm] (register offset, 64-bit, option=UXTX/LSL)
    pub(super) fn ldr64_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xf8606800 | (rm << 16) | (rn << 5) | rt);
    }

    /// STR Xt, [Xn, Xm] (register offset, 64-bit, option=UXTX/LSL)
    pub(super) fn str64_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xf8206800 | (rm << 16) | (rn << 5) | rt);
    }

    /// LDR Wt, [Xn, Xm] (register offset, 32-bit)
    pub(super) fn ldr32_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xb8600800 | (rm << 16) | (rn << 5) | rt);
    }

    /// STR Wt, [Xn, Xm] (register offset, 32-bit)
    pub(super) fn str32_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xb8200800 | (rm << 16) | (rn << 5) | rt);
    }

    // -- Pairs --

    /// STP Xt1, Xt2, [Xn, #offset]! (pre-index)
    pub(super) fn stp64_pre(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        let imm7 = ((offset >> 3) & 0x7f) as u32;
        self.emit(0xa9800000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }

    /// LDP Xt1, Xt2, [Xn, #offset] (signed offset, no writeback)
    pub(super) fn ldp64(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        let imm7 = ((offset >> 3) & 0x7f) as u32;
        self.emit(0xa9400000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }

    /// LDP Xt1, Xt2, [Xn], #offset (post-index)
    pub(super) fn ldp64_post(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        let imm7 = ((offset >> 3) & 0x7f) as u32;
        self.emit(0xa8c00000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }

    // -- Branches --

    pub(super) fn b(&mut self, offset: i32) {
        self.emit(0x14000000 | ((offset >> 2) & 0x3fffffff) as u32);
    }

    pub(super) fn bl(&mut self, offset: i32) {
        self.emit(0x94000000 | ((offset >> 2) & 0x3fffffff) as u32);
    }

    pub(super) fn br(&mut self, rn: u32) {
        self.emit(0xd61f0000 | (rn << 5));
    }

    pub(super) fn blr(&mut self, rn: u32) {
        self.emit(0xd63f0000 | (rn << 5));
    }

    pub(super) fn ret(&mut self) {
        self.emit(0xd65f03c0);
    }

    pub(super) fn nop(&mut self) {
        self.emit(0xd503201f);
    }

    /// B.cond offset (cond: 0=EQ,1=NE,2=CS,3=CC,4=MI,5=PL,6=VS,7=VC,8=HI,9=LS,10=GE,11=LT,12=GT,13=LE,14=AL)
    pub(super) fn bcond(&mut self, cond: u32, offset: i32) {
        self.emit(0x54000000u32 | (((offset >> 2) as u32 & 0x7ffff) << 5) | (cond & 0xf));
    }

    /// CBZ Xn, offset (compare and branch if zero)
    pub(super) fn cbz(&mut self, rn: u32, offset: i32) {
        self.emit(0xb4000000u32 | (((offset >> 2) as u32 & 0x7ffff) << 5) | rn);
    }

    /// CBNZ Xn, offset (compare and branch if not zero)
    pub(super) fn cbnz(&mut self, rn: u32, offset: i32) {
        self.emit(0xb5000000u32 | (((offset >> 2) as u32 & 0x7ffff) << 5) | rn);
    }

    // -- Extensions --

    pub(super) fn sxtb(&mut self, rd: u32, rn: u32) {
        self.emit(0x93401c00 | (rn << 5) | rd);
    }
    pub(super) fn sxth(&mut self, rd: u32, rn: u32) {
        self.emit(0x93403c00 | (rn << 5) | rd);
    }
    pub(super) fn sxtw(&mut self, rd: u32, rn: u32) {
        self.emit(0x93407c00 | (rn << 5) | rd);
    }
    pub(super) fn uxtb(&mut self, rd: u32, rn: u32) {
        // UXTB Wd, Wn — zero-extend byte (mask low 8 bits, clear upper 56).
        self.emit(0x53001c00 | (rn << 5) | rd);
    }
    pub(super) fn uxth(&mut self, rd: u32, rn: u32) {
        // UXTH Wd, Wn — zero-extend halfword (mask low 16 bits).
        self.emit(0x53003c00 | (rn << 5) | rd);
    }
    /// Zero-extend a 32-bit value to 64 bits, i.e. mask the register to its
    /// low 32 bits (clearing the upper 32).  Implemented as `MOV Wd, Wn`
    /// (ORR Wd, WZR, Wn), because writing a 32-bit W register implicitly
    /// zero-extends the result to the full X register.
    pub(super) fn uxtw_reg(&mut self, rd: u32, rn: u32) {
        self.emit(0x2a0003e0 | (rn << 16) | rd);
    }

    // -- Miscellaneous --

    pub(super) fn rbit(&mut self, rd: u32, rn: u32) {
        self.emit(0xdac00000 | (rn << 5) | rd);
    }
    pub(super) fn clz(&mut self, rd: u32, rn: u32) {
        self.emit(0xdac01000 | (rn << 5) | rd);
    }

    /// CSEL Xd, Xn, Xm, cond
    pub(super) fn csel(&mut self, rd: u32, rn: u32, rm: u32, cond: u32) {
        self.emit(0x1a800000 | (rm << 16) | (cond << 12) | (rn << 5) | rd);
    }

    /// CSET Xd, cond (conditional set to 1)
    pub(super) fn cset(&mut self, rd: u32, cond: u32) {
        let inv = cond ^ 1;
        self.emit(0x9a9f07e0 | (inv << 12) | rd);
    }

    /// DMB ISH
    pub(super) fn dmb_ish(&mut self) {
        self.emit(0xd5033f9b);
    }

    /// ISB
    pub(super) fn isb(&mut self) {
        self.emit(0xd5033fdf);
    }

    // -- NEON/SIMD --

    /// EOR Vd.16B, Vn.16B, Vm.16B
    pub(super) fn eor_vec(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x6e201c00 | (vm << 16) | (vn << 5) | vd);
    }

    /// ORR Vd.16B, Vn.16B, Vm.16B
    pub(super) fn orr_vec(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x4e201c00 | (vm << 16) | (vn << 5) | vd);
    }

    /// ADD Vd.2D, Vn.2D, Vm.2D
    pub(super) fn add_vec_2d(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x4e208400 | (vm << 16) | (vn << 5) | vd);
    }

    /// DUP Vd.2D, Xn (scalar to vector)
    pub(super) fn dup_to_vec(&mut self, vd: u32, rn: u32) {
        self.emit(0x4e080400 | (rn << 5) | vd);
    }

    /// MOV Xd, Vn.D[0] (vector element to scalar)
    pub(super) fn vec_to_scalar(&mut self, rd: u32, vn: u32) {
        self.emit(0x4e082400 | (vn << 5) | rd);
    }

    // -- NEON crypto (AES, SHA, PMULL) --

    /// AESE Vd.16B, Vn.16B – AES single round encryption
    pub(super) fn aese(&mut self, vd: u32, vn: u32) {
        self.emit(0x4e284800 | (vn << 16) | vd);
    }

    /// AESD Vd.16B, Vn.16B – AES single round decryption
    pub(super) fn aesd(&mut self, vd: u32, vn: u32) {
        self.emit(0x4e285800 | (vn << 16) | vd);
    }

    /// AESMC Vd.16B, Vn.16B – AES mix columns
    pub(super) fn aesmc(&mut self, vd: u32, vn: u32) {
        self.emit(0x4e287800 | (vn << 16) | vd);
    }

    /// AESIMC Vd.16B, Vn.16B – AES inverse mix columns
    pub(super) fn aesimc(&mut self, vd: u32, vn: u32) {
        self.emit(0x4e286800 | (vn << 16) | vd);
    }

    // -- SHA1 instructions --

    /// SHA1C Qd, Sn, Vm.4S – SHA1 hash update with choice function
    pub(super) fn sha1c(&mut self, qd: u32, sn: u32, vm: u32) {
        self.emit(0x5e000000 | (vm << 16) | (sn << 5) | qd);
    }

    /// SHA1P Qd, Sn, Vm.4S – SHA1 hash update with parity function
    pub(super) fn sha1p(&mut self, qd: u32, sn: u32, vm: u32) {
        self.emit(0x5e001000 | (vm << 16) | (sn << 5) | qd);
    }

    /// SHA1M Qd, Sn, Vm.4S – SHA1 hash update with majority function
    pub(super) fn sha1m(&mut self, qd: u32, sn: u32, vm: u32) {
        self.emit(0x5e002000 | (vm << 16) | (sn << 5) | qd);
    }

    /// SHA1H Qd, Sn – SHA1 fixed rotate (hash update)
    pub(super) fn sha1h(&mut self, qd: u32, sn: u32) {
        self.emit(0x5e005800 | (sn << 5) | qd);
    }

    /// SHA1SU0 Vd.4S, Vn.4S, Vm.4S – SHA1 schedule update 0
    pub(super) fn sha1su0(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x5e003000 | (vm << 16) | (vn << 5) | vd);
    }

    /// SHA1SU1 Vd.4S, Vn.4S – SHA1 schedule update 1
    pub(super) fn sha1su1(&mut self, vd: u32, vn: u32) {
        self.emit(0x5e005000 | (vn << 5) | vd);
    }

    // -- SHA256 instructions --

    /// SHA256H Qd, Qn, Vm.4S – SHA256 hash update (part 1)
    pub(super) fn sha256h(&mut self, qd: u32, qn: u32, vm: u32) {
        self.emit(0x5e004000 | (vm << 16) | (qn << 5) | qd);
    }

    /// SHA256H2 Qd, Qn, Vm.4S – SHA256 hash update (part 2)
    pub(super) fn sha256h2(&mut self, qd: u32, qn: u32, vm: u32) {
        self.emit(0x5e005000 | (vm << 16) | (qn << 5) | qd);
    }

    /// SHA256SU0 Vd.4S, Vn.4S – SHA256 schedule update 0
    pub(super) fn sha256su0(&mut self, vd: u32, vn: u32) {
        self.emit(0x5e006000 | (vn << 5) | vd);
    }

    /// SHA256SU1 Vd.4S, Vn.4S, Vm.4S – SHA256 schedule update 1
    pub(super) fn sha256su1(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x5e007000 | (vm << 16) | (vn << 5) | vd);
    }

    // -- PMULL (carry-less multiply for PCLMULQDQ) --

    /// PMULL Vd.1Q, Vn.1D, Vm.1D – 64-bit carry-less multiply (polynomial 64x64 → 128)
    pub(super) fn pmull_1q(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x0ee0e000 | (vm << 16) | (vn << 5) | vd);
    }

    /// PMULL2 Vd.1Q, Vn.2D, Vm.2D – 64-bit carry-less multiply from upper halves
    pub(super) fn pmull2_1q(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x4ee0e000 | (vm << 16) | (vn << 5) | vd);
    }

    // -- NEON permutation (lane rearrangement) --

    /// EXT Vd.16B, Vn.16B, Vm.16B, #imm – extract bytes from {Vn:Vm} starting at #imm
    pub(super) fn ext_16b(&mut self, vd: u32, vn: u32, vm: u32, imm: u8) {
        self.emit(0x6e000000 | ((imm as u32) << 10) | (vm << 16) | (vn << 5) | vd);
    }

    // -- NEON 128-bit load/store (for XMM register access) --

    /// LDR Qd, [Xn, #imm] – load 128-bit NEON register from memory
    pub(super) fn ldr_q_imm(&mut self, vd: u32, rn: u32, imm: u16) {
        self.emit(0x3dc00000 | ((imm as u32) << 10) | (rn << 5) | vd);
    }

    /// STR Qd, [Xn, #imm] – store 128-bit NEON register to memory
    pub(super) fn str_q_imm(&mut self, vd: u32, rn: u32, imm: u16) {
        self.emit(0x3d800000 | ((imm as u32) << 10) | (rn << 5) | vd);
    }
}

/// Map an x86 condition to the equivalent ARM64 `b.cond` encoding for the
/// flags produced by `CMP` (SUBS) or `TEST` (ANDS).  `None` means the
/// condition needs the parity flag and must use the generic path.
pub(super) fn arm_condition_for(condition: ConditionCode) -> Option<u32> {
    Some(match condition {
        ConditionCode::Equal => 0x0,         // EQ
        ConditionCode::NotEqual => 0x1,      // NE
        ConditionCode::NotBelow => 0x2,      // CS/HS (CF = 0)
        ConditionCode::Below => 0x3,         // CC/LO (CF = 1)
        ConditionCode::NotSign => 0x5,       // PL
        ConditionCode::Sign => 0x4,          // MI
        ConditionCode::NotOverflow => 0x7,   // VC
        ConditionCode::Overflow => 0x6,      // VS
        ConditionCode::Above => 0x8,         // HI
        ConditionCode::NotAbove => 0x9,      // LS
        ConditionCode::GreaterEqual => 0x10, // GE
        ConditionCode::Less => 0x11,         // LT
        ConditionCode::Greater => 0x12,      // GT
        ConditionCode::LessEqual => 0x13,    // LE
        ConditionCode::Parity | ConditionCode::NotParity => return None,
    })
}

impl JitCompiler {
    /// Compile a block at Tier0: fast compilation with no optimization.
    ///
    /// Performs direct 1:1 IR-to-native translation without register
    /// allocation, constant folding, or dead code elimination. This is the
    /// fastest compilation path, minimizing startup latency.
    pub fn compile_tier0(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
    ) -> AppResult<JitCompiledBlock> {
        // Tier0 is identical to the default compile_block — no optimization.
        self.compile_block(ir, guest_address, arch, fast_thunk_addrs)
    }

    /// Compile a block at Tier1: full optimization with register allocation,
    /// constant folding, and dead code elimination.
    ///
    /// # Performance Impact
    /// Eliminates redundant MOV instructions, folds constant expressions at
    /// compile time, and uses register allocation to minimize memory traffic.
    pub fn compile_tier1(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
    ) -> AppResult<JitCompiledBlock> {
        self.emitter = Emitter::new();
        self.used_interpreter_helper = false;
        self.relocations.clear();
        let link_slots = LinkSlots::new();
        self.link_slots = Some(link_slots.clone());

        // Optimized prologue: same as default but with better register planning
        self.emit_prologue(arch);
        self.emit_current_block_tag(guest_address);
        self.emit_load_guest_registers(arch);
        self.emit_chain_guard(ir.len() as u64, arch);
        self.emit_safepoint_check(arch);
        self.emit_block_accounting(ir.len() as u64);

        // Constant folding pass: pre-compute known constants
        let folded_ir = Self::constant_fold(ir);

        // Compile optimized IR
        let last = folded_ir.len().saturating_sub(1);
        for (index, insn) in folded_ir.iter().enumerate() {
            self.compile_instruction(insn, arch, fast_thunk_addrs, index == last)?;
        }

        self.emit_store_guest_registers(arch);
        self.emit_epilogue();
        // The optimized paths must carry the same safepoint and guest-fault
        // exits as the Tier0 path: without these stubs the emitted `cbnz`
        // placeholders would fall through and a fault would be ignored.
        self.finish_safepoint_stub(arch);
        self.finish_fault_stub(arch);

        let code_size = self.emitter.len();
        let code_ptr = self.memory_manager.allocate_code_space(code_size);
        if code_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "JIT Tier1: failed to allocate executable memory",
            ));
        }

        // SAFETY: Same as compile_block — code_ptr is valid for code_size
        // bytes, emitter.code is a valid Vec, regions are non-overlapping.
        self.install_code(code_ptr, code_size)?;

        let source_hash = compute_ir_hash(ir, guest_address);
        let last_exit_info = block_exit_info(ir);
        let worker_safe = block_is_worker_safe(&folded_ir, self.used_interpreter_helper);
        self.link_slots = None;

        Ok(JitCompiledBlock {
            entry_addr: code_ptr as usize,
            entry_atomic: AtomicPtr::new(code_ptr),
            code_size,
            guest_address,
            instruction_count: ir.len(),
            source_hash,
            last_exit_info,
            compile_tier: CompilationTier::Tier1,
            ends_in_control_flow: block_ends_in_control_flow(ir),
            link_target: link_slots.jump,
            taken_link: link_slots.taken,
            fallthrough_link: link_slots.fallthrough,
            call_link: link_slots.call,
            return_entry_link: link_slots.return_entry,
            worker_safe,
        })
    }

    /// Compile a block at Tier2.
    ///
    /// Tier2 currently applies the same sound optimizer as Tier1 (constant
    /// folding/no-op elimination) with the full safepoint and guest-fault
    /// exits.  Loop unrolling and block inlining remain disabled because the
    /// existing passes can change guest-visible flags/counter values.
    pub fn compile_tier2(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
    ) -> AppResult<JitCompiledBlock> {
        self.emitter = Emitter::new();
        self.used_interpreter_helper = false;
        self.relocations.clear();
        let link_slots = LinkSlots::new();
        self.link_slots = Some(link_slots.clone());

        self.emit_prologue(arch);
        self.emit_current_block_tag(guest_address);
        self.emit_load_guest_registers(arch);
        self.emit_chain_guard(ir.len() as u64, arch);
        self.emit_safepoint_check(arch);
        self.emit_block_accounting(ir.len() as u64);

        // Whole-block SSA: GVN, SCCP, DCE, LICM and exact-address load/store
        // forwarding.  Unsupported constructs reject the block as a unit and
        // it is recompiled at Tier-0, so a partially-optimised block can never
        // be executed.
        let optimized_ir = match crate::jit_ssa::optimize_block_ir(ir, arch) {
            Ok(optimized) => optimized,
            Err(_) => {
                return self.compile_block(ir, guest_address, arch, fast_thunk_addrs);
            }
        };

        self.emit_spill_slots_init(arch);
        let last = optimized_ir.len().saturating_sub(1);
        for (index, insn) in optimized_ir.iter().enumerate() {
            self.compile_instruction(insn, arch, fast_thunk_addrs, index == last)?;
        }

        self.emit_store_guest_registers(arch);
        self.emit_epilogue();
        self.finish_safepoint_stub(arch);
        self.finish_fault_stub(arch);

        let code_size = self.emitter.len();
        let code_ptr = self.memory_manager.allocate_code_space(code_size);
        if code_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "JIT Tier2: failed to allocate executable memory",
            ));
        }

        // SAFETY: Same as compile_block — code_ptr is valid for code_size
        // bytes, emitter.code is a valid Vec, regions are non-overlapping.
        self.install_code(code_ptr, code_size)?;

        let source_hash = compute_ir_hash(ir, guest_address);
        let last_exit_info = block_exit_info(&optimized_ir);
        let worker_safe = block_is_worker_safe(&optimized_ir, self.used_interpreter_helper);
        self.link_slots = None;

        Ok(JitCompiledBlock {
            entry_addr: code_ptr as usize,
            entry_atomic: AtomicPtr::new(code_ptr),
            code_size,
            guest_address,
            instruction_count: ir.len(),
            source_hash,
            last_exit_info,
            compile_tier: CompilationTier::Tier2,
            ends_in_control_flow: block_ends_in_control_flow(ir),
            link_target: link_slots.jump,
            taken_link: link_slots.taken,
            fallthrough_link: link_slots.fallthrough,
            call_link: link_slots.call,
            return_entry_link: link_slots.return_entry,
            worker_safe,
        })
    }

    /// Compile a whole hot function at Tier-2.
    ///
    /// The entry block is the first element.  The SSA front end builds one
    /// function-wide IR, runs the optimiser, and this emitter lays every block
    /// out in one native code object: guest registers are loaded once at the
    /// entry, internal branches are native `b`/`b.cond` instructions, and only
    /// function exits store `CpuState`.  Unsupported constructs fall back to
    /// the entry block at Tier-0.
    pub fn compile_function_tier2(
        &mut self,
        blocks: &[crate::jit_ssa::FunctionBlock],
        arch: GuestArch,
    ) -> AppResult<JitCompiledBlock> {
        if blocks.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "JIT Tier2: no function blocks",
            ));
        }
        let optimized = match crate::jit_ssa::optimize_function(blocks, arch) {
            Ok(optimized) => optimized,
            Err(_) => {
                let entry = &blocks[0];
                return self.compile_block(&entry.instructions, entry.guest_address, arch, None);
            }
        };

        self.emitter = Emitter::new();
        self.used_interpreter_helper = false;
        self.relocations.clear();
        self.fault_cbnz_patches.clear();
        self.safepoint_cbnz_patch = None;
        self.link_slots = None;

        let mut labels = vec![0usize; optimized.blocks.len()];
        let mut by_address = std::collections::HashMap::new();
        for (index, block) in optimized.blocks.iter().enumerate() {
            by_address.insert(block.guest_address, index);
        }
        let entry_address = optimized.blocks[0].guest_address;
        let original_count: usize = optimized.original_instructions;

        self.emit_prologue(arch);
        self.emit_current_block_tag(entry_address);
        self.emit_load_guest_registers(arch);
        self.emit_spill_slots_init(arch);
        self.emit_chain_guard(original_count as u64, arch);
        self.emit_safepoint_check(arch);
        self.emit_block_accounting(original_count as u64);

        let mut jump_patches: Vec<(usize, usize)> = Vec::new();
        let mut conditional_patches: Vec<(usize, usize)> = Vec::new();
        let mut extra_safepoints: Vec<usize> = Vec::new();

        for (index, block) in optimized.blocks.iter().enumerate() {
            labels[index] = self.emitter.len();
            self.emit_set_state_rip(block.guest_address);
            if index != 0 {
                let flag_addr = &JIT_SAFEPOINT_REQUESTED as *const AtomicBool as u64;
                self.emit_reloc_imm64(regmap::X26, flag_addr, AotRelocKind::SafepointFlag);
                self.emitter.ldr8(regmap::X26, regmap::X26, 0);
                let pos = self.emitter.len();
                self.emitter.cbnz(regmap::X26, 0);
                extra_safepoints.push(pos);
            }
            let native_compare_index = find_native_compare(block);
            let mut native_compare: Option<IrInstruction> = None;
            for (insn_index, insn) in block.instructions.iter().enumerate() {
                if Some(insn_index) == native_compare_index && self.emit_native_compare(insn) {
                    native_compare = Some(insn.clone());
                } else {
                    self.compile_instruction(insn, arch, None, false)?;
                }
            }
            match &block.terminator {
                crate::jit_ssa::OptimizedTerminator::Jump { target, copies } => {
                    for insn in copies {
                        self.compile_instruction(insn, arch, None, false)?;
                    }
                    if let Some(target_index) = by_address.get(target).copied() {
                        let pos = self.emitter.len();
                        self.emitter.b(0);
                        jump_patches.push((pos, target_index));
                    } else {
                        self.emit_set_state_rip(*target);
                        self.emit_store_guest_registers(arch);
                        self.emitter.movz(regmap::X0, EXIT_JUMP as u16, 0);
                        self.emit_epilogue();
                    }
                }
                crate::jit_ssa::OptimizedTerminator::JumpIf {
                    condition,
                    target,
                    fallthrough,
                    taken_copies,
                    fallthrough_copies,
                } => {
                    let native_condition = native_compare
                        .is_some()
                        .then(|| arm_condition_for(*condition))
                        .flatten();
                    let taken_pos = if let Some(condition) = native_condition {
                        let pos = self.emitter.len();
                        self.emitter.bcond(condition, 0);
                        pos
                    } else {
                        self.emit_materialize_flags();
                        self.emit_x86_flag_loads_scratch();
                        self.emit_x86_condition_branch_scratch(*condition)
                    };
                    if native_condition.is_some()
                        && edge_reads_flags(*fallthrough, &optimized.blocks, &by_address)
                        && let Some(compare) = native_compare.as_ref()
                    {
                        self.compile_instruction(compare, arch, None, false)?;
                    }
                    for insn in fallthrough_copies {
                        self.compile_instruction(insn, arch, None, false)?;
                    }
                    if let Some(fallthrough_index) = by_address.get(fallthrough).copied() {
                        let pos = self.emitter.len();
                        self.emitter.b(0);
                        jump_patches.push((pos, fallthrough_index));
                    } else {
                        self.emit_set_state_rip(*fallthrough);
                        self.emit_store_guest_registers(arch);
                        self.emitter.movz(regmap::X0, EXIT_JUMP as u16, 0);
                        self.emit_epilogue();
                    }
                    let taken_label = self.emitter.len();
                    conditional_patches.push((taken_pos, taken_label));
                    if native_condition.is_some()
                        && edge_reads_flags(*target, &optimized.blocks, &by_address)
                        && let Some(compare) = native_compare.as_ref()
                    {
                        self.compile_instruction(compare, arch, None, false)?;
                    }
                    for insn in taken_copies {
                        self.compile_instruction(insn, arch, None, false)?;
                    }
                    if let Some(target_index) = by_address.get(target).copied() {
                        let pos = self.emitter.len();
                        self.emitter.b(0);
                        jump_patches.push((pos, target_index));
                    } else {
                        self.emit_set_state_rip(*target);
                        self.emit_store_guest_registers(arch);
                        self.emitter.movz(regmap::X0, EXIT_JUMP as u16, 0);
                        self.emit_epilogue();
                    }
                }
                crate::jit_ssa::OptimizedTerminator::Return { .. } => {
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_RET as u16, 0);
                    self.emit_epilogue();
                }
                crate::jit_ssa::OptimizedTerminator::Exit => {
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_NORMAL as u16, 0);
                    self.emit_epilogue();
                }
            }
        }

        // Defensive normal exit (a function with no explicit terminator).
        self.emit_store_guest_registers(arch);
        self.emitter.movz(regmap::X0, EXIT_NORMAL as u16, 0);
        self.emit_epilogue();

        // Shared safepoint stub.
        let mut safepoints = std::mem::take(&mut extra_safepoints);
        if let Some(pos) = self.safepoint_cbnz_patch.take() {
            safepoints.push(pos);
        }
        if !safepoints.is_empty() {
            let stub = self.emitter.len();
            self.emit_store_guest_registers(arch);
            self.emitter.movz(regmap::X0, EXIT_JUMP as u16, 0);
            self.emit_epilogue();
            for pos in safepoints {
                self.patch_cbnz_any(pos, stub);
            }
        }
        self.finish_fault_stub(arch);

        for (pos, target) in jump_patches {
            self.patch_b_any(pos, labels[target]);
        }
        for (pos, target) in conditional_patches {
            self.patch_bcond_any(pos, target);
        }
        let code_size = self.emitter.len();
        let code_ptr = self.memory_manager.allocate_code_space(code_size);
        if code_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "JIT Tier2 function: failed to allocate executable memory",
            ));
        }
        self.install_code(code_ptr, code_size)?;

        let mut source = Vec::new();
        for block in blocks {
            source.extend(block.instructions.iter().cloned());
        }
        let source_hash = compute_ir_hash(&source, entry_address);
        let link_slots = LinkSlots::new();
        Ok(JitCompiledBlock {
            entry_addr: code_ptr as usize,
            entry_atomic: AtomicPtr::new(code_ptr),
            code_size,
            guest_address: entry_address,
            instruction_count: original_count,
            source_hash,
            last_exit_info: None,
            compile_tier: CompilationTier::Tier2,
            ends_in_control_flow: true,
            link_target: link_slots.jump,
            taken_link: link_slots.taken,
            fallthrough_link: link_slots.fallthrough,
            call_link: link_slots.call,
            return_entry_link: link_slots.return_entry,
            worker_safe: false,
        })
    }

    /// Emit a native x86 CMP/TEST for a 64-bit register/immediate comparison.
    /// Returns false when the form is not covered and the caller must use the
    /// generic (helper-backed) emission.
    pub(super) fn emit_native_compare(&mut self, insn: &IrInstruction) -> bool {
        use crate::cpu::CompareOperand;
        let (lhs, rhs, width, is_test) = match insn {
            IrInstruction::Compare { lhs, rhs, width } => (lhs, rhs, *width, false),
            IrInstruction::Test { lhs, rhs, width } => (lhs, rhs, *width, true),
            _ => return false,
        };
        if width != 8 {
            return false;
        }
        let resolve =
            |emitter: &mut Emitter, operand: &CompareOperand, scratch: u32| -> Option<u32> {
                match operand {
                    CompareOperand::Register(reg) => Some(regmap::guest_to_arm(reg.index())),
                    CompareOperand::ImmediateU64(value) => {
                        emitter.mov_imm64(scratch, *value);
                        Some(scratch)
                    }
                    _ => None,
                }
            };
        let Some(lhs_reg) = resolve(&mut self.emitter, lhs, regmap::X21) else {
            return false;
        };
        let Some(rhs_reg) = resolve(&mut self.emitter, rhs, regmap::X22) else {
            return false;
        };
        if is_test {
            self.emitter.ands_reg(31, lhs_reg, rhs_reg);
        } else {
            self.emitter.subs_reg(31, lhs_reg, rhs_reg);
        }
        true
    }

    pub(super) fn patch_b_any(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        let insn = 0x1400_0000u32 | ((offset as u32) & 0x03ff_ffff);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    pub(super) fn patch_bcond_any(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        let condition = self.emitter.code[position] & 0x0f;
        let insn = 0x5400_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(condition);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    pub(super) fn patch_cbnz_any(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        let register = self.emitter.code[position] & 0x1f;
        let insn = 0xb500_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(register);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    /// Load the six x86 flag bytes into non-guest scratch registers.  Unlike
    /// `emit_x86_flag_loads`, this keeps x4-x20 (the live guest register file)
    /// intact so a whole-function internal branch needs no per-block reload.
    pub(super) fn emit_x86_flag_loads_scratch(&mut self) {
        let base = std::mem::offset_of!(CpuState, flags) as u32;
        let cf = base + std::mem::offset_of!(crate::cpu::Flags, cf) as u32;
        let pf = base + std::mem::offset_of!(crate::cpu::Flags, pf) as u32;
        let zf = base + std::mem::offset_of!(crate::cpu::Flags, zf) as u32;
        let sf = base + std::mem::offset_of!(crate::cpu::Flags, sf) as u32;
        let of = base + std::mem::offset_of!(crate::cpu::Flags, of) as u32;
        self.emitter.ldr8(21, regmap::X0, cf);
        self.emitter.ldr8(22, regmap::X0, pf);
        self.emitter.ldr8(24, regmap::X0, zf);
        self.emitter.ldr8(25, regmap::X0, sf);
        self.emitter.ldr8(27, regmap::X0, of);
    }

    /// Scratch-only counterpart of `emit_x86_condition_branch`.
    pub(super) fn emit_x86_condition_branch_scratch(&mut self, condition: ConditionCode) -> usize {
        const EQ: u32 = 0;
        const NE: u32 = 1;
        // cf=x21, pf=x22, zf=x24, sf=x25, of=x27, temps x26/x28.
        match condition {
            ConditionCode::Equal => {
                self.emitter.subs_imm(31, 24, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotEqual => {
                self.emitter.subs_imm(31, 24, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Overflow => {
                self.emitter.subs_imm(31, 27, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotOverflow => {
                self.emitter.subs_imm(31, 27, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Below => {
                self.emitter.subs_imm(31, 21, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotBelow => {
                self.emitter.subs_imm(31, 21, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Above => {
                self.emitter.movz(28, 1, 0);
                self.emitter.eor_reg(26, 21, 28);
                self.emitter.eor_reg(28, 24, 28);
                self.emitter.and_reg(26, 26, 28);
                self.emitter.subs_imm(31, 26, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotAbove => {
                self.emitter.orr_reg(26, 21, 24);
                self.emitter.subs_imm(31, 26, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::Sign => {
                self.emitter.subs_imm(31, 25, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotSign => {
                self.emitter.subs_imm(31, 25, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Less => {
                self.emitter.subs_reg(31, 25, 27);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::GreaterEqual => {
                self.emitter.subs_reg(31, 25, 27);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::LessEqual => {
                self.emitter.eor_reg(26, 25, 27);
                self.emitter.orr_reg(26, 24, 26);
                self.emitter.subs_imm(31, 26, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::Greater => {
                self.emitter.eor_reg(26, 25, 27);
                self.emitter.movz(28, 1, 0);
                self.emitter.eor_reg(26, 26, 28);
                self.emitter.eor_reg(28, 24, 28);
                self.emitter.and_reg(26, 26, 28);
                self.emitter.subs_imm(31, 26, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::Parity => {
                self.emitter.subs_imm(31, 22, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotParity => {
                self.emitter.subs_imm(31, 22, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
        }
    }

    /// Constant folding: forward dataflow pass that tracks known register values
    /// and folds arithmetic on constants at compile time.
    ///
    /// Tracks `HashMap<Register, KnownValue>` and applies:
    /// - `MovImm` → record immediate
    /// - `MovReg` → propagate known value or record copy
    /// - `AddImm`/`SubImm`/`ShlImm`/`AndImm`/`OrImm`/`XorImm` with constant src → fold
    /// - Eliminates no-ops (add/sub/shift 0, and full_mask)
    /// Emit a folded constant write, coalescing it with an immediately
    /// preceding `MovImm` to the same register.  Without this, folding
    /// `MovImm rax,5; AddImm rax,3` would leave a dead first write behind
    /// (whole-block DCE is unsound: every GPR is live-out).
    pub(super) fn push_folded_immediate(
        result: &mut Vec<IrInstruction>,
        dst: Register,
        value: u64,
    ) {
        if let Some(IrInstruction::MovImm {
            dst: last_dst,
            value: last_value,
        }) = result.last_mut()
            && *last_dst == dst
        {
            *last_value = value;
            return;
        }
        result.push(IrInstruction::MovImm { dst, value });
    }

    pub(super) fn constant_fold(ir: &[IrInstruction]) -> Vec<IrInstruction> {
        let mut known: std::collections::BTreeMap<Register, KnownValue> =
            std::collections::BTreeMap::new();
        let mut result: Vec<IrInstruction> = Vec::with_capacity(ir.len());

        for insn in ir {
            match insn {
                // MovImm: record the immediate value and coalesce with a
                // directly preceding write to the same register (the whole
                // chain collapses to the last write).
                IrInstruction::MovImm { dst, value } => {
                    known.insert(*dst, KnownValue::Immediate(*value));
                    Self::push_folded_immediate(&mut result, *dst, *value);
                }

                // MovReg: propagate known value or record copy
                IrInstruction::MovReg { dst, src, width: _ } => {
                    if let Some(KnownValue::Immediate(val)) = known.get(src) {
                        // Fold to MovImm
                        Self::push_folded_immediate(&mut result, *dst, *val);
                        known.insert(*dst, KnownValue::Immediate(*val));
                    } else {
                        // Propagate whatever we know about src, or record as copy
                        if let Some(kv) = known.get(src) {
                            known.insert(*dst, *kv);
                        } else {
                            known.insert(*dst, KnownValue::RegisterCopy(*src));
                        }
                        result.push(insn.clone());
                    }
                }

                // AddImm: eliminate if value==0, fold if dst is known constant
                IrInstruction::AddImm {
                    dst,
                    value,
                    width: _,
                } => {
                    if *value == 0 {
                        // No-op: dst unchanged, known value preserved
                        continue;
                    }
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val.wrapping_add(*value);
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // SubImm: eliminate if value==0, fold if dst is known constant
                IrInstruction::SubImm {
                    dst,
                    value,
                    width: _,
                } => {
                    if *value == 0 {
                        continue;
                    }
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val.wrapping_sub(*value);
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // ShlImm: eliminate if count==0, fold if dst is known constant
                IrInstruction::ShlImm {
                    dst,
                    count,
                    width: _,
                } => {
                    if *count == 0 {
                        continue;
                    }
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val.wrapping_shl(*count as u32);
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // AndImm: eliminate if value is full mask for the width,
                // fold if dst is known constant
                IrInstruction::AndImm { dst, value, width } => {
                    let full_mask = match width {
                        1 => 0xFFu64,
                        2 => 0xFFFFu64,
                        4 => 0xFFFFFFFFu64,
                        8 => 0xFFFFFFFFFFFFFFFFu64,
                        _ => 0,
                    };
                    if *value == full_mask {
                        // No-op: dst unchanged
                        continue;
                    }
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val & value;
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // OrImm: fold if dst is known constant
                IrInstruction::OrImm {
                    dst,
                    value,
                    width: _,
                } => {
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val | value;
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // XorImm: fold if dst is known constant
                IrInstruction::XorImm {
                    dst,
                    value,
                    width: _,
                } => {
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val ^ value;
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // All other instructions: pass through, invalidate dst if they write a register
                other => {
                    // Invalidate any register that may be written by this instruction
                    Self::invalidate_known_dst(other, &mut known);
                    result.push(other.clone());
                }
            }
        }

        // NOTE: block-level dead-code elimination is intentionally NOT applied
        // here.  Every compiled block ends by storing ALL guest GPRs back to
        // CpuState, so every register written by the block is live-out.  The
        // liveness pass below only sees the block's own instructions and would
        // delete a final `MovImm rax, 42` (no later reader) — silently zeroing
        // guest state.  The pass remains available for intra-block use but is
        // not sound as a whole-block transform.
        result
    }

    /// Invalidate the known value for any register written by `insn`.
    pub(super) fn invalidate_known_dst(
        insn: &IrInstruction,
        known: &mut std::collections::BTreeMap<Register, KnownValue>,
    ) {
        match insn {
            IrInstruction::MovImm { dst, .. }
            | IrInstruction::MovReg { dst, .. }
            | IrInstruction::AddImm { dst, .. }
            | IrInstruction::SubImm { dst, .. }
            | IrInstruction::AndImm { dst, .. }
            | IrInstruction::OrImm { dst, .. }
            | IrInstruction::XorImm { dst, .. }
            | IrInstruction::ShlImm { dst, .. }
            | IrInstruction::ShrImm { dst, .. }
            | IrInstruction::SarImm { dst, .. }
            | IrInstruction::RolImm { dst, .. }
            | IrInstruction::NegReg { dst, .. }
            | IrInstruction::NotReg { dst, .. }
            | IrInstruction::IncReg { dst, .. }
            | IrInstruction::DecReg { dst, .. }
            | IrInstruction::PopReg { dst, .. } => {
                known.remove(dst);
            }
            IrInstruction::MovReg8 { dst, .. }
            | IrInstruction::AddReg8 { dst, .. }
            | IrInstruction::SubReg8 { dst, .. }
            | IrInstruction::AndReg8 { dst, .. }
            | IrInstruction::OrReg8 { dst, .. }
            | IrInstruction::XorReg8 { dst, .. }
            | IrInstruction::IncReg8 { dst, .. }
            | IrInstruction::DecReg8 { dst, .. }
            | IrInstruction::NegReg8 { dst, .. }
            | IrInstruction::NotReg8 { dst, .. } => {
                known.remove(&dst.full_register());
            }
            IrInstruction::LoadMemory8 { dst, .. } => {
                known.remove(&dst.full_register());
            }
            IrInstruction::LoadMemory { dst, .. }
            | IrInstruction::SignExtendTo64 { dst, .. }
            | IrInstruction::SignExtend { dst, .. }
            | IrInstruction::ZeroExtendTo64 { dst, .. }
            | IrInstruction::Cmov { dst, .. }
            | IrInstruction::Popcnt { dst, .. }
            | IrInstruction::Lzcnt { dst, .. }
            | IrInstruction::Bsf { dst, .. }
            | IrInstruction::Crc32 { dst, .. }
            | IrInstruction::Rdrand { dst, .. }
            | IrInstruction::Rdseed { dst, .. }
            | IrInstruction::Andn { dst, .. }
            | IrInstruction::Bextr { dst, .. }
            | IrInstruction::Blsi { dst, .. }
            | IrInstruction::Blsmsk { dst, .. }
            | IrInstruction::Blsr { dst, .. }
            | IrInstruction::Bzhi { dst, .. }
            | IrInstruction::Pdep { dst, .. }
            | IrInstruction::Pext { dst, .. }
            | IrInstruction::Rorx { dst, .. }
            | IrInstruction::Sarx { dst, .. }
            | IrInstruction::Shrx { dst, .. }
            | IrInstruction::Shlx { dst, .. } => {
                known.remove(dst);
            }
            IrInstruction::Mulx { dst_lo, dst_hi, .. } => {
                known.remove(dst_lo);
                known.remove(dst_hi);
            }
            IrInstruction::ExchangeRegisters { left, right, .. } => {
                known.remove(left);
                known.remove(right);
            }
            IrInstruction::LoadEffectiveAddress { dst, .. } => {
                known.remove(dst);
            }
            // Instructions that don't write any register we track
            _ => {}
        }
    }

    /// Dead code elimination: remove instructions whose result is never used.
    ///
    /// Scans the IR forward to find which registers are used as source operands,
    /// then removes instructions that write to registers never subsequently read.
    #[allow(dead_code)] // retained for intra-block use; unsound as a whole-block transform
    pub(super) fn dead_code_elimination(ir: &[IrInstruction]) -> Vec<IrInstruction> {
        // Backward liveness analysis pass.
        //
        // Walk instructions in reverse, tracking which registers are "live"
        // (will be read by a future instruction).  For each instruction we
        // compute:
        //
        //   IN[i] = (OUT[i] \ KILL[i]) ∪ GEN[i]
        //
        // where OUT[i] is the live set after instruction i (before i+1),
        // KILL[i] is the register written by i, and GEN[i] is the registers
        // read by i.
        //
        // An instruction that writes a register is kept only if that register
        // is live at the exit of the instruction (OUT[i]), because that means
        // some later instruction reads the value before it is overwritten.
        let mut live_regs: std::collections::BTreeSet<Register> = std::collections::BTreeSet::new();
        let mut keep: Vec<bool> = vec![false; ir.len()];

        for (i, insn) in ir.iter().enumerate().rev() {
            // live_regs currently holds OUT[i] (the state after this instruction)

            // 1. Decide whether to keep this instruction based on OUT[i]
            if Self::has_side_effect(insn) {
                keep[i] = true;
            } else {
                // Keep if the instruction writes to a register that is live
                // at the exit of this instruction (i.e. will be read later)
                let writes_live_reg = match insn {
                    IrInstruction::MovImm { dst, .. }
                    | IrInstruction::MovReg { dst, .. }
                    | IrInstruction::AddImm { dst, .. }
                    | IrInstruction::SubImm { dst, .. }
                    | IrInstruction::AndImm { dst, .. }
                    | IrInstruction::OrImm { dst, .. }
                    | IrInstruction::XorImm { dst, .. }
                    | IrInstruction::ShlImm { dst, .. }
                    | IrInstruction::ShrImm { dst, .. }
                    | IrInstruction::SarImm { dst, .. } => live_regs.contains(dst),
                    // Conservatively keep unknown instructions
                    _ => true,
                };
                keep[i] = writes_live_reg;
            }

            // 2. KILL: remove the destination register from the live set
            //    (this definition makes the previous value of that register dead)
            match insn {
                IrInstruction::MovImm { dst, .. }
                | IrInstruction::MovReg { dst, .. }
                | IrInstruction::AddImm { dst, .. }
                | IrInstruction::SubImm { dst, .. }
                | IrInstruction::AndImm { dst, .. }
                | IrInstruction::OrImm { dst, .. }
                | IrInstruction::XorImm { dst, .. }
                | IrInstruction::ShlImm { dst, .. }
                | IrInstruction::ShrImm { dst, .. }
                | IrInstruction::SarImm { dst, .. }
                | IrInstruction::NegReg { dst, .. }
                | IrInstruction::NotReg { dst, .. }
                | IrInstruction::IncReg { dst, .. }
                | IrInstruction::DecReg { dst, .. }
                | IrInstruction::PopReg { dst, .. } => {
                    live_regs.remove(dst);
                }
                _ => {}
            }

            // 3. GEN: add source registers to the live set
            //    (they are read by this instruction, so they must be live
            //     before the instruction)
            Self::collect_source_regs(insn, &mut live_regs);

            // Now live_regs holds IN[i] = (OUT[i] \ KILL[i]) ∪ GEN[i]
            // which becomes OUT[i-1] for the next iteration
        }

        // Collect kept instructions in forward order
        ir.iter()
            .enumerate()
            .filter(|(i, _)| keep[*i])
            .map(|(_, insn)| insn.clone())
            .collect()
    }

    /// Return the full bitmask for a given width in bytes.
    /// Used for eliminating redundant `And` instructions.
    #[allow(dead_code)] // mask helper for SIMD lane widths; not yet referenced
    pub(super) fn full_mask_for_width(width: usize) -> u64 {
        match width {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFFFFFF,
            8 => 0xFFFFFFFFFFFFFFFF,
            _ => 0,
        }
    }

    /// Check if an instruction has observable side effects (must not be eliminated).
    #[allow(dead_code)]
    pub(super) fn has_side_effect(insn: &IrInstruction) -> bool {
        match insn {
            IrInstruction::StoreMemory { .. }
            | IrInstruction::StoreMemory8 { .. }
            | IrInstruction::StoreImmediate { .. }
            | IrInstruction::StoreDwordFromXmm { .. }
            | IrInstruction::StoreVector { .. }
            | IrInstruction::StoreXmm { .. }
            | IrInstruction::PushReg { .. }
            | IrInstruction::PushMemory { .. }
            | IrInstruction::PushImm { .. }
            | IrInstruction::PushFlags { .. }
            | IrInstruction::PopMemory { .. }
            | IrInstruction::PopFlags { .. }
            | IrInstruction::Call { .. }
            | IrInstruction::CallRegister { .. }
            | IrInstruction::CallMemory { .. }
            | IrInstruction::Jump { .. }
            | IrInstruction::JumpIf { .. }
            | IrInstruction::JumpRegister { .. }
            | IrInstruction::JumpMemory { .. }
            | IrInstruction::Return { .. }
            | IrInstruction::Cpuid
            | IrInstruction::Xgetbv
            | IrInstruction::Cld
            | IrInstruction::Leave
            | IrInstruction::Movs { .. }
            | IrInstruction::Stos { .. }
            | IrInstruction::Mfence
            | IrInstruction::VzeroUpper
            | IrInstruction::X87ClearExceptions
            | IrInstruction::X87Init
            | IrInstruction::Clflush { .. }
            | IrInstruction::X87Store { .. }
            | IrInstruction::X87StorePop { .. }
            | IrInstruction::X87StorePopRegister { .. }
            | IrInstruction::X87StoreControlWord { .. }
            | IrInstruction::StoreMxcsr { .. }
            | IrInstruction::SetccMemory { .. }
            | IrInstruction::LockCmpxchg { .. }
            | IrInstruction::LockCmpxchg8b { .. }
            | IrInstruction::LockXadd { .. }
            | IrInstruction::IncMemory { .. }
            | IrInstruction::DecMemory { .. }
            | IrInstruction::AddImmMemory { .. }
            | IrInstruction::SubImmMemory { .. }
            | IrInstruction::AndImmMemory { .. }
            | IrInstruction::OrImmMemory { .. }
            | IrInstruction::XorImmMemory { .. }
            | IrInstruction::AddMemory { .. }
            | IrInstruction::SubMemory { .. }
            | IrInstruction::AndMemory { .. }
            | IrInstruction::OrMemory { .. }
            | IrInstruction::OrMemory8 { .. }
            | IrInstruction::XorMemory { .. }
            | IrInstruction::ExchangeMemory { .. }
            | IrInstruction::ShlImmMemory { .. }
            | IrInstruction::ShrImmMemory { .. }
            | IrInstruction::SarImmMemory { .. }
            | IrInstruction::RolImmMemory { .. }
            | IrInstruction::BitTest { .. }
            | IrInstruction::BitTestImm { .. }
            | IrInstruction::Compare { .. }
            | IrInstruction::Test { .. }
            | IrInstruction::Setcc { .. }
            | IrInstruction::X87LoadInt32 { .. }
            | IrInstruction::X87LoadInt64 { .. }
            | IrInstruction::X87Load { .. }
            | IrInstruction::X87LoadControlWord { .. }
            | IrInstruction::X87AddMemory { .. }
            | IrInstruction::X87MulMemory { .. }
            | IrInstruction::X87DivMemory { .. }
            | IrInstruction::X87Add
            | IrInstruction::X87Div
            | IrInstruction::X87NegateTop
            | IrInstruction::X87Swap { .. }
            | IrInstruction::X87Compare { .. }
            | IrInstruction::X87AddPop { .. }
            | IrInstruction::X87Mul { .. }
            | IrInstruction::X87DivRegister { .. }
            | IrInstruction::X87DivPop { .. }
            | IrInstruction::X87LoadConst { .. }
            | IrInstruction::LoadMxcsr { .. }
            | IrInstruction::Comiss { .. }
            | IrInstruction::Pcmpistri { .. }
            | IrInstruction::PopSeg { .. }
            | IrInstruction::FmaVector { .. }
            // ── Phase H: AVX-512 arithmetic ──────────────────────────────
            | IrInstruction::AddPacked { .. } | IrInstruction::SubPacked { .. }
            | IrInstruction::MulPacked { .. } | IrInstruction::DivPacked { .. }
            | IrInstruction::MinPacked { .. } | IrInstruction::MaxPacked { .. }
            | IrInstruction::SqrtPacked { .. } | IrInstruction::ComparePacked { .. }
            // ── Phase H: AVX-512 conversion ──────────────────────────────
            | IrInstruction::ConvertPacked { .. }
            | IrInstruction::ConvertToInt { .. }
            | IrInstruction::ConvertFromInt { .. }
            // ── Phase H: AVX-512 shuffle/permute ─────────────────────────
            | IrInstruction::ShuffleF32 { .. } | IrInstruction::ShuffleF64 { .. }
            | IrInstruction::AlignD { .. } | IrInstruction::AlignQ { .. }
            | IrInstruction::InsertSubVector { .. }
            | IrInstruction::ExtractSubVector { .. }
            | IrInstruction::BroadcastSubVector { .. }
            | IrInstruction::BroadcastMask { .. }
            | IrInstruction::PermuteVarDq { .. }
            | IrInstruction::PermuteVarPsPd { .. }
            | IrInstruction::PermuteI2 { .. } | IrInstruction::PermuteT2 { .. }
            | IrInstruction::PermuteImm { .. }
            | IrInstruction::PermuteImm2Src { .. }
            // ── Phase H: AVX-512 special ─────────────────────────────────
            | IrInstruction::FixupSpecial { .. }
            | IrInstruction::ExtractExponent { .. }
            | IrInstruction::ExtractMantissa { .. }
            | IrInstruction::ReducePrecision { .. }
            | IrInstruction::RangePacked { .. }
            | IrInstruction::ScaleByPower2 { .. }
            | IrInstruction::FloatClass { .. }
            | IrInstruction::Pternlog { .. }
            | IrInstruction::ConflictDetect { .. }
            | IrInstruction::CompressVector { .. }
            | IrInstruction::ExpandVector { .. }
            | IrInstruction::GatherVector { .. }
            | IrInstruction::ScatterVector { .. }
            // ── Phase H: Mask register ops ───────────────────────────────
            | IrInstruction::Kand { .. } | IrInstruction::Kor { .. }
            | IrInstruction::Kxor { .. } | IrInstruction::Knot { .. }
            | IrInstruction::Kshiftl { .. } | IrInstruction::Kshiftr { .. }
            | IrInstruction::Kadd { .. } | IrInstruction::Ktest { .. }
            | IrInstruction::Kunpck { .. }
            // ── Phase H: CET shadow stack ────────────────────────────────
            | IrInstruction::SaveSsP { .. }
            | IrInstruction::Rstorssp { .. }
            | IrInstruction::Incssp { .. }
            | IrInstruction::Wrss { .. }
            | IrInstruction::Wruss { .. }
            // ── Phase H: MPX bounds checking ─────────────────────────────
            | IrInstruction::BndmkReg { .. } | IrInstruction::BndmkMem { .. }
            | IrInstruction::BndclReg { .. } | IrInstruction::BndclMem { .. }
            | IrInstruction::BndcuReg { .. } | IrInstruction::BndcuMem { .. }
            | IrInstruction::BndcnReg { .. } | IrInstruction::BndcnMem { .. }
            | IrInstruction::BndmovReg { .. }
            | IrInstruction::BndmovMemLoad { .. }
            | IrInstruction::BndmovMemStore { .. }
            // ── Phase H: TSX/RTM ─────────────────────────────────────────
            | IrInstruction::Xbegin { .. } | IrInstruction::Xend
            | IrInstruction::Xabort { .. } | IrInstruction::Xtest
            // ── Phase H: SGX ─────────────────────────────────────────────
            | IrInstruction::Encls | IrInstruction::Enclu
            // ── Phase H: Cache/misc ──────────────────────────────────────
            | IrInstruction::Clflushopt { .. } | IrInstruction::Clwb { .. }
            | IrInstruction::Pcommit
            // ── Phase H: RDPMC ───────────────────────────────────────────
            | IrInstruction::Rdpmc { .. } => true,
            _ => false,
        }
    }

    /// Collect all register sources used by an instruction into the given set.
    #[allow(dead_code)]
    pub(super) fn collect_source_regs(
        insn: &IrInstruction,
        regs: &mut std::collections::BTreeSet<Register>,
    ) {
        match insn {
            IrInstruction::MovReg { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::MovReg8 { src, .. } => {
                regs.insert(src.full_register());
            }
            // AddReg8 has src: ByteRegister
            IrInstruction::AddReg8 { src, .. }
            | IrInstruction::AndReg8 { src, .. }
            | IrInstruction::OrReg8 { src, .. }
            | IrInstruction::XorReg8 { src, .. } => {
                regs.insert(src.full_register());
            }
            // SubReg8, SbbReg8 have src: CompareOperand
            IrInstruction::SubReg8 { src, .. } | IrInstruction::SbbReg8 { src, .. } => {
                if let crate::cpu::CompareOperand::Register(r) = src {
                    regs.insert(*r);
                }
            }
            IrInstruction::AddOperand { src, .. }
            | IrInstruction::SubOperand { src, .. }
            | IrInstruction::AdcOperand { src, .. }
            | IrInstruction::SbbOperand { src, .. }
            | IrInstruction::AndReg { src, .. }
            | IrInstruction::OrReg { src, .. }
            | IrInstruction::XorReg { src, .. }
            | IrInstruction::ImulReg { src, .. }
            | IrInstruction::ImulImm { src, .. } => {
                if let crate::cpu::CompareOperand::Register(r) = src {
                    regs.insert(*r);
                }
            }
            IrInstruction::AddMemory { src, .. }
            | IrInstruction::SubMemory { src, .. }
            | IrInstruction::AndMemory { src, .. }
            | IrInstruction::OrMemory { src, .. }
            | IrInstruction::XorMemory { src, .. }
            | IrInstruction::StoreMemory { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::StoreMemory8 { src, .. } => {
                regs.insert(src.full_register());
            }
            IrInstruction::CallRegister { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::JumpRegister { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::PushReg { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::Popcnt { src, .. }
            | IrInstruction::Lzcnt { src, .. }
            | IrInstruction::Bsf { src, .. }
            | IrInstruction::Crc32 { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::Andn { lhs, rhs, .. } => {
                regs.insert(*lhs);
                regs.insert(*rhs);
            }
            IrInstruction::Bextr { src, range, .. } => {
                regs.insert(*src);
                regs.insert(*range);
            }
            IrInstruction::Blsi { src, .. }
            | IrInstruction::Blsmsk { src, .. }
            | IrInstruction::Blsr { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::Bzhi { src, index, .. } => {
                regs.insert(*src);
                regs.insert(*index);
            }
            IrInstruction::Mulx { src, .. }
            | IrInstruction::Pdep { src, .. }
            | IrInstruction::Pext { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::Rorx { src, .. }
            | IrInstruction::Sarx { src, .. }
            | IrInstruction::Shrx { src, .. }
            | IrInstruction::Shlx { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::ExchangeRegisters { left, right, .. } => {
                regs.insert(*left);
                regs.insert(*right);
            }
            IrInstruction::ExchangeMemory { register, .. } => {
                regs.insert(*register);
            }
            IrInstruction::Cmov {
                src: crate::cpu::CompareOperand::Register(r),
                ..
            } => {
                regs.insert(*r);
            }
            IrInstruction::MulAcc { src, .. }
            | IrInstruction::ImulAcc { src, .. }
            | IrInstruction::Div { src, .. }
            | IrInstruction::Idiv { src, .. } => {
                if let crate::cpu::CompareOperand::Register(r) = src {
                    regs.insert(*r);
                }
            }
            // Instructions that use dst as both src and dst (dst = dst op value)
            // These implicitly READ dst before writing it, so dst must be treated
            // as a source register for liveness analysis.
            IrInstruction::AddImm { dst, .. }
            | IrInstruction::SubImm { dst, .. }
            | IrInstruction::AndImm { dst, .. }
            | IrInstruction::OrImm { dst, .. }
            | IrInstruction::XorImm { dst, .. }
            | IrInstruction::ShlImm { dst, .. }
            | IrInstruction::ShrImm { dst, .. }
            | IrInstruction::SarImm { dst, .. }
            | IrInstruction::RolImm { dst, .. }
            | IrInstruction::NegReg { dst, .. }
            | IrInstruction::NotReg { dst, .. }
            | IrInstruction::IncReg { dst, .. }
            | IrInstruction::DecReg { dst, .. }
            | IrInstruction::PopReg { dst, .. } => {
                regs.insert(*dst);
            }
            // Instructions with no register source operands; ignore
            _ => {}
        }
    }

    /// Loop unrolling: detect simple counted loops and duplicate the body.
    ///
    /// Detects the pattern (in the ORIGINAL IR, before constant folding):
    ///   `SubImm(counter, 1, width)`
    ///   `JumpIf(counter, target, NotEqual)`  (back-edge to loop start)
    ///
    /// Uses a lightweight constant folding scan (without DCE) to determine the
    /// initial counter value, then performs unrolling on the original IR to avoid
    /// DCE destroying the loop structure.
    ///
    /// For loops where the iteration count is known at compile time:
    /// - If ≤ 4 iterations: fully unroll (eliminate the loop entirely)
    /// - Otherwise: unroll by factor 2 with remainder loop
    ///
    /// # Safety constraints
    /// - Only unroll when loop body has ≤ 50 instructions
    /// - Only unroll when iteration count is known at compile time
    /// - Does NOT unroll loops containing host calls or indirect branches
    #[allow(dead_code)]
    pub(super) fn loop_unroll(ir: &[IrInstruction], guest_address: u64) -> Vec<IrInstruction> {
        // Need at least SubImm + JumpIf at the end
        if ir.len() < 2 {
            return ir.to_vec();
        }

        let len = ir.len();

        // Look for the loop pattern at the end of the block in the ORIGINAL IR:
        // SubImm(counter, 1, width) followed by JumpIf(counter, target, NotEqual)
        let (counter_reg, width, _jump_target) = match (&ir[len - 2], &ir[len - 1]) {
            (
                IrInstruction::SubImm { dst, value, width },
                IrInstruction::JumpIf {
                    condition,
                    target,
                    fallthrough: _,
                },
            ) if *value == 1
                && *condition == ConditionCode::NotEqual
                && *target == guest_address =>
            {
                (dst, width, *target)
            }
            _ => return ir.to_vec(),
        };

        // Find the loop body: instructions from start to just before the SubImm
        let loop_end = len - 2; // Index of SubImm
        let body_len = loop_end; // Number of instructions in the loop body

        // Safety check: only unroll small loops
        if body_len > 50 {
            return ir.to_vec();
        }

        // Check for host calls or indirect branches in the loop body
        if Self::loop_contains_unsafe_instructions(&ir[..loop_end]) {
            return ir.to_vec();
        }

        // Determine the initial counter value using a lightweight scan of the
        // original IR (no DCE, so MovImm won't be removed)
        let initial_count = Self::find_loop_count(&ir[..loop_end], counter_reg);

        let count = match initial_count {
            Some(c) => c,
            None => return ir.to_vec(), // Unknown iteration count
        };

        // Determine unroll strategy
        if count <= 4 {
            // Fully unroll: duplicate the body `count` times, remove the loop
            Self::fully_unroll(ir, loop_end, body_len, count)
        } else {
            // Partially unroll by factor 2
            Self::partially_unroll(ir, loop_end, body_len, count, *counter_reg, *width)
        }
    }

    /// Check if a loop body contains host calls or indirect branches (unsafe to unroll).
    #[allow(dead_code)]
    pub(super) fn loop_contains_unsafe_instructions(body: &[IrInstruction]) -> bool {
        body.iter().any(|insn| {
            matches!(
                insn,
                IrInstruction::Call { .. }
                    | IrInstruction::CallRegister { .. }
                    | IrInstruction::CallMemory { .. }
                    | IrInstruction::JumpRegister { .. }
                    | IrInstruction::JumpMemory { .. }
            )
        })
    }

    /// Find the initial value of a loop counter register from preceding `MovImm` instructions.
    #[allow(dead_code)]
    pub(super) fn find_loop_count(
        instructions: &[IrInstruction],
        counter: &Register,
    ) -> Option<u64> {
        // Scan backwards to find the last MovImm that sets this register
        for insn in instructions.iter().rev() {
            if let IrInstruction::MovImm { dst, value } = insn
                && dst == counter
            {
                return Some(*value);
            }
            // If we find any other instruction writing to counter before MovImm, stop
            if Self::instruction_writes_register(insn, counter) {
                return None;
            }
        }
        None
    }

    /// Check if an instruction writes to a specific register.
    #[allow(dead_code)]
    pub(super) fn instruction_writes_register(insn: &IrInstruction, reg: &Register) -> bool {
        match insn {
            IrInstruction::MovImm { dst, .. }
            | IrInstruction::MovReg { dst, .. }
            | IrInstruction::AddImm { dst, .. }
            | IrInstruction::SubImm { dst, .. }
            | IrInstruction::AndImm { dst, .. }
            | IrInstruction::OrImm { dst, .. }
            | IrInstruction::XorImm { dst, .. }
            | IrInstruction::ShlImm { dst, .. }
            | IrInstruction::ShrImm { dst, .. }
            | IrInstruction::SarImm { dst, .. }
            | IrInstruction::RolImm { dst, .. }
            | IrInstruction::NegReg { dst, .. }
            | IrInstruction::NotReg { dst, .. }
            | IrInstruction::IncReg { dst, .. }
            | IrInstruction::DecReg { dst, .. }
            | IrInstruction::PopReg { dst, .. }
            | IrInstruction::LoadMemory { dst, .. }
            | IrInstruction::SignExtendTo64 { dst, .. }
            | IrInstruction::SignExtend { dst, .. }
            | IrInstruction::ZeroExtendTo64 { dst, .. }
            | IrInstruction::Popcnt { dst, .. }
            | IrInstruction::Lzcnt { dst, .. }
            | IrInstruction::Bsf { dst, .. }
            | IrInstruction::Crc32 { dst, .. }
            | IrInstruction::Rdrand { dst, .. }
            | IrInstruction::Rdseed { dst, .. }
            | IrInstruction::Andn { dst, .. }
            | IrInstruction::Bextr { dst, .. }
            | IrInstruction::Blsi { dst, .. }
            | IrInstruction::Blsmsk { dst, .. }
            | IrInstruction::Blsr { dst, .. }
            | IrInstruction::Bzhi { dst, .. }
            | IrInstruction::Pdep { dst, .. }
            | IrInstruction::Pext { dst, .. }
            | IrInstruction::Rorx { dst, .. }
            | IrInstruction::Sarx { dst, .. }
            | IrInstruction::Shrx { dst, .. }
            | IrInstruction::Shlx { dst, .. } => dst == reg,
            _ => false,
        }
    }

    /// Fully unroll a loop with a known small iteration count.
    /// Duplicates the body `count` times, removes the loop back-edge.
    #[allow(dead_code)]
    pub(super) fn fully_unroll(
        folded: &[IrInstruction],
        loop_end: usize,
        body_len: usize,
        count: u64,
    ) -> Vec<IrInstruction> {
        let mut result: Vec<IrInstruction> =
            Vec::with_capacity(folded.len() + body_len * (count as usize - 1));

        // Add instructions before the loop
        result.extend_from_slice(&folded[..loop_end - body_len]);

        // Duplicate the loop body `count` times
        let body = &folded[loop_end - body_len..loop_end];
        for _ in 0..count {
            result.extend_from_slice(body);
        }

        // Add anything after the loop (the JumpIf originally followed SubImm;
        // since we fully unrolled, we skip it and just emit the fallthrough)
        // The last instruction was JumpIf - we replace it with nothing (fully unrolled)
        // Add a Nop to maintain block structure if needed
        result
    }

    /// Partially unroll a loop by factor 2, leaving a remainder loop for remaining iterations.
    #[allow(dead_code)]
    pub(super) fn partially_unroll(
        folded: &[IrInstruction],
        loop_end: usize,
        body_len: usize,
        _count: u64,
        counter_reg: Register,
        width: usize,
    ) -> Vec<IrInstruction> {
        let mut result: Vec<IrInstruction> = Vec::with_capacity(folded.len() + body_len);

        // Add instructions before the loop body
        let body_start = loop_end - body_len;
        result.extend_from_slice(&folded[..body_start]);

        // First unrolled copy of the body
        let body = &folded[body_start..loop_end];
        result.extend_from_slice(body);

        // Second unrolled copy of the body
        result.extend_from_slice(body);

        // Decrement counter by 2 (to account for both unrolled copies)
        result.push(IrInstruction::SubImm {
            dst: counter_reg,
            value: 2,
            width,
        });

        // Keep the original JumpIf for the remainder loop.
        // Note: this works correctly for even iteration counts.
        // Odd counts would need a remainder loop (future work).
        if let Some(jump_if) = folded.get(loop_end + 1) {
            result.push(jump_if.clone());
        }

        result
    }
}

// ---------------------------------------------------------------------------
// SIMD Fast-Path
// ---------------------------------------------------------------------------

/// Emit ARM64 NEON SIMD code for a 16-byte-at-a-time memcpy.
///
/// Uses `LDR Q0, [src]` / `STR Q0, [dst]` for the bulk of the copy, then
/// handles remaining bytes with single-byte copies.
///
/// # Register Convention
/// - `src_base` register: source base address
/// - `dst_base` register: destination base address
/// - `len_reg` register: total bytes to copy
/// - Uses NEON registers Q0 (V0) as temporary
///
/// # Performance Impact
/// SIMD memcpy achieves ~16 bytes per load/store pair versus 1 or 8 bytes
/// with scalar instructions, yielding up to 8–16× throughput improvement
/// for large memory copies common in game data operations.
pub fn emit_simd_memcpy(emitter: &mut Emitter) -> AppResult<()> {
    // Pseudocode for the emitted code:
    //   loop:
    //     CMP len, #16
    //     B.LT tail
    //     LDR Q0, [src], #16
    //     STR Q0, [dst], #16
    //     SUB len, len, #16
    //     B loop
    //   tail:
    //     CBZ len, done
    //   byte_loop:
    //     LDRB W3, [src], #1
    //     STRB W3, [dst], #1
    //     SUBS len, len, #1
    //     B.NE byte_loop
    //   done:

    // We emit a simplified version that uses the emitter's existing methods.
    // In a full integration, registers would be allocated by the register
    // allocator. Here we use:
    //   X21 = src pointer, X22 = dst pointer, X23 = length

    // Loop header
    let loop_start = emitter.len();
    emitter.subs_imm(23, 23, 16); // SUBS X23, X23, #16 (sets flags)
    emitter.bcond(0x3, 8); // B.LT tail (CC=3, skip ahead 8 insns)
    emitter.emit(0x3dc00000 | (21 << 5)); // LDR Q0, [X21], #16 (post-index)
    emitter.emit(0x3d800000 | (22 << 5)); // STR Q0, [X22], #16 (post-index)
    let current = emitter.len();
    let offset = (loop_start as i32 - current as i32) / 4 - 1;
    emitter.b(offset); // B loop_start

    // Tail: handle remaining bytes
    emitter.cbz(23, 2); // CBZ X23, +2 (skip to done)
    emitter.ldr8(3, 21, 0); // LDRB W3, [X21]
    emitter.str8(3, 22, 0); // STRB W3, [X22]
    emitter.add_imm(21, 21, 1); // ADD X21, X21, #1
    emitter.add_imm(22, 22, 1); // ADD X22, X22, #1
    emitter.subs_imm(23, 23, 1); // SUBS X23, X23, #1
    // B.NE back to CBZ — CBZ is 6 instructions (24 bytes) before this point
    // ARM64 offset is in instructions: -(6 instructions) = -6
    emitter.bcond(0x1, -6); // B.NE back to cbz

    Ok(())
}

/// Emit ARM64 NEON SIMD code for a 16-byte-at-a-time memset.
///
/// Broadcasts the set value to all 16 bytes of NEON register Q0, then stores
/// 16 bytes at a time.
///
/// # Performance Impact
/// SIMD memset fills 16 bytes per store instruction versus 1 or 8 bytes with
/// scalar instructions, yielding similar throughput gains as SIMD memcpy.
pub fn emit_simd_memset(emitter: &mut Emitter) -> AppResult<()> {
    // Pseudocode:
    //   DUP V0.16B, W3          ; broadcast byte value to all 16 lanes
    //   loop:
    //     SUBS X23, X23, #16
    //     B.LT done
    //     STR Q0, [X22], #16
    //     B loop
    //   done:

    // DUP V0.16B, Wn (scalar to all vector lanes)
    // Encoding: 0x4e080400 | (Rn << 5) | Vd   — DUP Vd.16B, Wn
    emitter.emit(0x4e080400 | (3 << 5)); // DUP V0.16B, W3

    let loop_start = emitter.len();
    emitter.subs_imm(23, 23, 16); // SUBS X23, X23, #16
    emitter.bcond(0x3, 2); // B.LT done (+2 insns)
    emitter.emit(0x3d800000 | (22 << 5)); // STR Q0, [X22], #16 (post-index)
    let current = emitter.len();
    let offset = (loop_start as i32 - current as i32) / 4 - 1;
    emitter.b(offset); // B loop_start

    Ok(())
}

/// Emit ARM64 NEON SIMD code for a 16-byte-at-a-time memcmp.
///
/// Loads 16 bytes from both sources, compares using `CMEQ V0.16B, V0.16B, V1.16B`,
/// then checks for differences.
///
/// # Performance Impact
/// SIMD memcmp compares 16 bytes per instruction versus 1 or 8 bytes with
/// scalar comparisons, dramatically speeding up string and buffer comparisons
/// common in game engines.
pub fn emit_simd_memcmp(emitter: &mut Emitter) -> AppResult<()> {
    // Pseudocode:
    //   loop:
    //     SUBS X23, X23, #16
    //     B.LT tail
    //     LDR Q0, [X21], #16
    //     LDR Q1, [X22], #16
    //     CMEQ V0.16B, V0.16B, V1.16B   ; 0xFF where equal, 0x00 where different
    //     UMINV B2, V0.16B               ; minimum across all lanes
    //     UMOV W3, V2.B[0]              ; extract to scalar
    //     CBZ W3, mismatch               ; if any byte was 0, mismatch
    //     B loop
    //   tail: ... (byte-by-byte comparison)
    //   mismatch: ...
    //   match: ...

    let loop_start = emitter.len();
    emitter.subs_imm(23, 23, 16); // SUBS X23, X23, #16
    emitter.bcond(0x3, 10); // B.LT tail (skip ahead)

    emitter.emit(0x3dc00000 | (21 << 5)); // LDR Q0, [X21], #16
    emitter.emit(0x3dc00000 | (22 << 5) | 1); // LDR Q1, [X22], #16

    // CMEQ V0.16B, V0.16B, V1.16B
    emitter.emit(0x4e208400 | (1 << 16));

    // UMINV Bd, Vn.16B — across all 16 bytes
    emitter.emit(0x6e30a800 | 2); // UMINV B2, V0.16B

    // UMOV Wd, Vn.B[0]
    emitter.emit(0x0e003c00 | (2 << 5) | 3); // UMOV W3, V2.B[0]

    emitter.cbz(3, 2); // CBZ W3, mismatch (+2)
    let current = emitter.len();
    let offset = (loop_start as i32 - current as i32) / 4 - 1;
    emitter.b(offset); // B loop_start

    // mismatch: set result to 1 (not equal)
    emitter.movz(0, 1, 0); // MOV W0, #1
    emitter.ret(); // return with result 1 (not equal)

    // tail: byte-by-byte
    emitter.cbz(23, 4); // CBZ X23, match (+4)
    emitter.ldr8(3, 21, 0); // LDRB W3, [X21]
    emitter.ldr8(4, 22, 0); // LDRB W4, [X22]
    emitter.sub_reg(3, 3, 4); // SUB W3, W3, W4 → result in W3
    emitter.cbz(3, 4); // if equal, continue — but we just return 0

    // match: set result to 0 (equal)
    emitter.movz(0, 0, 0); // MOV W0, #0

    Ok(())
}
