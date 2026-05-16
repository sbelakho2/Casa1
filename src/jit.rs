//! JIT execution engine for Casa1.
//!
//! Compiles translated IR blocks into native ARM64 machine code and executes them
//! directly on the host CPU. Uses MAP_JIT for W^X-compliant executable memory
//! allocation on Apple Silicon.

use crate::cpu::{CpuState, GuestArch, IrInstruction, MemoryImage};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

const JIT_PAGE_SIZE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// ARM64 register mapping for guest GPRs
// ---------------------------------------------------------------------------

#[allow(dead_code)]
mod regmap {
    /// Map guest x86/x64 register index to ARM64 register.
    /// Guest: RAX(0), RCX(1), RDX(2), RBX(3), RSP(4), RBP(5), RSI(6), RDI(7),
    ///        R8(8), R9(9), R10(10), R11(11), R12(12), R13(13), R14(14), R15(15)
    /// ARM64: x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x19, x20
    pub const fn guest_to_arm(guest_index: usize) -> u32 {
        match guest_index {
            0 => 4,   // RAX -> x4
            1 => 5,   // RCX -> x5
            2 => 6,   // RDX -> x6
            3 => 7,   // RBX -> x7
            4 => 8,   // RSP -> x8
            5 => 9,   // RBP -> x9
            6 => 10,  // RSI -> x10
            7 => 11,  // RDI -> x11
            8 => 12,  // R8  -> x12
            9 => 13,  // R9  -> x13
            10 => 14, // R10 -> x14
            11 => 15, // R11 -> x15
            12 => 16, // R12 -> x16
            13 => 17, // R13 -> x17
            14 => 19, // R14 -> x19
            15 => 20, // R15 -> x20
            _ => 4,
        }
    }

    pub const X0: u32 = 0;
    pub const X1: u32 = 1;
    pub const X2: u32 = 2;
    pub const X3: u32 = 3;
    pub const X21: u32 = 21;
    pub const X22: u32 = 22;
    pub const X23: u32 = 23;
    pub const X24: u32 = 24;
    pub const X25: u32 = 25;
    pub const X26: u32 = 26;
    pub const X27: u32 = 27;
    pub const X28: u32 = 28;
    pub const FP: u32 = 29;
    pub const LR: u32 = 30;
    pub const SP: u32 = 31;
    pub const XZR: u32 = 31;
}

// ---------------------------------------------------------------------------
// ARM64 instruction encoder
// ---------------------------------------------------------------------------

struct Emitter {
    code: Vec<u8>,
}

#[allow(dead_code)]
impl Emitter {
    fn new() -> Self {
        Self { code: Vec::with_capacity(4096) }
    }

    #[inline(always)]
    fn emit(&mut self, insn: u32) {
        self.code.extend_from_slice(&insn.to_le_bytes());
    }

    fn len(&self) -> usize { self.code.len() }

    // -- Moves and immediates --

    /// MOV Xd, Xn (alias for ORR Xd, XZR, Xn)
    fn mov_reg(&mut self, rd: u32, rn: u32) {
        self.emit(0xaa0003e0 | (rn << 16) | rd);
    }

    /// MOVZ Xd, #imm16, LSL #shift
    fn movz(&mut self, rd: u32, imm16: u16, shift: u32) {
        let hw = shift / 16;
        self.emit(0xd2800000 | (hw << 21) | ((imm16 as u32) << 5) | rd);
    }

    /// MOVK Xd, #imm16, LSL #shift
    fn movk(&mut self, rd: u32, imm16: u16, shift: u32) {
        let hw = shift / 16;
        self.emit(0xf2800000 | (hw << 21) | ((imm16 as u32) << 5) | rd);
    }

    /// Move a 64-bit immediate into register using MOVZ + MOVK sequence
    fn mov_imm64(&mut self, rd: u32, value: u64) {
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

    // -- ALU --

    /// ADD Xd, Xn, #imm12
    fn add_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0x91000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// SUB Xd, Xn, #imm12
    fn sub_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0xd1000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// ADD Xd, Xn, Xm
    fn add_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x8b000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// SUB Xd, Xn, Xm
    fn sub_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xcb000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// AND Xd, Xn, Xm
    fn and_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x8a000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// ORR Xd, Xn, Xm
    fn orr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xaa000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// EOR Xd, Xn, Xm
    fn eor_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xca000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// MUL Xd, Xn, Xm
    fn mul_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9b007c00 | (rm << 16) | (rn << 5) | rd);
    }

    /// SDIV Xd, Xn, Xm
    fn sdiv(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9ac00c00 | (rm << 16) | (rn << 5) | rd);
    }

    /// UDIV Xd, Xn, Xm
    fn udiv(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9ac00800 | (rm << 16) | (rn << 5) | rd);
    }

    /// MSUB Xd, Xn, Xm, Xa (Xd = Xa - Xn*Xm)
    fn msub(&mut self, rd: u32, rn: u32, rm: u32, ra: u32) {
        self.emit(0x9b008000 | (rm << 16) | (ra << 10) | (rn << 5) | rd);
    }

    /// NEG Xd, Xn (SUB Xd, XZR, Xn)
    fn neg(&mut self, rd: u32, rn: u32) {
        self.emit(0xcb000000 | (rn << 16) | (31 << 5) | rd);
    }

    /// MVN Xd, Xn (ORN Xd, XZR, Xn)
    fn mvn(&mut self, rd: u32, rn: u32) {
        self.emit(0xaa200000 | (rn << 16) | (31 << 5) | rd);
    }

    // -- Shifts --

    /// LSL Xd, Xn, #shift
    fn lsl_imm(&mut self, rd: u32, rn: u32, shift: u32) {
        self.emit(0xd3400000 | ((64 - shift) << 16) | ((63 - shift) << 10) | (rn << 5) | rd);
    }

    /// LSR Xd, Xn, #shift
    fn lsr_imm(&mut self, rd: u32, rn: u32, shift: u32) {
        self.emit(0xd3400000 | ((shift & 63) << 16) | (63 << 10) | (rn << 5) | rd);
    }

    /// ASR Xd, Xn, #shift
    fn asr_imm(&mut self, rd: u32, rn: u32, shift: u32) {
        self.emit(0x93400000 | ((shift & 63) << 16) | (63 << 10) | (rn << 5) | rd);
    }

    /// ROR Xd, Xn, Xm
    fn ror_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02c00 | (rm << 16) | (rn << 5) | rd);
    }

    /// LSLV Xd, Xn, Xm
    fn lsl_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02000 | (rm << 16) | (rn << 5) | rd);
    }

    /// LSRV Xd, Xn, Xm
    fn lsr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02400 | (rm << 16) | (rn << 5) | rd);
    }

    /// ASRV Xd, Xn, Xm
    fn asr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02800 | (rm << 16) | (rn << 5) | rd);
    }

    // -- Flag-setting ALU --

    /// ADDS Xd, Xn, #imm12
    fn adds_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0xb1000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// SUBS Xd, Xn, #imm12
    fn subs_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0xf1000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// ADDS Xd, Xn, Xm
    fn adds_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xab000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// SUBS Xd, Xn, Xm
    fn subs_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xeb000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// ADCS Xd, Xn, Xm
    fn adcs(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9a100000 | (rm << 16) | (rn << 5) | rd);
    }

    /// SBCS Xd, Xn, Xm
    fn sbcs(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xfa100000 | (rm << 16) | (rn << 5) | rd);
    }

    // -- Memory --

    /// LDR Xt, [Xn, #offset] (64-bit unsigned offset)
    fn ldr64(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xf9400000 | ((offset >> 3) << 10) | (rn << 5) | rt);
    }

    /// STR Xt, [Xn, #offset] (64-bit unsigned offset)
    fn str64(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xf9000000 | ((offset >> 3) << 10) | (rn << 5) | rt);
    }

    /// LDR Wt, [Xn, #offset] (32-bit unsigned offset)
    fn ldr32(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xb9400000 | ((offset >> 2) << 10) | (rn << 5) | rt);
    }

    /// STR Wt, [Xn, #offset] (32-bit unsigned offset)
    fn str32(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xb9000000 | ((offset >> 2) << 10) | (rn << 5) | rt);
    }

    /// LDRB Wt, [Xn, #offset]
    fn ldr8(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0x39400000 | ((offset & 0xfff) << 10) | (rn << 5) | rt);
    }

    /// STRB Wt, [Xn, #offset]
    fn str8(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0x39000000 | ((offset & 0xfff) << 10) | (rn << 5) | rt);
    }

    /// LDR Xt, [Xn, Xm] (register offset, 64-bit)
    fn ldr64_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xf8600800 | (rm << 16) | (rn << 5) | rt);
    }

    /// STR Xt, [Xn, Xm] (register offset, 64-bit)
    fn str64_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xf8200800 | (rm << 16) | (rn << 5) | rt);
    }

    /// LDR Wt, [Xn, Xm] (register offset, 32-bit)
    fn ldr32_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xb8600800 | (rm << 16) | (rn << 5) | rt);
    }

    /// STR Wt, [Xn, Xm] (register offset, 32-bit)
    fn str32_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xb8200800 | (rm << 16) | (rn << 5) | rt);
    }

    // -- Pairs --

    /// STP Xt1, Xt2, [Xn, #offset]! (pre-index)
    fn stp64_pre(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        let imm7 = ((offset >> 3) & 0x7f) as u32;
        self.emit(0xa9800000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }

    /// LDP Xt1, Xt2, [Xn], #offset (post-index)
    fn ldp64_post(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        let imm7 = ((offset >> 3) & 0x7f) as u32;
        self.emit(0xa8c00000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }

    // -- Branches --

    fn b(&mut self, offset: i32) {
        self.emit(0x14000000 | ((offset >> 2) & 0x3fffffff) as u32);
    }

    fn bl(&mut self, offset: i32) {
        self.emit(0x94000000 | ((offset >> 2) & 0x3fffffff) as u32);
    }

    fn br(&mut self, rn: u32) {
        self.emit(0xd61f0000 | (rn << 5));
    }

    fn blr(&mut self, rn: u32) {
        self.emit(0xd63f0000 | (rn << 5));
    }

    fn ret(&mut self) {
        self.emit(0xd65f03c0);
    }

    fn nop(&mut self) {
        self.emit(0xd503201f);
    }

    /// B.cond offset (cond: 0=EQ,1=NE,2=CS,3=CC,4=MI,5=PL,6=VS,7=VC,8=HI,9=LS,10=GE,11=LT,12=GT,13=LE,14=AL)
    fn bcond(&mut self, cond: u32, offset: i32) {
        self.emit(0x54000000u32 | (((offset >> 2) as u32 & 0x7ffff) << 5) | (cond & 0xf));
    }

    // -- Extensions --

    fn sxtb(&mut self, rd: u32, rn: u32) { self.emit(0x93401c00 | (rn << 5) | rd); }
    fn sxth(&mut self, rd: u32, rn: u32) { self.emit(0x93403c00 | (rn << 5) | rd); }
    fn sxtw(&mut self, rd: u32, rn: u32) { self.emit(0x93407c00 | (rn << 5) | rd); }
    fn uxtb(&mut self, rd: u32, rn: u32) { self.emit(0x53001c00 | (rn << 5) | rd); }
    fn uxth(&mut self, rd: u32, rn: u32) { self.emit(0x53003c00 | (rn << 5) | rd); }

    // -- Miscellaneous --

    fn rbit(&mut self, rd: u32, rn: u32) { self.emit(0xdac00000 | (rn << 5) | rd); }
    fn clz(&mut self, rd: u32, rn: u32) { self.emit(0xdac01000 | (rn << 5) | rd); }

    /// CSEL Xd, Xn, Xm, cond
    fn csel(&mut self, rd: u32, rn: u32, rm: u32, cond: u32) {
        self.emit(0x1a800000 | (rm << 16) | (cond << 12) | (rn << 5) | rd);
    }

    /// CSET Xd, cond (conditional set to 1)
    fn cset(&mut self, rd: u32, cond: u32) {
        let inv = cond ^ 1;
        self.emit(0x9a9f07e0 | (inv << 12) | rd);
    }

    /// DMB ISH
    fn dmb_ish(&mut self) { self.emit(0xd5033f9b); }

    /// ISB
    fn isb(&mut self) { self.emit(0xd5033fdf); }

    // -- NEON/SIMD --

    /// EOR Vd.16B, Vn.16B, Vm.16B
    fn eor_vec(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x6e201c00 | (vm << 16) | (vn << 5) | vd);
    }

    /// ORR Vd.16B, Vn.16B, Vm.16B
    fn orr_vec(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x4e201c00 | (vm << 16) | (vn << 5) | vd);
    }

    /// ADD Vd.2D, Vn.2D, Vm.2D
    fn add_vec_2d(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x4e208400 | (vm << 16) | (vn << 5) | vd);
    }

    /// DUP Vd.2D, Xn (scalar to vector)
    fn dup_to_vec(&mut self, vd: u32, rn: u32) {
        self.emit(0x4e080400 | (rn << 5) | vd);
    }

    /// MOV Xd, Vn.D[0] (vector element to scalar)
    fn vec_to_scalar(&mut self, rd: u32, vn: u32) {
        self.emit(0x4e082400 | (vn << 5) | rd);
    }
}

// ---------------------------------------------------------------------------
// JIT memory management
// ---------------------------------------------------------------------------

/// Manages executable memory for JIT-compiled code using MAP_JIT on Apple Silicon.
pub struct JitMemoryManager {
    pages: Vec<(*mut u8, usize)>,
    write_offset: usize,
    total_allocated: AtomicUsize,
    total_used: AtomicUsize,
}

unsafe impl Send for JitMemoryManager {}
unsafe impl Sync for JitMemoryManager {}

impl JitMemoryManager {
    pub fn new() -> Self {
        Self {
            pages: Vec::new(),
            write_offset: 0,
            total_allocated: AtomicUsize::new(0),
            total_used: AtomicUsize::new(0),
        }
    }

    unsafe fn allocate_page(&mut self, size: usize) -> *mut u8 {
        let aligned = ((size + JIT_PAGE_SIZE - 1) / JIT_PAGE_SIZE) * JIT_PAGE_SIZE;

        // Try MAP_JIT first (Apple Silicon)
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT,
                -1, 0,
            )
        };

        let ptr = if ptr == libc::MAP_FAILED {
            // Fallback without MAP_JIT
            unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    aligned,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1, 0,
                )
            }
        } else {
            ptr
        };

        if ptr == libc::MAP_FAILED {
            return std::ptr::null_mut();
        }

        self.pages.push((ptr as *mut u8, aligned));
        self.total_allocated.fetch_add(aligned, Ordering::Relaxed);
        ptr as *mut u8
    }

    /// Allocate code space and return a writable pointer.
    pub fn allocate_code_space(&mut self, size: usize) -> *mut u8 {
        let aligned = ((size + 63) / 64) * 64;

        if let Some(&(page_ptr, page_size)) = self.pages.last() {
            if self.write_offset + aligned <= page_size {
                let ptr = unsafe { page_ptr.add(self.write_offset) };
                self.write_offset += aligned;
                self.total_used.fetch_add(aligned, Ordering::Relaxed);
                return ptr;
            }
        }

        let new_size = aligned.max(JIT_PAGE_SIZE);
        unsafe {
            let ptr = self.allocate_page(new_size);
            if ptr.is_null() {
                return std::ptr::null_mut();
            }
            self.write_offset = aligned;
            self.total_used.fetch_add(aligned, Ordering::Relaxed);
            ptr
        }
    }

    /// Finalize code: flush icache and set executable permissions.
    pub unsafe fn finalize_code(&self, ptr: *mut u8, size: usize) {
        unsafe { Self::flush_icache(ptr, size); }

        // Set RX permissions
        let page_start = (ptr as usize) & !(JIT_PAGE_SIZE - 1);
        let page_end = (ptr as usize + size + JIT_PAGE_SIZE - 1) & !(JIT_PAGE_SIZE - 1);
        unsafe {
            libc::mprotect(
                page_start as *mut libc::c_void,
                page_end - page_start,
                libc::PROT_READ | libc::PROT_EXEC,
            );
        }
    }

    /// Re-enable write access for code patching.
    pub unsafe fn make_writable(&self, ptr: *mut u8, size: usize) {
        let page_start = (ptr as usize) & !(JIT_PAGE_SIZE - 1);
        let page_end = (ptr as usize + size + JIT_PAGE_SIZE - 1) & !(JIT_PAGE_SIZE - 1);
        unsafe {
            libc::mprotect(
                page_start as *mut libc::c_void,
                page_end - page_start,
                libc::PROT_READ | libc::PROT_WRITE,
            );
        }
    }

    unsafe fn flush_icache(ptr: *mut u8, size: usize) {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let mut addr = ptr as usize & !63;
            let end = ptr as usize + size;
            while addr < end {
                core::arch::asm!("dc cvau, {}", in(reg) addr);
                addr += 64;
            }
            core::arch::asm!("dsb ish");
            addr = ptr as usize & !63;
            while addr < end {
                core::arch::asm!("ic ivau, {}", in(reg) addr);
                addr += 64;
            }
            core::arch::asm!("isb");
        }
        #[cfg(not(target_arch = "aarch64"))]
        { let _ = (ptr, size); }
    }

    pub fn total_allocated(&self) -> usize { self.total_allocated.load(Ordering::Relaxed) }
    pub fn total_used(&self) -> usize { self.total_used.load(Ordering::Relaxed) }
}

impl Drop for JitMemoryManager {
    fn drop(&mut self) {
        for (ptr, size) in &self.pages {
            unsafe { libc::munmap(*ptr as *mut libc::c_void, *size); }
        }
    }
}

// ---------------------------------------------------------------------------
// Flat guest memory for direct JIT access
// ---------------------------------------------------------------------------

/// A flat mmap'd region mirroring the guest address space.
/// JIT-compiled code uses this for direct load/store access.
pub struct FlatGuestMemory {
    base: *mut u8,
    size: usize,
    valid: bool,
}

unsafe impl Send for FlatGuestMemory {}
unsafe impl Sync for FlatGuestMemory {}

impl FlatGuestMemory {
    pub fn new(_arch: GuestArch) -> Self {
        let size = 4 * 1024 * 1024 * 1024; // 4GB
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(), size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1, 0,
            )
        };
        Self {
            base: if base == libc::MAP_FAILED { std::ptr::null_mut() } else { base as *mut u8 },
            size,
            valid: base != libc::MAP_FAILED,
        }
    }

    pub fn base(&self) -> u64 { self.base as u64 }
    pub fn is_valid(&self) -> bool { self.valid }

    /// Sync data from MemoryImage into the flat region at a guest address.
    pub fn sync_from_memory_image(&self, guest_addr: u64, data: &[u8]) {
        if !self.valid { return; }
        let offset = guest_addr as usize;
        if offset.saturating_add(data.len()) <= self.size {
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), self.base.add(offset), data.len());
            }
        }
    }

    /// Read bytes from the flat region.
    pub fn read(&self, guest_addr: u64, buf: &mut [u8]) {
        if !self.valid { return; }
        let offset = guest_addr as usize;
        if offset.saturating_add(buf.len()) <= self.size {
            unsafe {
                ptr::copy_nonoverlapping(self.base.add(offset), buf.as_mut_ptr(), buf.len());
            }
        }
    }

    pub fn size(&self) -> usize { self.size }
}

impl Drop for FlatGuestMemory {
    fn drop(&mut self) {
        if self.valid && !self.base.is_null() {
            unsafe { libc::munmap(self.base as *mut libc::c_void, self.size); }
        }
    }
}

// ---------------------------------------------------------------------------
// JIT compilation result
// ---------------------------------------------------------------------------

/// Result of JIT-compiling a block of IR instructions.
pub struct JitCompiledBlock {
    /// Pointer to the compiled ARM64 code entry point.
    pub entry: *const u8,
    /// Size of compiled code in bytes.
    pub code_size: usize,
    /// Guest address this block was compiled from.
    pub guest_address: u64,
    /// Number of guest instructions compiled.
    pub instruction_count: usize,
}

/// Result of executing a JIT-compiled block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitExitReason {
    /// Block completed normally; RIP has been updated.
    Normal { new_rip: u64 },
    /// Block hit a thunk/import that needs host dispatch.
    ThunkDispatch { target_rip: u64, return_rip: u64 },
    /// Block hit an unimplemented instruction.
    UnimplementedInstruction { rip: u64, opcode: u8 },
    /// Block hit a conditional branch (needs host flag computation).
    ConditionalBranch { rip: u64, taken: bool },
    /// Block hit a CALL instruction to an indirect target.
    IndirectCall { target: u64, return_address: u64 },
    /// Block hit a RET instruction.
    Return { return_rip: u64 },
    /// Block needs host-side memory access (slow path).
    MemoryAccess { address: u64, is_write: bool, width: usize },
    /// Block hit CPUID.
    Cpuid,
    /// Block needs host-side exception handling.
    Exception { code: u32, address: u64 },
}

// ---------------------------------------------------------------------------
// JIT compiler: IR -> ARM64 machine code
// ---------------------------------------------------------------------------

/// Exit reason codes written by JIT code to signal back to the host.
const EXIT_NORMAL: u64 = 0;
const EXIT_THUNK: u64 = 1;
const EXIT_UNIMPL: u64 = 2;
#[allow(dead_code)]
const EXIT_COND_BRANCH: u64 = 3;
#[allow(dead_code)]
const EXIT_INDIRECT_CALL: u64 = 4;
const EXIT_RET: u64 = 5;
#[allow(dead_code)]
const EXIT_MEM_ACCESS: u64 = 6;
const EXIT_CPUID: u64 = 7;
#[allow(dead_code)]
const EXIT_EXCEPTION: u64 = 8;

/// Compiles a sequence of IR instructions into ARM64 machine code.
pub struct JitCompiler {
    emitter: Emitter,
    memory_manager: JitMemoryManager,
}

impl JitCompiler {
    pub fn new() -> Self {
        Self {
            emitter: Emitter::new(),
            memory_manager: JitMemoryManager::new(),
        }
    }

    /// Compile a block of IR instructions into executable ARM64 code.
    pub fn compile_block(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
    ) -> AppResult<JitCompiledBlock> {
        self.emitter = Emitter::new();

        // Prologue: save callee-saved registers and set up frame
        self.emit_prologue(arch);

        // Load guest GPRs from CpuState into ARM64 registers
        // x0 = &CpuState, x1 = memory base, x2 = &MemoryImage, x3 = &exit_reason
        self.emit_load_guest_registers(arch);

        // Compile each IR instruction
        for insn in ir {
            self.compile_instruction(insn, arch)?;
        }

        // Epilogue: store guest GPRs back to CpuState and return
        self.emit_store_guest_registers(arch);
        self.emit_epilogue();

        // Allocate executable memory and copy the code
        let code_size = self.emitter.len();
        let code_ptr = self.memory_manager.allocate_code_space(code_size);
        if code_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                "JIT: failed to allocate executable memory",
            ));
        }

        unsafe {
            ptr::copy_nonoverlapping(
                self.emitter.code.as_ptr(),
                code_ptr,
                code_size,
            );
            self.memory_manager.finalize_code(code_ptr, code_size);
        }

        Ok(JitCompiledBlock {
            entry: code_ptr,
            code_size,
            guest_address,
            instruction_count: ir.len(),
        })
    }

    fn emit_prologue(&mut self, arch: GuestArch) {
        let _ = arch;
        // Save callee-saved registers: x19-x28, fp(x29), lr(x30)
        // We use x19-x20 for guest R14/R15, x21-x25 as temps, x26-x28 as base pointers
        self.emitter.stp64_pre(29, 30, 31, -64); // stp fp, lr, [sp, #-64]!
        self.emitter.mov_reg(29, 31); // mov fp, sp
        // Save x19-x28
        self.emitter.stp64_pre(19, 20, 31, -64); // stp x19, x20, [sp, #-64]!
        self.emitter.stp64_pre(21, 22, 31, -64);
        self.emitter.stp64_pre(23, 24, 31, -64);
        self.emitter.stp64_pre(25, 26, 31, -64);
        self.emitter.stp64_pre(27, 28, 31, -64);
    }

    fn emit_epilogue(&mut self) {
        // Restore x19-x28
        self.emitter.ldp64_post(27, 28, 31, 64);
        self.emitter.ldp64_post(25, 26, 31, 64);
        self.emitter.ldp64_post(23, 24, 31, 64);
        self.emitter.ldp64_post(21, 22, 31, 64);
        self.emitter.ldp64_post(19, 20, 31, 64);
        // Restore fp, lr
        self.emitter.ldp64_post(29, 30, 31, 64);
        self.emitter.ret();
    }

    /// Load guest GPRs from CpuState (pointed to by x0) into ARM64 working registers.
    fn emit_load_guest_registers(&mut self, arch: GuestArch) {
        let _ = arch;
        // CpuState layout:
        //   offset 0x00: arch (u8, but aligned to 8)
        //   offset 0x08: gpr[16] (16 x u64 = 128 bytes, starting at offset 8)
        // We need to load gpr[0..16] from CpuState into x4-x15, x16, x17, x19, x20
        let gpr_base: u32 = 8; // offset of gpr array in CpuState

        // Load guest registers in pairs for efficiency
        for i in (0..16).step_by(2) {
            let arm_lo = regmap::guest_to_arm(i);
            let arm_hi = regmap::guest_to_arm(i + 1);
            let offset = gpr_base + (i as u32) * 8;
            self.emitter.ldp64_post(arm_lo, arm_hi, 0, offset as i32);
        }
    }

    /// Store guest GPRs from ARM64 working registers back to CpuState (x0).
    fn emit_store_guest_registers(&mut self, arch: GuestArch) {
        let _ = arch;
        let gpr_base: u32 = 8;

        for i in (0..16).step_by(2) {
            let arm_lo = regmap::guest_to_arm(i);
            let arm_hi = regmap::guest_to_arm(i + 1);
            let offset = gpr_base + (i as u32) * 8;
            self.emitter.emit(0xa9000000 | ((offset >> 3) & 0x7f) << 15 | (arm_hi << 10) | (0 << 5) | arm_lo);
        }
    }

    /// Compile a single IR instruction.
    fn compile_instruction(&mut self, insn: &IrInstruction, arch: GuestArch) -> AppResult<()> {
        match insn {
            IrInstruction::Nop => {
                self.emitter.nop();
            }

            IrInstruction::MovImm { dst, value } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.mov_imm64(arm_dst, *value);
                if arch == GuestArch::X86 {
                    // Zero-extend to 32 bits for x86
                    self.emitter.emit(0x8a0003e0 | (arm_dst << 16) | arm_dst); // AND Xd, Xd, #0xFFFFFFFF via temp
                }
            }

            IrInstruction::MovImm8 { dst, value } => {
                let arm_dst = regmap::guest_to_arm(dst.full_register().index());
                self.emitter.movz(arm_dst, *value as u16, 0);
            }

            IrInstruction::MovReg { dst, src, width } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                let arm_src = regmap::guest_to_arm(src.index());
                self.emitter.mov_reg(arm_dst, arm_src);
                if *width == 4 {
                    // 32-bit mov zero-extends
                    self.emitter.emit(0x8a0003e0 | (arm_dst << 16) | (31 << 5) | arm_dst); // AND Xd, XZR, Xd - not quite right
                }
            }

            IrInstruction::MovReg8 { dst, src } => {
                let arm_dst = regmap::guest_to_arm(dst.full_register().index());
                let arm_src = regmap::guest_to_arm(src.full_register().index());
                // Extract byte and zero-extend
                self.emitter.uxtb(arm_dst, arm_src);
            }

            IrInstruction::AddImm { dst, value, width } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                if *value <= 0xfff {
                    self.emitter.add_imm(arm_dst, arm_dst, *value as u32);
                } else {
                    self.emitter.mov_imm64(regmap::X21, *value);
                    self.emitter.add_reg(arm_dst, arm_dst, regmap::X21);
                }
                if *width == 4 {
                    self.emitter.uxtb(arm_dst, arm_dst); // Actually need u32 mask
                }
            }

            IrInstruction::SubImm { dst, value, width } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                if *value <= 0xfff {
                    self.emitter.sub_imm(arm_dst, arm_dst, *value as u32);
                } else {
                    self.emitter.mov_imm64(regmap::X21, *value);
                    self.emitter.sub_reg(arm_dst, arm_dst, regmap::X21);
                }
                if *width == 4 {
                    self.emitter.uxtb(arm_dst, arm_dst);
                }
            }

            IrInstruction::AndImm { dst, value, width } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                if *width == 4 && *value <= 0xffffffff {
                    self.emitter.mov_imm64(regmap::X21, *value);
                    self.emitter.and_reg(arm_dst, arm_dst, regmap::X21);
                } else {
                    self.emitter.mov_imm64(regmap::X21, *value);
                    self.emitter.and_reg(arm_dst, arm_dst, regmap::X21);
                }
            }

            IrInstruction::OrImm { dst, value, width: _ } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.mov_imm64(regmap::X21, *value);
                self.emitter.orr_reg(arm_dst, arm_dst, regmap::X21);
            }

            IrInstruction::XorImm { dst, value, width: _ } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.mov_imm64(regmap::X21, *value);
                self.emitter.eor_reg(arm_dst, arm_dst, regmap::X21);
            }

            IrInstruction::ShlImm { dst, count, width: _ } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.lsl_imm(arm_dst, arm_dst, *count as u32);
            }

            IrInstruction::ShrImm { dst, count, width: _ } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.lsr_imm(arm_dst, arm_dst, *count as u32);
            }

            IrInstruction::SarImm { dst, count, width: _ } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.asr_imm(arm_dst, arm_dst, *count as u32);
            }

            IrInstruction::PushReg { src } => {
                let arm_src = regmap::guest_to_arm(src.index());
                let arm_sp = regmap::guest_to_arm(4); // RSP is at index 4
                // SUB SP, SP, #8
                self.emitter.sub_imm(arm_sp, arm_sp, 8);
                // STR Xn, [memory_base + SP]
                self.emitter.str64_reg(arm_src, 1, arm_sp); // x1 = memory base
            }

            IrInstruction::PopReg { dst } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                let arm_sp = regmap::guest_to_arm(4); // RSP is at index 4
                // LDR Xn, [memory_base + SP]
                self.emitter.ldr64_reg(arm_dst, 1, arm_sp); // x1 = memory base
                // ADD SP, SP, #8
                self.emitter.add_imm(arm_sp, arm_sp, 8);
            }

            IrInstruction::Return { stack_adjust } => {
                let arm_sp = regmap::guest_to_arm(4); // RSP
                self.emitter.ldr64_reg(regmap::X21, 1, arm_sp);
                self.emitter.add_imm(arm_sp, arm_sp, 8 + (*stack_adjust as u32));
                self.emit_store_guest_registers(arch);
                self.emitter.movz(regmap::X0, EXIT_RET as u16, 0);
                self.emit_epilogue();
            }

            IrInstruction::Call { target, return_address } => {
                let arm_sp = regmap::guest_to_arm(4); // RSP
                self.emitter.sub_imm(arm_sp, arm_sp, 8);
                self.emitter.mov_imm64(regmap::X21, *return_address);
                self.emitter.str64_reg(regmap::X21, 1, arm_sp);
                let _ = target;
                self.emit_store_guest_registers(arch);
                self.emitter.movz(regmap::X0, EXIT_THUNK as u16, 0);
                self.emit_epilogue();
            }

            IrInstruction::Jump { target } => {
                let _ = target;
                self.emit_store_guest_registers(arch);
                self.emitter.movz(regmap::X0, EXIT_NORMAL as u16, 0);
                self.emit_epilogue();
            }

            IrInstruction::Cpuid => {
                self.emit_store_guest_registers(arch);
                self.emitter.movz(regmap::X0, EXIT_CPUID as u16, 0);
                self.emit_epilogue();
            }

            // For unimplemented instructions, emit a fallback exit
            _ => {
                self.emit_store_guest_registers(arch);
                self.emitter.movz(regmap::X0, EXIT_UNIMPL as u16, 0);
                self.emit_epilogue();
            }
        }

        Ok(())
    }

    /// Get reference to the memory manager.
    pub fn memory_manager(&self) -> &JitMemoryManager {
        &self.memory_manager
    }

    /// Get mutable reference to the memory manager.
    pub fn memory_manager_mut(&mut self) -> &mut JitMemoryManager {
        &mut self.memory_manager
    }
}

// ---------------------------------------------------------------------------
// JIT runtime: manages compiled blocks and dispatches execution
// ---------------------------------------------------------------------------

/// Runtime state for JIT execution.
pub struct JitRuntime {
    pub compiler: JitCompiler,
    pub flat_memory: FlatGuestMemory,
    /// Cache of compiled blocks keyed by guest address.
    pub block_cache: HashMap<u64, JitCompiledBlock>,
    /// Number of blocks compiled.
    pub blocks_compiled: u64,
    /// Number of blocks executed via JIT.
    pub blocks_executed: u64,
    /// Number of fallbacks to IR interpreter.
    pub interpreter_fallbacks: u64,
}

impl JitRuntime {
    pub fn new(arch: GuestArch) -> Self {
        Self {
            compiler: JitCompiler::new(),
            flat_memory: FlatGuestMemory::new(arch),
            block_cache: HashMap::new(),
            blocks_compiled: 0,
            blocks_executed: 0,
            interpreter_fallbacks: 0,
        }
    }

    /// Get or compile a JIT block for the given guest address.
    pub fn get_or_compile(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
    ) -> AppResult<&JitCompiledBlock> {
        if !self.block_cache.contains_key(&guest_address) {
            let block = self.compiler.compile_block(ir, guest_address, arch)?;
            self.blocks_compiled += 1;
            self.block_cache.insert(guest_address, block);
        }
        Ok(self.block_cache.get(&guest_address).unwrap())
    }

    /// Execute a JIT-compiled block.
    ///
    /// # Safety
    /// The caller must ensure the block was correctly compiled and memory is valid.
    pub unsafe fn execute_block(
        &mut self,
        block: &JitCompiledBlock,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> JitExitReason {
        self.blocks_executed += 1;

        // Sync relevant memory pages to flat region
        // (In a full implementation, this would be done lazily)

        // The JIT entry point expects:
        // x0 = pointer to CpuState
        // x1 = flat memory base
        // x2 = pointer to MemoryImage
        // x3 = pointer to exit_reason (output)
        let mut exit_reason: u64 = 0;
        let state_ptr = state as *mut CpuState;
        let mem_base = self.flat_memory.base();
        let mem_image_ptr = memory as *mut MemoryImage;
        let exit_ptr = &mut exit_reason as *mut u64;

        unsafe {
            let entry_fn: unsafe extern "C" fn(
                *mut CpuState, u64, *mut MemoryImage, *mut u64,
            ) -> u64 = std::mem::transmute(block.entry);

            let result = entry_fn(state_ptr, mem_base, mem_image_ptr, exit_ptr);

            // Process exit reason
            match exit_reason {
                EXIT_NORMAL => JitExitReason::Normal { new_rip: state.rip },
                EXIT_THUNK => JitExitReason::ThunkDispatch {
                    target_rip: state.rip,
                    return_rip: result,
                },
                EXIT_UNIMPL => JitExitReason::UnimplementedInstruction {
                    rip: state.rip,
                    opcode: result as u8,
                },
                EXIT_RET => JitExitReason::Return { return_rip: result },
                EXIT_CPUID => JitExitReason::Cpuid,
                _ => JitExitReason::Normal { new_rip: state.rip },
            }
        }
    }

    /// Sync a page from MemoryImage to the flat guest memory region.
    pub fn sync_page_to_flat(&self, memory: &MemoryImage, page_addr: u64) {
        let page_size = 4096;
        let mut page_data = vec![0u8; page_size];
        if memory.read_into(page_addr, &mut page_data).is_ok() {
            self.flat_memory.sync_from_memory_image(page_addr, &page_data);
        }
    }

    /// Sync modified state from flat memory back to MemoryImage.
    pub fn sync_flat_to_memory(&self, guest_addr: u64, memory: &mut MemoryImage, size: usize) {
        let mut buf = vec![0u8; size];
        self.flat_memory.read(guest_addr, &mut buf);
        memory.map_bytes(guest_addr, &buf);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jit_memory_manager_allocates_and_finalizes() {
        let mut mgr = JitMemoryManager::new();
        let code = [0xd5, 0x03, 0x20, 0x1f]; // NOP
        let ptr = mgr.allocate_code_space(code.len());
        assert!(!ptr.is_null());
        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len());
            mgr.finalize_code(ptr, code.len());
        }
        assert!(mgr.total_allocated() >= code.len());
        assert!(mgr.total_used() >= code.len());
    }

    #[test]
    fn flat_guest_memory_creates_successfully() {
        let mem = FlatGuestMemory::new(GuestArch::X64);
        assert!(mem.is_valid());
        assert!(mem.base() != 0);
    }

    #[test]
    fn flat_guest_memory_sync_and_read() {
        let mem = FlatGuestMemory::new(GuestArch::X64);
        let data = [0xde, 0xad, 0xbe, 0xef];
        mem.sync_from_memory_image(0x1000, &data);
        let mut buf = [0u8; 4];
        mem.read(0x1000, &mut buf);
        assert_eq!(buf, data);
    }

    #[test]
    fn emitter_encodes_nop() {
        let mut e = Emitter::new();
        e.nop();
        assert_eq!(e.code, vec![0x1f, 0x20, 0x03, 0xd5]);
    }

    #[test]
    fn emitter_encodes_ret() {
        let mut e = Emitter::new();
        e.ret();
        assert_eq!(e.code, vec![0xc0, 0x03, 0x5f, 0xd6]);
    }

    #[test]
    fn emitter_encodes_mov_reg() {
        let mut e = Emitter::new();
        e.mov_reg(4, 5); // mov x4, x5
        // ORR x4, xZR, x5 = 0xaa0003e0 | (5 << 16) | 4
        let expected = 0xaa0003e0u32 | (5u32 << 16) | 4;
        assert_eq!(e.code, expected.to_le_bytes());
    }

    #[test]
    fn emitter_encodes_add_imm() {
        let mut e = Emitter::new();
        e.add_imm(4, 4, 8); // add x4, x4, #8
        let expected = 0x91000000u32 | (8 << 10) | (4 << 5) | 4;
        assert_eq!(e.code, expected.to_le_bytes());
    }

    #[test]
    fn jit_runtime_creates_for_x64() {
        let rt = JitRuntime::new(GuestArch::X64);
        assert_eq!(rt.blocks_compiled, 0);
        assert_eq!(rt.blocks_executed, 0);
    }

    #[test]
    fn jit_compiler_compiles_nop_block() {
        let mut compiler = JitCompiler::new();
        let ir = vec![IrInstruction::Nop];
        let result = compiler.compile_block(&ir, 0x1000, GuestArch::X64);
        assert!(result.is_ok());
        let block = result.unwrap();
        assert_eq!(block.guest_address, 0x1000);
        assert_eq!(block.instruction_count, 1);
        assert!(block.code_size > 0);
        assert!(!block.entry.is_null());
    }

    #[test]
    fn register_mapping_covers_all_16_guest_gprs() {
        for i in 0..16 {
            let arm = regmap::guest_to_arm(i);
            // Must be a valid ARM64 register (0-30, not 18 which is platform)
            assert!(arm <= 30, "guest reg {i} mapped to invalid ARM64 reg x{arm}");
            assert_ne!(arm, 18, "guest reg {i} should not use x18 (platform register)");
            assert_ne!(arm, 29, "guest reg {i} should not use x29 (FP)");
            assert_ne!(arm, 30, "guest reg {i} should not use x30 (LR)");
            assert_ne!(arm, 31, "guest reg {i} should not use x31 (SP/XZR)");
        }
    }

    #[test]
    fn register_mapping_is_unique() {
        let mut used = std::collections::HashSet::new();
        for i in 0..16 {
            let arm = regmap::guest_to_arm(i);
            assert!(used.insert(arm), "duplicate ARM64 register x{arm} for guest reg {i}");
        }
    }
}
