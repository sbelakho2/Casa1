use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Register {
    /// Reconstruct a `Register` from its architectural index (0..15).  Used
    /// by the Tier-2 register allocator when lowering SSA locations back to
    /// IR operands.
    pub fn from_index(index: usize) -> Self {
        match index & 0x0f {
            0 => Self::Rax,
            1 => Self::Rcx,
            2 => Self::Rdx,
            3 => Self::Rbx,
            4 => Self::Rsp,
            5 => Self::Rbp,
            6 => Self::Rsi,
            7 => Self::Rdi,
            8 => Self::R8,
            9 => Self::R9,
            10 => Self::R10,
            11 => Self::R11,
            12 => Self::R12,
            13 => Self::R13,
            14 => Self::R14,
            _ => Self::R15,
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::Rax => 0,
            Self::Rcx => 1,
            Self::Rdx => 2,
            Self::Rbx => 3,
            Self::Rsp => 4,
            Self::Rbp => 5,
            Self::Rsi => 6,
            Self::Rdi => 7,
            Self::R8 => 8,
            Self::R9 => 9,
            Self::R10 => 10,
            Self::R11 => 11,
            Self::R12 => 12,
            Self::R13 => 13,
            Self::R14 => 14,
            Self::R15 => 15,
        }
    }

    pub(crate) fn from_modrm(code: u8) -> Self {
        match code & 0x0f {
            0 => Self::Rax,
            1 => Self::Rcx,
            2 => Self::Rdx,
            3 => Self::Rbx,
            4 => Self::Rsp,
            5 => Self::Rbp,
            6 => Self::Rsi,
            7 => Self::Rdi,
            8 => Self::R8,
            9 => Self::R9,
            10 => Self::R10,
            11 => Self::R11,
            12 => Self::R12,
            13 => Self::R13,
            14 => Self::R14,
            _ => Self::R15,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Rax => "rax",
            Self::Rcx => "rcx",
            Self::Rdx => "rdx",
            Self::Rbx => "rbx",
            Self::Rsp => "rsp",
            Self::Rbp => "rbp",
            Self::Rsi => "rsi",
            Self::Rdi => "rdi",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::R10 => "r10",
            Self::R11 => "r11",
            Self::R12 => "r12",
            Self::R13 => "r13",
            Self::R14 => "r14",
            Self::R15 => "r15",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct XmmValue {
    pub low: u64,
    pub high: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct YmmValue {
    pub low: XmmValue,
    pub high: XmmValue,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZmmValue {
    pub low: YmmValue,
    pub high: YmmValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CpuState {
    pub arch: GuestArch,
    pub gpr: [u64; 16],
    pub xmm: [XmmValue; 16],
    #[serde(default)]
    pub ymm_upper: [XmmValue; 16],
    #[serde(default)]
    pub zmm_upper: [YmmValue; 16],
    #[serde(default)]
    pub opmask: [u64; 8],
    pub flags: Flags,
    #[serde(default)]
    pub eflags_extra: u64,
    pub x87: X87State,
    #[serde(default = "default_mxcsr")]
    pub mxcsr: u32,
    #[serde(default)]
    pub segment_bases: SegmentBases,
    pub rip: u64,
    /// Debug registers DR0-DR7 (MOV DRn, r / MOV r, DRn).
    #[serde(default)]
    pub dr: [u64; 8],
    /// MPX bounds registers BND0-BND3 (lower, upper).
    #[serde(default)]
    pub bnd: [(u64, u64); 4],
    /// CET shadow stack pointer (SSP).
    #[serde(default)]
    pub ssp: u64,
    /// Fault channel from JIT-compiled code to the dispatcher: set by
    /// `jit_helper_load` when a guest read hits unmapped memory (the helper
    /// cannot propagate an error through the extern "C" ABI).  The dispatcher
    /// (`CpuEngine::execute_with_jit`) checks and clears this marker after a
    /// compiled block returns and converts it into the same "unmapped guest
    /// memory" error the interpreter raises, so an access violation is never
    /// silently observed as a successful zero-valued read.
    #[serde(default)]
    pub jit_pending_fault: Option<u64>,
    /// Access type of the pending JIT fault: `true` when
    /// `jit_pending_fault` was set by a guest WRITE (`jit_helper_store`),
    /// `false` for a guest read (`jit_helper_load`).  Valid only while
    /// `jit_pending_fault` is `Some`.
    #[serde(default)]
    pub jit_pending_fault_write: bool,
    /// Deferred arithmetic flags (interpreter lazy-flag fast path).  While
    /// `Some`, the arithmetic bits in `flags` are stale and are recomputed
    /// from these operands on the first read.  Always `None` at API
    /// boundaries — `execute_ir_with_hashing` materialises before returning.
    #[serde(skip)]
    pub(crate) pending_flags: Option<PendingFlags>,
    /// Tier-2 JIT spill slots.  This is host-only scratch storage: the
    /// interpreter and every JIT tier preserve it, but it is never part of
    /// the guest-visible register or memory state (serialization skips it).
    #[serde(default, skip)]
    pub(crate) jit_spill: [u64; 32],
}

impl CpuState {
    pub fn new(arch: GuestArch) -> Self {
        Self {
            arch,
            gpr: [0; 16],
            xmm: [XmmValue::default(); 16],
            ymm_upper: [XmmValue::default(); 16],
            zmm_upper: [YmmValue::default(); 16],
            opmask: [0u64; 8],
            flags: Flags {
                cf: false,
                pf: false,
                af: false,
                zf: false,
                sf: false,
                of: false,
            },
            eflags_extra: 0,
            x87: X87State::default(),
            mxcsr: default_mxcsr(),
            segment_bases: SegmentBases::default(),
            rip: 0,
            dr: [0u64; 8],
            bnd: [(0u64, 0u64); 4],
            ssp: 0,
            jit_pending_fault: None,
            jit_pending_fault_write: false,
            pending_flags: None,
            jit_spill: [0; 32],
        }
    }

    pub fn get(&self, reg: Register) -> u64 {
        self.gpr[reg.index()] & self.arch.register_mask()
    }

    pub fn set(&mut self, reg: Register, value: u64) {
        self.gpr[reg.index()] = value & self.arch.register_mask();
    }

    pub fn get_byte(&self, reg: ByteRegister) -> u8 {
        let shift = match reg {
            ByteRegister::Ah | ByteRegister::Ch | ByteRegister::Dh | ByteRegister::Bh => 8,
            _ => 0,
        };
        ((self.get(reg.full_register()) >> shift) & 0xff) as u8
    }

    pub fn set_byte(&mut self, reg: ByteRegister, value: u8) {
        let full = reg.full_register();
        let (mask, shift) = match reg {
            ByteRegister::Ah | ByteRegister::Ch | ByteRegister::Dh | ByteRegister::Bh => {
                (!0xff00_u64, 8)
            }
            _ => (!0xff_u64, 0),
        };
        let next = (self.get(full) & mask) | ((value as u64) << shift);
        self.set(full, next);
    }

    pub fn segment_base(&self, segment: SegmentRegister) -> u64 {
        match segment {
            SegmentRegister::Fs => self.segment_bases.fs,
            SegmentRegister::Gs => self.segment_bases.gs,
        }
    }

    pub fn get_xmm(&self, index: u8) -> XmmValue {
        self.xmm[index as usize]
    }

    pub fn set_xmm(&mut self, index: u8, value: XmmValue) {
        self.xmm[index as usize] = value;
    }

    pub fn get_ymm(&self, index: u8) -> YmmValue {
        YmmValue {
            low: self.get_xmm(index),
            high: self.ymm_upper[index as usize],
        }
    }

    pub fn set_ymm(&mut self, index: u8, value: YmmValue) {
        self.set_xmm(index, value.low);
        self.ymm_upper[index as usize] = value.high;
    }

    pub fn clear_ymm_upper(&mut self, index: u8) {
        self.ymm_upper[index as usize] = XmmValue::default();
    }

    pub fn clear_all_ymm_upper(&mut self) {
        self.ymm_upper.fill(XmmValue::default());
    }

    pub fn get_zmm(&self, index: u8) -> ZmmValue {
        ZmmValue {
            low: self.get_ymm(index),
            high: self.zmm_upper[index as usize],
        }
    }

    pub fn set_zmm(&mut self, index: u8, value: ZmmValue) {
        self.set_ymm(index, value.low);
        self.zmm_upper[index as usize] = value.high;
    }

    pub fn clear_zmm_upper(&mut self, index: u8) {
        self.zmm_upper[index as usize] = YmmValue::default();
    }

    pub fn clear_all_zmm_upper(&mut self) {
        self.zmm_upper.fill(YmmValue::default());
    }

    pub fn get_opmask(&self, index: u8) -> u64 {
        self.opmask[index as usize & 0x7]
    }

    pub fn set_opmask(&mut self, index: u8, value: u64) {
        self.opmask[index as usize & 0x7] = value;
    }

    /// Get MPX bounds register (BND0-BND3) as (lower, upper).
    pub fn get_bnd(&self, index: u8) -> (u64, u64) {
        self.bnd[index as usize & 0x3]
    }

    /// Set MPX bounds register (BND0-BND3) to (lower, upper).
    pub fn set_bnd(&mut self, index: u8, value: (u64, u64)) {
        self.bnd[index as usize & 0x3] = value;
    }

    // ── Lazy flag materialisation ───────────────────────────────────────

    /// Compute and install any parked arithmetic flags.  Cheap no-op when no
    /// computation is pending (the common case for non-ALU instructions).
    #[inline]
    pub(crate) fn materialize_flags(&mut self, stats: &mut LazyFlagStats) {
        if let Some(pending) = self.pending_flags.take() {
            self.flags = pending.evaluate();
            stats.materialised += 1;
        }
    }

    /// Park the flags of an ADD result.  Overwriting an already-parked set
    /// means its eager computation was skipped.
    #[inline]
    pub(crate) fn defer_add_flags(
        &mut self,
        lhs: u64,
        rhs: u64,
        result: u64,
        width_bits: usize,
        stats: &mut LazyFlagStats,
    ) {
        stats.skipped += u64::from(self.pending_flags.is_some());
        self.pending_flags = Some(PendingFlags {
            lhs,
            rhs,
            result,
            op: FlagOp::Add,
            width_bits: width_bits as u8,
        });
    }

    /// Park the flags of a SUB/CMP result.
    #[inline]
    pub(crate) fn defer_sub_flags(
        &mut self,
        lhs: u64,
        rhs: u64,
        result: u64,
        width_bits: usize,
        stats: &mut LazyFlagStats,
    ) {
        stats.skipped += u64::from(self.pending_flags.is_some());
        self.pending_flags = Some(PendingFlags {
            lhs,
            rhs,
            result,
            op: FlagOp::Sub,
            width_bits: width_bits as u8,
        });
    }

    /// Park the flags of a logic (AND/OR/XOR/TEST) result.
    #[inline]
    pub(crate) fn defer_logic_flags(
        &mut self,
        result: u64,
        width_bits: usize,
        stats: &mut LazyFlagStats,
    ) {
        stats.skipped += u64::from(self.pending_flags.is_some());
        self.pending_flags = Some(PendingFlags {
            lhs: 0,
            rhs: 0,
            result,
            op: FlagOp::Logic,
            width_bits: width_bits as u8,
        });
    }

    /// Drop a parked flag computation because an instruction wrote
    /// `state.flags` directly.  Counts as a skipped materialisation.
    #[inline]
    pub(crate) fn discard_pending_flags(&mut self, stats: &mut LazyFlagStats) {
        if self.pending_flags.take().is_some() {
            stats.skipped += 1;
        }
    }

    /// Materialise any parked arithmetic flags for JIT code.
    ///
    /// The interpreter parks ADD/SUB/CMP/LOGIC flag results in
    /// `CpuState::pending_flags` until the first flag read.  Native conditional
    /// branches read the six flag bytes directly from `CpuState`, so they must
    /// first force the parked computation into those bytes.  This is a no-op
    /// when no computation is pending (the common compiled-code case, because
    /// `jit_helper_set_flags` writes the flags eagerly and clears the park).
    pub(crate) fn materialize_pending_flags_for_jit(&mut self) {
        let mut stats = LazyFlagStats::default();
        self.materialize_flags(&mut stats);
        flush_lazy_flag_stats(stats);
    }
}

pub(crate) fn default_mxcsr() -> u32 {
    0x1f80
}
